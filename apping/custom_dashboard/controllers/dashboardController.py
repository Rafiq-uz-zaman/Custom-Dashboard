import copy
import datetime
import re
import uuid
from typing import Optional

from flask import request
from apping.custom_dashboard.model import (
    ChartData,
    DashboardRequest,
    DeleteDashboard,
    TableData,
    UpdateDashboard,
    VisualizationType,
    Visualization,
    VizData,
)
from apping.custom_dashboard.controllers.visualizationController import (
    create_bar_chart,
    save_visualizations,
)


from apping.custom_dashboard.controllers.filtersController import (
    CustomDashboardAdvancedFilters,
)


from apping import ResponseDto, date_delta, es, format_dates_list, daterange
from elasticsearch.exceptions import NotFoundError, RequestError, TransportError

from apping.custom_dashboard.controllers.esController import es_con
from utils.util import logger
import time
import json

# Cache variables
CACHE_TTL = 300  # seconds
_last_cache_time = 0
_field_sources_cache = {}


def convert_local_to_utc(local_date):
    # Try parsing with microseconds, fallback to without
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            local_datetime_obj = datetime.datetime.strptime(local_date, fmt)
            local_utc_time = local_datetime_obj.astimezone(
                datetime.timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            return local_utc_time
        except ValueError:
            continue
    raise ValueError(f"time data '{local_date}' does not match expected formats")


def convert_list_to_strings(json_obj, parent_key="", separator="."):
    items = {}
    for key, value in json_obj.items():
        new_key = f"{parent_key}{separator}{key}" if parent_key else key
        if isinstance(value, dict):
            items.update(convert_list_to_strings(value, new_key, separator))
        elif isinstance(value, list):
            if all(isinstance(item, dict) for item in value):
                items[new_key] = ", ".join(json.dumps(item) for item in value)
            else:
                items[new_key] = ", ".join(value)
        else:
            items[new_key] = value
    return items


def normalize_field(field: str) -> str:
    """
    Normalize field names for Elasticsearch aggregations.
    - Text fields → use `.keyword`
    - Numeric/date fields → keep as is
    - If already has .keyword or is @timestamp → keep as is
    """
    if field in ["@timestamp"]:  # keep timestamp as is
        return field
    if field.endswith(".keyword"):  # already normalized
        return field
    # Default: treat as text field → add .keyword
    return field + ".keyword"


def build_es_query(
    gte,
    lte,
    search=None,
    filter_response=None,
    selected_fields=None,
    size=20,
    from_=0,
    sort_field=None,
    sort_order=None,
    search_after=None,
    chart_type=None,
    chart_fields=None,
):

    if gte and lte:
        query_body = {
            "size": size,
            "from": from_,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": convert_local_to_utc(gte),
                                    "lte": convert_local_to_utc(lte),
                                    "format": "strict_date_optional_time",
                                }
                            }
                        }
                    ],
                    "must": [],
                    "must_not": [],
                }
            },
            "sort": [],
        }
    else:
        query_body = {
            "size": size,
            "from": from_,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [],
                    "must": [],
                    "must_not": [],
                }
            },
            "sort": [],
        }
    # normalized_fields = (
    #     [normalize_field(f) for f in selected_fields] if selected_fields else []
    # )
    if selected_fields:
        query_body["_source"] = {"includes": selected_fields}
    if search:
        query_body["query"]["bool"]["must"].append(
            {
                "multi_match": {
                    "query": search.replace('"', ""),
                    "type": "phrase" if '"' in search else "best_fields",
                    "lenient": True,
                }
            }
        )
    if filter_response:
        advanced_filter = CustomDashboardAdvancedFilters(filter_response, query_body)
        advanced_filter.evaluate_filter_expression()

    if chart_type in ["bar", "pie", "donut"]:
        if not chart_fields:
            raise ValueError("fields required for bar/pie/donut charts")
        normalized_fields = [normalize_field(f) for f in chart_fields]
        agg = None
        for i, field in enumerate(reversed(chart_fields)):
            if agg is None:
                agg = {"terms": {"field": field, "size": size}}
            else:
                agg = {
                    "terms": {"field": field, "size": size},
                    "aggs": {f"level_{i}": agg},
                }

        query_body["aggs"] = {"chart_data": agg}

    elif chart_type in ["line", "area"]:
        delta_obj = date_delta(gte, lte)
        query_body["aggs"] = {
            "chart_data": {
                "date_histogram": {
                    "field": "@timestamp",
                    **delta_obj.date_histogram_dict,
                    "min_doc_count": 0,
                    "extended_bounds": {"min": gte, "max": lte},
                }
            }
        }

    if sort_field and sort_order:
        query_body["sort"].append({sort_field: {"order": sort_order}})
    if search_after:
        query_body["search_after"] = search_after
    return query_body


def get_table_data(table: TableData):
    """
    Extracts table data from the visualizers in a dashboard.
    Returns a dictionary with the table data.
    """

    print(f"Received table request: {table}")

    # for table in table_request:
    index = table.index
    title = table.title
    custom_filters = table.custom_filter

    lte = None
    gte = None

    size = table.size
    page = table.page

    if page > 1:
        page = (page - 1) * size

    sort_field = table.sort_field
    sort_order = table.sort_order

    if (
        table.lte is not None
        and table.gte is not None
        and index != "wazuh-states-vulnerabilities-*"
    ):
        lte = table.lte
        gte = table.gte

    table_query = {
        "query": {
            "bool": {
                "must": [
                    {"term": {"title.keyword": title}},
                    {"term": {"index_name.keyword": index}},
                ]
            }
        },
    }

    print(f"Table query: {json.dumps(table_query, indent=2)}")

    table_data = {}

    res = es.search(index="saved_searches", body=table_query)
    print(f"Search result: {res}")
    for hit in res["hits"]["hits"]:
        print("??!!!")
        cols = hit["_source"]["columns"]
        filters = hit["_source"]["filter"]
        index = hit["_source"]["index_name"]

        if custom_filters is not None and len(custom_filters) > 0:
            filters.extend(custom_filters)

        query = build_es_query(
            gte=gte,
            lte=lte,
            search=None,
            filter_response=filters,
            selected_fields=cols,
            size=size,
            from_=page,
            sort_field=sort_field,
            sort_order=sort_order,
            search_after=None,  # Assuming no pagination with search_after for now
        )

        print(f"Executing query for index {index}: {json.dumps(query, indent=2)}")

        es_client = None
        if index == "logstash-*":
            es_client = es_con
        else:
            es_client = es

        data = es_client.search(
            index=index,
            body=query,
        )

        print(f"Query result: {data}")

        details_list = []
        for event in data["hits"]["hits"]:
            document_id = event["_id"]
            source_data = event["_source"]
            source_data = convert_list_to_strings(source_data)
            flattened_doc = source_data
            flattened_doc["_id"] = document_id
            details_list.append(flattened_doc)

        # table_data.append(
        #     {
        #         "details": details_list,
        #         "total_records": data["hits"]["total"]["value"],
        #     }
        # )

        table_data = {
            "details": details_list,
            "total_records": data["hits"]["total"]["value"],
        }

    return {
        "data": table_data,
        "responseDto": ResponseDto().ok(),
    }, 200


def resolve_field_name(es, index_pattern: str, field: str) -> Optional[str]:
    """
    Given an index pattern and a field, return the correct field name to use
    for aggregations (with or without .keyword).

    :param es: Elasticsearch client
    :param index_pattern: Index pattern (e.g., "logstash-*")
    :param field: Field name (e.g., "alert.action")
    :return: Correct field name for aggregations, or None if not found
    """
    try:
        mapping = es.indices.get_field_mapping(fields=field, index=index_pattern)
    except Exception as e:
        print(f"Error fetching mapping: {e}")
        return None

    # Flatten response
    for idx, data in mapping.items():
        field_mapping = data.get("mappings", {}).get(field, {}).get("mapping", {})
        if not field_mapping:
            continue

        # field_mapping looks like {"action": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}
        field_info = list(field_mapping.values())[0]

        if field_info.get("type") == "keyword":
            return field  # already keyword → safe to use directly

        if field_info.get("type") == "text":
            # check if it has a keyword subfield
            if "fields" in field_info and "keyword" in field_info["fields"]:
                return f"{field}.keyword"
            else:
                print(
                    f"Field {field} is text without keyword subfield — not suitable for terms agg."
                )
                return None

    return None


# ---------- CREATE DASHBOARD VISUALIZATIONS FUNCTION----------
def create_dashboard(body: DashboardRequest):
    """
    Create a dashboard resource
    """
    logger.info(msg=f"{body}")

    try:
        # Extract dashboard_id from the request body
        dashboard_id = body.dashboard_id
        dashboard_name = body.name

        # Check if document exists in custom_dashboard index
        try:
            if dashboard_id:
                # Search for existing dashboard with the same dashboard_id
                search_query = {
                    "query": {"term": {"dashboard_id.keyword": str(dashboard_id)}}
                }

                response = es.search(
                    index=".custom_dashboards", body=search_query, size=1
                )

                # Check if any documents were found
                if response["hits"]["total"]["value"] > 0:
                    return {
                        "message": "Dashboard with this ID already exists!",
                    }, 400

            # Check if dashboard with same NAME exists
            if dashboard_name:
                name_query = {"query": {"term": {"name.keyword": str(dashboard_name)}}}
                name_response = es.search(
                    index=".custom_dashboards", body=name_query, size=1
                )
                if name_response["hits"]["total"]["value"] > 0:
                    return {
                        "message": f"Dashboard name already exists!",
                    }, 400

            visualizers = body.visualizers

            inserted_visualizations, err = save_visualizations(
                ".saved_visualizations", visualizers
            )

            print(f"Inserted visualizations: {inserted_visualizations}")

            if inserted_visualizations is None:
                return {
                    "message": "Error saving visualizations",
                    "error": err,
                }, 500

            if len(inserted_visualizations) == 0:
                print("No visualizations were inserted.")

            print(f"Inserted visualizations: {inserted_visualizations}")

            # generating uuid
            body.dashboard_id = uuid.uuid4()

            # If no existing dashboard found, proceed with creation
            # Add timestamps

            dashboard_data = body.model_dump()
            # Convert Visualization objects to dictionaries for JSON serialization
            dashboard_data["visualizers"] = [
                viz.model_dump() for viz in inserted_visualizations
            ]

            dashboard_data["created_at"] = datetime.datetime.now().isoformat()
            dashboard_data["updated_at"] = datetime.datetime.now().isoformat()

            print(f"Dashboard data to index: {dashboard_data}")

            # Index the new dashboard document
            index_response = es.index(index=".custom_dashboards", body=dashboard_data)

            return {
                "message": "Dashboard created successfully",
                "responseDto": ResponseDto().ok(),
            }, 201

        except NotFoundError:

            return {
                "message": "index does not exist",
                "responseDto": ResponseDto().conflict(),
            }, 400

    except RequestError as e:
        logger.error(f"Elasticsearch request error: {e}")
        return {"error": "Failed to process dashboard creation", "details": str(e)}, 500

    except TransportError as e:
        logger.error(f"Elasticsearch transport error: {e}")
        return {"error": "Failed to connect to Elasticsearch", "details": str(e)}, 500

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {"error": "Internal server error", "details": str(e)}, 500


# ---------- Update DASHBOARD VISUALIZATIONS FUNCTION----------
def update_dashboard(body: DashboardRequest):
    """
    update a dashboard resource
    """
    # logger.info(msg=f"{body}")

    try:
        # Extract dashboard_id from the request body
        dashboard_id = body.dashboard_id
        dashboard_name = body.name

        # Check if document exists in custom_dashboard index
        try:
            if not dashboard_id:
                return {"message": "Dashboard ID is required"}, 400

            # Search for existing dashboard with the same dashboard_id
            search_query = {
                "query": {"term": {"dashboard_id.keyword": str(dashboard_id)}}
            }

            response = es.search(index=".custom_dashboards", body=search_query, size=1)

            # Check if dashboard exists
            if response["hits"]["total"]["value"] == 0:
                return {
                    "message": "Dashboard not found!",
                }, 404

            dashboard_es_id = response["hits"]["hits"][0]["_id"]
            current_dashboard = response["hits"]["hits"][0]["_source"]

            # Check if dashboard with same NAME exists (only if name is being changed)
            # if dashboard_name and dashboard_name != current_dashboard.get("name"):
            #     name_query = {"query": {"term": {"name.keyword": str(dashboard_name)}}}
            #     name_response = es.search(
            #         index=".custom_dashboards", body=name_query, size=1
            #     )
            #     if name_response["hits"]["total"]["value"] > 0:
            #         return {
            #             "message": f"Dashboard {dashboard_name} already exists!",
            #         }, 400

            visualizers = body.visualizers

            print(f"Visualizers to update: {visualizers}")

            inserted_visualizations, err = save_visualizations(
                ".saved_visualizations", visualizers
            )

            # print(f"Updated visualizations: {inserted_visualizations}")

            if inserted_visualizations is None:
                return {
                    "message": "Error saving visualizations",
                    "error": err,
                }, 500

            if len(inserted_visualizations) == 0:
                print("No visualizations were updated.")

            # Prepare update data
            dashboard_data = body.model_dump()
            # Convert Visualization objects to dictionaries for JSON serialization
            dashboard_data["visualizers"] = [
                viz.model_dump() for viz in inserted_visualizations
            ]

            dashboard_data["updated_at"] = datetime.datetime.now().isoformat()

            # Remove fields that shouldn't be updated
            dashboard_data.pop("created_at", None)

            # Update the existing dashboard document
            update_response = es.update(
                index=".custom_dashboards",
                id=dashboard_es_id,
                body={"doc": dashboard_data},
            )

            return {
                "message": "Dashboard updated successfully",
                "responseDto": ResponseDto().ok(),
            }, 200

        except NotFoundError:

            return {
                "message": "index does not exist",
                "responseDto": ResponseDto().conflict(),
            }, 400

    except RequestError as e:
        logger.error(f"Elasticsearch request error: {e}")
        return {"error": "Failed to process dashboard creation", "details": str(e)}, 500

    except TransportError as e:
        logger.error(f"Elasticsearch transport error: {e}")
        return {"error": "Failed to connect to Elasticsearch", "details": str(e)}, 500

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return {"error": "Internal server error", "details": str(e)}, 500


# ---------- UPDATE DASHBOARD VISUALIZATONS FUNCTION----------
def update_dashboard_info(body: UpdateDashboard):
    """
    Update a dashboard by id (query param) with logging and its info like name and description.
    """

    logger.info(f"Received update request: {body}")

    try:
        dashboard_id = body.dashboard_id
        new_name = body.name
        new_description = body.description

        if not dashboard_id:
            return {"message": "dashboard_id is required"}, 400

        # Search for dashboard by dashboard_id
        search_query = {"query": {"term": {"dashboard_id.keyword": str(dashboard_id)}}}
        search_result = es.search(index=".custom_dashboards", body=search_query, size=1)

        if search_result["hits"]["total"]["value"] == 0:
            return {"message": "Dashboard not found"}, 404

        # Check if dashboard with same NAME exists
        if new_name:
            name_query = {"query": {"term": {"name.keyword": str(new_name)}}}
            name_response = es.search(
                index=".custom_dashboards", body=name_query, size=1
            )
            if name_response["hits"]["total"]["value"] > 0:
                return {
                    "message": f"Dashboard name already exists!",
                }, 400

        dashboard_es_id = search_result["hits"]["hits"][0]["_id"]
        old_data = search_result["hits"]["hits"][0]["_source"]

        update_data = {}
        if new_name is not None:
            update_data["name"] = new_name
        if new_description is not None:
            update_data["description"] = new_description
        update_data["updated_at"] = datetime.datetime.now().isoformat()

        # Log before changes
        logger.info(
            f"[UPDATE] Dashboard '{old_data.get('name')}' (ID: {dashboard_id}) - BEFORE: {old_data}"
        )

        es.update(
            index=".custom_dashboards", id=dashboard_es_id, body={"doc": update_data}
        )

        # Log after changes
        new_data = {**old_data, **update_data}
        logger.info(
            f"[UPDATE] Dashboard '{new_data.get('name')}' (ID: {dashboard_id}) - AFTER: {new_data}"
        )

        return {
            "message": "Dashboard updated successfully",
            "dashboard_id": dashboard_id,
            "responseDto": ResponseDto().ok(),
        }, 200

    except Exception as e:
        logger.error(f"Error updating dashboard: {e}")
        return {"error": "Internal server error", "details": str(e)}, 500


# ---------- DELETE DASHBOARD FUNCTION----------
def delete_dashboard(body: DeleteDashboard):
    """
    Delete a dashboard by NAME (query param) with logging
    """

    logger.info(f"Received update request: {body}")

    try:
        dashboard_name = body.dashboard_id
        if not dashboard_name:
            return {"message": "Query parameter 'name' is required"}, 400

        # Search existing dashboard
        search_query = {
            "query": {"term": {"dashboard_id.keyword": str(dashboard_name)}}
        }
        search_result = es.search(index=".custom_dashboards", body=search_query, size=1)

        if search_result["hits"]["total"]["value"] == 0:
            return {"message": "Dashboard not found"}, 404

        dashboard_id = search_result["hits"]["hits"][0]["_id"]
        old_data = search_result["hits"]["hits"][0]["_source"]

        # Log before deletion
        logger.info(
            f"[DELETE] Dashboard '{dashboard_name}' (ID: {dashboard_id}) - DATA: {old_data}"
        )

        # Perform delete
        es.delete(index=".custom_dashboards", id=dashboard_id)

        return {
            "message": "Dashboard deleted successfully",
            "dashboard_id": dashboard_name,
            "responseDto": ResponseDto().ok(),
        }

    except Exception as e:
        logger.error(f"Error deleting dashboard: {e}")
        return {"error": "Internal server error", "details": str(e)}, 500


# ---------- LIST ALL DASHBOARDS FUNCTION----------
def list_dashboards():
    """
    List all dashboards with name, description, updated_at
    Sorted by latest updated first
    """
    try:
        # Get pagination params from request (default: page=1, size=20)
        page = int(request.args.get("page", 1))
        size = int(request.args.get("size", 20))
        sort_field = request.args.get("field", "updated_at")
        sort_order = request.args.get("order", "desc")

        # Use .keyword for sortable text fields
        sortable_fields = {"name", "description", "dashboard_id"}
        es_sort_field = sort_field
        if sort_field in sortable_fields:
            es_sort_field = f"{sort_field}.keyword"

        # Calculate from_ for ES pagination
        from_ = (page - 1) * size

        query = {
            "_source": ["dashboard_id", "name", "description", "updated_at"],
            "query": {"match_all": {}},
            "sort": [{es_sort_field: {"order": sort_order}}],
        }
        response = es.search(
            index=".custom_dashboards", body=query, size=size, from_=from_
        )

        dashboards = [
            {
                "dashboard_id": hit["_source"].get("dashboard_id"),
                "name": hit["_source"].get("name"),
                "description": hit["_source"].get("description"),
                "updated_at": hit["_source"].get("updated_at"),
            }
            for hit in response["hits"]["hits"]
        ]

        total = response["hits"]["total"]["value"]
        return {
            "dashboards": dashboards,
            "total": total,
            "page": page,
            "size": size,
            "responseDto": ResponseDto().ok(),
        }

    except Exception as e:
        logger.error(f"Failed to list dashboards: {e}")
        return {"error": "Internal server error", "details": str(e)}, 500


# ---------- VIEW DASHBOARD DETAILS FUCNTION----------
def get_dashboard_details(dashboard_name: str):
    search_query = {"query": {"match": {"name": dashboard_name}}}
    response = es.search(index=".custom_dashboards", body=search_query, size=1)

    if response["hits"]["total"]["value"] == 0:
        return {"message": "Dashboard not found"}, 404

    source = response["hits"]["hits"][0]["_source"]

    # Only return selected fields
    filtered_data = {
        "visualizers": source.get("visualizers", []),
        "filters": source.get("filters", []),
        "time_filter": source.get("time_filter", None),
    }

    return {"dashboard": filtered_data, "responseDto": ResponseDto().ok()}


# ---------- FIELDS OPERATORS FOR DASHBOARD AND VISUALIZATONS FUNCTION----------
def fields_operators():
    field_name = request.args.get("field")
    if not field_name:
        return {"error": "Missing 'field' parameter"}, 400

    field_type, pattern = get_field_type_for_field(field_name)
    if not field_type:
        return {"error": f"Field '{field_name}' not found"}, 400

    operator_map = {
        "keyword": [
            "is",
            "is_not",
            "is_one_of",
            "is_not_one_of",
            "exists",
            "does_not_exist",
        ],
        "text": [
            "is",
            "is_not",
            "exists",
            "does_not_exist",
        ],
        "date": [
            "is",
            "is_not",
            "is_before",
            "is_after",
            "is_between",
            "exists",
            "does_not_exist",
        ],
        "integer": [
            "is",
            "is_not",
            "is_greater_than",
            "is_less_than",
            "is_between",
            "exists",
            "does_not_exist",
        ],
        "long": [
            "is",
            "is_not",
            "is_greater than",
            "is_less_than",
            "is_between",
            "exists",
            "does_not_exist",
        ],
        "double": [
            "is",
            "is_not",
            "is_greater_than",
            "is_less_than",
            "is_between",
            "exists",
            "does_not_exist",
        ],
        "float": [
            "is",
            "is_not",
            "is_greater_than",
            "is_less_than",
            "is_between",
            "exists",
            "does_not_exist",
        ],
        "boolean": ["is_true", "is_false", "exists", "does_not_exist"],
    }
    operators = operator_map.get(
        field_type, ["is", "is_not", "exists", "does_not_exist"]
    )

    # Determine case for UI dropdowns
    if field_type in ["keyword", "text", "date"]:
        value_case = "dropdown"
    elif field_type in ["integer", "long", "double", "float"]:
        value_case = "integer"
    elif field_type == "boolean":
        value_case = "boolean"
    else:
        value_case = "text"

    return {
        "case": value_case,
        "fieldDataType": field_type,
        "operators": operators,
        "sourceIndex": pattern,
        "responseDto": ResponseDto().ok(),
    }


# ---------- FIELDS VALUES FOR DASHBOARD AND VISUALIZATONS FUNCTION----------
def fields_values():
    # try:
    #     # Parse request body
    #     date = {"lte": request.json["lte"], "gte": request.json["gte"]}
    # except KeyError as err:
    #     return {"message": f"Timestamp not provided in request body: {str(err)}"}, 400

    # # Validate date format
    # if not isinstance(date, dict) or "lte" not in date or "gte" not in date:
    #     return {
    #         "message": "Invalid date format. Expected a dictionary with 'lte' and 'gte' keys."
    #     }, 400

    field_name = request.args.get("field")
    if not field_name:
        return {"error": "Missing 'field' parameter"}, 400

    values = get_field_values_service(field_name)
    return {"values": values, "responseDto": ResponseDto().ok()}


# ---------- REFRESH SOURCES FOR DASHBOARD AND VISUALIZATONS FUNCTION----------
def refresh_field_sources():
    """Fetch fresh field-to-index mapping from ES."""
    global _field_sources_cache, _last_cache_time

    index_patterns = {
        "wazuh-alerts-*": get_flattened_fields(es, "wazuh-alerts-*"),
        "wazuh-states-vulnerabilities-*": get_flattened_fields(
            es, "wazuh-states-vulnerabilities-*"
        ),
        "logstash-*": get_flattened_fields(es_con, "logstash-*"),
    }

    field_sources = {}
    for pattern, fields in index_patterns.items():
        for field in fields:
            field_sources.setdefault(field, []).append(pattern)

    _field_sources_cache = field_sources
    _last_cache_time = time.time()


# ---------- FIELDS FLATS FOR DASHBOARD AND VISUALIZATONS FUNCTION----------
def flatten_fields(properties, parent_key=""):
    """Recursively flatten Elasticsearch mapping properties."""
    fields = set()
    for field, value in properties.items():
        full_key = f"{parent_key}.{field}" if parent_key else field
        fields.add(full_key)
        if "properties" in value:
            fields.update(flatten_fields(value["properties"], full_key))
        elif value.get("type") == "nested" and "properties" in value:
            fields.update(flatten_fields(value["properties"], full_key))
    return fields


# ---------- GET FLATED FIELDS FOR DASHBOARD AND VISUALIZATONS FUNCTION----------
def get_flattened_fields(es_client, index_pattern):
    """Get all flattened fields for an index pattern."""
    mappings = set()
    try:
        all_mappings = es_client.indices.get_mapping(index=index_pattern)
        for idx, mapping in all_mappings.items():
            props = mapping["mappings"].get("properties", {})
            mappings.update(flatten_fields(props))
    except Exception as e:
        print(f"Error fetching fields for {index_pattern}: {e}")
    return mappings


# ---------- FIELDS TYPE FOR DASHBOARD AND VISUALIZATONS FUNCTION----------


def get_field_type(es, index_pattern: str, field: str) -> Optional[str]:
    """
    Return the type of `field` across all indices in `index_pattern`.
    If the field is not declared in any index, return None.
    Assumes the type is consistent across indices.
    """
    resp = es.indices.get_field_mapping(
        index=index_pattern, fields=field, params={"filter_path": "**.mappings.*"}
    )

    print(f"Field mapping response for {field} in {index_pattern}: {resp}")

    for payload in resp.values():
        mapping = payload.get("mappings", {}).get(field, {})
        if "mapping" in mapping:
            inner = mapping["mapping"]
            if isinstance(inner, dict) and inner:
                # Example: {"category": {"type": "text", "fields": {...}}}
                type_info = next(iter(inner.values()))
                return type_info.get("type")
    return None


# ---------- GET FIELDS SOURCES FOR DASHBOARD AND VISUALIZATONS FUNCTION----------
def get_all_fields_with_sources():
    """Return cached mapping unless TTL expired."""
    global _last_cache_time
    if not _field_sources_cache or (time.time() - _last_cache_time > CACHE_TTL):
        refresh_field_sources()
    return _field_sources_cache


# ---------- GET FIELDS TYPE BASED FOR DASHBOARD AND VISUALIZATONS FUNCTION----------
def get_field_type_for_field(field_name):
    """
    Finds which index pattern(s) contain the field and returns its type.
    Checks the right ES cluster based on the pattern.
    """
    field_sources = get_all_fields_with_sources()
    # print(field_sources)
    if field_name not in field_sources:
        return None, None  # Not found

    print("Field sources:", field_sources[field_name])
    for pattern in field_sources[field_name]:
        print("??")
        es_client = es_con if pattern == "logstash-*" else es
        field_type = get_field_type(es_client, pattern, field_name)
        if field_type:
            return field_type, pattern

    return None, None


# ---------- FIELDS VALUES BY TYPE FOR DASHBOARD AND VISUALIZATONS FUNCTION----------
def get_field_values_service(field_name):
    """
    Gets unique values for a field, searching only until the first pattern with results.
    """
    field_sources = get_all_fields_with_sources()
    if field_name not in field_sources:
        return []  # Not found

    for pattern in field_sources[field_name]:
        es_client = es_con if pattern == "logstash-*" else es
        field_type = get_field_type(es_client, pattern, field_name)

        # print(f"Checking {field_name} in {pattern} with type {field_type}")

        # Skip if we can't determine field type
        if not field_type:
            continue

        # Default to using field name directly
        field_query_name = field_name

        print(f"field type: {field_type} type: {type(field_type)}")

        # Append .keyword only if it exists in mapping
        if field_type not in ["long", "integer", "double", "float", "boolean", "date"]:
            print("??")
            field_query_name = resolve_field_name(es_client, pattern, field_name)

        print(f"Using field for aggregation: {field_query_name}")

        try:
            query = {
                "size": 0,
                "aggs": {
                    "field_values": {"terms": {"field": field_query_name, "size": 1000}}
                },
            }

            print(f"Executing query on {pattern}: {query}")

            res = es_client.search(index=pattern, body=query)
            buckets = (
                res.get("aggregations", {}).get("field_values", {}).get("buckets", [])
            )

            if buckets:  # Stop as soon as we find data
                return sorted([bucket["key"] for bucket in buckets])

        except Exception as e:
            logger.error(f"Error fetching values for {field_name} in {pattern}: {e}")

    return []  # No values found in any pattern


# ---------- GET SAVED SEARCHES TITLE FOR DASHBOARD AND VISUALIZATONS FUNCTION FOR TABLE DATA----------
def saved_searches_all_titles():
    """
    Retrieve all titles from the 'saved_searches' index in Elasticsearch.

    Returns:
        dict: A dictionary containing the response.
            If successful and titles are found, returns an 'ok' response with the list of titles.
            If no titles are found, returns a 'no_content' response.
            If an error occurs, returns an 'error' response with the message.
    """
    try:
        # Elasticsearch query to fetch all titles (no role filter)
        query = {
            "query": {"match_all": {}},
            "size": 1000,
            "_source": ["title", "index_name"],
        }

        response = es.search(index="saved_searches", body=query)

        hits = response["hits"]["hits"]

        if hits:
            titles = [
                {
                    "title": hit["_source"].get("title"),
                    "index": hit["_source"].get("index_name"),
                }
                for hit in hits
                if "title" in hit["_source"] and "index_name" in hit["_source"]
            ]
            return {"responseDto": ResponseDto().ok(), "saved_searches": titles}
        else:
            return {"responseDto": ResponseDto().no_content()}

    except Exception as e:
        return {"responseDto": ResponseDto().error(str(e))}


# ---------- LIST ALL INDICES FOR DASHBOARD AND VISUALIZATONS FUNCTION----------
def resolve_indices_patterns(pattern):
    indices = es.indices.get_alias(index=pattern).keys()
    labels = {}
    alerts_pattern = re.compile(r"^wazuh-alerts-4\.x-\d{4}\.\d{2}\.\d{2}$")
    alerts_found = False

    excluded = {"wazuh-agents", "wazuh-users"}

    for idx in indices:
        if idx in excluded:
            continue
        if alerts_pattern.match(idx):
            alerts_found = True
        elif "wazuh-states-vulnerabilities-devops" in idx:
            labels["Vulnerability"] = "wazuh-states-vulnerabilities-devops*"

    if alerts_found:
        labels["SIEM"] = "wazuh-alerts-*"

    # Check for logstash-* indices in remote Elasticsearch (es_con)
    logstash_indices = es_con.indices.get_alias(index="logstash-*").keys()
    if logstash_indices:
        labels["NDR"] = "logstash-*"

    return labels


# ---------- FIELDS PER INDEX FOR DASHBOARD AND VISUALIZATONS FUNCTION----------
def get_indices_field_mappings(pattern):
    mappings = []
    resolved_labels = resolve_indices_patterns(
        pattern
    )  # Now returns labels like ["SIEM", "NDR", "Vulnerabilities"]

    if "SIEM" in resolved_labels:
        alert_indices = es.indices.get_alias(index="wazuh-alerts-*").keys()
        for real_idx in alert_indices:
            props = es.indices.get_mapping(index=real_idx)[real_idx]["mappings"].get(
                "properties", {}
            )
            mappings.extend(flatten_fields(props))

    if "NDR" in resolved_labels:
        logstash_indices = es_con.indices.get_alias(index="logstash-*").keys()
        for real_idx in logstash_indices:
            props = es_con.indices.get_mapping(index=real_idx)[real_idx][
                "mappings"
            ].get("properties", {})
            mappings.extend(flatten_fields(props))

    if "Vulnerability" in resolved_labels:
        vuln_indices = es.indices.get_alias(
            index="wazuh-states-vulnerabilities-devops"
        ).keys()
        for real_idx in vuln_indices:
            props = es.indices.get_mapping(index=real_idx)[real_idx]["mappings"].get(
                "properties", {}
            )
            mappings.extend(flatten_fields(props))

    return sorted(list(set(mappings)))


# ---------- UPDATE VISUALIZATONS FUNCTION----------
def update_visualization(dashboard_name: str, visualization: dict):
    """
    Add or update a visualization inside a dashboard.
    - If viz_id exists, update the existing visualization.
    - If no viz_id, create a new visualization with a new UUID.
    """

    try:
        # Find the dashboard
        search_query = {"query": {"match": {"name": dashboard_name}}}
        search_result = es.search(index=".custom_dashboards", body=search_query, size=1)

        if search_result["hits"]["total"]["value"] == 0:
            return {"message": "Dashboard not found"}, 404

        dashboard_id = search_result["hits"]["hits"][0]["_id"]
        dashboard_source = search_result["hits"]["hits"][0]["_source"]

        # Ensure visualizers is a list
        visualizers = dashboard_source.get("visualizers") or []

        # If no viz_id → new visualization
        if not visualization.get("viz_id"):
            visualization["viz_id"] = str(uuid.uuid4())
            visualization["created_at"] = datetime.datetime.now().isoformat()
            visualizers.append(visualization)
        else:
            # Update existing visualization
            found = False
            for i, viz in enumerate(visualizers):
                if viz.get("viz_id") == visualization["viz_id"]:
                    visualizers[i].update(visualization)
                    found = True
                    break
            if not found:
                return {"message": "Visualization not found in this dashboard"}, 404

        # Update dashboard
        update_data = {
            "visualizers": visualizers,
            "updated_at": datetime.datetime.now().isoformat(),
        }

        es.update(
            index=".custom_dashboards", id=dashboard_id, body={"doc": update_data}
        )

        return {
            "message": "Visualization updated successfully",
            "viz_id": visualization["viz_id"],
            "responseDto": ResponseDto().ok(),
        }

    except Exception as e:
        logger.error(f"Error updating visualization: {e}")
        return {"error": "Internal server error", "details": str(e)}, 500


# ---------- DELETE VISUALIZATONS FUNCTION----------
def delete_visualization(dashboard_name: str, viz_title: str):
    """
    Delete a visualization from a dashboard by viz_id
    """
    try:
        search_query = {"query": {"match": {"name": dashboard_name}}}
        search_result = es.search(index=".custom_dashboards", body=search_query, size=1)

        if search_result["hits"]["total"]["value"] == 0:
            return {"message": "Dashboard not found"}, 404

        dashboard_id = search_result["hits"]["hits"][0]["_id"]
        dashboard_source = search_result["hits"]["hits"][0]["_source"]

        visualizers = dashboard_source.get("visualizers") or []
        new_visualizers = [viz for viz in visualizers if viz.get("title") != viz_title]

        if len(new_visualizers) == len(visualizers):
            return {"message": "Visualization not found"}, 404

        es.update(
            index=".custom_dashboards",
            id=dashboard_id,
            body={
                "doc": {
                    "visualizers": new_visualizers,
                    "updated_at": datetime.datetime.now().isoformat(),
                }
            },
        )

        return {
            "message": "Visualization deleted successfully",
            "responseDto": ResponseDto().ok(),
        }

    except Exception as e:
        logger.error(f"Error deleting visualization: {e}")
        return {"error": "Internal server error", "details": str(e)}, 500


# ---------- DUPLICATE VISUALIZATIONS FUNCTION (by title) ----------
def _generate_unique_copy_title(existing_titles: set, base_title: str) -> str:
    """
    Return a unique copy title like 'Title (Copy)', 'Title (Copy 2)', ...
    """
    candidate = f"{base_title} (Copy)"
    if candidate not in existing_titles:
        return candidate
    i = 2
    while True:
        candidate = f"{base_title} (Copy {i})"
        if candidate not in existing_titles:
            return candidate
        i += 1


def duplicate_visualization(dashboard_name: str, viz_title: str):
    """
    Duplicate an existing visualization in a dashboard by its title.
    Creates a new viz with a new UUID and a unique '(Copy ...)' title.
    """
    try:
        # find dashboard
        search_query = {"query": {"match": {"name": dashboard_name}}}
        search_result = es.search(index=".custom_dashboards", body=search_query, size=1)

        if search_result["hits"]["total"]["value"] == 0:
            return {"message": "Dashboard not found"}, 404

        dashboard_id = search_result["hits"]["hits"][0]["_id"]
        dashboard_source = search_result["hits"]["hits"][0]["_source"]

        visualizers = dashboard_source.get("visualizers") or []
        titles = {v.get("title") for v in visualizers}

        # locate source viz by title
        src_viz = next((v for v in visualizers if v.get("title") == viz_title), None)
        if not src_viz:
            return {"message": "Visualization not found"}, 404

        # make deep copy, assign new uuid, unique title
        new_viz = copy.deepcopy(src_viz)
        new_viz["viz_id"] = str(uuid.uuid4())
        new_viz["title"] = _generate_unique_copy_title(titles, viz_title)

        visualizers.append(new_viz)

        es.update(
            index=".custom_dashboards",
            id=dashboard_id,
            body={
                "doc": {
                    "visualizers": visualizers,
                    "updated_at": datetime.datetime.now().isoformat(),
                }
            },
        )

        logger.info(
            f"[DUP-VIZ] Dashboard='{dashboard_name}' FromTitle='{viz_title}' NewTitle='{new_viz['title']}'"
        )
        return {
            "message": "Visualization duplicated successfully",
            "new_viz": new_viz,
            "responseDto": ResponseDto().ok(),
        }

    except Exception as e:
        logger.error(f"Error duplicating visualization (by title): {e}")
        return {"error": "Internal server error", "details": str(e)}, 500


def get_dashboard(dashboard_id: str) -> Optional[DashboardRequest]:
    """Fetch a single dashboard by name from Elasticsearch"""
    try:
        result = es.search(
            index=".custom_dashboards",
            body={"query": {"term": {"dashboard_id.keyword": dashboard_id}}},
        )

        if result["hits"]["total"]["value"] > 0:
            dashboard_data = result["hits"]["hits"][0]["_source"]
            dashboard = DashboardRequest.model_validate(dashboard_data)
            return dashboard
        return None
    except Exception as e:
        return None


def get_visualization(viz_id: str) -> Optional[Visualization]:
    try:

        print(f"Fetching visualization with ID: {viz_id}")

        result = es.search(
            index=".saved_visualizations",
            body={"query": {"term": {"viz_id.keyword": viz_id}}},
        )

        print(f"Visualization search result: {result}")

        if result["hits"]["total"]["value"] > 0:
            visualization_data = result["hits"]["hits"][0]["_source"]
            visualization = Visualization.model_validate(visualization_data)
            return visualization
        return None
    except Exception as e:
        return None


# ------------------------------
#  View Dashboard with Data
# ------------------------------
def view_dashboard(dashboard_id: uuid.UUID, lte: str, gte: str):
    dashboard = get_dashboard(str(dashboard_id))
    if not dashboard:
        return {"error": "Dashboard not found"}, 404

    enriched_visualizers = []

    # if not dashboard.visualizers:
    #     return {"dashboard": {"name": dashboard.name, "visualizers": []}}

    print(f"Dashboard visualizers: {dashboard.visualizers}")
    print(f"lte : {lte}, gte: {gte}")

    for visualizer_info in dashboard.visualizers:
        viz_id = str(visualizer_info.viz_id)
        visualization = get_visualization(viz_id)
        print(f"Visualization: {visualization}")
        print(f"Visualization: {visualization.type}")
        if visualization.type == VisualizationType.TABLE:
            print(f"Processing TABLE visualization: {visualization.title}")
            print(f"table query: {visualization.table_data}")
            table_query = visualization.table_data
            table = TableData.model_validate(table_query)
            table.lte = lte
            table.gte = gte
            table_data = get_table_data(table)
            data = None
            if table_data:
                data = table_data[0]["data"]
            enriched_visualizers.append(
                {
                    "viz_id": visualization.viz_id,
                    "title": visualization.title,
                    "type": visualization.type,
                    "query": table_query.model_dump(),
                    "options": visualization.options.model_dump(),
                    "data": data,
                }
            )
        if visualization.type == VisualizationType.BAR:
            print(f"Processing Bar visualization: {visualization.title}")
            print(f"bar query: {visualization.viz_data}")
            bar_chart = VizData.model_validate(visualization.viz_data)
            bar_chart.lte = lte
            bar_chart.gte = gte
            bar_data = create_bar_chart(bar_chart)
            print(f"Bar chart data: {bar_data}")
            data = None
            if bar_data:
                data = bar_data["data"]
            enriched_visualizers.append(
                {
                    "viz_id": visualization.viz_id,
                    "title": visualization.title,
                    "type": visualization.type,
                    "query": bar_chart.model_dump(),
                    "options": visualization.options.model_dump(),
                    "data": data,
                }
            )
    return {
        "dashboard": {
            "name": dashboard.name,
            "dashboard_id": str(dashboard.dashboard_id),
            "filters": dashboard.filters,
            "lte": dashboard.lte if dashboard.lte else None,
            "gte": dashboard.gte if dashboard.gte else None,
            "description": dashboard.description,
            "visualizers": enriched_visualizers,
        }
    }


def parse_buckets(buckets):
    """
    Recursively parse ES aggregation buckets into nested dicts.
    """
    results = []
    for b in buckets:
        entry = {"key": b["key"], "count": b["doc_count"]}
        # check for nested aggregations
        for k, v in b.items():
            if isinstance(v, dict) and "buckets" in v:
                entry["children"] = parse_buckets(v["buckets"])
        results.append(entry)
    return results


def format_es_response(aggregations, chart_type, gte=None, lte=None, delta_obj=None):
    """
    Format Elasticsearch aggregation response into chart-ready data.
    Supports single-field and multi-field nested aggs.
    """
    if not aggregations:
        return {"responseDto": ResponseDto().no_content()}

    # 🔹 BAR / PIE / DONUT charts (single + multi-field support)
    if chart_type in ["bar", "pie", "donut"]:
        buckets = aggregations["chart_data"]["buckets"]
        parsed = parse_buckets(buckets)
        return {"data": parsed, "responseDto": ResponseDto().ok()}

    # 🔹 LINE / AREA charts (date histogram)
    elif chart_type in ["line", "area"]:
        buckets = aggregations["chart_data"]["buckets"]

        # full timeline (fill 0s if missing)
        full_dates = daterange(gte, lte)
        formatted_dates = format_dates_list(full_dates, gte, lte)

        data_sets = [{"label": "timestamp", "data": [0] * len(formatted_dates)}]

        for bucket in buckets:
            bucket_label = datetime.fromtimestamp(bucket["key"] / 1000).strftime(
                {
                    "seconds": "%H:%M:%S",
                    "minutes": "%H:%M:%S",
                    "hours": "%Y-%m-%d %H",
                    "days": "%Y-%m-%d",
                    "months": "%Y-%m",
                }[delta_obj.date_case]
            )

            if bucket_label in formatted_dates:
                idx = formatted_dates.index(bucket_label)
                data_sets[0]["data"][idx] = bucket["doc_count"]

        return {
            "dataSets": data_sets,
            "datesList": formatted_dates,
            "responseDto": ResponseDto().ok(),
        }

    # 🔹 Default: No content
    return {"responseDto": ResponseDto().no_content()}


def get_chart_data(chart: ChartData):
    """
    Extract chart data from Elasticsearch based on ChartData model.
    Works for bar, pie, line, area, donut.
    """

    print(f"Received chart request: {chart}")

    index = chart.index
    gte = None
    lte = None
    fields = chart.fields
    type = chart.type
    sizes = chart.size
    filters = chart.filter or []

    if chart.lte is not None and chart.gte is not None:
        lte = chart.lte
        gte = chart.gte

    query = build_es_query(
        gte=gte,
        lte=lte,
        search=None,
        filter_response=filters,
        chart_fields=fields,
        chart_type=type,
        size=sizes,
        search_after=None,  # Assuming no pagination with search_after for now
    )

    print(f"Executing query for index {chart.index}: {json.dumps(query, indent=2)}")

    # Run query
    es_client = es_con if index == "logstash-*" else es
    data = es_client.search(index=index, body=query)

    # Format response
    response = format_es_response(
        data.get("aggregations"),
        chart.type,
        gte=gte,
        lte=lte,
        delta_obj=date_delta(gte, lte) if chart.type in ["line", "area"] else None,
    )

    return response


def get_indices_field_types(es_client, index_pattern):
    """Return a dict of field name -> type for all indices matching the pattern."""
    field_types = {}
    try:
        all_mappings = es_client.indices.get_mapping(index=index_pattern)
        for idx, mapping in all_mappings.items():
            props = mapping["mappings"].get("properties", {})
            for field, value in props.items():
                # Get type, handle nested/multi-field if needed
                field_type = value.get("type")
                if not field_type and "fields" in value:
                    for sub_field in value["fields"].values():
                        if "type" in sub_field:
                            field_type = sub_field["type"]
                            break
                field_types[field] = field_type
    except Exception as e:
        print(f"Error fetching field types for {index_pattern}: {e}")
    return field_types
