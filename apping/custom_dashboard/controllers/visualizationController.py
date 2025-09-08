from elasticsearch import helpers
import uuid
from apping import es, ResponseDto
from apping.custom_dashboard.model import Visualization, VizData, Axis
import datetime
from apping.custom_dashboard.controllers.esController import es_con

from typing import Tuple


def save_visualizations(
    index: str, visualizations: list[Visualization]
) -> Tuple[list[Visualization], str]:

    print(f"Saving visualizations to index '{index}'")

    if not visualizations or len(visualizations) == 0:
        return [], "No visualizations to save"

    try:
        # Prepare bulk actions for both inserts and updates
        actions = []
        for viz in visualizations:
            if viz.viz_id:
                # print("????")
                print(f"Updating visualization with ID: {viz.viz_id}")
                # Search for existing visualization
                existing_viz = es.search(
                    index=index,
                    body={"query": {"term": {"viz_id.keyword": str(viz.viz_id)}}},
                )

                print(f"Existing visualization search result: {existing_viz}")

                if existing_viz["hits"]["total"]["value"] > 0:
                    # Update existing visualization using its ES _id
                    es_id = existing_viz["hits"]["hits"][0]["_id"]
                    actions.append(
                        {
                            "_op_type": "update",
                            "_index": index,
                            "_id": es_id,
                            "doc": viz.model_dump(),
                        }
                    )
            else:
                # Generate a new UUID for new visualizations
                viz.viz_id = uuid.uuid4()
                actions.append(
                    {
                        "_op_type": "index",
                        "_index": index,
                        "_source": viz.model_dump(),
                    }
                )

        # Perform bulk operation
        helpers.bulk(es, actions)
        print(f"Processed {len(actions)} visualizations in index '{index}'")
        return [
            Visualization(viz_id=viz.viz_id, title=viz.title) for viz in visualizations
        ], None

    except Exception as e:
        print(f"Error saving visualizations: {e}")
        return None, f"Error saving visualizations: {str(e)}"


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


def build_elasticsearch_filter(filter_groups: list) -> list:
    results = []

    for fg in filter_groups:
        must_clauses = []
        query_strings = []

        for f in fg.get("filters", []):
            field = f["field"]
            value = f["value"]
            operator = f["operator"].lower()

            if operator == "is one of":
                qs = f"{field}:({' OR '.join(map(str, value))})"
                must_clauses.append({"query_string": {"query": qs}})
                query_strings.append(qs)

            elif operator == "is not one of":
                qs = f"{field}:({' OR '.join(map(str, value))})"
                must_clauses.append(
                    {"bool": {"must_not": {"query_string": {"query": qs}}}}
                )
                query_strings.append(f"NOT ({qs})")

            elif operator == "exists":
                must_clauses.append({"exists": {"field": field}})
                query_strings.append(f"_exists_:{field}")

            elif operator == "does not exist":
                must_clauses.append(
                    {"bool": {"must_not": {"exists": {"field": field}}}}
                )
                query_strings.append(f"NOT _exists_:{field}")

            elif operator == "regex":
                must_clauses.append({"regexp": {field: value}})
                query_strings.append(f"{field}:/{value}/")

            else:
                raise ValueError(f"Unsupported operator: {operator}")

        condition = fg.get("condition", "ALL").upper()
        if condition == "ALL":
            filters = {"bool": {"must": must_clauses}}
            query_str = " AND ".join(query_strings)
        elif condition == "ANY":
            filters = {"bool": {"should": must_clauses, "minimum_should_match": 1}}
            query_str = " OR ".join(query_strings)
        else:
            raise ValueError(f"Unsupported condition: {condition}")

        results.append({"filter": filters, "query_string": query_str})

    print(f"Built Elasticsearch results: {results}")
    return results


def es_barchat(data):
    """
    Convert a terms/multi-terms aggregation (agg name always 'x')
    into a simple Chart.js-compatible response.
    """

    buckets = data["aggregations"]["x"].get("buckets", [])

    labels = []
    chart_data = []

    for bucket in buckets:

        print(f"Processing bucket: {bucket}")
        key = bucket["key"]

        if isinstance(key, str):
            labels.append(key)
        elif isinstance(key, int) or isinstance(key, float):
            labels.append(str(key))
        elif isinstance(key, dict):
            merged_label = ", ".join(f"{k}: {v}" for k, v in key.items())
            labels.append(merged_label)
        elif isinstance(key, list) and all(isinstance(item, str) for item in key):
            merged_label = ", ".join(key)
            labels.append(merged_label)
        else:
            key_as_string = bucket["key_as_string"]
            if key_as_string:
                labels.append(key_as_string)

        chart_data.append(bucket.get("doc_count", 0))

    print(f"Labels: {labels}")
    print(f"Data: {chart_data}")

    return {
        "labels": labels,
        "data": chart_data,
    }


def es_breakdowns_chart(es):
    buckets = es.get("aggregations", {}).get("x", {}).get("buckets", [])
    labels = [str(b.get("key", "")) for b in buckets]

    # collect all breakdown keys
    all_keys = set()
    for b in buckets:
        for bb in b.get("breakdown", {}).get("buckets", []):
            all_keys.add(str(bb.get("key", "")))

    # one dataset per breakdown key
    datasets = []
    for k in sorted(all_keys):
        series = []
        for b in buckets:
            count = 0
            for bb in b.get("breakdown", {}).get("buckets", []):
                if str(bb.get("key", "")) == k:
                    count = int(bb.get("doc_count", 0))
                    break
            series.append(count)
        datasets.append({"label": k, "data": series})

    return {"labels": labels, "datasets": datasets}


def create_bar_chart(vizData: VizData) -> Visualization:

    print("??")

    ez_query = {
        "size": 0,
        "aggs": {},
        "query": {"bool": {"filter": [], "must": [], "must_not": []}},
    }

    if vizData.lte and vizData.gte:
        ez_query["query"] = {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": convert_local_to_utc(vizData.gte),
                                "lte": convert_local_to_utc(vizData.lte),
                                "format": "strict_date_optional_time",
                            }
                        }
                    }
                ],
                "must": [],
                "must_not": [],
            }
        }

    custom_filters = vizData.custom_filter

    print("!!")

    if custom_filters and len(custom_filters) > 0:
        filters_array = build_elasticsearch_filter(custom_filters)
        print(f"Built custom filters: {filters_array}")

        for filter_group in filters_array:
            ez_query["query"]["bool"]["filter"].append(filter_group["filter"])

    is_breakdown = False
    has_x_axis = False

    if vizData.xAxis is not None:
        has_x_axis = True
        if vizData.xAxis.has_filters:
            filters_array = build_elasticsearch_filter(vizData.xAxis.filters)
            # print(f"Built filters for xAxis: {filters_array}")

            filters_dict = {}
            for filter_group in filters_array:
                group_name = f"{filter_group['query_string']}"
                filters_dict[group_name] = filter_group["filter"]

            ez_query["aggs"]["x"] = {
                "filters": {"keyed": False, "filters": filters_dict}
            }

        else:
            if len(vizData.xAxis.fields) == 1:
                x_field = vizData.xAxis.fields[0]
                ez_query["aggs"]["x"] = {
                    "terms": {"field": x_field, "size": vizData.xAxis.size}
                }
            else:
                terms = []
                for field in vizData.xAxis.fields:
                    terms.append({"field": field})
                ez_query["aggs"]["x"] = {
                    "multi_terms": {"terms": terms, "size": vizData.xAxis.size}
                }

    if vizData.breakdown is not None:
        is_breakdown = True
        if has_x_axis:
            if vizData.breakdown.has_filters:
                # print("xAxis has filters, breakdown will be nested inside xAxis filters")
                filters_array = build_elasticsearch_filter(vizData.breakdown.filters)
                # print(f"Built filters for xAxis: {filters_array}")

                filters_dict = {}
                for filter_group in filters_array:
                    group_name = f"{filter_group['query_string']}"
                    filters_dict[group_name] = filter_group["filter"]
                ez_query["aggs"]["x"]["aggs"] = {
                    "breakdown": {"filters": {"keyed": False, "filters": filters_dict}}
                }
            else:
                if len(vizData.breakdown.fields) == 1:
                    breakdown_field = vizData.breakdown.fields[0]
                    ez_query["aggs"]["x"]["aggs"] = {
                        "breakdown": {
                            "terms": {
                                "field": breakdown_field,
                                "size": vizData.breakdown.size,
                            }
                        }
                    }
                else:
                    terms = []
                    for field in vizData.breakdown.fields:
                        terms.append({"field": field})
                    ez_query["aggs"]["x"]["aggs"] = {
                        "breakdown": {"multi_terms": {"terms": terms}}
                    }
        else:

            if vizData.breakdown.has_filters:
                filters_array = build_elasticsearch_filter(vizData.breakdown.filters)

                filters_dict = {}
                for filter_group in filters_array:
                    group_name = f"{filter_group['query_string']}"
                    filters_dict[group_name] = filter_group["filter"]

                ez_query["aggs"]["x"] = {
                    "filters": {"keyed": False, "filters": filters_dict}
                }
            else:
                if len(vizData.breakdown.fields) == 1:
                    breakdown_field = vizData.breakdown.fields[0]
                    ez_query["aggs"]["x"] = {
                        "terms": {
                            "field": breakdown_field,
                            "size": vizData.breakdown.size,
                        }
                    }
                else:
                    terms = []
                    for field in vizData.breakdown.fields:
                        terms.append({"field": field})
                    ez_query["aggs"]["x"] = {
                        "multi_terms": {"terms": terms, "size": vizData.breakdown.size}
                    }
    else:
        pass

    index = vizData.index
    print(f"Executing query on index '{index}': {ez_query}")

    es_client = es_con if index == "logstash-*" else es

    response = es_client.search(index=index, body=ez_query)

    print(f"Elasticsearch response: {response}")

    if is_breakdown:
        print("Processing breakdown chart data")
        data = es_breakdowns_chart(response)
        return {
            "message": "Bar chart created successfully",
            "responseDto": ResponseDto().ok(),
            "query": vizData.model_dump(),
            "data": data,
        }
    else:
        bar_chart = es_barchat(response)
        bar_chart["y_axis_label"] = vizData.yAxis.label if vizData.yAxis else "Count"
        bar_chart["x_axis_label"] = vizData.xAxis.label if vizData.xAxis else "Count"
        return {
            "data": bar_chart,
            "query": vizData.model_dump(),
            "message": "Bar chart created successfully",
            "responseDto": ResponseDto().ok(),
        }
