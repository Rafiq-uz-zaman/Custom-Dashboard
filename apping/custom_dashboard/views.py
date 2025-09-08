"""
API routes for data management module
"""

import logging


from flask import request
from flask_cors import cross_origin

from apping import ResponseDto
from apping.custom_dashboard.model import (
    ChartData,
    DashboardRequest,
    DeleteDashboard,
    TableData,
    UpdateDashboard,
    VizData,
)
from flask_pydantic import validate
from apping.custom_dashboard.controllers import dashboardController as controller
from apping.custom_dashboard.controllers import (
    visualizationController as viz_controller,
)


from . import custom_dashboard


logger = logging.getLogger(__name__)


# ---------- Get table data ----------
@custom_dashboard.route("/create_table", methods=["POST"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
@validate()
def create_table(body: TableData):
    return controller.get_table_data(body)


# ---------- Create ----------
@custom_dashboard.route("/create_dashboard", methods=["POST"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
@validate()
def create(body: DashboardRequest):
    return controller.create_dashboard(body)


# ---------- UPDATE ----------
@custom_dashboard.route("/update_dashboard", methods=["PUT"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
@validate()
def update_dashboard(body: UpdateDashboard):
    return controller.update_dashboard_info(body)


# ---------- UPDATE  ----------
@custom_dashboard.route("/update_dashboard_visualizations", methods=["PUT"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
@validate()
def update_dashboard_visualizations(body: DashboardRequest):
    return controller.update_dashboard(body)


# ---------- DELETE ----------
@custom_dashboard.route("/delete_dashboard", methods=["DELETE"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
@validate()
def delete_dashboards(body: DeleteDashboard):
    return controller.delete_dashboard(body)


# ---------- LIST ----------
@custom_dashboard.route("/list_dashboards", methods=["GET"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
def list():
    return controller.list_dashboards()


# ---------- VIEW DASHBOARD DATA ----------
@custom_dashboard.route("view_dashboard", methods=["GET"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
def view_dashboard():
    dashboard_id = request.args.get("dashboard_id")
    lte = request.args.get("lte", None)
    gte = request.args.get("gte", None)
    print("??")
    print(f"Dashboard ID: {dashboard_id}, lte: {lte}, gte: {gte}")
    return controller.view_dashboard(dashboard_id, lte, gte)


# ---------- FILTER FIELDS ----------
@custom_dashboard.route("/filter-fields", methods=["GET"])
def get_combined_fields():
    """Returns all fields with their source indices."""
    field_sources = controller.get_all_fields_with_sources()
    return {"fields": sorted(field_sources.keys()), "responseDto": ResponseDto().ok()}


# ---------- FILTER FIELDS OPERATORS ----------
@custom_dashboard.route("/filter-operators", methods=["GET"])
def get_field_operators_route():
    return controller.fields_operators()


# ---------- FILTER FILEDS VALUES ----------
@custom_dashboard.route("/filter-values", methods=["POST"])
def get_field_values_route():
    return controller.fields_values()


# ---------- GET SAVED SEARCH ----------
@custom_dashboard.route("/saved_searches_titles", methods=["GET"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
def get_all_titles_view():
    """
    Retrieve all titles from the 'saved_searches' index in Elasticsearch and return them as a JSON response.

    Returns:
        JSON response containing the titles retrieved from Elasticsearch.
    """
    titles = controller.saved_searches_all_titles()

    return titles


# ---------- UPDATE DASHBOARD VISUALIZATONS----------
@custom_dashboard.route("/update_visualization", methods=["PUT"])
def update_visualization():
    name = request.args.get("name")
    if not name:
        return {"message": "Dashboard name is required"}, 400

    visualization = request.get_json()
    return controller.update_visualization(name, visualization)


@custom_dashboard.route("/create_chart", methods=["POST"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
@validate()
def create_chart(body: ChartData):
    return controller.get_chart_data(body)


@custom_dashboard.route("/create_bar_chart", methods=["POST"])
@cross_origin(origin="*", headers=["Content-Type", "Authorization"])
@validate()
def create_bar_chart(body: VizData):
    return viz_controller.create_bar_chart(body)


# ---------- DELETE DASBOARD Visualizations------------
@custom_dashboard.route("/delete_visualization", methods=["DELETE"])
def delete_visualization_route():
    name = request.args.get("name")
    title = request.args.get("title")
    if not name or not title:
        return {"message": "Dashboard name and viz_id are required"}, 400
    return controller.delete_visualization(name, title)


# ---------- DUPLICATE DASHBOARD Visualization-----------
@custom_dashboard.route("/duplicate_visualization", methods=["POST"])
def duplicate_visualization_route():
    name = request.args.get("name")
    title = request.args.get("title")
    if not name or not title:
        return {"message": "Dashboard name and viz_id are required"}, 400
    return controller.duplicate_visualization(name, title)


# ---------- LIST ALL INDICES----------
@custom_dashboard.route("list_indices", methods=["GET"])
def get_indices():
    pattern = request.args.get("pattern")
    return {
        "indices": controller.resolve_indices_patterns(pattern),
        "responseDto": ResponseDto().ok(),
    }


# ---------- GET INDEX WISE FIELDS----------
@custom_dashboard.route("indices_fields", methods=["GET"])
def get_mappings():

    label = request.args.get("index")
    if not label:
        return {"error": "index parameter is required"}, 400

    # Map label to actual index pattern
    label_to_pattern = {
        "SIEM": "wazuh-alerts-*",
        "NDR": "logstash-*",
        "Vulnerability": "wazuh-states-vulnerabilities-devops",
    }

    pattern = label_to_pattern.get(
        label, label
    )  # fallback to raw input if not a known label

    return {
        "fields": controller.get_indices_field_mappings(pattern),
        "responseDto": ResponseDto().ok(),
    }
