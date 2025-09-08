"""
Custom Dashboard Module to manage Daahboards and Visualizations
"""

from flask import Blueprint

custom_dashboard = Blueprint("custom_dashboard", __name__)

from . import views
