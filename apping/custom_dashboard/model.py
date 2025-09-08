from pydantic import BaseModel, RootModel
from typing import List, Optional, Dict, Any
from enum import Enum
import uuid
from uuid import UUID


class VisualizationOptions(BaseModel):
    xField: Optional[str] = None
    yField: Optional[str] = None
    height: int
    width: int


class VisualizationType(str, Enum):
    BAR = "bar"
    PIE_CHART = "pie"
    LINE = "line"
    TABLE = "table"


class Axis(BaseModel):
    fields: Optional[List[str]] = None
    function: Optional[str] = None
    size: Optional[int] = 5
    label: Optional[str] = None
    rankBy: Optional[str] = None
    has_filters: Optional[bool] = False
    filters: Optional[List[Dict[str, Any]]] = None


class VizData(BaseModel):
    index: str
    title: str
    type: VisualizationType
    xAxis: Optional[Axis] = None
    yAxis: Optional[Axis] = None
    breakdown: Optional[Axis] = None
    lte: Optional[str] = None
    gte: Optional[str] = None
    custom_filter: Optional[List[Dict[str, Any]]] = None


class TableData(BaseModel):
    index: str
    title: str
    custom_filter: Optional[List[Dict[str, Any]]] = None
    lte: Optional[str] = None
    gte: Optional[str] = None
    page: Optional[int] = 1
    size: Optional[int] = 20
    sort_field: Optional[str] = None
    sort_order: Optional[str] = None


class ChartData(BaseModel):
    index: str
    title: Optional[str] = None
    type: VisualizationType
    fields: List[str]
    filter: Optional[List[Dict[str, Any]]] = None
    lte: Optional[str] = None
    gte: Optional[str] = None
    size: Optional[int] = 10


# class TableRequest(BaseModel):
#     data: List[TableData]


class Visualization(BaseModel):
    title: str
    viz_id: Optional[uuid.UUID] = None
    type: Optional[VisualizationType] = None
    chart_data: Optional[ChartData] = None
    table_data: Optional[TableData] = None
    viz_data: Optional[VizData] = None
    options: Optional[VisualizationOptions] = None


class DashboardRequest(BaseModel):
    name: str
    dashboard_id: Optional[uuid.UUID] = None
    description: Optional[str] = None
    visualizers: Optional[List[Visualization]] = None
    filters: Optional[List[dict]] = None
    lte: Optional[str] = None
    gte: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class UpdateDashboard(BaseModel):
    dashboard_id: uuid.UUID
    name: Optional[str] = None
    description: Optional[str] = None


class DeleteDashboard(BaseModel):
    dashboard_id: UUID
