import configparser
import datetime
import json
from dataclasses import dataclass
from http import HTTPStatus

from flask import Flask
from flask_cors import CORS
import urllib3
from dateutil.relativedelta import relativedelta
from elasticsearch import Elasticsearch, RequestsHttpConnection

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
mysql_user = None
mysql_password = None
mysql_host = None
config = configparser.ConfigParser()
config.read("config.ini", encoding="utf-8")



es = Elasticsearch(
    hosts=str(config["url"]["elasticsearch_connection"]),
    verify_certs=False,
    connection_class=RequestsHttpConnection,
    use_ssl=True,
    timeout=150,
    max_retries=10,
    retry_on_timeout=True
)
    
api_url = str(config["url"]["wazuh_api"])

zone_diff = str(datetime.datetime.now() - datetime.datetime.utcnow()).split(":")


main = Flask(__name__)
main.debug = True
main.config["SECRET_KEY"] = "super-secret"
cors = CORS(main, resources={r"/*": {"origins": "*"}})
main.config["CORS_HEADERS"] = "Content-Type"
main.config["JWT_ACCESS_TOKEN_EXPIRES"] = datetime.timedelta(minutes=60)
main.config["JWT_EXPIRATION_DELTA"] = datetime.timedelta(minutes=60)
main.config["JWT_REFRESH_TOKEN_EXPIRES"] = datetime.timedelta(minutes=15)
main.config["JWT_SECRET_KEY"] = "super-secret"
main.config["JWT_DEFAULT_REALM"] = None


@dataclass
class ResponseDto:
    responseCode: int = None
    responseMessage: str = None
    detailMessage: str = None

    def no_content(
        self, responseMessage=HTTPStatus.NO_CONTENT.phrase, detailMessage=None
    ):
        self.responseCode = HTTPStatus.NO_CONTENT.value
        self.responseMessage = responseMessage
        self.detailMessage = detailMessage
        return self.__dict__

    def ok(self, responseMessage=HTTPStatus.OK.phrase, detailMessage=None):
        self.responseCode = HTTPStatus.OK.value
        self.responseMessage = responseMessage
        self.detailMessage = detailMessage
        return self.__dict__

    def conflict(self, responseMessage=HTTPStatus.CONFLICT.phrase):
        self.responseCode = HTTPStatus.CONFLICT.value
        self.responseMessage = responseMessage
        return self.__dict__
    
    def bad_request(self):
        return {"responseCode": 400, "status": "BAD_REQUEST"}


class DateDelta:
    """
    This class is used in conjunction with the date_delta method
    The `DateDelta` object has the following properties:
        * a dictionary that specifies the interval for elastic aggregations
        * a timedelta object used to populate the dates_list parameter for histogram endpoints
        * two datetime objects modified to match the timestamps in the aggregation buckets of elastic
            response. These are the timestamp ranges
        * `date_case` specifies the condition on bases of which the dates_list is modified. This is used
          in the `format_dates_list` method
    """

    def __init__(
        self,
        date_histogram_dict,
        time_delta_obj,
        start_datetime_obj,
        end_datetime_obj,
        date_case=None,
    ):
        self.date_histogram_dict = date_histogram_dict
        self.time_delta_obj = time_delta_obj
        self.start_datetime_obj = start_datetime_obj
        self.end_datetime_obj = end_datetime_obj
        self.date_case = date_case

    def __repr__(self):
        return f"DateDelta(date_histogram_dict={self.date_histogram_dict},\
            time_delta_obj={self.time_delta_obj},\
            self.start_datetime_obj={self.start_datetime_obj},\
            end_datetime_obj={self.end_datetime_obj},\
            date_case={self.date_case}"


def get_date_from_zone(date):
    try:
        date_time_obj = datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError as ve1:
        try:
            date_time_obj = datetime.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError as ve2:
            if "+00:00" in date:
                date_time_obj = datetime.datetime.strptime(
                    date.replace("+00:00", "Z"), "%Y-%m-%dT%H:%M:%SZ"
                )
    days = None
    hours = None
    if "day" in zone_diff[0]:
        day_split = zone_diff[0].split(",")
        days = day_split[0].split("day")[0].strip()
        hours = day_split[1].strip()
    else:
        hours = zone_diff[0]
    converted_date = (
        date_time_obj + datetime.timedelta(days=int(days))
        if days is not None
        else date_time_obj
    )
    converted_date = (
        converted_date + datetime.timedelta(hours=int(hours))
        if int(hours) != 0
        else converted_date
    )
    converted_date = (
        converted_date + datetime.timedelta(minutes=int(zone_diff[1]))
        if int(zone_diff[1]) != 0
        else converted_date
    )
    converted_date = (
        converted_date + datetime.timedelta(seconds=round(float(zone_diff[2])))
        if round(float(zone_diff[2])) != 0
        else converted_date
    )
    return converted_date


def daterange(start_date, end_date):
    """
    returns a list of dates following a step size
    the start date, end date and step size are returned by the `date_delta` method.
    the step size or delta depends on the cases mathched in the `date_delta` method
    """
    dates_list = []
    date_delta_obj = date_delta(start_date, end_date)
    while date_delta_obj.start_datetime_obj <= date_delta_obj.end_datetime_obj:
        dates_list.append(
            datetime.datetime.strftime(
                date_delta_obj.start_datetime_obj, "%Y-%m-%dT%H:%M:%S"
            )
        )
        date_delta_obj.start_datetime_obj += date_delta_obj.time_delta_obj
    return dates_list


def format_dates_list(dates_list, start_date, end_date):
    """
    This method changes the format of the dates in `dates_list` that is used in histogram endpoints depending
    on the date_case attribute of the DateDelta object
    """
    case = date_delta(start_date, end_date).date_case
    if case == "seconds":
        formated_dates_list = []
        for date_str in dates_list:
            date_item = datetime.datetime.strptime(
                date_str, format("%Y-%m-%dT%H:%M:%S")
            )
            formated_dates_list.append(date_item.strftime("%H:%M:%S"))
    if case == "minutes":
        formated_dates_list = []
        for date_str in dates_list:
            date_item = datetime.datetime.strptime(
                date_str, format("%Y-%m-%dT%H:%M:%S")
            )
            formated_dates_list.append(date_item.strftime("%H:%M:%S"))
    if case == "hours":
        formated_dates_list = []
        for date_str in dates_list:
            date_item = datetime.datetime.strptime(
                date_str, format("%Y-%m-%dT%H:%M:%S")
            )
            formated_dates_list.append(
                date_item.strftime("%Y-%m-%dT%H").replace("T", " ")
            )
    if case == "days":
        formated_dates_list = [item.split("T")[0] for item in dates_list]
    if case == "months":
        formated_dates_list = []
        for date_str in dates_list:
            date_item = datetime.datetime.strptime(
                date_str, format("%Y-%m-%dT%H:%M:%S")
            )
            formated_dates_list.append(date_item.strftime("%Y-%m"))
    return formated_dates_list


def date_delta(start_date, end_date):
    """
    This method decides the division intervals for all the timeline charts given a date range
    It creates a `DateDelta` object which has the following properties:
        * a dictionary that specifies the interval for elastic aggregations
        * a timedelta object used to populate the dates_list parameter for histogram endpoints
        * two datetime objects modified to match the timestamps in the aggregation buckets of elastic
            response
        * `date_case` specifies the condition on bases of which the dates_list is modified. This is used
          in the `format_dates_list` method
    """
    start_datetime_obj = datetime.datetime.strptime(
        start_date, format("%Y-%m-%dT%H:%M:%S.%fZ")
    ).replace(microsecond=0)
    end_datetime_obj = datetime.datetime.strptime(
        end_date, format("%Y-%m-%dT%H:%M:%S.%fZ")
    ).replace(microsecond=0)

    start_utc_time = datetime.datetime.strptime(
        convert_local_to_utc(start_date), format("%Y-%m-%dT%H:%M:%S.%fZ")
    ).replace(microsecond=0)
    end_utc_time = datetime.datetime.strptime(
        convert_local_to_utc(end_date), format("%Y-%m-%dT%H:%M:%S.%fZ")
    ).replace(microsecond=0)
    date_difference = end_utc_time - start_utc_time

    delta_total_seconds = date_difference.total_seconds()

    # delta_cases stores all the conditions for time difference
    if delta_total_seconds >= 1 and delta_total_seconds <= 15:  # between 1 and 15 secs
        return DateDelta(
            {
                "fixed_interval": "1s",
                "offset": f"{start_datetime_obj.second}s",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(seconds=1),
            start_datetime_obj.replace(microsecond=0),
            end_datetime_obj.replace(microsecond=0),
            date_case="seconds",
        )
    elif (
        delta_total_seconds > 15 and delta_total_seconds <= 30
    ):  # between 15 and 30 secs
        return DateDelta(
            {
                "fixed_interval": "2s",
                "offset": f"{start_datetime_obj.second}s",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(seconds=2),
            start_datetime_obj.replace(microsecond=0),
            end_datetime_obj.replace(microsecond=0),
            date_case="seconds",
        )
    elif (
        delta_total_seconds > 30 and delta_total_seconds <= 60
    ):  # between 30 and 60 secs
        return DateDelta(
            {
                "fixed_interval": "5s",
                "offset": f"{start_datetime_obj.second}s",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(seconds=5),
            start_datetime_obj.replace(microsecond=0),
            end_datetime_obj.replace(microsecond=0),
            date_case="seconds",
        )
    elif (
        delta_total_seconds > 60 and delta_total_seconds <= 60 * 15
    ):  # between 1 and 15 min
        return DateDelta(
            {
                "fixed_interval": "1m",
                "offset": f"{start_datetime_obj.minute}m",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(minutes=1),
            start_datetime_obj.replace(second=0, microsecond=0),
            end_datetime_obj.replace(second=0, microsecond=0),
            date_case="minutes",
        )
    elif (
        delta_total_seconds > 60 * 15 and delta_total_seconds <= 60 * 30
    ):  # between 15 and 30 min
        return DateDelta(
            {
                "fixed_interval": "2m",
                "offset": f"{start_datetime_obj.minute}m",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(minutes=2),
            start_datetime_obj.replace(second=0, microsecond=0),
            end_datetime_obj.replace(second=0, microsecond=0),
            date_case="minutes",
        )
    elif (
        delta_total_seconds > 60 * 30 and delta_total_seconds <= 60 * 60
    ):  # between 30 min and 1 hour
        return DateDelta(
            {
                "fixed_interval": "15m",
                "offset": f"{start_datetime_obj.minute}m",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(minutes=15),
            start_datetime_obj.replace(second=0, microsecond=0),
            end_datetime_obj.replace(second=0, microsecond=0),
            date_case="minutes",
        )
    elif (
        delta_total_seconds > 60 * 60 and delta_total_seconds <= 60 * 60 * 12
    ):  # between 1 and 12 hours
        return DateDelta(
            {
                "fixed_interval": "1h",
                "offset": f"{start_datetime_obj.hour}h",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(hours=1),
            start_datetime_obj.replace(minute=0, second=0, microsecond=0),
            end_datetime_obj.replace(minute=0, second=0, microsecond=0),
            date_case="hours",
        )
    elif (
        delta_total_seconds > 60 * 60 * 12 and delta_total_seconds <= 60 * 60 * 24
    ):  # between 12 and 24 hours
        return DateDelta(
            {
                "fixed_interval": "2h",
                "offset": f"{start_datetime_obj.hour}h",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(hours=2),
            start_datetime_obj.replace(minute=0, second=0, microsecond=0),
            end_datetime_obj.replace(minute=0, second=0, microsecond=0),
            date_case="hours",
        )
    elif (
        date_difference.days >= 1 and date_difference.days <= 6
    ):  # between 1 and 6 days
        return DateDelta(
            {
                "fixed_interval": "12h",
                "offset": f"{start_datetime_obj.hour}h",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(hours=12),
            start_datetime_obj.replace(minute=0, second=0, microsecond=0),
            end_datetime_obj.replace(minute=0, second=0, microsecond=0),
            date_case="hours",
        )
    elif (
        date_difference.days > 6 and date_difference.days <= 14
    ):  # between 7 and 14 days
        return DateDelta(
            {
                "fixed_interval": "1d",
                "offset": f"{start_datetime_obj.day}d",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(days=1),
            start_datetime_obj.replace(hour=0, minute=0, second=0, microsecond=0),
            end_datetime_obj.replace(hour=0, minute=0, second=0, microsecond=0),
            date_case="days",
        )
    elif (
        date_difference.days > 14 and date_difference.days <= 30
    ):  # between 14 and 30 days
        return DateDelta(
            {
                "fixed_interval": "1d",
                "offset": f"{start_datetime_obj.day}d",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            datetime.timedelta(days=1),
            start_datetime_obj.replace(hour=0, minute=0, second=0, microsecond=0),
            end_datetime_obj.replace(hour=0, minute=0, second=0, microsecond=0),
            date_case="days",
        )
    elif (
        date_difference.days > 30 and date_difference.days <= 90
    ):  # between 30 and 90 days
        monday = start_utc_time - datetime.timedelta(days=start_utc_time.weekday())
        return DateDelta(
            {"calendar_interval": "1w", "time_zone": f'{config["url"]["timezone"]}'},
            datetime.timedelta(weeks=1),
            monday.replace(hour=0, minute=0, second=0, microsecond=0),
            end_datetime_obj.replace(hour=0, minute=0, second=0, microsecond=0),
            date_case="days",
        )
    elif date_difference.days > 90:  # greater than 3 months
        return DateDelta(
            {
                "calendar_interval": "1M",
                "offset": f"{0}d",
                "time_zone": f'{config["url"]["timezone"]}',
            },
            relativedelta(months=+1),
            start_datetime_obj.replace(
                day=1, hour=0, minute=0, second=0, microsecond=0
            ),
            end_datetime_obj.replace(day=1, hour=0, minute=0, second=0, microsecond=0),
            date_case="months",
        )


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



def convert_local_to_utc(local_date):
    local_datetime_obj = datetime.datetime.strptime(
        local_date, format("%Y-%m-%dT%H:%M:%S.%fZ")
    )
    local_utc_time = local_datetime_obj.astimezone(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )
    return local_utc_time

from apping.custom_dashboard import custom_dashboard

main.register_blueprint(custom_dashboard, url_prefix="/custom_dashboard")
