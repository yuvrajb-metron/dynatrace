from datetime import datetime, timezone

from dateutil import parser


def normalize_datetime(dt_input):
    dt = dt_input if isinstance(dt_input, datetime) else parser.parse(dt_input)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.strftime("%Y-%m-%dT%H:%M:%S%z")
