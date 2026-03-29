from schemas.event_schema import CanonicalEvent
from typing import List, Dict
from datetime import datetime
import re


def _extract_path_params(path: str) -> tuple:
    """
    Converts concrete URL to template + extracts path params.
    e.g. /api/users/123 → ("/api/users/{id}", {"id": "123"})
    """
    patterns = [
        (r"^(/api/users/)(\d+)(.*)$",    "/api/users/{id}",    "id"),
        (r"^(/api/products/)(\d+)(.*)$", "/api/products/{id}", "id"),
        (r"^(/api/orders/)(\d+)(.*)$",   "/api/orders/{id}",   "id"),
    ]
    for pattern, template, param_name in patterns:
        match = re.match(pattern, path)
        if match:
            return template, {param_name: match.group(2)}
    return path, {}


def normalize(raw_logs: List[Dict]) -> List[CanonicalEvent]:
    """
    Converts raw log dicts → CanonicalEvent objects.
    """
    events = []
    for log in raw_logs:
        raw_path = log.get("endpoint", log.get("request_path", ""))
        template, path_params = _extract_path_params(raw_path)

        raw_ts = log.get("timestamp", "")
        ts = datetime.fromisoformat(raw_ts) if isinstance(raw_ts, str) else raw_ts

        event = CanonicalEvent(
            timestamp     = ts,
            source_ip     = log.get("ip", log.get("source_ip", "")),
            user_id       = log.get("user_id", None),
            request_path  = template,
            http_method   = log.get("method", log.get("http_method", "GET")),
            response_code = log.get("status_code", log.get("response_code", 200)),
            bytes_sent    = log.get("bytes_sent", None),
            session_id    = log.get("session_id", None),
            path_params   = path_params,
            query_params  = log.get("query_params", {}),
        )
        events.append(event)
    return events