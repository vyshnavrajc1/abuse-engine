from schemas.event_schema import CanonicalEvent
from typing import List, Dict
from datetime import datetime
import re


def _extract_path_params(endpoint: str) -> tuple:
    """
    Converts concrete URL to template + extracts path params.
    e.g. /api/users/123 → ("/api/users/{id}", {"id": "123"})
    """
    patterns = [
        (r"^(/api/users/)(\d+)(.*)$", "/api/users/{id}", "id"),
        (r"^(/api/products/)(\d+)(.*)$", "/api/products/{id}", "id"),
        (r"^(/api/orders/)(\d+)(.*)$", "/api/orders/{id}", "id"),
    ]
    for pattern, template, param_name in patterns:
        match = re.match(pattern, endpoint)
        if match:
            return template, {param_name: match.group(2)}
    return endpoint, {}


def normalize(raw_logs: List[Dict]) -> List[CanonicalEvent]:
    """
    Converts raw log dicts → CanonicalEvent objects.
    - Parses timestamp string → datetime object
    - Extracts path params from concrete URLs
    - Maps all fields including new semantic fields
    """
    events = []
    for log in raw_logs:
        raw_endpoint = log.get("endpoint", "")
        template, path_params = _extract_path_params(raw_endpoint)

        # Parse timestamp string → datetime
        raw_ts = log.get("timestamp", "")
        if isinstance(raw_ts, str):
            ts = datetime.fromisoformat(raw_ts)
        else:
            ts = raw_ts

        event = CanonicalEvent(
            timestamp=ts,
            ip=log.get("ip", ""),
            user_id=log.get("user_id", None),
            tenant_id=log.get("tenant_id", "default"),
            session_id=log.get("session_id", None),
            endpoint=template,
            method=log.get("method", "GET"),
            status_code=log.get("status_code", 200),
            user_agent=log.get("user_agent", ""),
            response_time=log.get("response_time", None),
            path_params=path_params,
            query_params=log.get("query_params", {}),
            request_body=log.get("request_body", None),
        )
        events.append(event)
    return events