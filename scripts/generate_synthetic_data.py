import json
import random
import os
from datetime import datetime, timedelta


def generate_normal_user(user_id, start_time, count=10):
    endpoints = ["/api/users/me", "/api/products", "/api/search", "/api/orders", "/api/logout"]
    events = []
    t = start_time
    for _ in range(count):
        t += timedelta(seconds=random.uniform(2, 30))
        events.append({
            "timestamp": t.isoformat(),
            "ip": f"10.0.0.{random.randint(1, 254)}",
            "user_id": user_id,
            "tenant_id": "tenant1",
            "session_id": f"{user_id}_sess",
            "endpoint": random.choice(endpoints),
            "method": "GET",
            "status_code": 200,
            "user_agent": "Mozilla/5.0",
            "response_time": random.uniform(50, 500),
            "query_params": {},
            "request_body": None,
        })
    return events


def generate_bot_scraper(user_id, start_time, count=200):
    events = []
    t = start_time
    for i in range(count):
        t += timedelta(seconds=random.uniform(0.1, 0.5))
        events.append({
            "timestamp": t.isoformat(),
            "ip": "192.168.1.100",
            "user_id": user_id,
            "tenant_id": "tenant1",
            "session_id": f"{user_id}_sess",
            "endpoint": f"/api/users/{i + 1}",
            "method": "GET",
            "status_code": 200,
            "user_agent": "python-requests/2.28",
            "response_time": random.uniform(10, 50),
            "query_params": {},
            "request_body": None,
        })
    return events


def generate_brute_force(user_id, start_time, count=50):
    events = []
    t = start_time
    for _ in range(count):
        t += timedelta(seconds=random.uniform(0.2, 1.0))
        events.append({
            "timestamp": t.isoformat(),
            "ip": "172.16.0.50",
            "user_id": user_id,
            "tenant_id": "tenant1",
            "session_id": f"{user_id}_sess",
            "endpoint": "/api/login",
            "method": "POST",
            "status_code": random.choice([401, 401, 401, 403, 200]),
            "user_agent": "curl/7.68",
            "response_time": random.uniform(20, 100),
            "query_params": {},
            "request_body": None,
        })
    return events


def generate_enumeration(user_id, start_time, count=100):
    events = []
    t = start_time
    for i in range(count):
        t += timedelta(seconds=random.uniform(0.3, 1.5))
        events.append({
            "timestamp": t.isoformat(),
            "ip": "10.10.10.10",
            "user_id": user_id,
            "tenant_id": "tenant1",
            "session_id": f"{user_id}_sess",
            "endpoint": f"/api/products/{i + 1}",
            "method": "GET",
            "status_code": random.choice([200, 200, 200, 404]),
            "user_agent": "Mozilla/5.0",
            "response_time": random.uniform(30, 150),
            "query_params": {},
            "request_body": None,
        })
    return events


if __name__ == "__main__":
    all_logs = []
    base = datetime(2026, 3, 5, 10, 0, 0)

    for i in range(5):
        all_logs.extend(generate_normal_user(f"normal_user_{i}", base))
    all_logs.extend(generate_bot_scraper("bot_user_1", base))
    all_logs.extend(generate_brute_force("brute_user_1", base))
    all_logs.extend(generate_enumeration("enum_user_1", base))

    os.makedirs("datasets", exist_ok=True)
    with open("datasets/mock_logs.json", "w") as f:
        json.dump(all_logs, f, indent=2)

    print(f"Generated {len(all_logs)} log entries -> datasets/mock_logs.json")