"""
Semantic Guard Agent

Detects violations of declared API intent and object-level semantics.
Operates per user per time window.

Input: List of CanonicalEvent objects
Output: Per-user risk score with rule breakdown and confidence.
"""

import yaml
import json
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import re
import logging

from schemas.event_schema import CanonicalEvent

logger = logging.getLogger(__name__)


# -------------------- Data Models --------------------

@dataclass
class Endpoint:
    """Represents an API endpoint with its semantic metadata."""
    path: str
    method: str
    type: str  # single_object, collection, search, admin, mutation, bulk_operation
    owner_field: Optional[str] = None  # path parameter name that holds object ID
    expected_rate: Optional[str] = None  # e.g., "low", "medium", "high"
    parameters: Dict[str, Any] = field(default_factory=dict)  # schema info
    authentication_required: bool = True
    is_public: bool = False

    def __hash__(self):
        return hash((self.path, self.method))


class EndpointRegistry:
    """Registry of all endpoints keyed by (path, method)."""
    def __init__(self):
        self._endpoints: Dict[Tuple[str, str], Endpoint] = {}

    def add(self, endpoint: Endpoint):
        self._endpoints[(endpoint.path, endpoint.method)] = endpoint

    def get(self, path: str, method: str) -> Optional[Endpoint]:
        return self._endpoints.get((path, method))

    def items(self):
        return self._endpoints.items()


# -------------------- Spec Loader --------------------

class SpecLoader:
    """Loads and parses OpenAPI specification to build endpoint registry."""

    @staticmethod
    def load_from_file(file_path: str) -> EndpointRegistry:
        """
        Load OpenAPI spec from JSON or YAML file.
        Extracts: path, method, parameters, security, and custom x-* fields.
        """
        with open(file_path, 'r') as f:
            if file_path.endswith(('.yaml', '.yml')):
                spec = yaml.safe_load(f)
            else:
                spec = json.load(f)

        registry = EndpointRegistry()
        paths = spec.get('paths', {})

        for path, path_item in paths.items():
            for method, operation in path_item.items():
                method = method.upper()
                if method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']:
                    continue

                # Determine endpoint type based on operationId, tags, or custom field
                endpoint_type = SpecLoader._classify_endpoint(operation, path, method)

                # Extract owner field (custom extension or from path parameters)
                owner_field = None
                parameters = operation.get('parameters', [])
                # Look for a parameter marked with x-owner=true
                for param in parameters:
                    if param.get('in') == 'path' and param.get('x-owner'):
                        owner_field = param.get('name')
                        break
                # If not found, try to guess from path template (e.g., /users/{id})
                if not owner_field and endpoint_type == 'single_object':
                    # Assume the last path parameter is the object ID
                    path_params = re.findall(r'\{(\w+)\}', path)
                    if path_params:
                        owner_field = path_params[-1]

                # Expected rate (custom extension)
                expected_rate = operation.get('x-expected-rate', 'medium')

                # Authentication required
                security = operation.get('security', spec.get('security', []))
                auth_required = len(security) > 0

                # Build parameter schema (simplified)
                param_schema = {}
                for param in parameters:
                    param_schema[param['name']] = {
                        'in': param['in'],
                        'required': param.get('required', False),
                        'type': param.get('schema', {}).get('type', 'string')
                    }

                endpoint = Endpoint(
                    path=path,
                    method=method,
                    type=endpoint_type,
                    owner_field=owner_field,
                    expected_rate=expected_rate,
                    parameters=param_schema,
                    authentication_required=auth_required,
                    is_public=not auth_required
                )
                registry.add(endpoint)

        return registry

    @staticmethod
    def _classify_endpoint(operation: Dict, path: str, method: str) -> str:
        """Classify endpoint into one of the predefined types."""
        op_id = operation.get('operationId', '').lower()
        tags = operation.get('tags', [])

        if 'admin' in tags or 'admin' in op_id:
            return 'admin'
        if 'bulk' in op_id or 'batch' in op_id or method == 'POST' and '/bulk' in path:
            return 'bulk_operation'
        if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            return 'mutation'
        if method == 'GET':
            if re.search(r'\{[^}]+\}', path):
                last_segment = path.split('/')[-1]
                if '{' in last_segment:
                    return 'single_object'
                else:
                    return 'collection'
            else:
                if 'search' in op_id or 'query' in op_id:
                    return 'search'
                return 'collection'
        return 'mutation'


# -------------------- Semantic Rule Engine --------------------

class SemanticRuleEngine:
    """Applies all semantic rules to a user's events within a window."""

    def __init__(self, registry: EndpointRegistry, owner_resolver: Callable[[str, str], Optional[str]],
                 config: Dict[str, Any]):
        """
        :param registry: EndpointRegistry with endpoint metadata.
        :param owner_resolver: Function(object_id, tenant_id) -> owner_id (or None).
        :param config: Dict with thresholds and weights.
        """
        self.registry = registry
        self.owner_resolver = owner_resolver
        self.config = config

    def evaluate(self, user_events: List[CanonicalEvent], user_id: str, tenant_id: str) -> Dict[str, float]:
        """
        Compute rule scores for a single user in a window.
        Returns dict with rule names as keys and scores (0-1) as values.
        """
        endpoint_events = defaultdict(list)
        object_access_sequence = []
        unique_objects_per_endpoint = defaultdict(set)
        probing_events = []

        for event in user_events:
            endpoint = self.registry.get(event.endpoint, event.method)
            if not endpoint:
                continue

            obj_id = None
            if endpoint.type == 'single_object' and endpoint.owner_field:
                obj_id = event.path_params.get(endpoint.owner_field)
                if obj_id:
                    object_access_sequence.append(obj_id)
                    unique_objects_per_endpoint[endpoint].add(obj_id)

            if event.status_code in (403, 404) and obj_id:
                probing_events.append({
                    'obj_id': obj_id,
                    'timestamp': event.timestamp
                })

            endpoint_events[endpoint].append(event)

        ownership_score = self._rule_ownership(user_events, user_id, tenant_id)
        seq_score = self._rule_sequential(object_access_sequence)
        volume_score = self._rule_volume_mismatch(unique_objects_per_endpoint)
        tamper_score = self._rule_parameter_tampering(endpoint_events)
        probe_score = self._rule_probing(probing_events)

        return {
            'ownership_violation': ownership_score,
            'enumeration': seq_score,
            'volume_mismatch': volume_score,
            'parameter_tampering': tamper_score,
            'probing': probe_score
        }

    def _rule_ownership(self, events: List[CanonicalEvent], user_id: str, tenant_id: str) -> float:
        violations = 0
        total = 0
        for event in events:
            endpoint = self.registry.get(event.endpoint, event.method)
            if not endpoint or endpoint.type != 'single_object' or not endpoint.owner_field:
                continue
            obj_id = event.path_params.get(endpoint.owner_field)
            if not obj_id:
                continue
            total += 1
            owner = self.owner_resolver(obj_id, tenant_id)
            if owner is None:
                continue
            if owner != user_id:
                violations += 1
        return violations / total if total > 0 else 0.0

    def _rule_sequential(self, object_ids: List[str]) -> float:
        if len(object_ids) < 2:
            return 0.0
        nums = []
        for oid in object_ids:
            try:
                nums.append(int(oid))
            except ValueError:
                pass
        if len(nums) < 2:
            return 0.0
        nums.sort()
        consecutive_pairs = 0
        total_pairs = len(nums) - 1
        for i in range(len(nums)-1):
            if nums[i+1] - nums[i] == 1:
                consecutive_pairs += 1
        return consecutive_pairs / total_pairs

    def _rule_volume_mismatch(self, unique_objects_per_endpoint: Dict[Endpoint, Set]) -> float:
        threshold_map = {
            'low': self.config.get('volume_low_threshold', 5),
            'medium': self.config.get('volume_medium_threshold', 20),
            'high': self.config.get('volume_high_threshold', 100)
        }
        max_score = 0.0
        for endpoint, obj_set in unique_objects_per_endpoint.items():
            if endpoint.type != 'single_object':
                continue
            count = len(obj_set)
            expected = endpoint.expected_rate or 'medium'
            threshold = threshold_map.get(expected, 20)
            if count <= threshold:
                score = 0.0
            else:
                score = min(1.0, (count - threshold) / (2 * threshold))
            max_score = max(max_score, score)
        return max_score

    def _rule_parameter_tampering(self, endpoint_events: Dict[Endpoint, List[CanonicalEvent]]) -> float:
        tamper_count = 0
        total = 0
        for endpoint, events in endpoint_events.items():
            expected_params = endpoint.parameters
            for event in events:
                request_params = {}
                request_params.update(event.path_params)
                request_params.update(event.query_params)
                unexpected = [k for k in request_params if k not in expected_params]
                if unexpected:
                    tamper_count += 1
                total += 1
        return tamper_count / total if total > 0 else 0.0

    def _rule_probing(self, probing_events: List[Dict]) -> float:
        if len(probing_events) < 2:
            return 0.0
        unique_obj = set(e['obj_id'] for e in probing_events)
        return len(unique_obj) / len(probing_events)


# -------------------- Main Agent --------------------

class SemanticGuardAgent:
    """
    Agent 1: Semantic Guard.
    Processes a stream of events over a time window and outputs per-user risk scores.
    """

    def __init__(self, spec_file: str, owner_resolver: Callable[[str, str], Optional[str]],
                 config: Optional[Dict] = None):
        """
        :param spec_file: Path to OpenAPI spec file (JSON/YAML).
        :param owner_resolver: Function to get owner ID from object ID and tenant.
        :param config: Configuration dict with thresholds, weights, whitelists.
        """
        self.registry = SpecLoader.load_from_file(spec_file)
        self.owner_resolver = owner_resolver
        self.config = config or {}
        self.rule_engine = SemanticRuleEngine(self.registry, owner_resolver, self.config)

        # Whitelists
        self.admin_users = set(self.config.get('admin_users', []))
        self.public_endpoints = set(self.config.get('public_endpoints', []))  # (path,method)
        self.pagination_params = self.config.get('pagination_params', ['page', 'limit', 'offset'])

        # Rule weights (normalized later)
        self.weights = self.config.get('weights', {
            'ownership_violation': 0.3,
            'enumeration': 0.25,
            'volume_mismatch': 0.2,
            'parameter_tampering': 0.15,
            'probing': 0.1
        })

        # Thresholds for confidence
        self.confidence_thresholds = self.config.get('confidence_thresholds', {
            'spec_coverage': 0.8,
            'data_completeness': 0.7
        })

    def process_window(self, events: List[CanonicalEvent],
                       window_start: datetime, window_end: datetime) -> Dict[str, Dict]:
        """
        Process events in a time window.
        Returns dict mapping user_id -> risk report.
        """
        # Filter events within window
        window_events = [e for e in events if window_start <= e.timestamp < window_end]

        # Group by user
        user_events = defaultdict(list)
        for event in window_events:
            if event.user_id in self.admin_users:
                continue
            user_events[event.user_id].append(event)

        results = {}
        for user_id, evs in user_events.items():
            # Use tenant_id from first event (assume consistent per user in window)
            tenant_id = evs[0].tenant_id or 'default'
            rule_scores = self.rule_engine.evaluate(evs, user_id, tenant_id)

            total_weight = sum(self.weights.values())
            if total_weight == 0:
                total_weight = 1.0
            overall = sum(rule_scores[rule] * self.weights.get(rule, 0) for rule in rule_scores) / total_weight
            overall = min(1.0, max(0.0, overall))

            confidence = self._compute_confidence(evs)

            results[user_id] = {
                'semantic_risk_score': overall,
                'rule_breakdown': rule_scores,
                'confidence': confidence
            }

        return results

    def _compute_confidence(self, events: List[CanonicalEvent]) -> float:
        # Spec coverage: proportion of endpoint+method pairs present in registry
        endpoints_in_events = set((e.endpoint, e.method) for e in events)
        known_endpoints = set()
        for ep, meth in endpoints_in_events:
            if self.registry.get(ep, meth):
                known_endpoints.add((ep, meth))
        spec_coverage = len(known_endpoints) / len(endpoints_in_events) if endpoints_in_events else 1.0

        # Data completeness: events have both path_params and query_params
        complete = sum(1 for e in events if e.path_params is not None and e.query_params is not None)
        data_completeness = complete / len(events) if events else 1.0

        return min(1.0, (spec_coverage + data_completeness) / 2)


# -------------------- Example Usage --------------------

if __name__ == "__main__":
    # Dummy owner resolver
    def dummy_owner_resolver(obj_id: str, tenant: str) -> Optional[str]:
        mapping = {
            "123": "userA",
            "124": "userA",
            "125": "userB",
        }
        return mapping.get(obj_id)

    config = {
        "admin_users": ["admin1"],
        "weights": {
            "ownership_violation": 0.4,
            "enumeration": 0.2,
            "volume_mismatch": 0.2,
            "parameter_tampering": 0.1,
            "probing": 0.1
        },
        "volume_low_threshold": 5,
        "volume_medium_threshold": 10,
        "volume_high_threshold": 20,
    }

    agent = SemanticGuardAgent("spec.yaml", dummy_owner_resolver, config)

    # Sample events using CanonicalEvent
    from datetime import datetime, timedelta
    now = datetime.utcnow()

    events = [
        CanonicalEvent(
            timestamp=now,
            ip="1.2.3.4",
            user_id="userA",
            tenant_id="tenant1",
            session_id="sess1",
            endpoint="/api/users/{id}",
            method="GET",
            status_code=200,
            user_agent="test",
            path_params={"id": "123"},
            query_params={}
        ),
        CanonicalEvent(
            timestamp=now + timedelta(minutes=1),
            ip="1.2.3.4",
            user_id="userA",
            tenant_id="tenant1",
            session_id="sess1",
            endpoint="/api/users/{id}",
            method="GET",
            status_code=200,
            user_agent="test",
            path_params={"id": "124"},
            query_params={}
        ),
        CanonicalEvent(
            timestamp=now + timedelta(minutes=2),
            ip="1.2.3.4",
            user_id="userA",
            tenant_id="tenant1",
            session_id="sess1",
            endpoint="/api/users/{id}",
            method="GET",
            status_code=403,
            user_agent="test",
            path_params={"id": "999"},
            query_params={}
        ),
        CanonicalEvent(
            timestamp=now,
            ip="5.6.7.8",
            user_id="userB",
            tenant_id="tenant1",
            session_id="sess2",
            endpoint="/api/users/{id}",
            method="GET",
            status_code=200,
            user_agent="test",
            path_params={"id": "125"},
            query_params={}
        )
    ]

    window_start = now - timedelta(minutes=5)
    window_end = now + timedelta(minutes=5)
    results = agent.process_window(events, window_start, window_end)

    import json
    print(json.dumps(results, indent=2))