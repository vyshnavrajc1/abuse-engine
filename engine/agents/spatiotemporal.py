"""
spatio_temporal_agent.py

Detects coordinated, distributed, or synchronized behavior that individual
session‑ or endpoint‑centric agents miss. Builds a graph of IPs, users, and
normalized endpoints over sliding time windows and flags anomalous graph
structures.
"""

import re
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple, Optional
from collections import defaultdict

import networkx as nx
from sklearn.ensemble import IsolationForest

# Assume CanonicalEvent is defined elsewhere; for completeness we define a minimal version.
class CanonicalEvent:
    """Minimal event structure expected by the agent."""
    def __init__(self, timestamp: datetime, source_ip: str, user_id: Optional[str],
                 request_path: str, http_method: str):
        self.timestamp = timestamp
        self.source_ip = source_ip
        self.user_id = user_id
        self.request_path = request_path
        self.http_method = http_method

class AgentResult:
    """Standard output format for all agents."""
    def __init__(self, agent: str, risk_score: float, flags: List[str], details: Dict[str, Any] = None):
        self.agent = agent
        self.risk_score = risk_score
        self.flags = flags
        self.details = details or {}

class SpatioTemporalAgent:
    """
    Graph‑based agent that analyzes relationships between IPs, users, and endpoints
    over time. Uses sliding windows and Isolation Forest on graph features.
    """

    def __init__(self,
                 window_size: timedelta = timedelta(minutes=5),
                 stride: timedelta = timedelta(minutes=2.5),
                 contamination: float = 0.1,
                 synchrony_threshold_seconds: float = 2.0,
                 ip_hopping_threshold: float = 3.0,
                 coordination_threshold: float = 10.0):
        """
        Args:
            window_size: length of each temporal window
            stride: step between consecutive windows (overlap allowed)
            contamination: expected proportion of outliers in the data (passed to IsolationForest)
            synchrony_threshold_seconds: max std dev of timestamps to flag "synchronized_endpoint_access"
            ip_hopping_threshold: min avg user_ip_count to flag "ip_hopping"
            coordination_threshold: min max shared_endpoint_ips to flag "coordinated_ips"
        """
        self.window_size = window_size
        self.stride = stride
        self.contamination = contamination
        self.synchrony_threshold = synchrony_threshold_seconds
        self.ip_hopping_threshold = ip_hopping_threshold
        self.coordination_threshold = coordination_threshold

        # Simple regex to normalize numeric IDs in paths (e.g., /orders/123 -> /orders/{id})
        self.id_pattern = re.compile(r'/\d+(/|$)')

    def normalize_endpoint(self, path: str) -> str:
        """Replace numeric ID segments with '{id}' placeholder."""
        # Remove query string if present
        path = path.split('?')[0]
        # Replace each occurrence of /digits with /{id}
        normalized = self.id_pattern.sub('/{id}\\1', path)
        return normalized

    def _build_window_graph(self, events: List[CanonicalEvent]) -> nx.Graph:
        """
        Build a graph from the given list of events.
        Nodes have a 'type' attribute: 'ip', 'user', or 'endpoint'.
        Edges store aggregated information: count, list of timestamps, set of methods.
        """
        G = nx.Graph()
        for ev in events:
            # Create node names with prefixes to avoid collisions (though types are separate)
            ip_node = f"ip::{ev.source_ip}"
            user_node = f"user::{ev.user_id}" if ev.user_id else "user::anonymous"
            endpoint_node = f"ep::{self.normalize_endpoint(ev.request_path)}"

            # Add nodes with type attribute
            G.add_node(ip_node, type='ip')
            G.add_node(user_node, type='user')
            G.add_node(endpoint_node, type='endpoint')

            # IP -> User edge
            ip_user = (ip_node, user_node)
            if G.has_edge(*ip_user):
                G.edges[ip_user]['count'] += 1
                G.edges[ip_user]['timestamps'].append(ev.timestamp)
                G.edges[ip_user]['methods'].add(ev.http_method)
            else:
                G.add_edge(ip_node, user_node,
                           count=1,
                           timestamps=[ev.timestamp],
                           methods={ev.http_method})

            # User -> Endpoint edge
            user_ep = (user_node, endpoint_node)
            if G.has_edge(*user_ep):
                G.edges[user_ep]['count'] += 1
                G.edges[user_ep]['timestamps'].append(ev.timestamp)
                G.edges[user_ep]['methods'].add(ev.http_method)
            else:
                G.add_edge(user_node, endpoint_node,
                           count=1,
                           timestamps=[ev.timestamp],
                           methods={ev.http_method})
        return G

    def _generate_windows(self, events: List[CanonicalEvent]) -> List[Tuple[datetime, datetime, nx.Graph]]:
        """
        Sort events by time and slide a window over the whole timeline.
        Returns a list of (window_start, window_end, subgraph) for each window.
        """
        if not events:
            return []

        # Sort events by timestamp
        events_sorted = sorted(events, key=lambda e: e.timestamp)
        start_time = events_sorted[0].timestamp
        end_time = events_sorted[-1].timestamp

        windows = []
        current_start = start_time
        while current_start <= end_time:
            window_end = current_start + self.window_size
            # Collect events that fall into this window
            window_events = [e for e in events_sorted if current_start <= e.timestamp < window_end]
            if window_events:
                G = self._build_window_graph(window_events)
                windows.append((current_start, window_end, G))
            current_start += self.stride
        return windows

    def _extract_features(self, G: nx.Graph) -> Dict[str, float]:
        """
        Compute a set of numerical features from the window graph.
        Returns a dictionary with feature names as keys.
        """
        # Collect nodes by type
        ip_nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == 'ip']
        user_nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == 'user']
        ep_nodes = [n for n, attr in G.nodes(data=True) if attr.get('type') == 'endpoint']

        # Helper to get neighbors of a given type
        def neighbors_of_type(node, target_type):
            return [nei for nei in G.neighbors(node) if G.nodes[nei].get('type') == target_type]

        # ----- Feature 1: ip_fan_out (average number of users per IP) -----
        ip_user_counts = [len(neighbors_of_type(ip, 'user')) for ip in ip_nodes]
        avg_ip_fan_out = np.mean(ip_user_counts) if ip_user_counts else 0.0

        # ----- Feature 2: user_ip_count (average number of IPs per user) -----
        user_ip_counts = [len(neighbors_of_type(user, 'ip')) for user in user_nodes]
        avg_user_ip_count = np.mean(user_ip_counts) if user_ip_counts else 0.0

        # ----- Feature 3: graph_density (edges per node, a simple proxy) -----
        num_nodes = G.number_of_nodes()
        num_edges = G.number_of_edges()
        density = num_edges / num_nodes if num_nodes > 0 else 0.0

        # ----- Feature 4: shared_endpoint_ips (max number of distinct IPs reaching same endpoint) -----
        endpoint_ip_counts = []
        for ep in ep_nodes:
            # Find all users that connect to this endpoint
            users_for_ep = neighbors_of_type(ep, 'user')
            # For each user, find IPs that connect to that user (within this window)
            ips = set()
            for user in users_for_ep:
                for ip in neighbors_of_type(user, 'ip'):
                    ips.add(ip)
            endpoint_ip_counts.append(len(ips))
        max_shared_ips = max(endpoint_ip_counts) if endpoint_ip_counts else 0

        # ----- Feature 5: request_synchrony (minimum std dev of timestamps for any endpoint) -----
        min_synchrony = float('inf')
        for ep in ep_nodes:
            # Collect all timestamps of requests to this endpoint
            timestamps = []
            for user in neighbors_of_type(ep, 'user'):
                edge_data = G.get_edge_data(user, ep)
                timestamps.extend(edge_data.get('timestamps', []))
            if len(timestamps) >= 2:  # need at least two to compute std dev
                # Convert to seconds since epoch for std dev calculation
                seconds = [ts.timestamp() for ts in timestamps]
                synchrony = np.std(seconds)
                if synchrony < min_synchrony:
                    min_synchrony = synchrony
        # If no endpoint had two requests, set a high value (not synchronized)
        if min_synchrony == float('inf'):
            min_synchrony = 1e6

        # ----- Feature 6: ip_endpoint_spread (average number of distinct endpoints per IP) -----
        ip_ep_counts = []
        for ip in ip_nodes:
            # Find users for this IP
            users_for_ip = neighbors_of_type(ip, 'user')
            # Collect endpoints reachable via those users
            eps = set()
            for user in users_for_ip:
                for ep in neighbors_of_type(user, 'endpoint'):
                    eps.add(ep)
            ip_ep_counts.append(len(eps))
        avg_ip_endpoint_spread = np.mean(ip_ep_counts) if ip_ep_counts else 0.0

        # ----- Feature 7: edge_growth_rate (number of edges in this window) -----
        # (Simplified: just use raw edge count; for real growth rate we'd need previous window)
        edge_count = num_edges

        return {
            'ip_fan_out': avg_ip_fan_out,
            'user_ip_count': avg_user_ip_count,
            'graph_density': density,
            'shared_endpoint_ips': max_shared_ips,
            'request_synchrony': min_synchrony,
            'ip_endpoint_spread': avg_ip_endpoint_spread,
            'edge_count': edge_count,
        }

    def _flag_anomalies(self, features: Dict[str, float]) -> List[str]:
        """Generate human‑readable flags based on feature thresholds."""
        flags = []
        if features['request_synchrony'] < self.synchrony_threshold:
            flags.append('synchronized_endpoint_access')
        if features['user_ip_count'] > self.ip_hopping_threshold:
            flags.append('ip_hopping')
        if features['shared_endpoint_ips'] > self.coordination_threshold:
            flags.append('coordinated_ips')
        # Additional heuristics can be added here
        return flags

    def run(self, events: List[CanonicalEvent]) -> AgentResult:
        """
        Main entry point: process events, compute window features,
        run Isolation Forest, and return an AgentResult.
        """
        if len(events) < 10:  # too few events to be meaningful
            return AgentResult(agent='spatio_temporal', risk_score=0.0, flags=[])

        # 1. Generate sliding windows
        windows = self._generate_windows(events)
        if not windows:
            return AgentResult(agent='spatio_temporal', risk_score=0.0, flags=[])

        # 2. Extract features for each window
        feature_list = []
        for start, end, G in windows:
            feats = self._extract_features(G)
            feature_list.append(feats)

        # 3. Convert to array for IsolationForest
        feature_names = list(feature_list[0].keys())
        X = np.array([[f[name] for name in feature_names] for f in feature_list])

    # 4. Fit Isolation Forest and get anomaly scores
        iso_forest = IsolationForest(contamination=self.contamination, random_state=42)
        iso_forest.fit(X)
    # decision_function: negative = anomaly, positive = normal
        scores = iso_forest.decision_function(X)

    # 5. Convert scores to per‑window risk (0 = normal, 1 = most anomalous)
        min_score = scores.min()
        max_score = scores.max()
        if max_score - min_score > 1e-9:
            per_window_risk = 1 - (scores - min_score) / (max_score - min_score)
        else:
            per_window_risk = np.zeros_like(scores)
        max_risk = float(np.max(per_window_risk))

    # 6. Generate flags based on **all** windows (heuristic thresholds)
        all_flags = set()
        for feats in feature_list:
            if feats['request_synchrony'] < self.synchrony_threshold:
                all_flags.add('synchronized_endpoint_access')
            if feats['user_ip_count'] > self.ip_hopping_threshold:
                all_flags.add('ip_hopping')
            if feats['shared_endpoint_ips'] > self.coordination_threshold:
                all_flags.add('coordinated_ips')
        flags = list(all_flags)

    # 7. Add a high‑level flag if the most anomalous window is very risky
        if max_risk > 0.8:
            flags.append('high_risk_graph_pattern')

    # 8. Prepare details (include the most anomalous window's features for debugging)
        worst_idx = np.argmax(per_window_risk)  # window with highest risk
        worst_features = feature_list[worst_idx]

        return AgentResult(
            agent='spatio_temporal',
            risk_score=max_risk,
            flags=flags,
            details={
                'num_windows': len(windows),
                'worst_window_features': worst_features,
                'worst_window_start': str(windows[worst_idx][0]),
                'worst_window_end': str(windows[worst_idx][1]),
                'per_window_risk': per_window_risk.tolist(),  # optional, for debugging
            }
        )


# Example usage (if run as script)
if __name__ == '__main__':
    # Generate synthetic test data
    from datetime import datetime, timedelta
    import random

    base = datetime.now()
    events = []
    # Normal traffic
    for i in range(100):
        t = base + timedelta(seconds=i*10)
        events.append(CanonicalEvent(t, f"192.168.1.{random.randint(1,10)}", f"user{i%20}",
                                      f"/api/data/{random.randint(1,5)}", "GET"))
    # Coordinated attack: 10 different IPs hitting the same endpoint within 2 seconds
    attack_time = base + timedelta(minutes=10)
    for i in range(10):
        t = attack_time + timedelta(milliseconds=random.randint(0, 2000))
        events.append(CanonicalEvent(t, f"10.0.0.{i}", f"attacker{i}",
                                      "/api/secret/data", "GET"))
    # IP hopping: one user from many IPs
    hopping_time = base + timedelta(minutes=15)
    for i in range(8):
        t = hopping_time + timedelta(seconds=i*30)
        events.append(CanonicalEvent(t, f"10.0.1.{i}", "target_user",
                                      "/api/profile", "GET"))

    agent = SpatioTemporalAgent()
    result = agent.run(events)
    print(f"Risk score: {result.risk_score:.3f}")
    print(f"Flags: {result.flags}")
    print(f"Details: {result.details}")