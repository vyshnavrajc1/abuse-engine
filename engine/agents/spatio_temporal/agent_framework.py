"""
agent_framework.py – Lightweight agentic graph execution engine.

Architecture overview
---------------------
This module implements the same conceptual model as LangGraph / LangChain agents:

    ┌──────────┐    state     ┌──────────┐    state     ┌──────────┐
    │  Node A  │ ──────────► │  Node B  │ ──────────► │  Node C  │
    └──────────┘             └──────────┘             └──────────┘
         ▲                                                   │
         └─────────── conditional edge (router) ─────────────┘

Key concepts
------------
Node        A callable unit (function or class) that reads from AgentState,
            does work, and writes results back into AgentState.
Edge        A directed connection between two nodes.
Router      A function that inspects AgentState and returns the name of the
            next node to execute (or END to stop).
AgentGraph  Compiles a set of nodes + edges into an executable plan and runs it.

This design is intentionally compatible with LangGraph's StateGraph API so that
migration to LangGraph (when it becomes available in the environment) is a
near-drop-in replacement — just swap AgentGraph for StateGraph.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime
from typing import Callable, Dict, List, Optional, Union

from schemas.agent_result import AgentState, AgentResult, Severity

logger = logging.getLogger(__name__)

END = "__END__"


# ---------------------------------------------------------------------------
# Node protocol
# ---------------------------------------------------------------------------

NodeFn = Callable[[AgentState], AgentState]


class Node:
    """
    Wraps a callable into a named, observable node.

    The callable must accept an AgentState and return an (optionally mutated)
    AgentState.  Exceptions are caught, logged, and stored in state.errors so
    the graph can continue gracefully.
    """

    def __init__(self, name: str, fn: NodeFn, description: str = ""):
        self.name = name
        self.fn = fn
        self.description = description

    def __call__(self, state: AgentState) -> AgentState:
        logger.debug("Node '%s' starting", self.name)
        t0 = time.perf_counter()
        try:
            state = self.fn(state)
        except Exception as exc:
            msg = f"Node '{self.name}' raised {type(exc).__name__}: {exc}"
            logger.error(msg, exc_info=True)
            state.errors.append(msg)
        elapsed_ms = (time.perf_counter() - t0) * 1000
        logger.debug("Node '%s' finished in %.1f ms", self.name, elapsed_ms)
        state.metadata[f"_node_{self.name}_elapsed_ms"] = elapsed_ms
        return state


# ---------------------------------------------------------------------------
# Conditional router
# ---------------------------------------------------------------------------

RouterFn = Callable[[AgentState], str]


# ---------------------------------------------------------------------------
# AgentGraph
# ---------------------------------------------------------------------------

class AgentGraph:
    """
    Directed graph of Nodes with optional conditional routing.

    Quick-start
    -----------
    graph = AgentGraph()
    graph.add_node("validate",  validate_fn)
    graph.add_node("score",     score_fn)
    graph.add_node("summarise", summarise_fn)

    graph.set_entry("validate")
    graph.add_edge("validate", "score")
    graph.add_conditional_edge("score", router_fn,
                                {"anomalous": "summarise", "normal": END})
    graph.add_edge("summarise", END)

    result_state = graph.run(initial_state)
    """

    def __init__(self, name: str = "agent_graph"):
        self.name = name
        self._nodes: Dict[str, Node] = {}
        self._edges: Dict[str, str] = {}
        self._conditional_edges: Dict[str, tuple[RouterFn, Dict[str, str]]] = {}
        self._entry: Optional[str] = None

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def add_node(self, name: str, fn: NodeFn, description: str = "") -> "AgentGraph":
        self._nodes[name] = Node(name, fn, description)
        return self

    def set_entry(self, node_name: str) -> "AgentGraph":
        if node_name not in self._nodes:
            raise ValueError(f"Unknown node '{node_name}'")
        self._entry = node_name
        return self

    def add_edge(self, from_node: str, to_node: str) -> "AgentGraph":
        """Unconditional edge: after *from_node*, always go to *to_node*."""
        if to_node != END and to_node not in self._nodes:
            raise ValueError(f"Unknown target node '{to_node}'")
        self._edges[from_node] = to_node
        return self

    def add_conditional_edge(
        self,
        from_node: str,
        router: RouterFn,
        mapping: Dict[str, str],
    ) -> "AgentGraph":
        """
        After *from_node*, call *router(state)* and use the returned key to
        look up the next node in *mapping*.  END is a valid mapping value.
        """
        self._conditional_edges[from_node] = (router, mapping)
        return self

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run(self, state: AgentState, max_steps: int = 50) -> AgentState:
        if self._entry is None:
            raise RuntimeError("No entry node set. Call graph.set_entry(node_name).")

        current = self._entry
        step = 0

        logger.info("Graph '%s' starting at node '%s'", self.name, current)

        while current != END and step < max_steps:
            if current not in self._nodes:
                state.errors.append(f"Unknown node '{current}' at step {step}")
                break

            state = self._nodes[current](state)
            step += 1

            # Determine next node
            if current in self._conditional_edges:
                router, mapping = self._conditional_edges[current]
                key = router(state)
                next_node = mapping.get(key)
                if next_node is None:
                    state.errors.append(
                        f"Router for '{current}' returned unknown key '{key}'"
                    )
                    break
            elif current in self._edges:
                next_node = self._edges[current]
            else:
                logger.debug("Node '%s' has no outgoing edge; stopping.", current)
                break

            logger.debug("Edge: %s → %s", current, next_node)
            current = next_node

        if step >= max_steps:
            state.errors.append(f"Graph exceeded max_steps={max_steps}")

        state.finished_at = datetime.utcnow()
        logger.info(
            "Graph '%s' finished in %d steps. errors=%d",
            self.name, step, len(state.errors),
        )
        return state


# ---------------------------------------------------------------------------
# Built-in utility nodes
# ---------------------------------------------------------------------------

def make_validation_node(min_events: int = 10) -> NodeFn:
    """
    Returns a node function that validates the event list in state and records
    a skip signal in metadata if there are too few events.
    """
    def validate(state: AgentState) -> AgentState:
        n = len(state.events)
        state.metadata["event_count"] = n
        if n < min_events:
            logger.info(
                "Validation: only %d events (min %d); marking as skip.", n, min_events
            )
            state.metadata["skip_scoring"] = True
            state.results.append(AgentResult(
                agent="validation",
                risk_score=0.0,
                severity=Severity.INFO,
                flags=["insufficient_events"],
                details={"event_count": n, "min_required": min_events},
            ))
        else:
            state.metadata["skip_scoring"] = False
        return state
    return validate


def skip_router(state: AgentState) -> str:
    """Route to 'skip' if validation flagged insufficient events, else 'score'."""
    return "skip" if state.metadata.get("skip_scoring") else "score"


def no_op(state: AgentState) -> AgentState:
    """A terminal no-op node — used as the 'skip' branch target."""
    logger.debug("no_op node: nothing to do.")
    return state


def make_severity_node() -> NodeFn:
    """
    Post-processing node that assigns a Severity level to each AgentResult,
    then records an overall session severity in metadata.

    Severity is derived from the 75th-percentile of per-window risk scores
    rather than the raw max (risk_score).  The max can be dominated by a
    single edge-case window (e.g. a sparse end-of-run window that happens to
    sit in the IF outlier region); p75 is a more robust indicator that
    sustained or repeated anomalous windows are present.

    risk_score (the max) is still exposed for downstream alerting — it just
    does not drive the human-facing severity label alone.
    """
    import numpy as _np

    def assign_severity(state: AgentState) -> AgentState:
        worst = Severity.INFO
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM,
                 Severity.HIGH, Severity.CRITICAL]

        for res in state.results:
            # Use p75 of per-window risks as the representative score.
            # Fall back to risk_score for results that don't have window detail.
            window_risks = [
                w["risk_score"]
                for w in res.details.get("per_window_details", [])
            ]
            rep_score = (
                float(_np.percentile(window_risks, 75))
                if window_risks
                else res.risk_score
            )

            if rep_score >= 0.70:
                res.severity = Severity.CRITICAL
            elif rep_score >= 0.50:
                res.severity = Severity.HIGH
            elif rep_score >= 0.30:
                res.severity = Severity.MEDIUM
            elif rep_score >= 0.10:
                res.severity = Severity.LOW
            else:
                res.severity = Severity.INFO

            if order.index(res.severity) > order.index(worst):
                worst = res.severity

        state.metadata["overall_severity"] = worst
        return state
    return assign_severity
