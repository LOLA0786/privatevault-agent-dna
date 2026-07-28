"""Deterministic signed-authority reachability, v0.1-experimental.

This package is intentionally outside the installable :mod:`agent_dna`
runtime. It is a separately testable protocol experiment, not a production
enforcement claim.
"""

from .adapters import (
    GenericJSONGraphAdapter,
    GraphAdapter,
    MappedCompanyGraphAdapter,
    merge_graphs,
)
from .engine import (
    AnalysisReport,
    ChangeAnalysis,
    ReachabilityFinding,
    analyze_change,
    analyze_reachability,
)
from .model import (
    GRAPH_SPEC,
    REPORT_SPEC,
    AuthorityGraph,
    EdgeKind,
    EvidenceClass,
    GraphEdge,
    GraphFormatError,
    GraphNode,
    NodeKind,
    ProtectedSink,
    ReachabilityState,
    Severity,
)
from .signing import (
    sign_analysis_report,
    verify_signed_analysis_report,
)

__all__ = [
    "GRAPH_SPEC",
    "REPORT_SPEC",
    "AnalysisReport",
    "AuthorityGraph",
    "ChangeAnalysis",
    "EdgeKind",
    "EvidenceClass",
    "GenericJSONGraphAdapter",
    "GraphAdapter",
    "GraphEdge",
    "GraphFormatError",
    "GraphNode",
    "MappedCompanyGraphAdapter",
    "NodeKind",
    "ProtectedSink",
    "ReachabilityFinding",
    "ReachabilityState",
    "Severity",
    "analyze_change",
    "analyze_reachability",
    "merge_graphs",
    "sign_analysis_report",
    "verify_signed_analysis_report",
]
