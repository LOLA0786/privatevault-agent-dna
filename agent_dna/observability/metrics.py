from prometheus_client import Counter
from prometheus_client import Histogram
from prometheus_client import Gauge
from prometheus_client import generate_latest
from prometheus_client import CONTENT_TYPE_LATEST

decision_counter = Counter(
    "pv_decisions_total",
    "Total decisions"
)

decision_denials = Counter(
    "pv_decision_denials_total",
    "Denied decisions"
)

runtime_latency = Histogram(
    "pv_runtime_latency_seconds",
    "Runtime latency"
)

active_agents = Gauge(
    "pv_active_agents",
    "Currently active agents"
)

class Metrics:

    def decision(
        self,
        allowed: bool,
    ):

        decision_counter.inc()

        if not allowed:
            decision_denials.inc()

    def latency(
        self,
        seconds: float,
    ):
        runtime_latency.observe(seconds)

    def active(
        self,
        count: int,
    ):
        active_agents.set(count)

    def export(self):

        return (
            generate_latest(),
            CONTENT_TYPE_LATEST,
        )

metrics = Metrics()
