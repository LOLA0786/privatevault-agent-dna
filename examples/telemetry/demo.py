import os
import sys

ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        "..",
    )
)

if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from agent_dna.observability import tracer, metrics

with tracer.start_as_current_span("decision"):
    metrics.decision(True)
    metrics.latency(0.024)
    metrics.active(8)

print("Telemetry OK")
