from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider

trace.set_tracer_provider(
    TracerProvider()
)

tracer = trace.get_tracer(
    "privatevault-agent-dna"
)
