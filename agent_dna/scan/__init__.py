"""Read-only analysis of logs a customer already has.

`pv scan` never enforces anything and never needs to be installed in a
request path. It reads an existing agent log, replays it through the
decision engine in shadow, and reports what WOULD have happened. The
point is to give an operator a number about their own system before
asking them to change it.

Because the output is a claim about someone else's production traffic,
ingest refuses to guess. A row that cannot be turned into a well-formed
action is skipped and counted with a reason, never inferred into
existence -- an invented action would corrupt the number the whole
exercise exists to produce.
"""

from .ingest import (
    FORMATS,
    IngestResult,
    SkippedRow,
    detect_format,
    ingest,
)
from .replay import (
    LEVELS,
    MoneyAtRisk,
    RefusedSample,
    ScanReport,
    action_amount,
    replay,
)

__all__ = [
    "FORMATS",
    "LEVELS",
    "IngestResult",
    "MoneyAtRisk",
    "RefusedSample",
    "ScanReport",
    "SkippedRow",
    "action_amount",
    "detect_format",
    "ingest",
    "replay",
]
