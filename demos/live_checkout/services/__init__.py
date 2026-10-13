"""The three services of the live demo, one process each.

    python -m demos.live_checkout.services.privatevault   --port 8702
    python -m demos.live_checkout.services.gate           --port 8703
    python -m demos.live_checkout.services.payments_api   --port 8704

``privatevault`` and ``gate`` are the real API server and the real receiver
gate with a thin logging wrapper. ``payments_api`` is a mock and says so.
"""
