"""Live agent checkout: a real Claude agent, real services over HTTP.

    make -C demos/live_checkout bootstrap up      # four services, local processes
    uv run python demos/live_checkout/approve.py  # terminal 2: the human approver
    uv run python demos/live_checkout/agent.py    # terminal 1: the agent

Nothing here is shipped in the wheel. See ``README.md`` in this directory.
"""
