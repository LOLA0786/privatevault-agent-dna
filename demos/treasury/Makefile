# Treasury demo. Run from anywhere: make -C demos/treasury <target>
SHELL := /bin/bash
HERE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO := $(abspath $(HERE)/../..)
RUN_DIR ?= $(HERE).run
export PV_TREASURY_RUN_DIR := $(RUN_DIR)
AGENT := cd $(REPO) && uv run python demos/treasury/agent.py --run-dir "$(RUN_DIR)" --compromised-tool

.PHONY: help bootstrap up down status logs approve scripted live naive policy replay demo clean

help:
	@echo "bootstrap   keys, bundles, merged policy and grants into $(RUN_DIR)"
	@echo "up / down   the three services (privatevault, gate, bank-api) as local processes"
	@echo "approve     the treasury approver terminal"
	@echo "scripted    both prompt modes with the deterministic model and an auto approver (no API, no human)"
	@echo "live        both prompt modes with the real model; approvals pause for approve.py"
	@echo "naive/policy one live mode"
	@echo "replay      re-render the latest saved run: make replay [RUN=runs/<ts>-<mode>.jsonl]"
	@echo "demo        bootstrap, up, scripted"

bootstrap:
	cd $(REPO) && uv run python demos/treasury/bootstrap.py --run-dir "$(RUN_DIR)"

up: bootstrap
	$(HERE)services.sh up

down:
	$(HERE)services.sh down

status:
	$(HERE)services.sh status

logs:
	$(HERE)services.sh logs

approve:
	cd $(REPO) && uv run python demos/treasury/approve.py --run-dir "$(RUN_DIR)"

scripted:
	$(AGENT) --model scripted --approver auto --prompt naive
	$(AGENT) --model scripted --approver auto --prompt policy

naive:
	$(AGENT) --prompt naive

policy:
	$(AGENT) --prompt policy

live: naive policy

RUN ?= $(shell ls -t $(HERE)runs/*.jsonl 2>/dev/null | head -1)
replay:
	cd $(REPO) && uv run python demos/treasury/agent.py --replay "$(RUN)"

demo: up scripted

clean: down
	rm -rf "$(RUN_DIR)"
