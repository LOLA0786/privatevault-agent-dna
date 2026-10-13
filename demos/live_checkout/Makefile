# Live checkout demo. Run from anywhere: make -C demos/live_checkout <target>
SHELL := /bin/bash
HERE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
REPO := $(abspath $(HERE)/../..)
RUN_DIR ?= $(HERE).run
export PV_LIVE_RUN_DIR := $(RUN_DIR)

.PHONY: help bootstrap up down status logs agent agent-plain replay approve receipts verify tmux docker-up docker-down docker-logs clean

help:
	@echo "bootstrap   generate keys, bundles, policy into $(RUN_DIR)"
	@echo "up / down   start or stop the three services as local processes"
	@echo "status      which services are running"
	@echo "logs        tail the three service logs"
	@echo "approve     the human approver terminal"
	@echo "agent       run the refund queue with the real model (request #11's tool is compromised)"
	@echo "agent-plain the same without the compromised tool"
	@echo "replay      re-render the latest saved run, no API: make replay [RUN=runs/<ts>.jsonl]"
	@echo "receipts    export the gate's receipts and public key for the other party"
	@echo "verify      run verify.sh on the exported receipts"
	@echo "tmux        four-pane layout (needs tmux)"
	@echo "docker-up / docker-down   the same three services under Docker Compose"

bootstrap:
	cd $(REPO) && uv run python demos/live_checkout/bootstrap.py --run-dir "$(RUN_DIR)"

up: bootstrap
	$(HERE)services.sh up

down:
	$(HERE)services.sh down

status:
	$(HERE)services.sh status

logs:
	$(HERE)services.sh logs

approve:
	cd $(REPO) && uv run python demos/live_checkout/approve.py --run-dir "$(RUN_DIR)"

agent:
	cd $(REPO) && uv run python demos/live_checkout/agent.py --run-dir "$(RUN_DIR)" --compromised-tool

agent-plain:
	cd $(REPO) && uv run python demos/live_checkout/agent.py --run-dir "$(RUN_DIR)"

RUN ?= $(shell ls -t $(HERE)runs/*.jsonl 2>/dev/null | head -1)
replay:
	cd $(REPO) && uv run python demos/live_checkout/agent.py --replay "$(RUN)"

receipts:
	@if [ -f "$(RUN_DIR)/gate/receiver.db" ]; then \
	  cd $(REPO) && uv run python -m network.receiver_kit.export_receipts --db "$(RUN_DIR)/gate/receiver.db" --out "$(RUN_DIR)/receipts.jsonl"; \
	else \
	  docker compose -f $(HERE)docker-compose.yml cp checkout-gate:/data/receiver.db "$(RUN_DIR)/gate/receiver.docker.db" && \
	  cd $(REPO) && uv run python -m network.receiver_kit.export_receipts --db "$(RUN_DIR)/gate/receiver.docker.db" --out "$(RUN_DIR)/receipts.jsonl"; \
	fi
	@echo "gate public key: $(RUN_DIR)/gate/receiver.pub"

verify:
	PYTHON="uv run python" $(HERE)verify.sh "$(RUN_DIR)/receipts.jsonl" "$(RUN_DIR)/gate/receiver.pub"

tmux:
	$(HERE)tmux.sh

docker-up: bootstrap
	docker compose -f $(HERE)docker-compose.yml up --build -d
	@echo "services: privatevault :8702  gate :8703  payments-api :8704"

docker-down:
	docker compose -f $(HERE)docker-compose.yml down -v

docker-logs:
	docker compose -f $(HERE)docker-compose.yml logs -f

clean: down
	rm -rf "$(RUN_DIR)"
