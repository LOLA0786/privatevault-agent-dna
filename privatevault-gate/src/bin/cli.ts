#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildServer } from "../server.js";
import { loadConfig } from "../config.js";
import { VERSION } from "../version.js";

const HELP = `privatevault-gate ${VERSION}

A pre-execution runtime gate for AI coding agents. Runs as an MCP server over
stdio and routes pv_* tool calls through PrivateVault's enforcement engine
before they execute. A non-allow verdict means the side effect never happens.

USAGE
  privatevault-gate            Run the MCP server on stdio (what an MCP client does)
  privatevault-gate --help     Show this message
  privatevault-gate --version  Print the version

Not an interactive command. Launched by hand it waits for an MCP client to
speak to it on stdin, which looks like a hang and is not one.

TOOLS
  pv_exec          shell.exec  enforced
  pv_write_file    fs.write    enforced
  pv_http_request  net.http    enforced
  pv_decide        caller      advisory only, executes nothing
  pv_blocked       -           read-only, lists recent BLOCK decisions

ENVIRONMENT
  PV_ENFORCE_URL  http://localhost:8000  Base URL of the enforcement API
  PV_AGENT_ID     privatevault-gate-dev  Identity recorded on every decision
  PV_API_KEY      unset                  Sent as x-api-key
  PV_TIMEOUT_MS   5000                   Decision timeout before failing closed
  PV_FAIL_OPEN    unset                  1 allows on transport failure. Dev only

MCP CLIENT CONFIG
  {
    "mcpServers": {
      "privatevault": {
        "command": "npx",
        "args": ["-y", "privatevault-gate"],
        "env": {
          "PV_ENFORCE_URL": "http://localhost:8000",
          "PV_AGENT_ID": "my-coding-agent"
        }
      }
    }
  }

Fails closed: if the engine is unreachable, times out, or returns something
unparseable, the verdict is block.

https://privatevault.ai`;

async function main() {
  const argv = process.argv.slice(2);
  if (argv.includes("--version") || argv.includes("-v")) {
    console.log(VERSION);
    return;
  }
  if (argv.includes("--help") || argv.includes("-h")) {
    console.log(HELP);
    return;
  }

  const config = loadConfig();
  console.error(`[privatevault-gate] v${VERSION} enforcing via ${config.enforceUrl}/v1/decide`);
  console.error(`[privatevault-gate] agent_id=${config.agentId} auth=${config.apiKey ? "x-api-key set" : "none"}`);
  if (config.failOpen) {
    console.error("[privatevault-gate] WARNING: PV_FAIL_OPEN=1 — unreachable enforcement will ALLOW. Dev only.");
  }
  const server = buildServer();
  await server.connect(new StdioServerTransport());
}

main().catch((err) => {
  console.error("[privatevault-gate] fatal:", err);
  process.exit(1);
});
