#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { buildServer } from "../server.js";
import { loadConfig } from "../config.js";

async function main() {
  const config = loadConfig();
  console.error(`[privatevault-gate] enforcing via ${config.enforceUrl}/v1/decide`);
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
