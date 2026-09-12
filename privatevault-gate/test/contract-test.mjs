// Contract test: the PUBLISHED gate against a REAL engine.
//
// Every schema-contract violation found on 11 Sep 2026 shipped through
// green CI because each half was only ever tested against a fake of the
// other. The decisive assertion here is the third one: a refusal must
// carry the engine's own triggered_by, never the gate's. A gate that
// cannot reach or satisfy the engine also "blocks" everything, and that
// looks identical to enforcement until you read the reason.
//
// Requires an engine at PV_ENFORCE_URL. Not part of `npm test`.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { existsSync, rmSync } from "node:fs";

const URL_ = process.env.PV_ENFORCE_URL ?? "http://127.0.0.1:8000";
const ALLOWED = "/tmp/pv-contract-allowed.txt";
const BLOCKED = "/tmp/pv-contract-blocked.txt";
for (const p of [ALLOWED, BLOCKED]) if (existsSync(p)) rmSync(p);

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok && detail) console.log(`      ${detail}`);
}

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/bin/cli.js"],
  env: { ...process.env, PV_ENFORCE_URL: URL_, PV_AGENT_ID: "gate-demo" },
});
const client = new Client({ name: "contract-test", version: "1.0.0" });
await client.connect(transport);

const allow = await client.callTool({
  name: "pv_write_file",
  arguments: { path: ALLOWED, content: "written after a real ALLOW" },
});
check(
  "declared capability executes",
  !allow.isError && existsSync(ALLOWED),
  allow.content[0].text.split("\n")[0]
);

const refuse = await client.callTool({
  name: "pv_exec",
  arguments: { command: `touch ${BLOCKED}` },
});
const text = refuse.content[0].text;
check(
  "undeclared capability produces no side effect",
  refuse.isError === true && !existsSync(BLOCKED),
  text.split("\n")[0]
);
check(
  "the refusal came from the engine, not from the gate failing closed",
  !text.includes("triggered_by: privatevault-gate"),
  text.split("\n").slice(0, 3).join(" | ")
);

await client.close();
const failed = results.filter((r) => !r.ok);
console.log(`\n=== ${results.length - failed.length}/${results.length} contract checks passed ===`);
process.exit(failed.length === 0 ? 0 : 1);
