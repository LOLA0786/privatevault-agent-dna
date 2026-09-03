import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { existsSync, rmSync } from "node:fs";

const ALLOWED_PATH = "/tmp/pv-allowed.txt";
const BLOCKED_PATH = "/etc/pv-should-never-exist.txt";

for (const p of [ALLOWED_PATH, BLOCKED_PATH]) if (existsSync(p)) rmSync(p);

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/bin/cli.js"],
  env: { ...process.env, PV_ENFORCE_URL: "http://localhost:8931", PV_AGENT_ID: "gate-test" },
});

const client = new Client({ name: "gate-test", version: "1.0.0" });
await client.connect(transport);

const tools = await client.listTools();
console.log("TOOLS:", tools.tools.map((t) => t.name).join(", "));

console.log("\n--- CASE 1: allowed write ---");
const allowed = await client.callTool({
  name: "pv_write_file",
  arguments: { path: ALLOWED_PATH, content: "written after ALLOW" },
});
console.log(allowed.content[0].text);
console.log("file exists on disk:", existsSync(ALLOWED_PATH));

console.log("\n--- CASE 2: blocked write ---");
const blocked = await client.callTool({
  name: "pv_write_file",
  arguments: { path: BLOCKED_PATH, content: "this must never be written" },
});
console.log(blocked.content[0].text);
console.log("isError:", blocked.isError);
console.log("file exists on disk:", existsSync(BLOCKED_PATH));

console.log("\n=== VERDICT ===");
const pass = existsSync(ALLOWED_PATH) && !existsSync(BLOCKED_PATH) && blocked.isError === true;
console.log(pass ? "PASS — block prevented the side effect" : "FAIL — enforcement did not hold");

await client.close();
process.exit(pass ? 0 : 1);
