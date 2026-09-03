import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { existsSync, rmSync } from "node:fs";

const ALLOWED_PATH = "/tmp/pv-real-allowed.txt";
const SIDE_EFFECT_PATH = "/tmp/pv-real-should-never-exist.txt";

for (const p of [ALLOWED_PATH, SIDE_EFFECT_PATH]) if (existsSync(p)) rmSync(p);

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/bin/cli.js"],
  env: {
    ...process.env,
    PV_ENFORCE_URL: process.env.PV_ENFORCE_URL ?? "http://localhost:8000",
    PV_AGENT_ID: "gate-demo",
  },
});

const client = new Client({ name: "real-engine-test", version: "1.0.0" });
await client.connect(transport);

console.log("--- CASE 1: fs.write (declared baseline capability) ---");
const allowed = await client.callTool({
  name: "pv_write_file",
  arguments: { path: ALLOWED_PATH, content: "written after a real ALLOW" },
});
console.log(allowed.content[0].text.split("\n")[0]);
console.log("file written:", existsSync(ALLOWED_PATH));

console.log("\n--- CASE 2: shell.exec (undeclared capability) ---");
const blocked = await client.callTool({
  name: "pv_exec",
  arguments: { command: `touch ${SIDE_EFFECT_PATH}` },
});
console.log(blocked.content[0].text);
console.log("\nside effect on disk:", existsSync(SIDE_EFFECT_PATH));

console.log("\n=== VERDICT ===");
const pass = existsSync(ALLOWED_PATH) && !existsSync(SIDE_EFFECT_PATH) && blocked.isError === true;
console.log(
  pass
    ? "PASS — the shell command never ran; the undeclared capability was stopped pre-execution"
    : "FAIL — enforcement did not hold"
);

await client.close();
process.exit(pass ? 0 : 1);
