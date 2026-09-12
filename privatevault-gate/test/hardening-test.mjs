// One case per reported gap. Each asserts the defensive behaviour, so a
// regression fails CI rather than being rediscovered by a reviewer.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { existsSync, rmSync } from "node:fs";

const CONTRADICTION_PATH = "/tmp/pv-TRIGGER-403-ALLOW.txt";
const DIGEST_PATH = "/tmp/pv-digest-probe.txt";
for (const p of [CONTRADICTION_PATH, DIGEST_PATH]) if (existsSync(p)) rmSync(p);

const transport = new StdioClientTransport({
  command: "node",
  args: ["dist/bin/cli.js"],
  env: {
    ...process.env,
    PV_ENFORCE_URL: "http://localhost:8931",
    PV_AGENT_ID: "hardening-test",
    PV_API_KEY: "pv_secret_that_must_not_leak",
  },
});
const client = new Client({ name: "hardening-test", version: "1.0.0" });
await client.connect(transport);

const results = [];
function check(name, ok, detail) {
  results.push({ name, ok });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok && detail) console.log(`      ${detail}`);
}

// 1. HTTP 403 carrying an allow body must not execute.
{
  const r = await client.callTool({
    name: "pv_write_file",
    arguments: { path: CONTRADICTION_PATH, content: "must not be written" },
  });
  const text = r.content[0].text;
  check(
    "403-with-allow-body does not execute",
    r.isError === true && !existsSync(CONTRADICTION_PATH) && text.includes("contradicted itself"),
    text.slice(0, 200)
  );
}

// 2. A redirect names a destination that was never decided on.
{
  const r = await client.callTool({
    name: "pv_http_request",
    arguments: { url: "http://127.0.0.1:8931/redirect-source", method: "GET" },
  });
  const text = r.content[0].text;
  check(
    "redirect is reported, not followed",
    text.includes("redirect NOT followed") && !text.includes("REDIRECT FOLLOWED"),
    text.slice(0, 200)
  );
}

// 3. A gated command must not be able to read the gate's own credential.
{
  const r = await client.callTool({
    name: "pv_exec",
    arguments: { command: 'echo "PV_API_KEY=[${PV_API_KEY:-EMPTY}]"' },
  });
  const text = r.content[0].text;
  check(
    "shell cannot read PV_API_KEY",
    text.includes("PV_API_KEY=[EMPTY]") && !text.includes("pv_secret_that_must_not_leak"),
    text.slice(0, 200)
  );
}

// 4. Equal-length, different-content writes must not share a decision input.
{
  await client.callTool({ name: "pv_write_file", arguments: { path: DIGEST_PATH, content: "AAAA" } });
  await client.callTool({ name: "pv_write_file", arguments: { path: DIGEST_PATH, content: "BBBB" } });
  const recorded = await (await fetch("http://127.0.0.1:8931/debug/decisions")).json();
  const writes = recorded.filter(
    (d) => d.capability === "fs.write" && d.arguments?.path === DIGEST_PATH
  );
  const digests = new Set(writes.map((d) => d.arguments.content_sha256));
  const lengths = new Set(writes.map((d) => d.arguments.bytes));
  check(
    "equal-length different content yields different decision inputs",
    writes.length === 2 && digests.size === 2 && lengths.size === 1,
    `writes=${writes.length} digests=${digests.size} lengths=${lengths.size}`
  );
}

// 5. The gate must not ask for a mintable record it cannot honour.
//    Sending a dispatch context requests DRP 0.2. Audit-only is refused
//    there by design, and naming pv-json-parameters/0.1 would assert a
//    wire format a file write does not have. Until a transport contract
//    exists per capability, the gate sends neither and relies on
//    arguments_digest for content binding.
{
  const recorded = await (await fetch("http://127.0.0.1:8931/debug/decisions")).json();
  const unbound = recorded.every((d) => d.execution_action === null && d.dispatch_context === null);
  const carriesDigest = recorded
    .filter((d) => d.capability === "fs.write")
    .every((d) => typeof d.arguments?.content_sha256 === "string");
  check(
    "no mintable binding is requested, and the content digest still travels",
    recorded.length > 0 && unbound && carriesDigest,
    `decisions=${recorded.length} unbound=${unbound} carriesDigest=${carriesDigest}`
  );
}

await client.close();
const failed = results.filter((r) => !r.ok);
console.log(`\n=== ${results.length - failed.length}/${results.length} hardening checks passed ===`);
process.exit(failed.length === 0 ? 0 : 1);
