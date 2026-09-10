import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { writeFile } from "node:fs/promises";
import { PrivateVaultClient, EnforceResult, DecideResponse } from "./client.js";
import { loadConfig } from "./config.js";

const execAsync = promisify(exec);

/**
 * An MCP server cannot intercept the host agent's BUILT-IN tools. Cursor's
 * own file write and Claude Code's own Bash never route through this
 * process. What this server does instead is structurally sound: it owns
 * the execution of the capabilities it exposes, so decide() happens BEFORE
 * the execution path is reachable and a BLOCK means the side effect never
 * runs. Real enforcement for actions routed through these tools; honestly
 * absent for actions that are not.
 */

function decisionIdOf(result: EnforceResult): string | null {
  const record = (result as DecideResponse).record;
  if (record && typeof record === "object" && "decision_id" in record) {
    const id = (record as Record<string, unknown>).decision_id;
    return typeof id === "string" ? id : null;
  }
  return null;
}

function blockedMessage(result: EnforceResult): string {
  const record = (result as DecideResponse).record as Record<string, unknown> | null;
  const recordHash = record && typeof record === "object" ? record.record_hash : undefined;
  const label =
    result.decision === "require_approval"
      ? "PrivateVault REQUIRE_APPROVAL (pending approval — NOT executed)"
      : "PrivateVault BLOCK (not executed)";
  return [
    label,
    `triggered_by: ${result.triggered_by}`,
    `reason: ${result.reason}`,
    recordHash ? `record_hash: ${recordHash}` : null,
    "",
    "This action did not run. Do not retry it by another route — route the",
    "same action through an approval path, or change the action itself.",
  ]
    .filter(Boolean)
    .join("\n");
}

export function buildServer(client: PrivateVaultClient = new PrivateVaultClient()): McpServer {
  const config = loadConfig();
  const server = new McpServer({ name: "privatevault-gate", version: "0.1.0" });

  async function gated<T>(
    capability: string,
    args: Record<string, unknown>,
    run: () => Promise<T>,
    describe: (result: T) => string
  ) {
    const verdict = await client.decide({ capability, arguments: args });

    if (verdict.decision !== "allow") {
      return { content: [{ type: "text" as const, text: blockedMessage(verdict) }], isError: true };
    }

    const decisionId = decisionIdOf(verdict);

    try {
      const result = await run();
      if (decisionId) await client.reportOutcome(decisionId, "ok", { dispatched: true });
      return { content: [{ type: "text" as const, text: describe(result) }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (decisionId) await client.reportOutcome(decisionId, "error", { dispatched: true, detail: message });
      return {
        content: [{ type: "text" as const, text: `Action was ALLOWED but failed during execution: ${message}` }],
        isError: true,
      };
    }
  }

  server.registerTool(
    "pv_exec",
    {
      description:
        "Run a shell command, gated by PrivateVault. Submitted for a pre-execution decision and only runs if the verdict is ALLOW.",
      inputSchema: {
        command: z.string().describe("The shell command to run"),
        cwd: z.string().optional().describe("Working directory"),
      },
    },
    async ({ command, cwd }) =>
      gated(
        "shell.exec",
        { command, cwd: cwd ?? null },
        () => execAsync(command, { cwd, timeout: 60000 }),
        (r) => `exit ok\n\nstdout:\n${r.stdout}\n\nstderr:\n${r.stderr}`
      )
  );

  server.registerTool(
    "pv_write_file",
    {
      description:
        "Write content to a file, gated by PrivateVault. Only happens if the verdict is ALLOW.",
      inputSchema: {
        path: z.string().describe("Path to write"),
        content: z.string().describe("Full content"),
      },
    },
    async ({ path, content }) =>
      gated(
        "fs.write",
        { path, bytes: Buffer.byteLength(content, "utf8") },
        async () => {
          await writeFile(path, content, "utf8");
          return path;
        },
        (p) => `wrote ${p}`
      )
  );

  server.registerTool(
    "pv_http_request",
    {
      description:
        "Make an outbound HTTP request, gated by PrivateVault. Only sent if the verdict is ALLOW.",
      inputSchema: {
        url: z.string().describe("Target URL"),
        method: z.string().default("GET").describe("HTTP method"),
        body: z.string().optional().describe("Request body"),
      },
    },
    async ({ url, method, body }) =>
      gated(
        "net.http",
        { url, method, has_body: body !== undefined },
        async () => {
          const res = await fetch(url, { method, body });
          const text = await res.text();
          return { status: res.status, text };
        },
        (r) => `HTTP ${r.status}\n\n${r.text.slice(0, 4000)}`
      )
  );

  server.registerTool(
    "pv_decide",
    {
      description:
        "Ask PrivateVault for a decision WITHOUT executing. Advisory only — nothing enforces that you honor the verdict, unlike the pv_* tools where execution is structurally behind the check.",
      inputSchema: {
        capability: z.string().describe("Capability identifier"),
        args: z.record(z.unknown()).default({}).describe("The action's arguments"),
      },
    },
    async ({ capability, args }) => {
      const verdict = await client.decide({ capability, arguments: args });
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              { decision: verdict.decision, triggered_by: verdict.triggered_by, reason: verdict.reason, record: verdict.record },
              null,
              2
            ),
          },
        ],
        isError: verdict.decision !== "allow",
      };
    }
  );

  server.registerTool(
    "pv_blocked",
    { description: "List recent BLOCK decisions for this agent.", inputSchema: {} },
    async () => {
      try {
        const res = await fetch(`${config.enforceUrl}/v1/blocked`, {
          headers: config.apiKey ? { "x-api-key": config.apiKey } : {},
          signal: AbortSignal.timeout(config.timeoutMs),
        });
        const text = await res.text();
        return { content: [{ type: "text" as const, text: `HTTP ${res.status}\n${text.slice(0, 4000)}` }] };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        return { content: [{ type: "text" as const, text: `could not reach /v1/blocked: ${message}` }], isError: true };
      }
    }
  );

  return server;
}
