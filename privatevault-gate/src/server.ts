import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { exec } from "node:child_process";
import { promisify } from "node:util";
import { writeFile } from "node:fs/promises";
import { resolve as resolvePath } from "node:path";
import { PrivateVaultClient, EnforceResult, DecideResponse } from "./client.js";
import { loadConfig } from "./config.js";
import { sha256 } from "./digest.js";
import { VERSION } from "./version.js";

const execAsync = promisify(exec);

const OUTBOUND_TIMEOUT_MS = 30_000;
const AUDIT_ONLY = "pv-audit-only/0.1";

/**
 * An MCP server cannot intercept the host agent's BUILT-IN tools. Cursor's
 * own file write and Claude Code's own Bash never route through this
 * process. What this server does instead is structurally sound: it owns
 * the execution of the capabilities it exposes, so decide() happens BEFORE
 * the execution path is reachable and a BLOCK means the side effect never
 * runs. Real enforcement for actions routed through these tools; honestly
 * absent for actions that are not.
 *
 * The decision is bound to a digest of the exact content or body, so two
 * different payloads can no longer share one approval. It is NOT bound to
 * the transport bytes: per ADR-0017 those need a serialization contract
 * this gate does not yet implement, and no permit is minted or consumed.
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

/** The gate's own credential must never be readable by a gated command. */
function scrubbedEnv(): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (k.startsWith("PV_")) continue;
    out[k] = v;
  }
  return out;
}

export function buildServer(client: PrivateVaultClient = new PrivateVaultClient()): McpServer {
  const config = loadConfig();
  const server = new McpServer({ name: "privatevault-gate", version: VERSION });

  const subjectKeyId = config.apiKey ? sha256(config.apiKey).slice(0, 23) : "pv-gate-unauthenticated";

  function action(capability: string, resource: string, parameters: Record<string, unknown>) {
    return {
      subject_principal: config.agentId,
      subject_key_id: subjectKeyId,
      action: capability,
      resource,
      parameters,
    };
  }

  function dispatch(transport: string, operation: string, destination: string, contentType: string) {
    return {
      adapter: "privatevault-gate",
      transport,
      operation,
      destination,
      wire_content_type: contentType,
      serialization: AUDIT_ONLY,
    };
  }

  async function gated<T>(
    capability: string,
    args: Record<string, unknown>,
    bind: { action: Record<string, unknown>; dispatch: Record<string, string> },
    run: () => Promise<T>,
    describe: (result: T) => string
  ) {
    const verdict = await client.decide({
      capability,
      arguments: args,
      executionAction: bind.action,
      dispatchContext: bind.dispatch,
    });
    if (verdict.decision !== "allow") {
      return { content: [{ type: "text" as const, text: blockedMessage(verdict) }], isError: true };
    }

    const decisionId = decisionIdOf(verdict);
    const notes: string[] = [];
    if (!decisionId) {
      notes.push(
        "WARNING: the engine returned no decision_id. No execution outcome could be recorded for this action, so the audit chain has no evidence of what followed the ALLOW."
      );
    }

    try {
      const result = await run();
      if (decisionId) {
        const r = await client.reportOutcome(decisionId, "ok", { dispatched: true });
        if ("error" in r) notes.push(`WARNING: outcome not recorded: ${r.error}`);
      }
      return { content: [{ type: "text" as const, text: [describe(result), ...notes].filter(Boolean).join("\n\n") }] };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // Whether the side effect happened is unknown: a write can be partial,
      // a request can reach the server before the connection drops. Claiming
      // "error" asserts it did not. INDETERMINATE is the honest status, and
      // it is what makes a blind retry visibly unsafe.
      if (decisionId) {
        const r = await client.reportOutcome(decisionId, "indeterminate", { detail: message });
        if ("error" in r) notes.push(`WARNING: outcome not recorded: ${r.error}`);
      }
      return {
        content: [
          {
            type: "text" as const,
            text: [
              "PrivateVault INDETERMINATE (allowed, outcome unknown)",
              `error: ${message}`,
              "",
              "The action was authorized and execution began. Whether the side effect",
              "completed is not known. Do NOT retry blindly — establish the current",
              "state first, then decide.",
              ...notes,
            ].join("\n"),
          },
        ],
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
    async ({ command, cwd }) => {
      const workdir = cwd ?? process.cwd();
      return gated(
        "shell.exec",
        { command, cwd: cwd ?? null },
        {
          action: action("shell.exec", workdir, { command, command_sha256: sha256(command), cwd: workdir }),
          dispatch: dispatch("process", "pv_exec", workdir, "text/plain"),
        },
        () => execAsync(command, { cwd, timeout: 60000, env: scrubbedEnv() }),
        (r) => `exit ok\n\nstdout:\n${r.stdout}\n\nstderr:\n${r.stderr}`
      );
    }
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
    async ({ path, content }) => {
      const target = resolvePath(path);
      const bytes = Buffer.byteLength(content, "utf8");
      return gated(
        "fs.write",
        { path, bytes },
        {
          action: action("fs.write", target, { path: target, bytes, content_sha256: sha256(content) }),
          dispatch: dispatch("file", "pv_write_file", target, "application/octet-stream"),
        },
        async () => {
          await writeFile(path, content, "utf8");
          return path;
        },
        (p) => `wrote ${p}`
      );
    }
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
    async ({ url, method, body }) => {
      let origin = url;
      try {
        origin = new URL(url).origin;
      } catch {
        /* decide on the raw string; the engine can refuse it */
      }
      return gated(
        "net.http",
        { url, method, has_body: body !== undefined },
        {
          action: action("net.http", url, {
            url,
            method,
            body_bytes: body === undefined ? 0 : Buffer.byteLength(body, "utf8"),
            body_sha256: body === undefined ? sha256("") : sha256(body),
          }),
          dispatch: dispatch("http", "pv_http_request", origin, "application/octet-stream"),
        },
        async () => {
          // The decision bound THIS url. A redirect names a destination that
          // was never decided on, so it is reported, not followed.
          const res = await fetch(url, {
            method,
            body,
            redirect: "manual",
            signal: AbortSignal.timeout(OUTBOUND_TIMEOUT_MS),
          });
          if (res.status >= 300 && res.status < 400) {
            return {
              status: res.status,
              text:
                `redirect NOT followed to ${res.headers.get("location") ?? "(no location header)"}\n` +
                `The decision bound ${url}. Re-submit the redirect target as its own action.`,
            };
          }
          return { status: res.status, text: await res.text() };
        },
        (r) => `HTTP ${r.status}\n\n${r.text.slice(0, 4000)}`
      );
    }
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
