import { loadConfig, GateConfig } from "./config.js";

export type Decision = "allow" | "require_approval" | "block";

const VALID_DECISIONS = new Set<string>(["allow", "require_approval", "block"]);

/** api/server.py STATUS_MAP. A response that disagrees with itself is not a decision. */
const STATUS_FOR_DECISION: Record<Decision, number> = {
  allow: 200,
  require_approval: 202,
  block: 403,
};

export interface DecideResponse {
  decision: Decision;
  triggered_by: string;
  reason: string;
  execution_id: string | null;
  record: Record<string, unknown>;
}

export interface GateFailure {
  decision: Decision;
  triggered_by: "privatevault-gate";
  reason: string;
  execution_id: null;
  record: null;
}

export type EnforceResult = DecideResponse | GateFailure;

export interface DecideInput {
  capability: string;
  arguments: Record<string, unknown>;
  /** Canonical five-field action. Bound into the sealed record by the engine. */
  executionAction?: Record<string, unknown>;
  /** Six-field pv-dispatch-context/0.2. */
  dispatchContext?: Record<string, string>;
  requestId?: string;
  executionId?: string;
  evidence?: Record<string, unknown>;
}

export class PrivateVaultClient {
  private config: GateConfig;

  constructor(config: GateConfig = loadConfig()) {
    this.config = config;
  }

  async decide(input: DecideInput): Promise<EnforceResult> {
    const url = `${this.config.enforceUrl}/v1/decide`;
    const body: Record<string, unknown> = {
      agent_id: this.config.agentId,
      capability: input.capability,
      timestamp: Date.now() / 1000,
      arguments: input.arguments ?? {},
      context: {},
      evidence: input.evidence ?? {},
      request_id: input.requestId ?? null,
      execution_id: input.executionId ?? null,
    };
    // Both or neither: the engine refuses one without the other.
    if (input.executionAction && input.dispatchContext) {
      body.execution_action = input.executionAction;
      body.dispatch_context = input.dispatchContext;
    }

    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(this.config.apiKey ? { "x-api-key": this.config.apiKey } : {}),
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });

      if (res.status !== 200 && res.status !== 202 && res.status !== 403) {
        const text = await res.text().catch(() => "");
        return this.failClosed(`/v1/decide returned unexpected HTTP ${res.status}: ${text.slice(0, 300)}`);
      }

      let parsed: DecideResponse;
      try {
        parsed = (await res.json()) as DecideResponse;
      } catch {
        return this.failClosed(`/v1/decide returned HTTP ${res.status} with an unparseable body`);
      }

      if (typeof parsed?.decision !== "string" || !VALID_DECISIONS.has(parsed.decision)) {
        return this.failClosed(
          `/v1/decide returned HTTP ${res.status} with no valid decision field: ${JSON.stringify(parsed).slice(0, 300)}`
        );
      }

      const expected = STATUS_FOR_DECISION[parsed.decision];
      if (res.status !== expected) {
        return this.failClosed(
          `/v1/decide contradicted itself: HTTP ${res.status} carrying decision "${parsed.decision}" ` +
            `(that decision is HTTP ${expected}). A response that disagrees with its own status is not trusted.`
        );
      }

      return parsed;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return this.failClosed(`could not reach ${url}: ${message}`);
    }
  }

  async reportOutcome(
    decisionId: string,
    status: "ok" | "error" | "refused" | "indeterminate",
    opts: { detail?: string; responseDigest?: string; dispatched?: boolean } = {}
  ): Promise<{ event: Record<string, unknown> } | { error: string }> {
    const url = `${this.config.enforceUrl}/v1/outcome`;
    const body = {
      decision_id: decisionId,
      status,
      detail: opts.detail ?? "",
      response_digest: opts.responseDigest ?? "",
      dispatched: opts.dispatched ?? null,
    };
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(this.config.apiKey ? { "x-api-key": this.config.apiKey } : {}),
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.config.timeoutMs),
      });
      if (!res.ok) {
        const text = await res.text().catch(() => "");
        return { error: `/v1/outcome returned HTTP ${res.status}: ${text.slice(0, 300)}` };
      }
      return (await res.json()) as { event: Record<string, unknown> };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return { error: `could not reach ${url}: ${message}` };
    }
  }

  private failClosed(reason: string): GateFailure {
    return {
      decision: this.config.failOpen ? "allow" : "block",
      triggered_by: "privatevault-gate",
      reason: this.config.failOpen
        ? `[privatevault-gate] ${reason} — PV_FAIL_OPEN=1 set, allowing anyway (dev only)`
        : `[privatevault-gate] ${reason} — failing closed`,
      execution_id: null,
      record: null,
    };
  }
}
