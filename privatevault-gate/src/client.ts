import { loadConfig, GateConfig } from "./config.js";

export type Decision = "allow" | "require_approval" | "block";

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
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);

    const body = {
      agent_id: this.config.agentId,
      capability: input.capability,
      timestamp: Date.now() / 1000,
      arguments: input.arguments ?? {},
      context: {},
      evidence: input.evidence ?? {},
      request_id: input.requestId ?? null,
      execution_id: input.executionId ?? null,
    };

    try {
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(this.config.apiKey ? { "x-api-key": this.config.apiKey } : {}),
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (res.status === 200 || res.status === 202 || res.status === 403) {
        const parsed = (await res.json()) as DecideResponse;
        if (!parsed.decision) {
          return this.failClosed(`/v1/decide returned HTTP ${res.status} with no decision field: ${JSON.stringify(parsed)}`);
        }
        return parsed;
      }

      const text = await res.text().catch(() => "");
      return this.failClosed(`/v1/decide returned unexpected HTTP ${res.status}: ${text.slice(0, 300)}`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return this.failClosed(`could not reach ${url}: ${message}`);
    } finally {
      clearTimeout(timeout);
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
