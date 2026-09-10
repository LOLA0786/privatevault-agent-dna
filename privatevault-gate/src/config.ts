export interface GateConfig {
  enforceUrl: string;
  apiKey?: string;
  agentId: string;
  timeoutMs: number;
  failOpen: boolean;
}

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "::1", "[::1]"]);

export function isLocalUrl(url: string): boolean {
  try {
    return LOCAL_HOSTS.has(new URL(url).hostname);
  } catch {
    return false;
  }
}

export function loadConfig(): GateConfig {
  const enforceUrl = (process.env.PV_ENFORCE_URL ?? "http://localhost:8000").replace(/\/+$/, "");
  const apiKey = process.env.PV_API_KEY;
  const agentId = process.env.PV_AGENT_ID ?? "privatevault-gate-dev";
  const timeoutMs = Number(process.env.PV_TIMEOUT_MS ?? 5000);
  const failOpen = process.env.PV_FAIL_OPEN === "1";

  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error(
      `[privatevault-gate] PV_TIMEOUT_MS must be a positive number, got ${JSON.stringify(process.env.PV_TIMEOUT_MS)}`
    );
  }

  // Fail-open is a development affordance. Against a remote enforcement
  // plane it is indistinguishable from no enforcement at all, so it is
  // refused rather than warned about.
  if (failOpen && !isLocalUrl(enforceUrl)) {
    throw new Error(
      `[privatevault-gate] PV_FAIL_OPEN=1 is refused with a non-local PV_ENFORCE_URL (${enforceUrl}). ` +
        `Fail-open is permitted only against localhost.`
    );
  }

  return { enforceUrl, apiKey, agentId, timeoutMs, failOpen };
}
