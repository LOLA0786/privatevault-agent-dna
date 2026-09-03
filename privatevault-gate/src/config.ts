export interface GateConfig {
  enforceUrl: string;
  apiKey?: string;
  agentId: string;
  timeoutMs: number;
  failOpen: boolean;
}

export function loadConfig(): GateConfig {
  const enforceUrl = (process.env.PV_ENFORCE_URL ?? "http://localhost:8000").replace(/\/+$/, "");
  const apiKey = process.env.PV_API_KEY;
  const agentId = process.env.PV_AGENT_ID ?? "privatevault-gate-dev";
  const timeoutMs = Number(process.env.PV_TIMEOUT_MS ?? 5000);
  const failOpen = process.env.PV_FAIL_OPEN === "1";
  return { enforceUrl, apiKey, agentId, timeoutMs, failOpen };
}
