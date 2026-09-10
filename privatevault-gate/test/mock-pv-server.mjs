// Mock of api/server.py's /v1/decide + /v1/outcome, matching the real
// STATUS_MAP (allow->200, require_approval->202, block->403).
//
// It also deliberately misbehaves on demand, so the gate's defensive
// paths have something to defend against:
//   * a path containing TRIGGER-403-ALLOW gets HTTP 403 carrying an
//     "allow" body — a response that disagrees with itself
//   * /redirect-source 302s to /redirect-target, to prove the gate does
//     not follow a destination that was never decided on
// Every decide body is recorded and served at /debug/decisions.
import { createServer } from "node:http";

const PORT = 8931;
const decisions = [];

const server = createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    if (req.url === "/debug/decisions") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(decisions));
      return;
    }
    if (req.url === "/redirect-source") {
      res.writeHead(302, { location: "http://127.0.0.1:8931/redirect-target" });
      res.end("");
      return;
    }
    if (req.url === "/redirect-target") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("REDIRECT FOLLOWED");
      return;
    }

    const body = raw ? JSON.parse(raw) : {};

    if (req.url === "/v1/decide") {
      decisions.push({
        capability: body.capability,
        execution_action: body.execution_action ?? null,
        dispatch_context: body.dispatch_context ?? null,
      });

      const args = JSON.stringify(body.arguments ?? {}) + JSON.stringify(body.execution_action ?? {});

      // A contradictory response: 403 status, allow body.
      if (args.includes("TRIGGER-403-ALLOW")) {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            decision: "allow",
            triggered_by: "none",
            reason: "contradictory response under test",
            execution_id: null,
            record: { decision_id: "dec_mock_403", record_hash: "c".repeat(64) },
          })
        );
        return;
      }

      const isDangerous = args.includes("/etc/") || args.includes("MUST-NOT-WRITE");
      const decision = isDangerous ? "block" : "allow";
      const status = isDangerous ? 403 : 200;
      res.writeHead(status, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          decision,
          triggered_by: isDangerous ? "L0.invariant" : "none",
          reason: isDangerous ? "path forbidden by invariant" : "no level objected",
          execution_id: null,
          record: {
            decision_id: "dec_mock_0001",
            record_hash: "a".repeat(64),
            agent_id: body.agent_id,
            capability: body.capability,
          },
        })
      );
      return;
    }

    if (req.url === "/v1/outcome") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ event: { decision_id: body.decision_id, status: body.status } }));
      return;
    }

    res.writeHead(404);
    res.end("{}");
  });
});

server.listen(PORT, () => console.log(`mock PV listening on ${PORT}`));
