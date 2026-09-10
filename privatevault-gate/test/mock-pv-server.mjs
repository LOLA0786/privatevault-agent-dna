// Mock of api/server.py's /v1/decide + /v1/outcome, matching the real
// STATUS_MAP (allow->200, require_approval->202, block->403).
import { createServer } from "node:http";

const PORT = 8931;

const server = createServer((req, res) => {
  let raw = "";
  req.on("data", (c) => (raw += c));
  req.on("end", () => {
    const body = raw ? JSON.parse(raw) : {};

    if (req.url === "/v1/decide") {
      const args = JSON.stringify(body.arguments ?? {});
      const isDangerous = args.includes("/etc/") || args.includes("MUST-NOT-WRITE");
      const decision = isDangerous ? "block" : "allow";
      const status = isDangerous ? 403 : 200;

      res.writeHead(status, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          decision,
          triggered_by: isDangerous ? "L0.invariant" : "none",
          reason: isDangerous ? "writes to /etc are forbidden by invariant" : "no level objected",
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
