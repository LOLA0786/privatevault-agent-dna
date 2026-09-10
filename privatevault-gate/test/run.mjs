// One command an evaluator can run: boot the mock engine, prove a block
// prevents the side effect, tear down. Exit code is the verdict.
import { spawn } from "node:child_process";
import { connect } from "node:net";

const PORT = 8931;

function waitForPort(port, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const attempt = () => {
      const s = connect({ port, host: "127.0.0.1" });
      s.once("connect", () => { s.destroy(); resolve(); });
      s.once("error", () => {
        s.destroy();
        if (Date.now() > deadline) reject(new Error(`mock engine never opened port ${port}`));
        else setTimeout(attempt, 200);
      });
    };
    attempt();
  });
}

const mock = spawn(process.execPath, ["test/mock-pv-server.mjs"], { stdio: "inherit" });
let code = 1;
try {
  await waitForPort(PORT);
  code = await new Promise((resolve) => {
    const t = spawn(process.execPath, ["test/gate-test.mjs"], { stdio: "inherit" });
    t.on("exit", (c) => resolve(c ?? 1));
  });
} catch (err) {
  console.error(`[test-runner] ${err.message}`);
} finally {
  mock.kill("SIGTERM");
}
process.exit(code);
