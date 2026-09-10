import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

function read(): string {
  try {
    const raw = readFileSync(join(here, "../package.json"), "utf8");
    const v = (JSON.parse(raw) as { version?: unknown }).version;
    return typeof v === "string" ? v : "unknown";
  } catch {
    return "unknown";
  }
}

/** Single source of truth: the installed package.json, read at startup. */
export const VERSION = read();
