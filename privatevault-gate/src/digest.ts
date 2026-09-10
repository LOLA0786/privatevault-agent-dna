import { createHash } from "node:crypto";

/** Engine convention: "sha256:" + lowercase hex. */
export function sha256(data: string | Buffer): string {
  return "sha256:" + createHash("sha256").update(data).digest("hex");
}
