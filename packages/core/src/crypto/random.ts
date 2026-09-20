import { randomBytes } from "node:crypto";

/** Cryptographically secure opaque token (base64url, no padding). */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

export function randomId(bytes = 16): string {
  return randomBytes(bytes).toString("base64url");
}
