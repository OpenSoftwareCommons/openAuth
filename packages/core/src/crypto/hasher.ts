import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual, type ScryptOptions } from "node:crypto";
import type { PasswordHasher } from "../ports.js";

function scryptAsync(password: string, salt: Buffer, keyLen: number, options: ScryptOptions): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scryptCb(password, salt, keyLen, options, (err, derived) => {
      if (err) reject(err);
      else resolve(derived as Buffer);
    });
  });
}

// OWASP-friendly defaults for scrypt (Node built-in, no native dep).
// N=16384, r=8, p=1, 32-byte key. ~50-100ms on modern hardware.
const DEFAULTS = { N: 16384, r: 8, p: 1, keyLen: 32, saltLen: 16 } as const;

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function unb64url(s: string): Buffer {
  return Buffer.from(s, "base64url");
}

export class ScryptPasswordHasher implements PasswordHasher {
  async hash(password: string): Promise<string> {
    const salt = randomBytes(DEFAULTS.saltLen);
    const key = await scryptAsync(password, salt, DEFAULTS.keyLen, {
      N: DEFAULTS.N,
      r: DEFAULTS.r,
      p: DEFAULTS.p,
    });
    return [
      "scrypt",
      "v1",
      String(DEFAULTS.N),
      String(DEFAULTS.r),
      String(DEFAULTS.p),
      b64url(salt),
      b64url(key),
    ].join("$");
  }

  async verify(stored: string, password: string): Promise<boolean> {
    const parts = stored.split("$");
    if (parts.length !== 7 || parts[0] !== "scrypt" || parts[1] !== "v1") {
      return false;
    }
    const [, , nStr, rStr, pStr, saltB64, keyB64] = parts;
    const N = Number(nStr);
    const r = Number(rStr);
    const p = Number(pStr);
    if (!Number.isInteger(N) || !Number.isInteger(r) || !Number.isInteger(p)) {
      return false;
    }
    try {
      const salt = unb64url(saltB64 as string);
      const expected = unb64url(keyB64 as string);
      const actual = await scryptAsync(password, salt, expected.length, {
        N,
        r,
        p,
      });
      if (actual.length !== expected.length) return false;
      return timingSafeEqual(actual, expected);
    } catch {
      return false;
    }
  }
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}
