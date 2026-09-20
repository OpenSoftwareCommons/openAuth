import * as jose from "jose";
import type { AccessTokenPayload } from "../types.js";

export interface TokenServiceOptions {
  /** HMAC secret (HS256). Use 32+ random bytes. For RS/ES, extend this class. */
  secret: string | Uint8Array;
  issuer?: string;
  audience?: string | string[];
  accessTokenTtlSeconds?: number;
  clockToleranceSeconds?: number;
}

function toKey(secret: string | Uint8Array): Uint8Array {
  return typeof secret === "string" ? new TextEncoder().encode(secret) : secret;
}

export class TokenService {
  readonly issuer: string;
  readonly audience: string | string[] | undefined;
  readonly accessTokenTtlSeconds: number;
  private readonly key: Uint8Array;
  private readonly clockTolerance: number;

  constructor(opts: TokenServiceOptions) {
    if (!opts.secret || (typeof opts.secret === "string" && opts.secret.length < 16)) {
      throw new Error("TokenService requires a secret of at least 16 chars");
    }
    this.key = toKey(opts.secret);
    this.issuer = opts.issuer ?? "openauth";
    this.audience = opts.audience;
    this.accessTokenTtlSeconds = opts.accessTokenTtlSeconds ?? 900;
    this.clockTolerance = opts.clockToleranceSeconds ?? 30;
  }

  async signAccessToken(payload: AccessTokenPayload): Promise<{ token: string; expiresInSeconds: number }> {
    // jose typing: apply audience conditionally
    let builder = new jose.SignJWT({ email: payload.email, roles: payload.roles })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setSubject(payload.sub)
      .setIssuedAt()
      .setIssuer(this.issuer)
      .setExpirationTime(`${this.accessTokenTtlSeconds}s`);
    if (this.audience) builder = builder.setAudience(this.audience);
    const token = await builder.sign(this.key);
    return { token, expiresInSeconds: this.accessTokenTtlSeconds };
  }

  async verifyAccessToken(token: string): Promise<AccessTokenPayload> {
    const verifyOpts: { issuer: string; clockTolerance: number; audience?: string | string[] } = {
      issuer: this.issuer,
      clockTolerance: this.clockTolerance,
    };
    if (this.audience !== undefined) verifyOpts.audience = this.audience;
    const { payload } = await jose.jwtVerify(token, this.key, verifyOpts);
    if (typeof payload.sub !== "string" || !payload.sub) {
      throw new Error("invalid sub");
    }
    return {
      sub: payload.sub,
      email: typeof payload["email"] === "string" ? (payload["email"] as string) : "",
      roles: Array.isArray(payload["roles"]) ? (payload["roles"] as string[]) : [],
    };
  }
}
