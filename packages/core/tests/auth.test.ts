import { describe, expect, it } from "vitest";
import { AuthService } from "../src/auth/auth-service.js";
import { ScryptPasswordHasher } from "../src/crypto/hasher.js";
import { InMemorySessionStore, InMemoryUserRepository } from "../src/stores/memory.js";
import { TokenService } from "../src/tokens/token-service.js";

function makeAuth() {
  return new AuthService({
    users: new InMemoryUserRepository(),
    sessions: new InMemorySessionStore(),
    hasher: new ScryptPasswordHasher(),
    tokens: new TokenService({ secret: "test-secret-32-bytes-long-12345678", issuer: "openauth-test" }),
    refreshTokenTtlSeconds: 3600,
  });
}

describe("register/login", () => {
  it("registers and logs in", async () => {
    const auth = makeAuth();
    const reg = await auth.register({ email: "Ada@Example.com", password: "supersecret1" });
    expect(reg.ok).toBe(true);
    if (!reg.ok) return;
    expect(reg.value.email).toBe("ada@example.com");

    const dup = await auth.register({ email: "ada@example.com", password: "supersecret1" });
    expect(dup.ok).toBe(false);
    if (dup.ok) return;
    expect(dup.error.code).toBe("EMAIL_TAKEN");

    const login = await auth.login({ email: "ada@example.com", password: "supersecret1" });
    expect(login.ok).toBe(true);
    if (!login.ok) return;
    expect(login.value.accessToken.length).toBeGreaterThan(20);
    expect(login.value.refreshToken.length).toBeGreaterThan(20);

    const bad = await auth.login({ email: "ada@example.com", password: "wrongpass1" });
    expect(bad.ok).toBe(false);
  });

  it("rejects weak input", async () => {
    const auth = makeAuth();
    const short = await auth.register({ email: "bob@example.com", password: "short" });
    expect(short.ok).toBe(false);
    const badEmail = await auth.register({ email: "not-an-email", password: "supersecret1" });
    expect(badEmail.ok).toBe(false);
  });

  it("verifies access tokens", async () => {
    const auth = makeAuth();
    await auth.register({ email: "carol@example.com", password: "supersecret1" });
    const login = await auth.login({ email: "carol@example.com", password: "supersecret1" });
    expect(login.ok).toBe(true);
    if (!login.ok) return;
    const v = await auth.verifyAccessToken(login.value.accessToken);
    expect(v.ok).toBe(true);
    if (!v.ok) return;
    expect(v.value.email).toBe("carol@example.com");

    const bad = await auth.verifyAccessToken("invalid.token.here");
    expect(bad.ok).toBe(false);
  });
});

describe("refresh rotation", () => {
  it("rotates and detects reuse", async () => {
    const auth = makeAuth();
    await auth.register({ email: "dave@example.com", password: "supersecret1" });
    const login = await auth.login({ email: "dave@example.com", password: "supersecret1" });
    expect(login.ok).toBe(true);
    if (!login.ok) return;

    const r1 = await auth.refresh({ refreshToken: login.value.refreshToken });
    expect(r1.ok).toBe(true);
    if (!r1.ok) return;

    // Old token reuse must fail with REFRESH_REUSED
    const reuse = await auth.refresh({ refreshToken: login.value.refreshToken });
    expect(reuse.ok).toBe(false);
    if (reuse.ok) return;
    expect(reuse.error.code).toBe("REFRESH_REUSED");

    // After theft detection, even the rotated token family is revoked
    const r2 = await auth.refresh({ refreshToken: r1.value.refreshToken });
    expect(r2.ok).toBe(false);
  });

  it("logout revokes", async () => {
    const auth = makeAuth();
    await auth.register({ email: "erin@example.com", password: "supersecret1" });
    const login = await auth.login({ email: "erin@example.com", password: "supersecret1" });
    expect(login.ok).toBe(true);
    if (!login.ok) return;
    const out = await auth.logout({ refreshToken: login.value.refreshToken });
    expect(out.ok).toBe(true);
    const again = await auth.refresh({ refreshToken: login.value.refreshToken });
    expect(again.ok).toBe(false);
  });
});
