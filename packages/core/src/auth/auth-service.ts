import { sha256Hex } from "../crypto/hasher.js";
import { randomId, randomToken } from "../crypto/random.js";
import { AuthError, err, ok, type Result } from "../errors.js";
import type { PasswordHasher, SessionStore, UserRepository } from "../ports.js";
import { loginSchema, registerSchema } from "../schemas.js";
import { TokenService } from "../tokens/token-service.js";
import { toPublicUser, type PublicUser, type TokenPair } from "../types.js";

export interface AuthServiceOptions {
  users: UserRepository;
  sessions: SessionStore;
  hasher: PasswordHasher;
  tokens: TokenService;
  refreshTokenTtlSeconds?: number;
  defaultRoles?: string[];
}

export class AuthService {
  private readonly users: UserRepository;
  private readonly sessions: SessionStore;
  private readonly hasher: PasswordHasher;
  private readonly tokens: TokenService;
  private readonly refreshTtl: number;
  private readonly defaultRoles: string[];

  constructor(opts: AuthServiceOptions) {
    this.users = opts.users;
    this.sessions = opts.sessions;
    this.hasher = opts.hasher;
    this.tokens = opts.tokens;
    this.refreshTtl = opts.refreshTokenTtlSeconds ?? 60 * 60 * 24 * 30;
    this.defaultRoles = opts.defaultRoles ?? ["user"];
  }

  async register(input: { email: string; password: string; roles?: string[] }): Promise<Result<PublicUser>> {
    const parsed = registerSchema.safeParse(input);
    if (!parsed.success) {
      return err(new AuthError("INVALID_INPUT", "invalid registration input", parsed.error.flatten()));
    }
    const email = parsed.data.email;
    const existing = await this.users.findByEmail(email);
    if (existing) return err(new AuthError("EMAIL_TAKEN", "email already registered"));

    const passwordHash = await this.hasher.hash(parsed.data.password);
    const user = await this.users.create({
      email,
      passwordHash,
      roles: parsed.data.roles ?? this.defaultRoles,
    });
    return ok(toPublicUser(user));
  }

  async login(input: { email: string; password: string }): Promise<Result<TokenPair>> {
    const parsed = loginSchema.safeParse(input);
    if (!parsed.success) {
      return err(new AuthError("INVALID_INPUT", "invalid login input", parsed.error.flatten()));
    }
    const user = await this.users.findByEmail(parsed.data.email);
    if (!user) return err(new AuthError("INVALID_CREDENTIALS", "invalid email or password"));

    const valid = await this.hasher.verify(user.passwordHash, parsed.data.password);
    if (!valid) return err(new AuthError("INVALID_CREDENTIALS", "invalid email or password"));

    return ok(await this.issueTokens(user.id, user.email, user.roles));
  }

  async refresh(input: { refreshToken: string }): Promise<Result<TokenPair>> {
    const tokenHash = sha256Hex(input.refreshToken);
    const session = await this.sessions.findByTokenHash(tokenHash);
    if (!session) return err(new AuthError("TOKEN_INVALID", "unknown refresh token"));

    // Reuse of an already-rotated token => possible theft. Revoke family.
    if (session.revokedAt) {
      await this.sessions.revokeAllForUser(session.userId);
      return err(new AuthError("REFRESH_REUSED", "refresh token reuse detected"));
    }
    if (session.expiresAt.getTime() <= Date.now()) {
      return err(new AuthError("REFRESH_EXPIRED", "refresh token expired"));
    }

    const user = await this.users.findById(session.userId);
    if (!user) return err(new AuthError("USER_NOT_FOUND", "user not found"));

    // Rotate: revoke old, link to replacement.
    const next = await this.issueTokens(user.id, user.email, user.roles);
    const nextHash = sha256Hex(next.refreshToken);
    const replacement = await this.sessions.findByTokenHash(nextHash);
    session.replacedById = replacement?.id ?? null;
    await this.sessions.revoke(session.id);
    if (replacement) {
      // persist replacedById linkage
      await this.sessions.save(session);
    }
    return ok(next);
  }

  async logout(input: { refreshToken: string }): Promise<Result<{ revoked: boolean }>> {
    const session = await this.sessions.findByTokenHash(sha256Hex(input.refreshToken));
    if (!session) return ok({ revoked: false });
    await this.sessions.revoke(session.id);
    return ok({ revoked: true });
  }

  async verifyAccessToken(token: string): Promise<Result<{ sub: string; email: string; roles: string[] }>> {
    try {
      const payload = await this.tokens.verifyAccessToken(token);
      return ok(payload);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "invalid token";
      if (/expired/i.test(msg)) return err(new AuthError("TOKEN_EXPIRED", "access token expired"));
      return err(new AuthError("TOKEN_INVALID", "invalid access token"));
    }
  }

  private async issueTokens(userId: string, email: string, roles: string[]): Promise<TokenPair> {
    const { token, expiresInSeconds } = await this.tokens.signAccessToken({
      sub: userId,
      email,
      roles,
    });
    const refreshToken = randomToken(32);
    const now = new Date();
    await this.sessions.save({
      id: randomId(),
      userId,
      tokenHash: sha256Hex(refreshToken),
      expiresAt: new Date(now.getTime() + this.refreshTtl * 1000),
      createdAt: now,
      revokedAt: null,
      replacedById: null,
    });
    return { accessToken: token, refreshToken, expiresInSeconds };
  }
}
