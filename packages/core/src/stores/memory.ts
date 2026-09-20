import { randomId } from "../crypto/random.js";
import type { RefreshSession, User } from "../types.js";

/** In-memory UserRepository for tests, examples and local dev. Not for production. */
export class InMemoryUserRepository {
  private byId = new Map<string, User>();
  private byEmail = new Map<string, User>();

  async findByEmail(email: string): Promise<User | null> {
    return this.byEmail.get(email.toLowerCase().trim()) ?? null;
  }

  async findById(id: string): Promise<User | null> {
    return this.byId.get(id) ?? null;
  }

  async create(input: { email: string; passwordHash: string; roles: string[] }): Promise<User> {
    const email = input.email.toLowerCase().trim();
    if (this.byEmail.has(email)) throw new Error("email taken");
    const now = new Date();
    const user: User = {
      id: randomId(),
      email,
      passwordHash: input.passwordHash,
      roles: [...input.roles],
      createdAt: now,
      updatedAt: now,
    };
    this.byId.set(user.id, user);
    this.byEmail.set(email, user);
    return user;
  }

  /** Test helper. */
  clear(): void {
    this.byId.clear();
    this.byEmail.clear();
  }
}

/** In-memory SessionStore for tests, examples and local dev. Not for production. */
export class InMemorySessionStore {
  private byId = new Map<string, RefreshSession>();
  private byTokenHash = new Map<string, RefreshSession>();

  async save(session: RefreshSession): Promise<void> {
    this.byId.set(session.id, session);
    this.byTokenHash.set(session.tokenHash, session);
  }

  async findByTokenHash(tokenHash: string): Promise<RefreshSession | null> {
    return this.byTokenHash.get(tokenHash) ?? null;
  }

  async findById(id: string): Promise<RefreshSession | null> {
    return this.byId.get(id) ?? null;
  }

  async revoke(id: string, at: Date = new Date()): Promise<void> {
    const s = this.byId.get(id);
    if (s && !s.revokedAt) {
      s.revokedAt = at;
    }
  }

  async revokeAllForUser(userId: string, at: Date = new Date()): Promise<void> {
    for (const s of this.byId.values()) {
      if (s.userId === userId && !s.revokedAt) s.revokedAt = at;
    }
  }

  /** Test helper. */
  clear(): void {
    this.byId.clear();
    this.byTokenHash.clear();
  }
}
