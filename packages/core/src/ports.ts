import type { RefreshSession, User } from "./types.js";

export interface UserRepository {
  findByEmail(email: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  create(input: { email: string; passwordHash: string; roles: string[] }): Promise<User>;
}

export interface SessionStore {
  save(session: RefreshSession): Promise<void>;
  findByTokenHash(tokenHash: string): Promise<RefreshSession | null>;
  findById(id: string): Promise<RefreshSession | null>;
  revoke(id: string, at?: Date): Promise<void>;
  revokeAllForUser(userId: string, at?: Date): Promise<void>;
}

export interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(hash: string, password: string): Promise<boolean>;
}
