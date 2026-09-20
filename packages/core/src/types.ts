export interface User {
  id: string;
  email: string;
  passwordHash: string;
  roles: string[];
  createdAt: Date;
  updatedAt: Date;
}

export interface NewUser {
  email: string;
  passwordHash: string;
  roles?: string[];
}

export interface PublicUser {
  id: string;
  email: string;
  roles: string[];
  createdAt: Date;
}

export interface RefreshSession {
  id: string;
  userId: string;
  /** SHA-256 hex of the opaque refresh token. Never store the plain token. */
  tokenHash: string;
  expiresAt: Date;
  createdAt: Date;
  revokedAt: Date | null;
  /** Set when rotated: id of the replacement session. Used for reuse detection. */
  replacedById: string | null;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresInSeconds: number;
}

export interface AccessTokenPayload {
  sub: string;
  email: string;
  roles: string[];
}

export function toPublicUser(user: User): PublicUser {
  return {
    id: user.id,
    email: user.email,
    roles: [...user.roles],
    createdAt: user.createdAt,
  };
}
