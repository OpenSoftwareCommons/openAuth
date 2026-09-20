export type AuthErrorCode =
  | "INVALID_INPUT"
  | "EMAIL_TAKEN"
  | "INVALID_CREDENTIALS"
  | "USER_NOT_FOUND"
  | "TOKEN_INVALID"
  | "TOKEN_EXPIRED"
  | "REFRESH_EXPIRED"
  | "REFRESH_REUSED"
  | "SESSION_REVOKED";

const STATUS_BY_CODE: Record<AuthErrorCode, number> = {
  INVALID_INPUT: 400,
  EMAIL_TAKEN: 409,
  INVALID_CREDENTIALS: 401,
  USER_NOT_FOUND: 404,
  TOKEN_INVALID: 401,
  TOKEN_EXPIRED: 401,
  REFRESH_EXPIRED: 401,
  REFRESH_REUSED: 401,
  SESSION_REVOKED: 401,
};

export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly status: number;
  readonly details?: unknown;

  constructor(code: AuthErrorCode, message: string, details?: unknown) {
    super(message);
    this.name = "AuthError";
    this.code = code;
    this.status = STATUS_BY_CODE[code];
    this.details = details;
  }
}

export type Result<T, E = AuthError> =
  | { ok: true; value: T }
  | { ok: false; error: E };

export function ok<T>(value: T): Result<T, never> {
  return { ok: true, value } as Result<T, never>;
}

export function err<E>(error: E): Result<never, E> {
  return { ok: false, error };
}
