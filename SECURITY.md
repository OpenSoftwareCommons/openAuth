# Security

Do not open public issues for vulnerabilities. Email the maintainers (see GitHub code owners) with repro steps.

Defaults enforced by `@openauth/core`:
- Passwords: scrypt (N=16384, r=8, p=1) + salt 16 bytes, `timingSafeEqual` on verify.
- Access tokens: JWT HS256 short-lived (default 15 min), `iss/aud/exp` validated.
- Refresh tokens: opaque 32 bytes, stored as SHA-256 hash, rotation + reuse detection (family revoked on reuse).
