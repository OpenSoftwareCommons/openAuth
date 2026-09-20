# openAuth

Lib de autenticação **framework-agnóstica** para TypeScript/Node.js. Open-source (MIT).

## Status

Fase 0 + 1 prontas: monorepo `pnpm + turbo`, `@openauth/core` com registro/login, JWT access + refresh com rotação, RBAC básico, stores em memória.

## Estrutura

```
packages/core   # @openauth/core — regras puras, sem framework/banco
apps/docs       # (planejado) VitePress
apps/examples   # (planejado) express/next
```

## Uso rápido

```ts
import {
  AuthService, InMemorySessionStore, InMemoryUserRepository,
  ScryptPasswordHasher, TokenService,
} from "@openauth/core";

const auth = new AuthService({
  users: new InMemoryUserRepository(),
  sessions: new InMemorySessionStore(),
  hasher: new ScryptPasswordHasher(),
  tokens: new TokenService({ secret: process.env.AUTH_SECRET!, issuer: "my-app" }),
});

const reg = await auth.register({ email: "ada@example.com", password: "supersecret1" });
const login = await auth.login({ email: "ada@example.com", password: "supersecret1" });
if (login.ok) {
  const { accessToken, refreshToken } = login.value;
}
```

## Scripts

```sh
pnpm install
pnpm build
pnpm test
pnpm typecheck
```

## Roadmap

- [x] Fase 0 — fundação (monorepo, CI, licença)
- [x] Fase 1 — core MVP (credenciais + JWT + refresh rotation)
- [x] Fase 2 (parcial) — RBAC helpers (`can`, `defineRoles`)
- [ ] Fase 3 — OAuth/OIDC (Google, GitHub)
- [ ] Fase 4 — sessões server-side + TOTP + magic-link + adapters Redis/Prisma
- [ ] Fase 5 — hardening + docs públicas + publish NPM com provenance
