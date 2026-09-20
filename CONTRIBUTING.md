# Contributing

1. Node >= 20, `pnpm@10`.
2. `pnpm install`, `pnpm build`, `pnpm test`, `pnpm typecheck`.
3. Commits em inglês, padrão Conventional Commits (`feat:`, `fix:`...).
4. Todo PR precisa de testes para comportamento novo e atualização de docs quando mudar API pública.
5. Segurança primeiro: nunca logue senhas/tokens plain, refresh sempre hasheado (SHA-256), segredos via env.
