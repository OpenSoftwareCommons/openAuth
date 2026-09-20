import { describe, expect, it } from "vitest";
import { ScryptPasswordHasher } from "../src/crypto/hasher.js";
import { can, defineRoles, permissionsForRoles } from "../src/rbac.js";

describe("hasher", () => {
  it("hashes and verifies, rejects wrong password", async () => {
    const h = new ScryptPasswordHasher();
    const hash = await h.hash("correct-horse-1");
    expect(hash.startsWith("scrypt$v1$")).toBe(true);
    expect(await h.verify(hash, "correct-horse-1")).toBe(true);
    expect(await h.verify(hash, "wrong")).toBe(false);
    expect(await h.verify("garbage", "x")).toBe(false);
  });
});

describe("rbac", () => {
  it("matches wildcards and exact", () => {
    const roles = defineRoles([
      { role: "admin", allows: ["*"] },
      { role: "editor", allows: ["posts:*"] },
      { role: "reader", allows: ["posts:read"] },
    ]);
    expect(can(permissionsForRoles(roles, ["admin"]), "anything:else")).toBe(true);
    expect(can(permissionsForRoles(roles, ["editor"]), "posts:delete")).toBe(true);
    expect(can(permissionsForRoles(roles, ["reader"]), "posts:delete")).toBe(false);
    expect(can(permissionsForRoles(roles, ["reader"]), "posts:read")).toBe(true);
  });
});
