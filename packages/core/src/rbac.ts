export type Permission = `${string}:${string}` | string;

export interface RoleDefinition {
  role: string;
  allows: Permission[];
}

/**
 * Minimal RBAC helper.
 * - `*` matches anything in that segment (`"posts:*"`, `"*:read"`, `"*"`).
 * - Exact match otherwise.
 */
export function can(userPermissions: Permission[], action: Permission): boolean {
  for (const granted of userPermissions) {
    if (granted === "*" || granted === action) return true;
    const [gRes, gAct] = granted.split(":");
    const [aRes, aAct] = action.split(":");
    if (gRes === "*" && gAct === aAct) return true;
    if (gAct === "*" && gRes === aRes) return true;
  }
  return false;
}

export function permissionsForRoles(roleMap: Record<string, Permission[]>, roles: string[]): Permission[] {
  const out = new Set<Permission>();
  for (const role of roles) {
    for (const p of roleMap[role] ?? []) out.add(p);
  }
  return [...out];
}

export function defineRoles(defs: RoleDefinition[]): Record<string, Permission[]> {
  const map: Record<string, Permission[]> = {};
  for (const d of defs) map[d.role] = [...d.allows];
  return map;
}
