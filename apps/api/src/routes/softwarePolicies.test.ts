import { describe, expect, it } from 'vitest';
import { executableRuleSchema, resolveOrgIdForWrite, softwareRulesSchema } from './softwarePolicies';
import { normalizeSoftwarePolicyRules } from '../services/softwarePolicyService';
import type { AuthContext } from '../middleware/auth';

function makeOrgAuth(orgId: string): AuthContext {
  return {
    scope: 'organization',
    orgId,
    canAccessOrg: (id: string) => id === orgId,
    orgCondition: () => null,
    user: { id: 'user-1' },
    accessibleOrgIds: [orgId],
  } as unknown as AuthContext;
}

function makePartnerAuth(orgIds: string[]): AuthContext {
  return {
    scope: 'partner',
    orgId: undefined,
    canAccessOrg: (id: string) => orgIds.includes(id),
    orgCondition: () => null,
    user: { id: 'user-1' },
    accessibleOrgIds: orgIds,
  } as unknown as AuthContext;
}

describe('resolveOrgIdForWrite', () => {
  it('org-scope token cannot write to a different org', () => {
    const auth = makeOrgAuth('org-A');
    const result = resolveOrgIdForWrite(auth, 'org-B');
    expect(result.error).toBeDefined();
    expect(result.orgId).toBeUndefined();
  });

  it('org-scope token can write to its own org', () => {
    const auth = makeOrgAuth('org-A');
    const result = resolveOrgIdForWrite(auth, 'org-A');
    expect(result.orgId).toBe('org-A');
    expect(result.error).toBeUndefined();
  });

  it('org-scope token uses its own org when no requestedOrgId', () => {
    const auth = makeOrgAuth('org-A');
    const result = resolveOrgIdForWrite(auth);
    expect(result.orgId).toBe('org-A');
  });

  it('partner-scope token denied for inaccessible org', () => {
    const auth = makePartnerAuth(['org-A', 'org-B']);
    const result = resolveOrgIdForWrite(auth, 'org-C');
    expect(result.error).toBeDefined();
  });

  it('partner-scope token allowed for accessible org', () => {
    const auth = makePartnerAuth(['org-A', 'org-B']);
    const result = resolveOrgIdForWrite(auth, 'org-B');
    expect(result.orgId).toBe('org-B');
  });
});

describe('executableRuleSchema', () => {
  it('accepts a fully-populated executable rule', () => {
    const parsed = executableRuleSchema.parse({
      name: 'Adobe Reader',
      sha256: 'a'.repeat(64),
      signer: 'Adobe Inc.',
      publisher: 'Adobe Systems Incorporated',
      pathGlob: 'C:\\Program Files\\Adobe\\**\\*.exe',
    });
    expect(parsed.name).toBe('Adobe Reader');
  });

  it('rejects sha256 that is not 64 hex chars', () => {
    expect(() => executableRuleSchema.parse({ name: 'X', sha256: 'not-a-hash' })).toThrow();
    expect(() => executableRuleSchema.parse({ name: 'X', sha256: 'a'.repeat(63) })).toThrow();
  });

  it('accepts uppercase sha256 (case-insensitive regex)', () => {
    expect(() => executableRuleSchema.parse({ name: 'X', sha256: 'A'.repeat(64) })).not.toThrow();
  });

  it('enforces caps on signer / publisher / pathGlob', () => {
    expect(() => executableRuleSchema.parse({ name: 'X', signer: 'a'.repeat(256) })).toThrow();
    expect(() => executableRuleSchema.parse({ name: 'X', publisher: 'a'.repeat(256) })).toThrow();
    expect(() => executableRuleSchema.parse({ name: 'X', pathGlob: 'a'.repeat(501) })).toThrow();
  });
});

describe('softwareRulesSchema — PAM-only / inventory-only / mixed', () => {
  it('accepts a PAM-only policy (executable[] populated, no software[])', () => {
    const parsed = softwareRulesSchema.parse({
      executable: [{ name: 'Adobe Reader', sha256: 'a'.repeat(64) }],
    });
    expect(parsed.executable).toHaveLength(1);
    expect(parsed.software).toBeUndefined();
  });

  it('accepts an inventory-only policy', () => {
    const parsed = softwareRulesSchema.parse({
      software: [{ name: 'Firefox' }],
    });
    expect(parsed.software).toHaveLength(1);
    expect(parsed.executable).toBeUndefined();
  });

  it('accepts a mixed policy', () => {
    const parsed = softwareRulesSchema.parse({
      software: [{ name: 'Firefox' }],
      executable: [{ name: 'Adobe', sha256: 'a'.repeat(64) }],
    });
    expect(parsed.software).toHaveLength(1);
    expect(parsed.executable).toHaveLength(1);
  });

  it('rejects a policy with neither software[] nor executable[]', () => {
    expect(() => softwareRulesSchema.parse({})).toThrow();
    expect(() => softwareRulesSchema.parse({ software: [], executable: [] })).toThrow();
  });

  it('PAM-only payload round-trips through validator + normalizer without losing executable[]', () => {
    // This is the regression Todd flagged: the previous schema stripped
    // `executable` because it was not defined on the Zod object. The
    // PAM bridge then loaded policies whose `executable[]` was always
    // undefined → always {match: null} in production.
    const payload = {
      executable: [{ name: 'Adobe Reader', sha256: 'a'.repeat(64), signer: 'Adobe Inc.' }],
    };
    const validated = softwareRulesSchema.parse(payload);
    const normalized = normalizeSoftwarePolicyRules(validated);
    expect(normalized.executable).toBeDefined();
    expect(normalized.executable).toHaveLength(1);
    expect(normalized.executable?.[0]?.name).toBe('Adobe Reader');
    expect(normalized.executable?.[0]?.sha256).toBe('a'.repeat(64));
    expect(normalized.executable?.[0]?.signer).toBe('Adobe Inc.');
    expect(normalized.software).toEqual([]);
  });
});
