import { DefaultPolicyRetrievalPoint } from '../src/prp/policy-retrieval-point';
import { DefaultPolicyInformationPoint } from '../src/pip/policy-information-point';
import {
  InMemoryDirectPolicyRepository,
  InMemoryMembershipRepository,
  InMemoryPolicyRepository,
  InMemoryRoleRepository,
} from '../src/adapters/in-memory.repositories';
import { AuthorizationEvaluationException } from '../src/exceptions/authorization.exceptions';
import type {
  AuthorizationRequestContext,
  Membership,
  Policy,
  Principal,
  Role,
} from '../src/authorization/authorization.types';

const baseCtx: AuthorizationRequestContext = { variables: {} };

const pricingPolicy: Policy = {
  id: 'p-pricing',
  name: 'BillingPricingRead',
  statements: [
    {
      sid: 'AllowPricingRead',
      effect: 'Allow',
      actions: ['billing:ReadPricing'],
      resources: ['rn:cc-api:billing::${cc:accountId}:Pricing/*'],
    },
  ],
};
const invoicePolicy: Policy = {
  id: 'p-invoice',
  name: 'BillingInvoiceRead',
  statements: [
    {
      sid: 'AllowInvoiceRead',
      effect: 'Allow',
      actions: ['billing:ReadInvoices'],
      resources: ['rn:cc-api:billing::${cc:accountId}:Invoices/*'],
    },
  ],
};
const auditPolicy: Policy = {
  id: 'p-audit',
  name: 'InternalAuditRead',
  statements: [
    { sid: 'Audit', effect: 'Allow', actions: ['internal:ReadAudit'], resources: ['*'] },
  ],
};
const healthPolicy: Policy = {
  id: 'p-health',
  name: 'HealthRead',
  statements: [
    { sid: 'Health', effect: 'Allow', actions: ['system:ReadHealth'], resources: ['*'] },
  ],
};

const billingOperator: Role = {
  id: 'r-billing',
  name: 'BillingOperator',
  systemDefault: false,
  unauthenticatedSystemDefault: false,
  internalAgentOnly: false,
  policies: [pricingPolicy],
};
const viewer: Role = {
  id: 'r-viewer',
  name: 'Viewer',
  systemDefault: false,
  unauthenticatedSystemDefault: false,
  internalAgentOnly: false,
  policies: [invoicePolicy],
};
const internalSupport: Role = {
  id: 'r-internal',
  name: 'InternalSupport',
  systemDefault: false,
  unauthenticatedSystemDefault: false,
  internalAgentOnly: true,
  policies: [auditPolicy],
};
const sysDefault: Role = {
  id: 'r-sys',
  name: 'AuthenticatedBaseline',
  systemDefault: true,
  unauthenticatedSystemDefault: false,
  internalAgentOnly: false,
  policies: [healthPolicy],
};
const publicDefault: Role = {
  id: 'r-pub',
  name: 'PublicHealth',
  systemDefault: false,
  unauthenticatedSystemDefault: true,
  internalAgentOnly: false,
  policies: [healthPolicy],
};

const memberships: Membership[] = [
  { principalId: 'user-123', accountId: 'account-123', roleIds: ['r-billing'] },
  { principalId: 'user-123', accountId: 'account-456', roleIds: ['r-viewer'] },
  // a customer somehow holding an internal-only role id:
  { principalId: 'user-123', accountId: 'account-789', roleIds: ['r-internal'] },
];

function buildPrp(
  overrides: Partial<{
    memberships: Membership[];
    roles: Role[];
    direct: Record<string, string[]>;
  }> = {},
) {
  const roleRepo = new InMemoryRoleRepository(
    overrides.roles ?? [billingOperator, viewer, internalSupport, sysDefault, publicDefault],
  );
  const prp = new DefaultPolicyRetrievalPoint(
    new InMemoryMembershipRepository(overrides.memberships ?? memberships),
    new InMemoryDirectPolicyRepository(overrides.direct ?? {}),
    roleRepo,
  );
  const pip = new DefaultPolicyInformationPoint(
    roleRepo,
    new InMemoryPolicyRepository([pricingPolicy, invoicePolicy, auditPolicy, healthPolicy]),
  );
  return { prp, pip };
}

describe('DefaultPolicyRetrievalPoint', () => {
  const user: Principal = { id: 'user-123', type: 'USER', authenticated: true };

  it('produces one scope per account membership (no merging)', async () => {
    const { prp } = buildPrp();
    const res = await prp.retrieve(user, baseCtx);
    const accounts = res.scopes.filter((s) => s.accountId).map((s) => s.accountId);
    expect(accounts).toEqual(['account-123', 'account-456', 'account-789']);
  });

  it('adds system-default role ids to every scope for authenticated principals', async () => {
    const { prp } = buildPrp();
    const res = await prp.retrieve(user, baseCtx);
    for (const scope of res.scopes) {
      expect(scope.roleIds).toContain('r-sys');
    }
  });

  it('creates a principal-scoped scope for direct policies', async () => {
    const { prp } = buildPrp({ direct: { 'svc-1': ['p-invoice'] } });
    const svc: Principal = { id: 'svc-1', type: 'SERVICE', authenticated: true };
    const res = await prp.retrieve(svc, baseCtx);
    const pscope = res.scopes.find((s) => s.contextId === 'principal:svc-1');
    expect(pscope?.directPolicyIds).toEqual(['p-invoice']);
  });

  it('unauthenticated principal only gets unauthenticated-default roles', async () => {
    const { prp } = buildPrp();
    const anon: Principal = { id: 'anon', type: 'USER', authenticated: false };
    const res = await prp.retrieve(anon, baseCtx);
    expect(res.scopes).toHaveLength(1);
    expect(res.scopes[0].roleIds).toEqual(['r-pub']);
  });

  it('internalAgentOnly system default is excluded for USER principals', async () => {
    const internalSys: Role = {
      ...internalSupport,
      id: 'r-internal-sys',
      systemDefault: true,
    };
    const { prp } = buildPrp({ roles: [internalSys] });
    const res = await prp.retrieve(user, baseCtx);
    for (const scope of res.scopes) {
      expect(scope.roleIds).not.toContain('r-internal-sys');
    }
  });

  it('internalAgentOnly system default IS included for AGENT principals', async () => {
    const internalSys: Role = {
      ...internalSupport,
      id: 'r-internal-sys',
      systemDefault: true,
    };
    const { prp } = buildPrp({ roles: [internalSys] });
    const agent: Principal = { id: 'agent-1', type: 'AGENT', authenticated: true };
    const res = await prp.retrieve(agent, baseCtx);
    const allRoleIds = res.scopes.flatMap((s) => s.roleIds);
    expect(allRoleIds).toContain('r-internal-sys');
  });

  it('wraps repository failures in AuthorizationEvaluationException', async () => {
    const prp = new DefaultPolicyRetrievalPoint(
      { findByPrincipalId: () => Promise.reject(new Error('db down')) },
      new InMemoryDirectPolicyRepository(),
      new InMemoryRoleRepository(),
    );
    await expect(prp.retrieve(user, baseCtx)).rejects.toBeInstanceOf(
      AuthorizationEvaluationException,
    );
  });
});

describe('DefaultPolicyInformationPoint', () => {
  const user: Principal = { id: 'user-123', type: 'USER', authenticated: true };

  it('expands role -> policies per scope, preserving boundaries', async () => {
    const { prp, pip } = buildPrp();
    const res = await prp.retrieve(user, baseCtx);
    const contexts = await pip.buildEvaluationContexts(res);

    const a123 = contexts.find((c) => c.accountId === 'account-123');
    const a456 = contexts.find((c) => c.accountId === 'account-456');
    expect(a123?.policies.map((p) => p.name)).toContain('BillingPricingRead');
    expect(a123?.policies.map((p) => p.name)).not.toContain('BillingInvoiceRead');
    expect(a456?.policies.map((p) => p.name)).toContain('BillingInvoiceRead');
    expect(a456?.policies.map((p) => p.name)).not.toContain('BillingPricingRead');
  });

  it('strips internalAgentOnly roles for USER principals (defense in depth)', async () => {
    const { prp, pip } = buildPrp();
    const res = await prp.retrieve(user, baseCtx);
    const contexts = await pip.buildEvaluationContexts(res);
    const a789 = contexts.find((c) => c.accountId === 'account-789');
    expect(a789?.roles.map((r) => r.name)).not.toContain('InternalSupport');
    expect(a789?.policies.map((p) => p.name)).not.toContain('InternalAuditRead');
  });

  it('keeps internalAgentOnly roles for AGENT principals', async () => {
    const { prp, pip } = buildPrp({
      memberships: [{ principalId: 'agent-1', accountId: 'account-1', roleIds: ['r-internal'] }],
    });
    const agent: Principal = { id: 'agent-1', type: 'AGENT', authenticated: true };
    const res = await prp.retrieve(agent, baseCtx);
    const contexts = await pip.buildEvaluationContexts(res);
    const a1 = contexts.find((c) => c.accountId === 'account-1');
    expect(a1?.policies.map((p) => p.name)).toContain('InternalAuditRead');
  });
});
