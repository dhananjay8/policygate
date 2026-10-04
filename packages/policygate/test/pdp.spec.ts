import { DefaultPolicyDecisionPoint } from '../src/pdp/policy-decision-point';
import type {
  AuthorizationContext,
  AuthorizationRequest,
  Policy,
  Principal,
  Role,
} from '../src/authorization/authorization.types';

const pdp = new DefaultPolicyDecisionPoint();

const user: Principal = { id: 'user-123', type: 'USER', authenticated: true };

function policy(id: string, name: string, stmts: Policy['statements']): Policy {
  return { id, name, statements: stmts };
}
function ctx(
  accountId: string | undefined,
  policies: Policy[],
  roles: Role[] = [],
): AuthorizationContext {
  return {
    contextId: accountId ? `account:${accountId}` : 'principal:p',
    accountId,
    roles,
    policies,
  };
}

const pricingAllow = policy('p1', 'BillingPricingRead', [
  {
    sid: 'AllowPricingRead',
    effect: 'Allow',
    actions: ['billing:ReadPricing'],
    resources: ['rn:cc-api:billing::${cc:accountId}:Pricing/*'],
  },
]);
const refundAllow = policy('p2', 'BillingRefund', [
  {
    sid: 'AllowRefund',
    effect: 'Allow',
    actions: ['billing:CreateRefund'],
    resources: ['rn:cc-api:billing::${cc:accountId}:Refunds/*'],
  },
]);

function req(over: Partial<AuthorizationRequest>): AuthorizationRequest {
  return {
    principal: user,
    action: 'billing:ReadPricing',
    resource: 'rn:cc-api:billing::account-123:Pricing/current',
    accountId: 'account-123',
    ...over,
  };
}

describe('DefaultPolicyDecisionPoint', () => {
  it('Rule 1: deny by default when nothing matches', () => {
    const d = pdp.evaluate(req({}), [ctx('account-123', [refundAllow])]);
    expect(d.allowed).toBe(false);
    expect(d.reasons.map((r) => r.code)).toContain('DEFAULT_DENY');
  });

  it('Rule 2: explicit deny wins over allow', () => {
    const deny = policy('p3', 'DenyPricing', [
      {
        sid: 'DenyPricing',
        effect: 'Deny',
        actions: ['billing:ReadPricing'],
        resources: ['rn:cc-api:billing::${cc:accountId}:Pricing/*'],
      },
    ]);
    const d = pdp.evaluate(req({}), [ctx('account-123', [pricingAllow, deny])]);
    expect(d.allowed).toBe(false);
    expect(d.reasons.map((r) => r.code)).toContain('EXPLICIT_DENY');
    expect(d.matchedStatements).toContain('DenyPricing');
  });

  it('deny in one context blocks even when another context allows', () => {
    const deny = policy('p3', 'DenyPricing', [
      {
        sid: 'DenyPricing',
        effect: 'Deny',
        actions: ['billing:*'],
        resources: ['rn:cc-api:billing::account-456:*'],
      },
    ]);
    // Request targets account-456; only the 456 context applies.
    const d = pdp.evaluate(
      req({ accountId: 'account-456', resource: 'rn:cc-api:billing::account-456:Pricing/x' }),
      [ctx('account-123', [pricingAllow]), ctx('account-456', [pricingAllow, deny])],
    );
    expect(d.allowed).toBe(false);
  });

  it('Rule 3: action exact + wildcard match', () => {
    const wildcard = policy('p4', 'BillingWildcard', [
      {
        sid: 'W',
        effect: 'Allow',
        actions: ['billing:*'],
        resources: ['rn:cc-api:billing::${cc:accountId}:*'],
      },
    ]);
    expect(
      pdp.evaluate(req({ action: 'billing:ReadPricing' }), [ctx('account-123', [wildcard])])
        .allowed,
    ).toBe(true);
    expect(
      pdp.evaluate(req({ action: 'orders:Read' }), [ctx('account-123', [wildcard])]).allowed,
    ).toBe(false);
  });

  it('Rule 4: resource must match the exact account segment', () => {
    const d = pdp.evaluate(
      req({ resource: 'rn:cc-api:billing::account-456:Pricing/current', accountId: 'account-456' }),
      [ctx('account-123', [pricingAllow]), ctx('account-456', [])],
    );
    expect(d.allowed).toBe(false);
  });

  it('Rule 5: conditions gate statements', () => {
    const conditional = policy('p5', 'Conditional', [
      {
        sid: 'Cond',
        effect: 'Allow',
        actions: ['billing:ReadPricing'],
        resources: ['rn:cc-api:billing::${cc:accountId}:Pricing/*'],
        conditions: { StringEquals: { 'cc:env': 'prod' } },
      },
    ]);
    expect(
      pdp.evaluate(req({ variables: { 'cc:env': 'prod' } }), [ctx('account-123', [conditional])])
        .allowed,
    ).toBe(true);
    expect(
      pdp.evaluate(req({ variables: { 'cc:env': 'dev' } }), [ctx('account-123', [conditional])])
        .allowed,
    ).toBe(false);
  });

  describe('multi-account isolation', () => {
    const contexts = [
      ctx('account-123', [pricingAllow, refundAllow]), // BillingOperator
      ctx('account-456', []), // Viewer -> no pricing
    ];

    it('account-123 permissions do not leak into account-456', () => {
      const d = pdp.evaluate(
        req({ accountId: 'account-456', resource: 'rn:cc-api:billing::account-456:Pricing/x' }),
        contexts,
      );
      expect(d.allowed).toBe(false);
      expect(d.evaluatedContexts).toEqual(['account:account-456']);
    });

    it('grants when the requested account context allows', () => {
      const d = pdp.evaluate(req({}), contexts);
      expect(d.allowed).toBe(true);
      expect(d.grantedByContextId).toBe('account:account-123');
    });

    it('no membership in requested account -> NO_APPLICABLE_CONTEXT', () => {
      const d = pdp.evaluate(
        req({ accountId: 'account-999', resource: 'rn:cc-api:billing::account-999:Pricing/x' }),
        contexts,
      );
      expect(d.allowed).toBe(false);
      expect(d.reasons.map((r) => r.code)).toContain('NO_APPLICABLE_CONTEXT');
    });

    it('account-123 refund grant cannot authorize account-456 refund', () => {
      const d = pdp.evaluate(
        req({
          action: 'billing:CreateRefund',
          resource: 'rn:cc-api:billing::account-456:Refunds/x',
          accountId: 'account-456',
        }),
        contexts,
      );
      expect(d.allowed).toBe(false);
    });
  });

  it('no accountId: any context may grant (principal-scoped service calls)', () => {
    const svcPolicy = policy('p6', 'Svc', [
      { sid: 'S', effect: 'Allow', actions: ['billing:ReadInvoices'], resources: ['*'] },
    ]);
    const d = pdp.evaluate(
      req({ accountId: undefined, action: 'billing:ReadInvoices', resource: 'anything' }),
      [ctx(undefined, [svcPolicy])],
    );
    expect(d.allowed).toBe(true);
  });

  it('empty context list denies', () => {
    expect(pdp.evaluate(req({}), []).allowed).toBe(false);
  });
});
