import { AuthorizationService } from '../src/authorization/authorization.service';
import { LocalAuthorizationEvaluator } from '../src/authorization/authorization-evaluator';
import { DefaultPolicyRetrievalPoint } from '../src/prp/policy-retrieval-point';
import { DefaultPolicyInformationPoint } from '../src/pip/policy-information-point';
import { DefaultPolicyDecisionPoint } from '../src/pdp/policy-decision-point';
import {
  InMemoryDirectPolicyRepository,
  InMemoryMembershipRepository,
  InMemoryPolicyRepository,
  InMemoryRoleRepository,
} from '../src/adapters/in-memory.repositories';
import { buildDemoSeed } from '../src/demo/fixtures';
import type { AuthorizationDecisionLogger } from '../src/logging/decision-logger';
import type { AuthorizationDecisionLog } from '../src/authorization/authorization.types';
import { InMemoryAuthorizationMetrics } from '../src/metrics/authorization-metrics';
import { AuthorizationDeniedException } from '../src/exceptions/authorization.exceptions';
import type { Principal } from '../src/authorization/authorization.types';

class CapturingLogger implements AuthorizationDecisionLogger {
  logs: AuthorizationDecisionLog[] = [];
  async log(d: AuthorizationDecisionLog): Promise<void> {
    this.logs.push(d);
  }
}

function buildStack() {
  const seed = buildDemoSeed();
  const roles = new InMemoryRoleRepository(seed.roles);
  const policies = new InMemoryPolicyRepository(seed.policies);
  const memberships = new InMemoryMembershipRepository(seed.memberships);
  const direct = new InMemoryDirectPolicyRepository(seed.directPolicies);
  const logger = new CapturingLogger();
  const metrics = new InMemoryAuthorizationMetrics();
  const service = new AuthorizationService(
    new LocalAuthorizationEvaluator(
      new DefaultPolicyRetrievalPoint(memberships, direct, roles),
      new DefaultPolicyInformationPoint(roles, policies),
      new DefaultPolicyDecisionPoint(),
    ),
    logger,
    metrics,
    { serviceName: 'test-svc' },
  );
  return { service, roles, policies, logger, metrics };
}

const user123: Principal = { id: 'user-123', type: 'USER', authenticated: true };

describe('AuthorizationService', () => {
  it('authorizes a valid request and emits a decision log', async () => {
    const { service, logger, metrics } = buildStack();
    await expect(
      service.authorize({
        principal: user123,
        action: 'billing:ReadPricing',
        resource: 'rn:cc-api:billing::account-123:Pricing/current',
        accountId: 'account-123',
      }),
    ).resolves.toBe(true);
    expect(logger.logs).toHaveLength(1);
    expect(logger.logs[0]).toMatchObject({
      principalId: 'user-123',
      accountId: 'account-123',
      action: 'billing:ReadPricing',
      decision: 'ALLOW',
      serviceName: 'test-svc',
    });
    expect(metrics.snapshot().authorization_allowed_total).toBe(1);
  });

  it('throws AuthorizationDeniedException on deny', async () => {
    const { service } = buildStack();
    await expect(
      service.authorize({
        principal: user123,
        action: 'billing:ReadPricing',
        resource: 'rn:cc-api:billing::account-456:Pricing/current',
        accountId: 'account-456',
      }),
    ).rejects.toBeInstanceOf(AuthorizationDeniedException);
  });

  describe('feature gating (same engine)', () => {
    it('feature enabled for account-123', async () => {
      const { service } = buildStack();
      await expect(service.isFeatureEnabled(user123, 'NewBillingUI', 'account-123')).resolves.toBe(
        true,
      );
    });
    it('feature disabled for account-456 (account isolation)', async () => {
      const { service } = buildStack();
      await expect(service.isFeatureEnabled(user123, 'NewBillingUI', 'account-456')).resolves.toBe(
        false,
      );
    });
    it('unknown feature disabled', async () => {
      const { service } = buildStack();
      await expect(
        service.isFeatureEnabled(user123, 'NonexistentFeature', 'account-123'),
      ).resolves.toBe(false);
    });
  });

  describe('revocation (no caching)', () => {
    it('removing a policy denies the very next request', async () => {
      const { service, roles } = buildStack();
      const [role] = await roles.findByIds(['role-billing-operator']);
      expect(role).toBeDefined();

      const req = {
        principal: user123,
        action: 'billing:ReadPricing',
        resource: 'rn:cc-api:billing::account-123:Pricing/current',
        accountId: 'account-123',
      };
      await expect(service.authorize(req)).resolves.toBe(true);

      // Revoke — mutate repo state (what a DB write would do)
      roles.save({
        ...role,
        policies: role.policies.filter((p) => p.name !== 'BillingPricingRead'),
      });

      await expect(service.authorize(req)).rejects.toBeInstanceOf(AuthorizationDeniedException);
    });
  });
});
