import 'reflect-metadata';
import type { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthorizationGuard } from '../src/guard/authorization.guard';
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
import { NoopDecisionLogger } from '../src/logging/decision-logger';
import { InMemoryAuthorizationMetrics } from '../src/metrics/authorization-metrics';
import {
  RequirePermission,
  RequirePermissions,
} from '../src/decorators/require-permission.decorator';
import { HeaderPrincipalResolver } from '../src/authentication/principal-resolver';
import { DefaultAccountContextResolver } from '../src/guard/account-context-resolver';
import { DefaultVariableResolver } from '../src/variables/variable-resolver';
import {
  AuthorizationDeniedException,
  AuthorizationEvaluationException,
  UnauthenticatedException,
} from '../src/exceptions/authorization.exceptions';
import type { Policy, Role } from '../src/authorization/authorization.types';

function buildService(overrides: {
  roles?: Role[];
  policies?: Policy[];
  memberships?: Parameters<InMemoryMembershipRepository['add']>[0][];
}) {
  const pricingPolicy: Policy = {
    id: 'p1',
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
  const billingOperator: Role = {
    id: 'r1',
    name: 'BillingOperator',
    systemDefault: false,
    unauthenticatedSystemDefault: false,
    internalAgentOnly: false,
    policies: [pricingPolicy],
  };
  const roles = new InMemoryRoleRepository(overrides.roles ?? [billingOperator]);
  const policies = new InMemoryPolicyRepository(overrides.policies ?? [pricingPolicy]);
  const memberships = new InMemoryMembershipRepository(
    overrides.memberships ?? [
      { principalId: 'user-123', accountId: 'account-123', roleIds: ['r1'] },
    ],
  );
  const direct = new InMemoryDirectPolicyRepository();
  const evaluator = new LocalAuthorizationEvaluator(
    new DefaultPolicyRetrievalPoint(memberships, direct, roles),
    new DefaultPolicyInformationPoint(roles, policies),
    new DefaultPolicyDecisionPoint(),
  );
  return new AuthorizationService(
    evaluator,
    new NoopDecisionLogger(),
    new InMemoryAuthorizationMetrics(),
    { serviceName: 'test' },
  );
}

class TestController {
  @RequirePermission({
    action: 'billing:ReadPricing',
    resource: 'rn:cc-api:billing::${cc:accountId}:Pricing/*',
  })
  getPricing() {
    return 'handler-executed';
  }

  unprotected() {
    return 'no-metadata';
  }
}

function makeContext(
  handler: object,
  params: Record<string, string>,
  headers: Record<string, string> = {},
): ExecutionContext {
  const request = { params, headers, method: 'GET', path: '/x' };
  return {
    switchToHttp: () => ({
      getRequest: () => request,
      getResponse: () => ({}),
    }),
    getHandler: () => handler,
    getClass: () => TestController,
    getArgs: () => [request],
  } as unknown as ExecutionContext;
}

function makeGuard(service: AuthorizationService) {
  return new AuthorizationGuard(
    new Reflector(),
    service,
    new HeaderPrincipalResolver(),
    new DefaultAccountContextResolver(),
    new DefaultVariableResolver(),
  );
}

const authHeaders = { 'x-principal-id': 'user-123', 'x-principal-type': 'USER' };

describe('AuthorizationGuard', () => {
  it('allows when a check is granted', async () => {
    const guard = makeGuard(buildService({}));
    const ctx = makeContext(
      TestController.prototype.getPricing,
      { accountId: 'account-123' },
      authHeaders,
    );
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it('denies (throws) when no statement matches', async () => {
    const guard = makeGuard(buildService({}));
    const ctx = makeContext(
      TestController.prototype.getPricing,
      { accountId: 'account-456' },
      authHeaders,
    );
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(AuthorizationDeniedException);
  });

  it('denied response carries failedChecks but no policy internals', async () => {
    const guard = makeGuard(buildService({}));
    const ctx = makeContext(
      TestController.prototype.getPricing,
      { accountId: 'account-456' },
      authHeaders,
    );
    const err = await guard.canActivate(ctx).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AuthorizationDeniedException);
    const body = (err as AuthorizationDeniedException).getResponse() as Record<string, unknown>;
    expect(body.code).toBe('AUTHORIZATION_DENIED');
    expect(body.failedChecks).toEqual([
      { action: 'billing:ReadPricing', resource: 'rn:cc-api:billing::account-456:Pricing/*' },
    ]);
  });

  it('passes through endpoints without metadata', async () => {
    const guard = makeGuard(buildService({}));
    const ctx = makeContext(TestController.prototype.unprotected, {}, {});
    await expect(guard.canActivate(ctx)).resolves.toBe(true);
  });

  it('propagates authentication failure as 401', async () => {
    const guard = new AuthorizationGuard(
      new Reflector(),
      buildService({}),
      { resolve: () => Promise.reject(new UnauthenticatedException()) },
      new DefaultAccountContextResolver(),
      new DefaultVariableResolver(),
    );
    const ctx = makeContext(TestController.prototype.getPricing, { accountId: 'account-123' }, {});
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(UnauthenticatedException);
  });

  it('fails closed on evaluator error', async () => {
    const failing = new AuthorizationService(
      { evaluate: () => Promise.reject(new Error('boom')) },
      new NoopDecisionLogger(),
      new InMemoryAuthorizationMetrics(),
    );
    const guard = makeGuard(failing);
    const ctx = makeContext(
      TestController.prototype.getPricing,
      { accountId: 'account-123' },
      authHeaders,
    );
    await expect(guard.canActivate(ctx)).rejects.toBeInstanceOf(AuthorizationEvaluationException);
  });

  describe('multi-check match semantics', () => {
    // user-123 can billing:ReadPricing on account-123 but NOT billing:CreateRefund
    class MultiController {
      @RequirePermissions(
        [
          {
            action: 'billing:ReadPricing',
            resource: 'rn:cc-api:billing::${cc:accountId}:Pricing/*',
          },
          {
            action: 'billing:CreateRefund',
            resource: 'rn:cc-api:billing::${cc:accountId}:Refunds/*',
          },
        ],
        { match: 'ANY' },
      )
      anyCheck() {
        return 'ok';
      }

      @RequirePermissions(
        [
          {
            action: 'billing:ReadPricing',
            resource: 'rn:cc-api:billing::${cc:accountId}:Pricing/*',
          },
          {
            action: 'billing:CreateRefund',
            resource: 'rn:cc-api:billing::${cc:accountId}:Refunds/*',
          },
        ],
        { match: 'ALL' },
      )
      allCheck() {
        return 'ok';
      }
    }

    function ctxFor(handler: object) {
      const request = { params: { accountId: 'account-123' }, headers: authHeaders };
      return {
        switchToHttp: () => ({ getRequest: () => request }),
        getHandler: () => handler,
        getClass: () => MultiController,
      } as unknown as ExecutionContext;
    }

    it('ANY: passes when at least one check allows', async () => {
      const guard = makeGuard(buildService({}));
      await expect(guard.canActivate(ctxFor(MultiController.prototype.anyCheck))).resolves.toBe(
        true,
      );
    });

    it('ALL: denies when any check fails', async () => {
      const guard = makeGuard(buildService({}));
      await expect(
        guard.canActivate(ctxFor(MultiController.prototype.allCheck)),
      ).rejects.toBeInstanceOf(AuthorizationDeniedException);
    });

    it('ANY: a check that fails to EVALUATE fails only that check — another check can still authorize', async () => {
      let calls = 0;
      const flaky = {
        evaluate: async () => {
          calls += 1;
          // First check errors during evaluation; the second check must
          // still be independently evaluated and can authorize.
          if (calls === 1) throw new Error('evaluator hiccup');
          return buildService({}).evaluate({
            principal: { id: 'user-123', type: 'USER', authenticated: true },
            action: 'billing:ReadPricing',
            resource: 'rn:cc-api:billing::account-123:Pricing/*',
            accountId: 'account-123',
          });
        },
      } as unknown as AuthorizationService;
      class FlakyController {
        @RequirePermissions(
          [
            {
              action: 'billing:ReadInvoices',
              resource: 'rn:cc-api:billing::${cc:accountId}:Invoices/*',
            },
            {
              action: 'billing:ReadPricing',
              resource: 'rn:cc-api:billing::${cc:accountId}:Pricing/*',
            },
          ],
          { match: 'ANY' },
        )
        handler() {
          return 'ok';
        }
      }
      const guard = makeGuard(flaky);
      const request = { params: { accountId: 'account-123' }, headers: authHeaders };
      const ctx = {
        switchToHttp: () => ({ getRequest: () => request }),
        getHandler: () => FlakyController.prototype.handler,
        getClass: () => FlakyController,
      } as unknown as ExecutionContext;
      await expect(guard.canActivate(ctx)).resolves.toBe(true);
    });

    it('ANY: when NO check can authorize AND an evaluation error occurred -> fail closed with the error', async () => {
      const broken = {
        evaluate: async () => {
          throw new Error('evaluator down');
        },
      } as unknown as AuthorizationService;
      const guard = makeGuard(broken);
      await expect(
        guard.canActivate(ctxFor(MultiController.prototype.anyCheck)),
      ).rejects.toBeInstanceOf(AuthorizationEvaluationException);
    });
  });

  it('attaches the resolved principal to the request', async () => {
    const guard = makeGuard(buildService({}));
    const request = { params: { accountId: 'account-123' }, headers: authHeaders };
    const ctx = {
      switchToHttp: () => ({ getRequest: () => request }),
      getHandler: () => TestController.prototype.getPricing,
      getClass: () => TestController,
    } as unknown as ExecutionContext;
    await guard.canActivate(ctx);
    expect((request as Record<string, unknown>).authzPrincipal).toMatchObject({
      id: 'user-123',
      type: 'USER',
      authenticated: true,
    });
  });
});
