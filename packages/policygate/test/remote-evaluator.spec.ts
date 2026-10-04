import { RemoteAuthorizationEvaluator } from '../src/authorization/authorization-evaluator';
import { AuthorizationEvaluationException } from '../src/exceptions/authorization.exceptions';
import type { AuthorizationRequest } from '../src/authorization/authorization.types';

const req: AuthorizationRequest = {
  principal: { id: 'user-123', type: 'USER', authenticated: true },
  action: 'billing:ReadPricing',
  resource: 'rn:cc-api:billing::account-123:Pricing/current',
  accountId: 'account-123',
};

describe('RemoteAuthorizationEvaluator', () => {
  it('maps a successful remote decision', async () => {
    const fetchImpl = jest.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({
          allowed: true,
          reasons: [{ code: 'ALLOWED', message: 'ok' }],
          matchedStatements: ['AllowPricingRead'],
          matchedPolicies: ['BillingPricingRead'],
          evaluatedContexts: ['account:account-123'],
          grantedByContextId: 'account:account-123',
        }),
    });
    const ev = new RemoteAuthorizationEvaluator({
      url: 'http://authz:3100',
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    const d = await ev.evaluate(req);
    expect(d.allowed).toBe(true);
    expect(d.matchedStatements).toContain('AllowPricingRead');
    expect(fetchImpl).toHaveBeenCalledWith(
      'http://authz:3100/v1/authorize',
      expect.objectContaining({ method: 'POST' }),
    );
  });

  it('non-2xx -> AuthorizationEvaluationException (fail closed)', async () => {
    const ev = new RemoteAuthorizationEvaluator({
      url: 'http://authz:3100',
      fetchImpl: jest.fn().mockResolvedValue({ ok: false, status: 503 }) as unknown as typeof fetch,
    });
    await expect(ev.evaluate(req)).rejects.toBeInstanceOf(AuthorizationEvaluationException);
  });

  it('timeout -> AuthorizationEvaluationException (fail closed)', async () => {
    const fetchImpl = jest.fn().mockImplementation(
      (_u: string, init?: RequestInit) =>
        new Promise((_r, reject) => {
          init?.signal?.addEventListener('abort', () => {
            const e = new Error('aborted');
            e.name = 'AbortError';
            reject(e);
          });
        }),
    );
    const ev = new RemoteAuthorizationEvaluator({
      url: 'http://authz:3100',
      timeoutMs: 10,
      fetchImpl: fetchImpl as unknown as typeof fetch,
    });
    await expect(ev.evaluate(req)).rejects.toBeInstanceOf(AuthorizationEvaluationException);
  });

  it('network error -> AuthorizationEvaluationException (fail closed)', async () => {
    const ev = new RemoteAuthorizationEvaluator({
      url: 'http://authz:3100',
      fetchImpl: jest.fn().mockRejectedValue(new Error('ECONNREFUSED')) as unknown as typeof fetch,
    });
    await expect(ev.evaluate(req)).rejects.toBeInstanceOf(AuthorizationEvaluationException);
  });

  it('missing url -> configuration-time error', () => {
    expect(() => new RemoteAuthorizationEvaluator({ url: '' })).toThrow();
  });
});
