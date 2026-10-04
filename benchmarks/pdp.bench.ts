/**
 * PDP microbenchmark: `npm run bench`
 * Measures pure evaluation latency at 100 / 500 / 1000 / 5000 policies
 * per authorization context. PDP does zero I/O — this is CPU-bound matching.
 */
import { DefaultPolicyDecisionPoint } from '../packages/policygate/src/pdp/policy-decision-point';
import type {
  AuthorizationContext,
  AuthorizationRequest,
  Policy,
} from '../packages/policygate/src/authorization/authorization.types';

function makePolicies(n: number): Policy[] {
  const policies: Policy[] = [];
  for (let i = 0; i < n; i++) {
    policies.push({
      id: `p-${i}`,
      name: `Policy${i}`,
      statements: [
        {
          sid: `s-${i}`,
          effect: 'Allow',
          actions: [`billing:ReadPricing`, `billing:Op${i}`],
          resources: [`rn:cc-api:billing::\${cc:accountId}:Pricing/*`, `rn:x:y::z:Other/${i}`],
          conditions: i % 7 === 0 ? { StringEquals: { 'cc:tier': 'gold' } } : undefined,
        },
      ],
    });
  }
  return policies;
}

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  return sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
}

function run(policyCount: number, iterations = 2000) {
  const pdp = new DefaultPolicyDecisionPoint();
  const ctx: AuthorizationContext = {
    contextId: 'account:account-123',
    accountId: 'account-123',
    roles: [],
    policies: makePolicies(policyCount),
  };
  const req: AuthorizationRequest = {
    principal: { id: 'u1', type: 'USER', authenticated: true },
    action: 'billing:ReadPricing',
    resource: 'rn:cc-api:billing::account-123:Pricing/current',
    accountId: 'account-123',
    variables: { 'cc:tier': 'gold' },
  };

  // warmup
  for (let i = 0; i < 200; i++) pdp.evaluate(req, [ctx]);

  const durations: number[] = [];
  for (let i = 0; i < iterations; i++) {
    const t0 = process.hrtime.bigint();
    pdp.evaluate(req, [ctx]);
    durations.push(Number(process.hrtime.bigint() - t0) / 1e3); // microseconds
  }
  durations.sort((a, b) => a - b);
  const fmt = (us: number) => `${(us / 1000).toFixed(3)}ms`;
  console.log(
    `policies=${String(policyCount).padStart(4)}  iters=${iterations}  ` +
      `p50=${fmt(percentile(durations, 50))}  ` +
      `p95=${fmt(percentile(durations, 95))}  ` +
      `p99=${fmt(percentile(durations, 99))}`,
  );
}

for (const n of [100, 500, 1000, 5000]) run(n);
