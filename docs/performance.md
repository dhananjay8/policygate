# Performance

## Design

- The PDP is **pure**: no DB/network/Redis calls. PRP/PIP do the I/O once
  per request and hand materialized contexts to the PDP.
- **No caching** — every request evaluates current policy state, so
  revocations take effect immediately.
- Matching is anchored, segment-aware regex over plain strings; statement
  evaluation short-circuits on the first mismatching dimension
  (action → resource → conditions).

## Benchmarks

Run: `npm run bench`

Measured on Apple Silicon (Node 22, single context, 2000 iterations after
200 warmup), pure `DefaultPolicyDecisionPoint.evaluate` — no I/O:

| Policies per context | p50      | p95      | p99      |
| -------------------- | -------- | -------- | -------- |
| 100                  | 0.129 ms | 0.185 ms | 0.214 ms |
| 500                  | 0.658 ms | 0.766 ms | 0.837 ms |
| 1,000                | 1.334 ms | 1.464 ms | 1.515 ms |
| 5,000                | 6.959 ms | 7.250 ms | 7.513 ms |

Evaluation scales linearly with policy count (~1.4 µs/policy), as expected
for sequential statement matching. If a context routinely carries thousands
of policies, partition policies by domain in the PIP so the PDP scans less.

Reproduce: `npm run bench` (source: `benchmarks/pdp.bench.ts`).

## Adding a cache later

Wrap `AUTHORIZATION_EVALUATOR` with a `ScopedAuthorizationCache`
implementation (TTL + explicit invalidation on policy writes) without
touching guards, decorators, the PDP, or controllers. Do not cache
decisions for sensitive writes unless revocation propagation is
synchronous and provably shorter than the cache TTL.
