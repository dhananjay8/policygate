import { Injectable } from '@nestjs/common';
import type { AuthorizationDecisionLog } from '../authorization/authorization.types';

/**
 * Metrics sink for authorization outcomes. Replaceable with a Prometheus /
 * OTel implementation without touching the engine.
 *
 * Canonical counters/gauges:
 *   authorization_requests_total
 *   authorization_allowed_total
 *   authorization_denied_total
 *   authorization_errors_total
 *   authorization_evaluation_duration_ms
 */
export interface AuthorizationMetrics {
  record(decision: AuthorizationDecisionLog): void;
}

@Injectable()
export class InMemoryAuthorizationMetrics implements AuthorizationMetrics {
  private requests = 0;
  private allowed = 0;
  private denied = 0;
  private errors = 0;
  private durations: number[] = [];

  record(decision: AuthorizationDecisionLog): void {
    this.requests += 1;
    if (decision.decision === 'ALLOW') this.allowed += 1;
    else if (decision.decision === 'DENY') this.denied += 1;
    else this.errors += 1;
    this.durations.push(decision.durationMs);
  }

  snapshot() {
    const sorted = [...this.durations].sort((a, b) => a - b);
    const pct = (p: number) =>
      sorted.length === 0
        ? 0
        : sorted[Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)];
    return {
      authorization_requests_total: this.requests,
      authorization_allowed_total: this.allowed,
      authorization_denied_total: this.denied,
      authorization_errors_total: this.errors,
      authorization_evaluation_duration_ms: { p50: pct(50), p95: pct(95), p99: pct(99) },
    };
  }
}
