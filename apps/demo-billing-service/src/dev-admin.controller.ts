import { Controller, Get, Inject, Param, Post } from '@nestjs/common';
import { AUTHORIZATION_METRICS, InMemoryAuthorizationMetrics } from 'policygate';
import { DemoState } from './demo-state';

/**
 * Dev-only administration endpoints (NOT protected by the guard — demo
 * purposes only). Used to demonstrate immediate revocation semantics:
 * no caching means the next request sees the new policy state.
 */
@Controller('/dev')
export class DevAdminController {
  constructor(
    private readonly state: DemoState,
    @Inject(AUTHORIZATION_METRICS)
    private readonly metrics: InMemoryAuthorizationMetrics,
  ) {}

  /** Authorization metrics snapshot (counters + latency percentiles). */
  @Get('/metrics')
  metricsSnapshot() {
    return this.metrics.snapshot();
  }

  /** Remove a policy from a role — effective on the NEXT request. */
  @Post('/roles/:roleId/revoke/:policyId')
  async revoke(@Param('roleId') roleId: string, @Param('policyId') policyId: string) {
    const [role] = await this.state.roles.findByIds([roleId]);
    if (!role) return { ok: false, reason: 'role not found' };
    this.state.roles.save({
      ...role,
      policies: role.policies.filter((p) => p.id !== policyId),
    });
    return { ok: true, roleId, revokedPolicy: policyId };
  }

  /** Restore the demo seed (re-grants revoked policies). */
  @Post('/reset')
  reset() {
    this.state.reset();
    return { ok: true };
  }

  @Get('/roles')
  async roles() {
    const all = await this.state.roles.findByIds([
      'role-billing-operator',
      'role-viewer',
      'role-internal-support',
    ]);
    return all.map((r) => ({ id: r.id, name: r.name, policies: r.policies.map((p) => p.name) }));
  }
}
