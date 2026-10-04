import { Controller, Get, Param, Post } from '@nestjs/common';
import {
  AuthzPrincipal,
  AuthorizationService,
  type Principal,
  RequirePermission,
} from 'policygate';

@Controller()
export class BillingController {
  constructor(private readonly authorization: AuthorizationService) {}

  @Get('/health')
  health(): { status: string } {
    return { status: 'ok' };
  }

  /**
   * Demonstrates unauthenticatedSystemDefault + systemDefault policies:
   * the PublicHealth role (unauthenticated default) and AuthenticatedBaseline
   * (system default) both carry the PublicHealthRead policy, so this
   * endpoint is reachable pre-login AND post-login — through the same
   * policy engine, not a guard bypass.
   */
  @RequirePermission({
    action: 'system:ReadHealth',
    resource: 'rn:cc-api:system::global:Health/status',
  })
  @Get('/health/details')
  healthDetails() {
    return { status: 'ok', authorizedBy: 'PublicHealthRead' };
  }

  @RequirePermission({
    action: 'billing:ReadPricing',
    resource: 'rn:cc-api:billing::${cc:accountId}:Pricing/*',
  })
  @Get('/accounts/:accountId/pricing')
  getPricing(@Param('accountId') accountId: string) {
    return { accountId, pricing: [{ sku: 'pro', price: 99 }] };
  }

  @RequirePermission({
    action: 'billing:ReadInvoices',
    resource: 'rn:cc-api:billing::${cc:accountId}:Invoices/*',
  })
  @Get('/accounts/:accountId/invoices')
  getInvoices(@Param('accountId') accountId: string) {
    return { accountId, invoices: [] };
  }

  @RequirePermission({
    action: 'billing:CreateRefund',
    resource: 'rn:cc-api:billing::${cc:accountId}:Refunds/*',
  })
  @Post('/accounts/:accountId/refunds')
  createRefund(@Param('accountId') accountId: string) {
    return { accountId, refundId: 'ref-1', status: 'created' };
  }

  /**
   * Service-principal path: svc-reporting authenticates via `x-api-key`,
   * has NO membership — only a directly-attached ServiceReportingRead
   * policy on an account-agnostic resource. This exercises the
   * "agent/service -> roles + direct policies" branch of the model.
   */
  @RequirePermission({
    action: 'service:ReadReports',
    resource: 'rn:cc-api:billing::global:Reports/*',
  })
  @Get('/reports')
  getReports(@AuthzPrincipal() principal: Principal) {
    return { reports: [{ id: 'monthly-rollup', principal: principal.id }] };
  }

  /**
   * Feature gate: evaluated by the SAME policy engine via
   * `feature:Enable<Name>` + Features/<Name> resource. The guard itself
   * performs the check (action/resource interpolate :featureName).
   */
  @RequirePermission({
    action: 'feature:Enable${cc:featureName}',
    resource: 'rn:cc-api:billing::${cc:accountId}:Features/${cc:featureName}',
  })
  @Get('/accounts/:accountId/features/:featureName')
  async getFeature(
    @Param('accountId') accountId: string,
    @Param('featureName') featureName: string,
    @AuthzPrincipal() principal: Principal,
  ) {
    const enabled = await this.authorization.isFeatureEnabled(principal, featureName, accountId);
    return { accountId, feature: featureName, enabled };
  }
}
