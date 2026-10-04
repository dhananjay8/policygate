import type { Membership, Policy, Principal, Role } from '../authorization/authorization.types';

/**
 * Demo/dev fixtures implementing the scenario from the spec:
 *   user-123 -> account-123 (BillingOperator: PricingRead + Refund + NewBillingUI)
 *           -> account-456 (Viewer: InvoiceRead only)
 *   agent-ops -> account-123 (InternalSupport: internalAgentOnly)
 *   svc-reporting -> direct policy (SERVICE principal, no membership)
 */
export interface DemoSeed {
  principals: Principal[];
  memberships: Membership[];
  roles: Role[];
  policies: Policy[];
  directPolicies: Record<string, string[]>;
}

export const POLICY_IDS = {
  pricingRead: 'policy-billing-pricing-read',
  invoiceRead: 'policy-billing-invoice-read',
  refund: 'policy-billing-refund',
  featureNewBillingUI: 'policy-feature-new-billing-ui',
  internalAudit: 'policy-internal-audit',
  healthRead: 'policy-health-read',
  reportingRead: 'policy-service-reporting-read',
} as const;

export const ROLE_IDS = {
  billingOperator: 'role-billing-operator',
  viewer: 'role-viewer',
  internalSupport: 'role-internal-support',
  authenticatedBaseline: 'role-authenticated-baseline',
  publicHealth: 'role-public-health',
} as const;

export function demoPolicies(): Policy[] {
  return [
    {
      id: POLICY_IDS.pricingRead,
      name: 'BillingPricingRead',
      statements: [
        {
          sid: 'AllowPricingRead',
          effect: 'Allow',
          actions: ['billing:ReadPricing'],
          resources: ['rn:cc-api:billing::${cc:accountId}:Pricing/*'],
        },
      ],
    },
    {
      id: POLICY_IDS.invoiceRead,
      name: 'BillingInvoiceRead',
      statements: [
        {
          sid: 'AllowInvoiceRead',
          effect: 'Allow',
          actions: ['billing:ReadInvoices'],
          resources: ['rn:cc-api:billing::${cc:accountId}:Invoices/*'],
        },
      ],
    },
    {
      id: POLICY_IDS.refund,
      name: 'BillingRefund',
      statements: [
        {
          sid: 'AllowRefund',
          effect: 'Allow',
          actions: ['billing:CreateRefund'],
          resources: ['rn:cc-api:billing::${cc:accountId}:Refunds/*'],
        },
      ],
    },
    {
      id: POLICY_IDS.featureNewBillingUI,
      name: 'NewBillingUIFeature',
      statements: [
        {
          sid: 'EnableNewBillingUI',
          effect: 'Allow',
          actions: ['feature:EnableNewBillingUI'],
          resources: ['rn:cc-api:billing::${cc:accountId}:Features/NewBillingUI'],
        },
      ],
    },
    {
      id: POLICY_IDS.internalAudit,
      name: 'InternalAuditRead',
      statements: [
        {
          sid: 'AllowInternalAudit',
          effect: 'Allow',
          actions: ['internal:ReadAudit'],
          resources: ['rn:cc-api:billing::${cc:accountId}:Audit/*'],
        },
      ],
    },
    {
      id: POLICY_IDS.healthRead,
      name: 'PublicHealthRead',
      statements: [
        {
          sid: 'AllowHealthRead',
          effect: 'Allow',
          actions: ['system:ReadHealth'],
          resources: ['rn:cc-api:system::*:Health/status'],
        },
      ],
    },
    {
      id: POLICY_IDS.reportingRead,
      name: 'ServiceReportingRead',
      statements: [
        {
          sid: 'AllowServiceReports',
          effect: 'Allow',
          actions: ['service:ReadReports'],
          // Account-agnostic: the principal-scoped (direct-policy) context
          // has no accountId, so account-scoped rns can never be authorized
          // by a service principal's direct policies.
          resources: ['rn:cc-api:billing::global:Reports/*'],
        },
      ],
    },
  ];
}

export function demoRoles(policies: Policy[]): Role[] {
  const byId = new Map(policies.map((p) => [p.id, p]));
  const pick = (...ids: string[]) =>
    ids.map((id) => byId.get(id)).filter((p): p is Policy => p !== undefined);

  return [
    {
      id: ROLE_IDS.billingOperator,
      name: 'BillingOperator',
      systemDefault: false,
      unauthenticatedSystemDefault: false,
      internalAgentOnly: false,
      policies: pick(POLICY_IDS.pricingRead, POLICY_IDS.refund, POLICY_IDS.featureNewBillingUI),
    },
    {
      id: ROLE_IDS.viewer,
      name: 'Viewer',
      systemDefault: false,
      unauthenticatedSystemDefault: false,
      internalAgentOnly: false,
      policies: pick(POLICY_IDS.invoiceRead),
    },
    {
      id: ROLE_IDS.internalSupport,
      name: 'InternalSupport',
      systemDefault: false,
      unauthenticatedSystemDefault: false,
      internalAgentOnly: true,
      policies: pick(POLICY_IDS.internalAudit),
    },
    {
      id: ROLE_IDS.authenticatedBaseline,
      name: 'AuthenticatedBaseline',
      systemDefault: true,
      unauthenticatedSystemDefault: false,
      internalAgentOnly: false,
      policies: pick(POLICY_IDS.healthRead),
    },
    {
      id: ROLE_IDS.publicHealth,
      name: 'PublicHealth',
      systemDefault: false,
      unauthenticatedSystemDefault: true,
      internalAgentOnly: false,
      policies: pick(POLICY_IDS.healthRead),
    },
  ];
}

export function buildDemoSeed(): DemoSeed {
  const policies = demoPolicies();
  const roles = demoRoles(policies);
  return {
    principals: [
      { id: 'user-123', type: 'USER', authenticated: true },
      { id: 'agent-ops', type: 'AGENT', authenticated: true },
      { id: 'svc-reporting', type: 'SERVICE', authenticated: true },
    ],
    memberships: [
      { principalId: 'user-123', accountId: 'account-123', roleIds: [ROLE_IDS.billingOperator] },
      { principalId: 'user-123', accountId: 'account-456', roleIds: [ROLE_IDS.viewer] },
      { principalId: 'agent-ops', accountId: 'account-123', roleIds: [ROLE_IDS.internalSupport] },
    ],
    roles,
    policies,
    directPolicies: {
      // Directly-attached policies only — no membership. The invoice policy
      // is account-scoped (${cc:accountId} can never resolve in a principal
      // context) so it grants nothing; ReportingRead is account-agnostic.
      'svc-reporting': [POLICY_IDS.invoiceRead, POLICY_IDS.reportingRead],
    },
  };
}
