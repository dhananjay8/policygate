import { Inject, Injectable } from '@nestjs/common';
import type {
  AuthorizationRequestContext,
  PolicyRetrievalResult,
  Principal,
  ScopedPolicySet,
} from '../authorization/authorization.types';
import {
  DIRECT_POLICY_REPOSITORY,
  MEMBERSHIP_REPOSITORY,
  ROLE_REPOSITORY,
} from '../authorization/authorization.constants';
import type {
  DirectPolicyRepository,
  MembershipRepository,
  RoleRepository,
} from '../adapters/repositories';
import { AuthorizationEvaluationException } from '../exceptions/authorization.exceptions';

export interface PolicyRetrievalPoint {
  retrieve(
    principal: Principal,
    requestContext: AuthorizationRequestContext,
  ): Promise<PolicyRetrievalResult>;
}

/**
 * Resolves which scopes the principal may be evaluated under.
 *
 * Produces ONE ScopedPolicySet per account membership — permissions are
 * never merged across accounts — plus one principal-scoped set for
 * directly-attached policies (service/API principals) and system-default
 * roles. Role flag rules (systemDefault / unauthenticatedSystemDefault /
 * internalAgentOnly) are enforced here, structurally.
 */
@Injectable()
export class DefaultPolicyRetrievalPoint implements PolicyRetrievalPoint {
  constructor(
    @Inject(MEMBERSHIP_REPOSITORY)
    private readonly memberships: MembershipRepository,
    @Inject(DIRECT_POLICY_REPOSITORY)
    private readonly directPolicies: DirectPolicyRepository,
    @Inject(ROLE_REPOSITORY)
    private readonly roles: RoleRepository,
  ) {}

  async retrieve(
    principal: Principal,
    _requestContext: AuthorizationRequestContext,
  ): Promise<PolicyRetrievalResult> {
    try {
      const scopes: ScopedPolicySet[] = [];

      if (principal.authenticated) {
        const [memberships, directPolicyIds, systemDefaults] = await Promise.all([
          this.memberships.findByPrincipalId(principal.id),
          this.directPolicies.findByPrincipalId(principal.id),
          this.roles.findSystemDefaults(),
        ]);

        const internalAgent = principal.type === 'AGENT';
        const allowedSystemDefaults = systemDefaults
          .filter((r) => !r.internalAgentOnly || internalAgent)
          .map((r) => r.id);

        for (const m of memberships) {
          scopes.push({
            contextId: `account:${m.accountId}`,
            accountId: m.accountId,
            roleIds: [...m.roleIds, ...allowedSystemDefaults],
            directPolicyIds: [],
          });
        }

        // Principal-level scope: directly attached policies + system defaults.
        if (directPolicyIds.length > 0 || allowedSystemDefaults.length > 0) {
          scopes.push({
            contextId: `principal:${principal.id}`,
            roleIds: allowedSystemDefaults,
            directPolicyIds,
          });
        }
      } else {
        const unauthenticatedDefaults = await this.roles.findUnauthenticatedDefaults();
        const allowed = unauthenticatedDefaults
          .filter((r) => !r.internalAgentOnly)
          .map((r) => r.id);
        if (allowed.length > 0) {
          scopes.push({
            contextId: `unauthenticated:${principal.id}`,
            roleIds: allowed,
            directPolicyIds: [],
          });
        }
      }

      return { principal, scopes };
    } catch (err) {
      if (err instanceof AuthorizationEvaluationException) throw err;
      throw new AuthorizationEvaluationException('Policy retrieval failed', err);
    }
  }
}
