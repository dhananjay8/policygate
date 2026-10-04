import { Inject, Injectable } from '@nestjs/common';
import type {
  AuthorizationContext,
  Policy,
  PolicyRetrievalResult,
  Role,
} from '../authorization/authorization.types';
import { POLICY_REPOSITORY, ROLE_REPOSITORY } from '../authorization/authorization.constants';
import type { PolicyRepository, RoleRepository } from '../adapters/repositories';
import { AuthorizationEvaluationException } from '../exceptions/authorization.exceptions';

export interface PolicyInformationPoint {
  buildEvaluationContexts(retrievalResult: PolicyRetrievalResult): Promise<AuthorizationContext[]>;
}

/**
 * Materializes raw scopes from the PRP into fully expanded
 * AuthorizationContexts: role -> policies (many-to-many), plus direct
 * policies. Account boundaries are preserved — each context is evaluated
 * independently by the PDP. internalAgentOnly roles are structurally
 * stripped for non-AGENT principals as defense-in-depth.
 */
@Injectable()
export class DefaultPolicyInformationPoint implements PolicyInformationPoint {
  constructor(
    @Inject(ROLE_REPOSITORY) private readonly roles: RoleRepository,
    @Inject(POLICY_REPOSITORY) private readonly policies: PolicyRepository,
  ) {}

  async buildEvaluationContexts(
    retrievalResult: PolicyRetrievalResult,
  ): Promise<AuthorizationContext[]> {
    const { principal, scopes } = retrievalResult;
    try {
      // Deduplicate lookups across scopes.
      const allRoleIds = new Set<string>();
      const allPolicyIds = new Set<string>();
      for (const s of scopes) {
        s.roleIds.forEach((id) => allRoleIds.add(id));
        s.directPolicyIds.forEach((id) => allPolicyIds.add(id));
      }
      const [roles, directPolicies] = await Promise.all([
        this.roles.findByIds([...allRoleIds]),
        this.policies.findByIds([...allPolicyIds]),
      ]);
      const roleById = new Map(roles.map((r) => [r.id, r]));
      const policyById = new Map(directPolicies.map((p) => [p.id, p]));

      return scopes.map((scope) => {
        const scopedRoles = scope.roleIds
          .map((id) => roleById.get(id))
          .filter((r): r is Role => r !== undefined)
          .filter((r) => !r.internalAgentOnly || principal.type === 'AGENT');

        const scopedPolicies = new Map<string, Policy>();
        for (const role of scopedRoles) {
          for (const p of role.policies) scopedPolicies.set(p.id, p);
        }
        for (const id of scope.directPolicyIds) {
          const p = policyById.get(id);
          if (p) scopedPolicies.set(p.id, p);
        }

        return {
          contextId: scope.contextId,
          accountId: scope.accountId,
          roles: scopedRoles,
          policies: [...scopedPolicies.values()],
        };
      });
    } catch (err) {
      if (err instanceof AuthorizationEvaluationException) throw err;
      throw new AuthorizationEvaluationException('Policy information resolution failed', err);
    }
  }
}
