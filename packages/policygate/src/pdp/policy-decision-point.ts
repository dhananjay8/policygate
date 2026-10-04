import { Inject, Injectable } from '@nestjs/common';
import type {
  AuthorizationContext,
  AuthorizationDecision,
  AuthorizationReason,
  AuthorizationRequest,
  AuthorizationVariables,
  PolicyStatement,
} from '../authorization/authorization.types';
import { CONDITION_EVALUATOR, VARIABLE_RESOLVER } from '../authorization/authorization.constants';
import type { ConditionEvaluator } from '../conditions/condition-evaluator';
import { DefaultConditionEvaluator } from '../conditions/condition-evaluator';
import type { VariableResolver } from '../variables/variable-resolver';
import { DefaultVariableResolver } from '../variables/variable-resolver';
import { matchAnyPattern } from '../resources/pattern-matcher';

export interface PolicyDecisionPoint {
  evaluate(request: AuthorizationRequest, contexts: AuthorizationContext[]): AuthorizationDecision;
}

/**
 * Pure, deterministic, side-effect-free evaluator.
 * Performs NO database/network/cache calls — PRP/PIP supply fully
 * materialized contexts; the PDP only matches action/resource/conditions.
 *
 * Rules:
 *  1. No applicable Allow  -> DENY (default deny)
 *  2. Any applicable Deny  -> DENY (explicit deny wins, across all contexts)
 *  3. Allowed only if at least one context independently grants access
 *     AND that context matches the requested account scope.
 */
@Injectable()
export class DefaultPolicyDecisionPoint implements PolicyDecisionPoint {
  constructor(
    @Inject(VARIABLE_RESOLVER)
    private readonly variableResolver: VariableResolver = new DefaultVariableResolver(),
    @Inject(CONDITION_EVALUATOR)
    private readonly conditionEvaluator: ConditionEvaluator = new DefaultConditionEvaluator(),
  ) {}

  evaluate(request: AuthorizationRequest, contexts: AuthorizationContext[]): AuthorizationDecision {
    const reasons: AuthorizationReason[] = [];
    const evaluatedContexts: string[] = [];
    const matchedStatements = new Set<string>();
    const matchedPolicies = new Set<string>();
    const denyReasons: AuthorizationReason[] = [];
    let grantingContext: string | undefined;

    const applicable = this.applicableContexts(request, contexts);
    if (applicable.length === 0) {
      reasons.push({
        code: 'NO_APPLICABLE_CONTEXT',
        message: request.accountId
          ? `Principal has no authorization context for account '${request.accountId}'`
          : 'No authorization contexts available for principal',
      });
    }

    for (const ctx of applicable) {
      evaluatedContexts.push(ctx.contextId);
      const vars = this.contextVariables(request, ctx);
      let contextAllowed = false;
      let contextDenied = false;

      for (const policy of ctx.policies) {
        for (const stmt of policy.statements) {
          const result = this.matchStatement(stmt, request, vars);
          if (!result.matched) continue;

          const sid = stmt.sid ?? `${policy.name}#stmt`;
          matchedStatements.add(sid);
          matchedPolicies.add(policy.name);

          if (stmt.effect === 'Deny') {
            contextDenied = true;
            denyReasons.push({
              code: 'EXPLICIT_DENY',
              message: `Explicitly denied by statement '${sid}' in policy '${policy.name}'`,
              contextId: ctx.contextId,
            });
          } else {
            contextAllowed = true;
          }
        }
      }

      if (contextDenied) continue;
      if (contextAllowed && grantingContext === undefined) {
        grantingContext = ctx.contextId;
      }
    }

    if (denyReasons.length > 0) {
      return {
        allowed: false,
        reasons: denyReasons,
        evaluatedContexts,
        matchedStatements: [...matchedStatements],
        matchedPolicies: [...matchedPolicies],
      };
    }

    if (grantingContext !== undefined) {
      reasons.push({
        code: 'ALLOWED',
        message: `Granted by context '${grantingContext}'`,
        contextId: grantingContext,
      });
      return {
        allowed: true,
        reasons,
        evaluatedContexts,
        matchedStatements: [...matchedStatements],
        matchedPolicies: [...matchedPolicies],
        grantedByContextId: grantingContext,
      };
    }

    if (reasons.length === 0 || reasons.every((r) => r.code !== 'NO_APPLICABLE_CONTEXT')) {
      reasons.push({ code: 'DEFAULT_DENY', message: 'No applicable Allow statement matched' });
    }
    return {
      allowed: false,
      reasons,
      evaluatedContexts,
      matchedStatements: [...matchedStatements],
      matchedPolicies: [...matchedPolicies],
    };
  }

  /**
   * If the request carries an accountId, ONLY the context for that account
   * may authorize it — an account-123 grant can never authorize an
   * account-456 resource. Requests without accountId may be granted by any
   * context (e.g. principal-scoped service policies).
   */
  private applicableContexts(
    request: AuthorizationRequest,
    contexts: AuthorizationContext[],
  ): AuthorizationContext[] {
    if (request.accountId === undefined) return contexts;
    return contexts.filter((c) => c.accountId === request.accountId);
  }

  /** Variables visible to this context. Server-side context wins over client input. */
  private contextVariables(
    request: AuthorizationRequest,
    ctx: AuthorizationContext,
  ): AuthorizationVariables {
    const vars: AuthorizationVariables = {
      ...(request.variables ?? {}),
      'cc:principalId': request.principal.id,
      'cc:principalType': request.principal.type,
    };
    if (request.requestContext) {
      for (const [k, v] of Object.entries(request.requestContext)) {
        vars[`cc:request:${k}`] = v;
      }
    }
    // Trusted context: the account of THIS evaluation context, never raw client input.
    if (ctx.accountId !== undefined) vars['cc:accountId'] = ctx.accountId;
    return vars;
  }

  private matchStatement(
    stmt: PolicyStatement,
    request: AuthorizationRequest,
    vars: AuthorizationVariables,
  ): { matched: boolean } {
    if (!matchAnyPattern(stmt.actions, request.action)) return { matched: false };

    const resolvedResources = stmt.resources.map((r) => this.variableResolver.resolve(r, vars));
    if (!matchAnyPattern(resolvedResources, request.resource)) return { matched: false };

    if (!this.conditionEvaluator.evaluate(stmt.conditions, vars)) return { matched: false };

    return { matched: true };
  }
}
