import { Inject, Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import type {
  AuthorizationDecision,
  AuthorizationDecisionLog,
  AuthorizationRequest,
  Principal,
} from './authorization.types';
import {
  AUTHORIZATION_EVALUATOR,
  AUTHORIZATION_METRICS,
  AUTHORIZATION_OPTIONS,
  DECISION_LOGGER,
} from './authorization.constants';
import type { AuthorizationEvaluator } from './authorization-evaluator';
import type { AuthorizationDecisionLogger } from '../logging/decision-logger';
import type { AuthorizationMetrics } from '../metrics/authorization-metrics';
import type { AuthorizationRuntimeOptions } from './authorization.options';
import {
  AuthorizationDeniedException,
  AuthorizationEvaluationException,
} from '../exceptions/authorization.exceptions';

/**
 * Public API of the package. Internally delegates to the configured
 * AuthorizationEvaluator (local or remote) — consumers never see
 * PRP/PIP/PDP.
 */
@Injectable()
export class AuthorizationService {
  constructor(
    @Inject(AUTHORIZATION_EVALUATOR) private readonly evaluator: AuthorizationEvaluator,
    @Inject(DECISION_LOGGER) private readonly decisionLogger: AuthorizationDecisionLogger,
    @Inject(AUTHORIZATION_METRICS) private readonly metrics: AuthorizationMetrics,
    @Inject(AUTHORIZATION_OPTIONS)
    private readonly options: AuthorizationRuntimeOptions = {},
  ) {}

  /** Evaluate a single authorization request and log the decision. */
  async evaluate(request: AuthorizationRequest): Promise<AuthorizationDecision> {
    const started = process.hrtime.bigint();
    const authorizationId = randomUUID();
    let decision: AuthorizationDecision | undefined;
    let error: unknown;
    try {
      decision = await this.evaluator.evaluate(request);
      return decision;
    } catch (err) {
      error = err;
      throw err;
    } finally {
      const durationMs = Number(process.hrtime.bigint() - started) / 1e6;
      await this.emitLog(request, decision, error, durationMs, authorizationId);
    }
  }

  /**
   * authorize() -> boolean. Throws AuthorizationDeniedException when denied
   * and AuthorizationEvaluationException on infrastructure failure.
   */
  async authorize(request: AuthorizationRequest): Promise<boolean> {
    const decision = await this.evaluate(request);
    if (!decision.allowed) {
      throw new AuthorizationDeniedException([
        { action: request.action, resource: request.resource },
      ]);
    }
    return true;
  }

  /**
   * Feature gating via the SAME policy engine. A feature is just an action
   * (`feature:Enable<Name>`) against a features resource scoped to an account.
   */
  async isFeatureEnabled(
    principal: Principal,
    featureName: string,
    accountId?: string,
  ): Promise<boolean> {
    const resource = this.buildFeatureResource(featureName, accountId);
    const request: AuthorizationRequest = {
      principal,
      action: `feature:Enable${featureName}`,
      resource,
      accountId,
      variables: {
        'cc:accountId': accountId,
        'cc:featureName': featureName,
        'cc:principalId': principal.id,
      },
    };
    try {
      const decision = await this.evaluate(request);
      return decision.allowed;
    } catch (err) {
      // Feature checks fail closed to "disabled", but evaluation failures
      // still surface as errors so operators can detect broken pipelines.
      if (err instanceof AuthorizationEvaluationException) throw err;
      return false;
    }
  }

  private buildFeatureResource(featureName: string, accountId?: string): string {
    const template =
      this.options.featureGating?.resourceTemplate ??
      'rn:cc-api:billing::${cc:accountId}:Features/${cc:featureName}';
    return template
      .replace('${cc:accountId}', accountId ?? 'global')
      .replace('${cc:featureName}', featureName);
  }

  private async emitLog(
    request: AuthorizationRequest,
    decision: AuthorizationDecision | undefined,
    error: unknown,
    durationMs: number,
    authorizationId: string,
  ): Promise<void> {
    const log: AuthorizationDecisionLog = {
      timestamp: new Date().toISOString(),
      principalId: request.principal.id,
      principalType: request.principal.type,
      authenticated: request.principal.authenticated,
      accountId: request.accountId,
      action: request.action,
      resource: request.resource,
      decision: decision ? (decision.allowed ? 'ALLOW' : 'DENY') : 'ERROR',
      reasons: decision?.reasons.map((r) => r.code) ?? [],
      matchedPolicies: decision?.matchedPolicies ?? [],
      matchedStatements: decision?.matchedStatements ?? [],
      durationMs: Math.round(durationMs * 1000) / 1000,
      correlationId: (request.requestContext?.correlationId as string | undefined) ?? undefined,
      authorizationId,
      serviceName: this.options.serviceName,
    };
    if (error && !decision) {
      log.reasons = ['DEFAULT_DENY'];
    }
    if (!decision?.allowed) {
      // Explainability: the specific action/resource check that failed,
      // so denied requests never reduce to a generic 403.
      log.failedChecks = [{ action: request.action, resource: request.resource }];
    }
    try {
      this.metrics.record(log);
      if (this.options.logging?.enabled !== false) {
        await this.decisionLogger.log(log);
      }
    } catch {
      // Logging must never break authorization, but it also never grants.
    }
  }
}
