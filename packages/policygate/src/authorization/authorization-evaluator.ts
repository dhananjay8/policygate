import { Inject, Injectable } from '@nestjs/common';
import type {
  AuthorizationDecision,
  AuthorizationRequest,
  AuthorizationRequestContext,
} from './authorization.types';
import {
  POLICY_DECISION_POINT,
  POLICY_INFORMATION_POINT,
  POLICY_RETRIEVAL_POINT,
} from './authorization.constants';
import type { PolicyRetrievalPoint } from '../prp/policy-retrieval-point';
import type { PolicyInformationPoint } from '../pip/policy-information-point';
import type { PolicyDecisionPoint } from '../pdp/policy-decision-point';
import { AuthorizationEvaluationException } from '../exceptions/authorization.exceptions';

/** Transport-agnostic authorization decision engine used by the guard. */
export interface AuthorizationEvaluator {
  evaluate(request: AuthorizationRequest): Promise<AuthorizationDecision>;
}

/**
 * Embeds PRP -> PIP -> PDP inside the consuming service's process.
 * No caching: every call retrieves current policy state.
 */
@Injectable()
export class LocalAuthorizationEvaluator implements AuthorizationEvaluator {
  constructor(
    @Inject(POLICY_RETRIEVAL_POINT) private readonly prp: PolicyRetrievalPoint,
    @Inject(POLICY_INFORMATION_POINT) private readonly pip: PolicyInformationPoint,
    @Inject(POLICY_DECISION_POINT) private readonly pdp: PolicyDecisionPoint,
  ) {}

  async evaluate(request: AuthorizationRequest): Promise<AuthorizationDecision> {
    const requestContext: AuthorizationRequestContext = {
      accountId: request.accountId,
      variables: request.variables ?? {},
      requestContext: request.requestContext,
    };
    const retrieval = await this.prp.retrieve(request.principal, requestContext);
    const contexts = await this.pip.buildEvaluationContexts(retrieval);
    return this.pdp.evaluate(request, contexts);
  }
}

/** Wire shape for POST {evaluatorUrl}/v1/authorize. */
export interface RemoteAuthorizeResponse {
  allowed: boolean;
  reasons?: { code: string; message: string; contextId?: string }[];
  evaluatedContexts?: string[];
  matchedStatements?: string[];
  matchedPolicies?: string[];
  grantedByContextId?: string;
}

export interface RemoteEvaluatorOptions {
  /** Base URL of the authorization service, e.g. http://authorization-service:3100 */
  url: string;
  /** Abort timeout per evaluation call (ms). Default 2000. */
  timeoutMs?: number;
  /** Optional static bearer token for service-to-service auth. */
  serviceToken?: string;
  /** Injectable fetch for testing. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
}

/**
 * Calls a centralized authorization service. Any transport failure maps to
 * AuthorizationEvaluationException — never to `allowed`.
 */
@Injectable()
export class RemoteAuthorizationEvaluator implements AuthorizationEvaluator {
  private readonly url: string;
  private readonly timeoutMs: number;
  private readonly serviceToken?: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: RemoteEvaluatorOptions) {
    if (!options.url) {
      throw new AuthorizationEvaluationException(
        'RemoteAuthorizationEvaluator requires a non-empty evaluator url',
      );
    }
    this.url = options.url.replace(/\/$/, '');
    this.timeoutMs = options.timeoutMs ?? 2000;
    this.serviceToken = options.serviceToken;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  async evaluate(request: AuthorizationRequest): Promise<AuthorizationDecision> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const res = await this.fetchImpl(`${this.url}/v1/authorize`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(this.serviceToken ? { authorization: `Bearer ${this.serviceToken}` } : {}),
        },
        body: JSON.stringify(request),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new AuthorizationEvaluationException(
          `Remote authorization evaluator returned HTTP ${res.status}`,
        );
      }
      const body = (await res.json()) as RemoteAuthorizeResponse;
      return {
        allowed: body.allowed === true,
        reasons: (body.reasons ?? []).map((r) => ({
          code: r.code as AuthorizationDecision['reasons'][number]['code'],
          message: r.message,
          contextId: r.contextId,
        })),
        evaluatedContexts: body.evaluatedContexts ?? [],
        matchedStatements: body.matchedStatements ?? [],
        matchedPolicies: body.matchedPolicies ?? [],
        grantedByContextId: body.grantedByContextId,
      };
    } catch (err) {
      if (err instanceof AuthorizationEvaluationException) throw err;
      const isTimeout = err instanceof Error && err.name === 'AbortError';
      throw new AuthorizationEvaluationException(
        isTimeout
          ? `Remote authorization evaluator timed out after ${this.timeoutMs}ms`
          : 'Remote authorization evaluator unavailable',
        err,
      );
    } finally {
      clearTimeout(timer);
    }
  }
}
