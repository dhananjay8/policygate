import type { Type } from '@nestjs/common';
import type { EvaluationMode } from './authorization.types';
import type { PrincipalResolver } from '../authentication/principal-resolver';
import type { AccountContextResolver } from '../guard/account-context-resolver';
import type { PolicyRetrievalPoint } from '../prp/policy-retrieval-point';
import type { PolicyInformationPoint } from '../pip/policy-information-point';
import type { PolicyDecisionPoint } from '../pdp/policy-decision-point';
import type { VariableResolver } from '../variables/variable-resolver';
import type { ConditionEvaluator } from '../conditions/condition-evaluator';
import type { AuthorizationDecisionLogger } from '../logging/decision-logger';
import type { AuthorizationMetrics } from '../metrics/authorization-metrics';
import type {
  DirectPolicyRepository,
  MembershipRepository,
  PolicyRepository,
  PrincipalRepository,
  RoleRepository,
} from '../adapters/repositories';
import type { RemoteEvaluatorOptions } from './authorization-evaluator';

/**
 * Module configuration. Any adapter may be replaced without modifying the
 * core engine — supply an instance or a provider `useClass`.
 */
export interface AuthorizationModuleOptions {
  /** 'local' embeds PRP/PIP/PDP; 'remote' delegates to a central service. */
  mode: EvaluationMode;

  /** Required: how to turn an incoming request into a normalized Principal. */
  principalResolver: PrincipalResolver | Type<PrincipalResolver>;
  /** Optional: override how the trusted account context is resolved. */
  accountContextResolver?: AccountContextResolver | Type<AccountContextResolver>;

  /** Local-mode repositories. Required when mode='local'. */
  repositories?: {
    roles: RoleRepository | Type<RoleRepository>;
    policies: PolicyRepository | Type<PolicyRepository>;
    memberships: MembershipRepository | Type<MembershipRepository>;
    directPolicies: DirectPolicyRepository | Type<DirectPolicyRepository>;
    principals?: PrincipalRepository | Type<PrincipalRepository>;
  };

  /** Advanced overrides for the pipeline stages. */
  policyRetrievalPoint?: PolicyRetrievalPoint | Type<PolicyRetrievalPoint>;
  policyInformationPoint?: PolicyInformationPoint | Type<PolicyInformationPoint>;
  policyDecisionPoint?: PolicyDecisionPoint | Type<PolicyDecisionPoint>;
  variableResolver?: VariableResolver | Type<VariableResolver>;
  conditionEvaluator?: ConditionEvaluator | Type<ConditionEvaluator>;

  /** Remote mode settings. */
  remote?: RemoteEvaluatorOptions;
  /** Shorthand: remote evaluator URL. */
  evaluatorUrl?: string;

  /** Decision logging. Enabled by default with console logger. */
  logging?: {
    enabled?: boolean;
    logger?: AuthorizationDecisionLogger | Type<AuthorizationDecisionLogger>;
  };
  /** Metrics sink; defaults to in-memory counters. */
  metrics?: AuthorizationMetrics | Type<AuthorizationMetrics>;

  /**
   * Fail-closed is always on. When failClosed=true (default) evaluation
   * failures produce 500s; when explicitly set false they produce 403s.
   * Neither ever grants access.
   */
  failClosed?: boolean;

  /** Name included in every decision log for traceability. */
  serviceName?: string;

  /** Feature-gating resource template override. */
  featureGating?: { resourceTemplate?: string };

  /**
   * When true (default), the AuthorizationGuard is registered globally via
   * APP_GUARD — set it to false to bind the guard manually.
   */
  globalGuard?: boolean;
}

/**
 * The subset of options the runtime services actually consume.
 * Tests and internal callers can construct this without a resolver.
 */
export type AuthorizationRuntimeOptions = Pick<
  AuthorizationModuleOptions,
  'serviceName' | 'featureGating' | 'logging' | 'failClosed'
>;

export interface AuthorizationModuleAsyncOptions {
  imports?: Array<Type<unknown> | { module: Type<unknown> }>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  inject?: any[];
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  useFactory: (...args: any[]) => Promise<AuthorizationModuleOptions> | AuthorizationModuleOptions;
}
