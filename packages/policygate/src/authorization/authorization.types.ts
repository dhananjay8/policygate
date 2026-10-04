/**
 * Core domain types for policygate.
 * Everything the engine operates on is defined here — no NestJS types,
 * no ORM types. Adapters translate persistence/transport shapes into these.
 */

export type PrincipalType = 'USER' | 'AGENT' | 'SERVICE';

/**
 * Normalized identity produced by a PrincipalResolver.
 * Authentication != authorization: `authenticated` only describes
 * whether identity was verified, not what the principal may do.
 */
export interface Principal {
  id: string;
  type: PrincipalType;
  authenticated: boolean;
  metadata?: Record<string, unknown>;
}

export type Effect = 'Allow' | 'Deny';

export interface PolicyStatement {
  sid?: string;
  effect: Effect;
  actions: string[];
  resources: string[];
  /** Operator -> (key -> expected value(s)). e.g. { StringEquals: { 'cc:accountId': 'x' } } */
  conditions?: Record<string, Record<string, unknown>>;
}

export interface Policy {
  id: string;
  name: string;
  statements: PolicyStatement[];
}

export interface Role {
  id: string;
  name: string;
  /** Applies automatically to every authenticated principal. */
  systemDefault: boolean;
  /** Applies to unauthenticated requests where explicitly required. */
  unauthenticatedSystemDefault: boolean;
  /** Only AGENT principals may ever receive this role. Enforced structurally in the PIP. */
  internalAgentOnly: boolean;
  /** Resolved policy objects (many-to-many). */
  policies: Policy[];
}

/** A principal's membership in an account/tenant with a set of roles. */
export interface Membership {
  principalId: string;
  accountId: string;
  roleIds: string[];
}

/**
 * Contextual facts about the incoming request, produced by the guard /
 * AccountContextResolver and fed to the PRP.
 */
export interface AuthorizationRequestContext {
  /** Server-trusted account context requested by the caller. */
  accountId?: string;
  /** Route params flattened as `cc:<paramName>` plus any custom variables. */
  variables: Record<string, unknown>;
  /** HTTP method, path, correlation id, etc. for logging/conditions. */
  requestContext?: Record<string, unknown>;
}

export interface AuthorizationRequest {
  principal: Principal;
  action: string;
  resource: string;
  /** Requested account scope; which context may authorize this. */
  accountId?: string;
  variables?: Record<string, unknown>;
  requestContext?: Record<string, unknown>;
}

export type ReasonCode =
  | 'ALLOWED'
  | 'EXPLICIT_DENY'
  | 'DEFAULT_DENY'
  | 'NO_APPLICABLE_CONTEXT'
  | 'INTERNAL_ROLE_FORBIDDEN'
  | 'UNAUTHENTICATED';

export interface AuthorizationReason {
  code: ReasonCode;
  message: string;
  contextId?: string;
}

export interface AuthorizationDecision {
  allowed: boolean;
  reasons: AuthorizationReason[];
  /** Context ids that were evaluated. */
  evaluatedContexts: string[];
  /** sids of statements that matched (allow or deny). */
  matchedStatements: string[];
  /** Names of policies that contributed matched statements. */
  matchedPolicies: string[];
  /** The context that granted access (when allowed). */
  grantedByContextId?: string;
}

/** Output of the PRP: raw role/policy references grouped by account boundary. */
export interface ScopedPolicySet {
  /** Unique context key, e.g. `account:account-123` or `principal:user-1`. */
  contextId: string;
  accountId?: string;
  roleIds: string[];
  directPolicyIds: string[];
}

export interface PolicyRetrievalResult {
  principal: Principal;
  scopes: ScopedPolicySet[];
}

/** Output of the PIP: fully materialized authorization context per account. */
export interface AuthorizationContext {
  contextId: string;
  accountId?: string;
  roles: Role[];
  policies: Policy[];
}

/** A single required check declared via @RequirePermission(s). */
export interface RequiredPermission {
  action: string;
  resource: string;
}

export interface RequiredAuthorizationMetadata {
  checks: RequiredPermission[];
  /** ANY = at least one check must allow (default). ALL = every check must allow. */
  match: 'ANY' | 'ALL';
}

/** Structured record emitted for every authorization attempt. */
export interface AuthorizationDecisionLog {
  timestamp: string;
  principalId: string;
  principalType: PrincipalType;
  authenticated: boolean;
  accountId?: string;
  action: string;
  resource: string;
  decision: 'ALLOW' | 'DENY' | 'ERROR';
  reasons: ReasonCode[];
  matchedPolicies: string[];
  matchedStatements: string[];
  failedChecks?: RequiredPermission[];
  durationMs: number;
  correlationId?: string;
  authorizationId: string;
  serviceName?: string;
}

/** Server-trusted account context for the current request. */
export interface AccountAuthorizationContext {
  accountId?: string;
  variables: Record<string, unknown>;
}

export type AuthorizationVariables = Record<string, unknown>;

/** Result of an authenticated-identity resolution failure category. */
export type EvaluationMode = 'local' | 'remote';
