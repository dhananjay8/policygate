/** DI tokens — consumers may replace any of these providers. */
export const AUTHORIZATION_OPTIONS = Symbol('AUTHORIZATION_OPTIONS');
export const PRINCIPAL_RESOLVER = Symbol('PRINCIPAL_RESOLVER');
export const ACCOUNT_CONTEXT_RESOLVER = Symbol('ACCOUNT_CONTEXT_RESOLVER');
export const POLICY_RETRIEVAL_POINT = Symbol('POLICY_RETRIEVAL_POINT');
export const POLICY_INFORMATION_POINT = Symbol('POLICY_INFORMATION_POINT');
export const POLICY_DECISION_POINT = Symbol('POLICY_DECISION_POINT');
export const AUTHORIZATION_EVALUATOR = Symbol('AUTHORIZATION_EVALUATOR');
export const VARIABLE_RESOLVER = Symbol('VARIABLE_RESOLVER');
export const CONDITION_EVALUATOR = Symbol('CONDITION_EVALUATOR');
export const DECISION_LOGGER = Symbol('DECISION_LOGGER');
export const AUTHORIZATION_METRICS = Symbol('AUTHORIZATION_METRICS');

export const ROLE_REPOSITORY = Symbol('ROLE_REPOSITORY');
export const POLICY_REPOSITORY = Symbol('POLICY_REPOSITORY');
export const MEMBERSHIP_REPOSITORY = Symbol('MEMBERSHIP_REPOSITORY');
export const DIRECT_POLICY_REPOSITORY = Symbol('DIRECT_POLICY_REPOSITORY');
export const PRINCIPAL_REPOSITORY = Symbol('PRINCIPAL_REPOSITORY');

/** Metadata key written by @RequirePermission(s) and read by the guard. */
export const REQUIRED_AUTHORIZATION_KEY = 'authz:required_checks';
