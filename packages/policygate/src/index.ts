// Public API of policygate.
// Consumers need: AuthorizationModule, decorators, AuthorizationService,
// and the interfaces/tokens used to plug in adapters.

export * from './authorization/authorization.types';
export * from './authorization/authorization.constants';
export * from './authorization/authorization.options';
export { AuthorizationModule } from './authorization/authorization.module';
export { AuthorizationService } from './authorization/authorization.service';
export {
  AuthorizationEvaluator,
  LocalAuthorizationEvaluator,
  RemoteAuthorizationEvaluator,
  RemoteAuthorizeResponse,
  RemoteEvaluatorOptions,
} from './authorization/authorization-evaluator';

// Authentication boundary
export {
  PrincipalResolver,
  HeaderPrincipalResolver,
  StrictHeaderPrincipalResolver,
  BearerTokenPrincipalResolver,
  ApiKeyPrincipalResolver,
  CompositePrincipalResolver,
} from './authentication/principal-resolver';
export type {
  TokenVerifier,
  VerifiedClaims,
  BearerPrincipalResolverOptions,
  ApiKeyLookup,
} from './authentication/principal-resolver';

// Guard + decorators
export { AuthorizationGuard } from './guard/authorization.guard';
export {
  AccountContextResolver,
  DefaultAccountContextResolver,
} from './guard/account-context-resolver';
export {
  RequirePermission,
  RequirePermissions,
  RequirePermissionsOptions,
} from './decorators/require-permission.decorator';
export { AuthzPrincipal } from './decorators/authz-principal.decorator';

// Pipeline stages
export { PolicyRetrievalPoint, DefaultPolicyRetrievalPoint } from './prp/policy-retrieval-point';
export {
  PolicyInformationPoint,
  DefaultPolicyInformationPoint,
} from './pip/policy-information-point';
export { PolicyDecisionPoint, DefaultPolicyDecisionPoint } from './pdp/policy-decision-point';

// Pure primitives
export {
  ConditionEvaluator,
  ConditionOperator,
  DefaultConditionEvaluator,
} from './conditions/condition-evaluator';
export { VariableResolver, DefaultVariableResolver } from './variables/variable-resolver';
export { segmentWildcardMatch, matchAnyPattern } from './resources/pattern-matcher';

// Persistence boundary
export {
  RoleRepository,
  PolicyRepository,
  MembershipRepository,
  DirectPolicyRepository,
  PrincipalRepository,
} from './adapters/repositories';
export {
  InMemoryRoleRepository,
  InMemoryPolicyRepository,
  InMemoryMembershipRepository,
  InMemoryDirectPolicyRepository,
  InMemoryPrincipalRepository,
} from './adapters/in-memory.repositories';
export {
  PrismaRoleRepository,
  PrismaPolicyRepository,
  PrismaMembershipRepository,
  PrismaDirectPolicyRepository,
  PrismaPrincipalRepository,
  PrismaClientLike,
} from './adapters/prisma/prisma.repositories';

// Observability
export {
  AuthorizationDecisionLogger,
  ConsoleDecisionLogger,
  NoopDecisionLogger,
} from './logging/decision-logger';
export {
  AuthorizationMetrics,
  InMemoryAuthorizationMetrics,
} from './metrics/authorization-metrics';

// Demo/dev fixtures
export { buildDemoSeed, demoPolicies, demoRoles, POLICY_IDS, ROLE_IDS } from './demo/fixtures';
export type { DemoSeed } from './demo/fixtures';

// Errors
export {
  AuthorizationDeniedException,
  AuthorizationEvaluationException,
  AuthorizationConfigurationException,
  UnauthenticatedException,
  FailedCheck,
} from './exceptions/authorization.exceptions';
