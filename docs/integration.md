# Integration guide

## Step 1 — implement a PrincipalResolver

```ts
@Injectable()
export class JwtPrincipalResolver implements PrincipalResolver {
  async resolve(ctx: ExecutionContext): Promise<Principal> {
    const req = ctx.switchToHttp().getRequest();
    const token = verifyJwt(extractBearer(req)); // your IdP/JWKS logic
    return {
      id: token.sub,
      type: token.aud === 'internal-ops' ? 'AGENT' : 'USER',
      authenticated: true,
      metadata: { iss: token.iss },
    };
  }
}
```

## Step 2 — wire repositories

Implement `RoleRepository`, `PolicyRepository`, `MembershipRepository`,
`DirectPolicyRepository` over your store, or reuse the Prisma reference
adapters:

```ts
import {
  PrismaRoleRepository,
  PrismaPolicyRepository,
  PrismaMembershipRepository,
  PrismaDirectPolicyRepository,
} from 'policygate';

const repos = {
  roles: new PrismaRoleRepository(prisma),
  policies: new PrismaPolicyRepository(prisma),
  memberships: new PrismaMembershipRepository(prisma),
  directPolicies: new PrismaDirectPolicyRepository(prisma),
};
```

## Step 3 — register the module

```ts
AuthorizationModule.forRootAsync({
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    mode: config.get('AUTHZ_MODE') === 'remote' ? 'remote' : 'local',
    remote: { url: config.get('AUTHZ_EVALUATOR_URL') },
    principalResolver: new JwtPrincipalResolver(),
    repositories: repos,
    serviceName: 'my-service',
    logging: { enabled: true },
  }),
});
```

## Step 4 — protect endpoints

```ts
@RequirePermission({
  action: 'billing:ReadPricing',
  resource: 'rn:cc-api:billing::${cc:accountId}:Pricing/*',
})
@Get('/accounts/:accountId/pricing')
getPricing() {}
```

Multiple checks (default `ANY`, or `{ match: 'ALL' }`):

```ts
@RequirePermissions([
  { action: 'billing:ReadPricing', resource: 'rn:cc-api:billing::${cc:accountId}:Pricing/*' },
  { action: 'billing:ReadInvoices', resource: 'rn:cc-api:billing::${cc:accountId}:Invoices/*' },
], { match: 'ALL' })
```

## Optional: custom account context

```ts
export class OrgAccountContextResolver implements AccountContextResolver {
  async resolve(ctx: ExecutionContext, principal: Principal) {
    const req = ctx.switchToHttp().getRequest();
    return {
      accountId: req.headers['x-org-id'],
      variables: { 'cc:orgId': req.headers['x-org-id'], 'cc:principalId': principal.id },
    };
  }
}
```

## Optional: custom decision logger

```ts
export class KafkaDecisionLogger implements AuthorizationDecisionLogger {
  async log(decision: AuthorizationDecisionLog) {
    /* produce to Kafka */
  }
}
// options: logging: { logger: new KafkaDecisionLogger(...) }
```

## Environment variables

| Var                          | Meaning                               |
| ---------------------------- | ------------------------------------- |
| `AUTHZ_MODE`                 | `local` \| `remote`                   |
| `AUTHZ_EVALUATOR_URL`        | remote evaluator base URL             |
| `AUTHZ_EVALUATOR_TIMEOUT_MS` | remote timeout (default 2000)         |
| `AUTHZ_DECISION_LOGGING`     | `true`/`false`                        |
| `AUTHZ_PERSISTENCE`          | `memory` \| `prisma` (reference apps) |
| `DATABASE_URL`               | Prisma datasource                     |

## Failure contract

Never converts infrastructure failure into access:
`PRP/PIP/PDP/remote` errors → 500 `AUTHORIZATION_EVALUATION_FAILED`;
policy denial → 403 `AUTHORIZATION_DENIED` with the specific
`failedChecks` (action + resource) that were not satisfied.

For `@RequirePermissions` with `match: 'ANY'`, an evaluation error fails
only that individual check — remaining checks are still evaluated and may
independently authorize the request. If no check authorizes, the error is
surfaced (500) rather than masked as a plain 403, so operators can tell a
broken evaluator apart from a legitimate deny. With `match: 'ALL'` a
single check failure (deny or error) rejects the request immediately.
