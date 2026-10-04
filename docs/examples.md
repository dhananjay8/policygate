# Examples

## End-to-end: separate microservice in ~20 lines

```ts
// app.module.ts
@Module({
  imports: [
    AuthorizationModule.forRoot({
      mode: 'local',
      principalResolver: new MyJwtPrincipalResolver(),
      repositories: {
        roles: new MyRoleRepository(),
        policies: new MyPolicyRepository(),
        memberships: new MyMembershipRepository(),
        directPolicies: new MyDirectPolicyRepository(),
      },
    }),
  ],
  controllers: [BillingController],
})
export class AppModule {}

// billing.controller.ts
@Controller()
export class BillingController {
  @RequirePermission({
    action: 'billing:ReadPricing',
    resource: 'rn:cc-api:billing::${cc:accountId}:Pricing/*',
  })
  @Get('/accounts/:accountId/pricing')
  getPricing(@Param('accountId') accountId: string) {
    return { accountId };
  }
}
```

The consuming service never sees PRP/PIP/PDP.

## Programmatic authorization

```ts
await this.authorization.authorize({
  principal,
  action: 'billing:CreateRefund',
  resource: `rn:cc-api:billing::${accountId}:Refunds/${refundId}`,
  accountId,
});
```

## Feature gating

```ts
const enabled = await this.authorization.isFeatureEnabled(principal, 'NewBillingUI', 'account-123');
```

Or declaratively:

```ts
@RequirePermission({
  action: 'feature:Enable${cc:featureName}',
  resource: 'rn:cc-api:billing::${cc:accountId}:Features/${cc:featureName}',
})
@Get('/accounts/:accountId/features/:featureName')
feature() {}
```

## Policy with conditions

```json
{
  "name": "RefundUnderLimit",
  "statements": [
    {
      "effect": "Allow",
      "actions": ["billing:CreateRefund"],
      "resources": ["rn:cc-api:billing::${cc:accountId}:Refunds/*"],
      "conditions": {
        "NumericLessThan": { "cc:amount": 1000 },
        "StringEquals": { "cc:region": "us-east-1" }
      }
    }
  ]
}
```

## Remote mode

```ts
AuthorizationModule.forRoot({
  mode: 'remote',
  remote: { url: 'http://authorization-service:3100', timeoutMs: 2000 },
  principalResolver: new MyJwtPrincipalResolver(),
});
```

The central service exposes `POST /v1/authorize`:

```bash
curl -X POST http://localhost:3100/v1/authorize \
  -H 'content-type: application/json' \
  -d '{"principal":{"id":"user-123","type":"USER"},
       "action":"billing:ReadPricing",
       "resource":"rn:cc-api:billing::account-123:Pricing/*",
       "accountId":"account-123"}'
```
