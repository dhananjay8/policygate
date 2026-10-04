# Evaluation rules

The PDP applies these rules in order, per request.

## Rule 1 — Deny by default

If no applicable `Allow` statement matches, the decision is `DENY`
(`DEFAULT_DENY`).

## Rule 2 — Explicit deny wins

Any applicable `Deny` statement blocks the request, even when another
statement (or context) would allow it (`EXPLICIT_DENY`).

## Rule 3 — Action matching

Exact match, or segment-aware wildcard: `*` matches within a `:`
segment only.

| Policy                | Request               | Match?                  |
| --------------------- | --------------------- | ----------------------- |
| `billing:ReadPricing` | `billing:ReadPricing` | yes                     |
| `billing:*`           | `billing:ReadInvoice` | yes                     |
| `billing:*`           | `billing:x:y`         | no                      |
| `billing:Read`        | `billing:ReadPricing` | no (no substring match) |
| `*`                   | anything              | yes                     |

## Rule 4 — Resource matching

Same segment-aware wildcard semantics. The `accountId` segment is a
distinct segment, so a pattern for `account-123` can never match an
`account-456` resource — even with `*` elsewhere.

## Rule 5 — Conditions

All operator blocks and all keys within a block are ANDed. Missing keys
fail non-`Exists` operators. Unknown operators fail closed.

## Multi-account rule

A request carrying `accountId` is evaluated **only** against the
`AuthorizationContext` for that account:

```
contexts.filter(c => c.accountId === request.accountId)
```

The request is allowed iff that single context independently grants it.
If no context exists for the requested account: `NO_APPLICABLE_CONTEXT` → deny.

Requests without `accountId` may be granted by any context (e.g.
principal-scoped direct policies for service accounts).

## Decision shape

```ts
{
  allowed: boolean,
  reasons: [{ code, message, contextId }],
  evaluatedContexts: string[],
  matchedStatements: string[],   // sids
  matchedPolicies: string[],     // policy names
  grantedByContextId?: string,
}
```
