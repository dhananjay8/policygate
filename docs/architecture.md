# Architecture

## Authentication → normalized Principal

Customer JWTs, internal support/operations tokens, portal tokens, and API
keys are all reduced to one `Principal { id, type, authenticated }` by a
`PrincipalResolver`. **Identity ≠ authority** — authentication only
decides WHO is calling; the policy engine decides what they may do.
`CompositePrincipalResolver` chains mechanisms (API key → bearer → header)
and takes the first authenticated result; all-absent produces the
anonymous principal, which can only reach `unauthenticatedSystemDefault`
policies.

```mermaid
flowchart LR
  A[Customer JWT] --> C[CompositePrincipalResolver]
  B[Internal-ops JWT / portal token] --> C
  K[API key] --> C
  H[Edge headers (dev)] --> C
  C --> P[Principal: id + USER/AGENT/SERVICE + authenticated]
  P --> G[AuthorizationGuard → PRP → PIP → PDP]
```

## Request flow

```mermaid
sequenceDiagram
  autonumber
  participant C as Client
  participant N as NestJS Microservice
  participant R as PrincipalResolver
  participant G as AuthorizationGuard
  participant PRP as PolicyRetrievalPoint
  participant PIP as PolicyInformationPoint
  participant PDP as PolicyDecisionPoint
  participant H as Handler

  C->>N: HTTP request
  N->>R: resolve(executionContext)
  R-->>G: Principal { id, type, authenticated }
  G->>G: read @RequirePermission metadata
  G->>G: resolve account context + interpolate template
  G->>PRP: retrieve(principal, requestContext)
  PRP-->>G: ScopedPolicySet[] (per account)
  G->>PIP: buildEvaluationContexts(scopes)
  PIP-->>G: AuthorizationContext[] (roles expanded)
  G->>PDP: evaluate(request, contexts)
  PDP-->>G: AuthorizationDecision
  alt allowed
    G->>H: handler executes
  else denied / error
    G-->>C: 403 AUTHORIZATION_DENIED / 5xx
  end
  G->>G: decision log + metrics
```

## Multi-account isolation

```mermaid
flowchart TB
  U[User user-123] --> MA[Membership: account-123]
  U --> MB[Membership: account-456]
  MA --> RA[Role: BillingOperator]
  MB --> RB[Role: Viewer]
  RA --> P1[BillingPricingRead]
  RA --> P2[BillingRefund]
  RB --> P3[BillingInvoiceRead]

  REQ1["request: account-456 + billing:ReadPricing"] -. evaluated ONLY against .-> CTXB["Context account:account-456"]
  CTXB --> DENY[DENY]
```

The PDP filters contexts by `request.accountId`. When a request is
account-scoped, only the matching context is evaluated.

## Local vs remote

```mermaid
flowchart LR
  subgraph local["mode: 'local'"]
    LS[NestJS service] --> LE[LocalAuthorizationEvaluator\nPRP+PIP+PDP embedded]
  end
  subgraph remote["mode: 'remote'"]
    RS[NestJS service] --> RE[RemoteAuthorizationEvaluator\nHTTP POST /v1/authorize]
    RE --> AS[authorization-service\nPRP+PIP+PDP]
  end
```

## Feature gating (same engine)

```mermaid
flowchart LR
  F[isFeatureEnabled\n'NewBillingUI'] --> A[action: feature:EnableNewBillingUI]
  F --> R[resource: .../Features/NewBillingUI]
  A --> P[Policy statement]
  R --> P
  P --> PDP[PDP evaluate]
  PDP --> D{Allow / Deny}
```

## Component responsibilities

| Component                | Responsibility                                              | I/O?          |
| ------------------------ | ----------------------------------------------------------- | ------------- |
| `PrincipalResolver`      | Identity only (JWT/session/API-key adapters)                | Yes (edge)    |
| `AuthorizationGuard`     | Metadata, template interpolation, orchestration             | Calls service |
| `PolicyRetrievalPoint`   | Which scopes apply (memberships, direct policies, defaults) | Reads repos   |
| `PolicyInformationPoint` | Materializes contexts (role→policy expansion)               | Reads repos   |
| `PolicyDecisionPoint`    | Pure matching: actions, resources, conditions, effects      | **None**      |
| `AuthorizationService`   | Public API, decision logging, metrics                       | —             |
| `AccountContextResolver` | Trusted account context from route/server state             | —             |
| `VariableResolver`       | `${key}` interpolation                                      | None          |
| `ConditionEvaluator`     | Pluggable operator blocks                                   | None          |

## Failure model

All failures fail closed:

```mermaid
flowchart LR
  F[PRP/PIP/PDP/remote error] --> E[AuthorizationEvaluationException]
  E --> X[request rejected — never allowed]
```

`AuthorizationDeniedException` (403) for policy denials;
`AuthorizationEvaluationException` (500) for infrastructure failures;
`AuthorizationConfigurationException` for misconfiguration at boot or for
malformed persisted policies.
