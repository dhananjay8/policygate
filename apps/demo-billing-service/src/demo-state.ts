import { Injectable, Module } from '@nestjs/common';
import {
  buildDemoSeed,
  InMemoryDirectPolicyRepository,
  InMemoryMembershipRepository,
  InMemoryPolicyRepository,
  InMemoryPrincipalRepository,
  InMemoryRoleRepository,
} from 'policygate';

/**
 * Holds the live in-memory repositories so the dev admin controller can
 * revoke grants at runtime — proving there is NO authorization caching:
 * the very next request re-reads current policy state.
 */
@Injectable()
export class DemoState {
  readonly roles: InMemoryRoleRepository;
  readonly policies: InMemoryPolicyRepository;
  readonly memberships: InMemoryMembershipRepository;
  readonly directPolicies: InMemoryDirectPolicyRepository;
  readonly principals: InMemoryPrincipalRepository;

  constructor() {
    const seed = buildDemoSeed();
    this.roles = new InMemoryRoleRepository(seed.roles);
    this.policies = new InMemoryPolicyRepository(seed.policies);
    this.memberships = new InMemoryMembershipRepository(seed.memberships);
    this.directPolicies = new InMemoryDirectPolicyRepository(seed.directPolicies);
    this.principals = new InMemoryPrincipalRepository(seed.principals);
  }

  reset(): void {
    const seed = buildDemoSeed();
    // Replace contents without changing the instance references the
    // AuthorizationModule factories captured.
    for (const r of seed.roles) this.roles.save(r);
    for (const p of seed.policies) this.policies.save(p);
  }
}

/** Exports DemoState so it can be injected into forRootAsync factories. */
@Module({
  providers: [DemoState],
  exports: [DemoState],
})
export class DemoStateModule {}
