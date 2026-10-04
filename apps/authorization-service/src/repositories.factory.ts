import {
  buildDemoSeed,
  InMemoryDirectPolicyRepository,
  InMemoryMembershipRepository,
  InMemoryPolicyRepository,
  InMemoryPrincipalRepository,
  InMemoryRoleRepository,
  PrismaClientLike,
  PrismaDirectPolicyRepository,
  PrismaMembershipRepository,
  PrismaPolicyRepository,
  PrismaPrincipalRepository,
  PrismaRoleRepository,
  type DirectPolicyRepository,
  type MembershipRepository,
  type PolicyRepository,
  type PrincipalRepository,
  type RoleRepository,
} from 'policygate';

export interface RepositoryBundle {
  roles: RoleRepository;
  policies: PolicyRepository;
  memberships: MembershipRepository;
  directPolicies: DirectPolicyRepository;
  principals: PrincipalRepository;
}

/**
 * AUTHZ_PERSISTENCE=prisma requires DATABASE_URL and `npm run db:generate`.
 * Anything else uses the in-memory demo seed.
 */
export function buildRepositories(): RepositoryBundle {
  if (process.env.AUTHZ_PERSISTENCE === 'prisma') {
    if (!process.env.DATABASE_URL) {
      throw new Error('AUTHZ_PERSISTENCE=prisma requires DATABASE_URL');
    }
    // Lazy require: prisma client must be generated only when actually used.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const { PrismaClient } = require('@prisma/client') as {
      PrismaClient: new () => PrismaClientLike;
    };
    const prisma = new PrismaClient();
    return {
      roles: new PrismaRoleRepository(prisma),
      policies: new PrismaPolicyRepository(prisma),
      memberships: new PrismaMembershipRepository(prisma),
      directPolicies: new PrismaDirectPolicyRepository(prisma),
      principals: new PrismaPrincipalRepository(prisma),
    };
  }

  const seed = buildDemoSeed();
  return {
    roles: new InMemoryRoleRepository(seed.roles),
    policies: new InMemoryPolicyRepository(seed.policies),
    memberships: new InMemoryMembershipRepository(seed.memberships),
    directPolicies: new InMemoryDirectPolicyRepository(seed.directPolicies),
    principals: new InMemoryPrincipalRepository(seed.principals),
  };
}
