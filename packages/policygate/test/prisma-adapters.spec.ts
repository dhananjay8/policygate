import {
  PrismaMembershipRepository,
  PrismaPolicyRepository,
  PrismaRoleRepository,
  type PrismaClientLike,
} from '../src/adapters/prisma/prisma.repositories';
import { AuthorizationConfigurationException } from '../src/exceptions/authorization.exceptions';

/** Minimal PrismaClientLike stub — rows shaped like prisma/schema.prisma. */
function stub(over: Partial<PrismaClientLike>): PrismaClientLike {
  return {
    role: { findMany: () => Promise.resolve([]) },
    policy: {
      findMany: () => Promise.resolve([]),
      findUnique: () => Promise.resolve(null),
    },
    membership: { findMany: () => Promise.resolve([]) },
    directPolicy: { findMany: () => Promise.resolve([]) },
    principal: { findUnique: () => Promise.resolve(null) },
    ...over,
  };
}

describe('Prisma repositories', () => {
  it('maps rows into domain types', async () => {
    const repo = new PrismaPolicyRepository(
      stub({
        policy: {
          findMany: () =>
            Promise.resolve([
              {
                id: 'p1',
                name: 'BillingPricingRead',
                statements: [
                  {
                    sid: 's',
                    effect: 'Allow',
                    actions: ['billing:ReadPricing'],
                    resources: ['*'],
                  },
                ],
              },
            ]),
          findUnique: () => Promise.resolve(null),
        },
      }),
    );
    const policies = await repo.findByIds(['p1']);
    expect(policies).toHaveLength(1);
    expect(policies[0].statements[0].sid).toBe('s');
  });

  it('malformed persisted policy -> AuthorizationConfigurationException (fail closed)', async () => {
    const repo = new PrismaPolicyRepository(
      stub({
        policy: {
          findMany: () =>
            Promise.resolve([
              { id: 'bad', name: 'Malformed', statements: [{ effect: 'Allow' }] }, // missing actions/resources
            ]),
          findUnique: () => Promise.resolve(null),
        },
      }),
    );
    await expect(repo.findByIds(['bad'])).rejects.toBeInstanceOf(
      AuthorizationConfigurationException,
    );
  });

  it('role expansion resolves role->policy join', async () => {
    const repo = new PrismaRoleRepository(
      stub({
        role: {
          findMany: () =>
            Promise.resolve([
              {
                id: 'r1',
                name: 'BillingOperator',
                systemDefault: false,
                unauthenticatedSystemDefault: false,
                internalAgentOnly: false,
                policies: [
                  {
                    policy: {
                      id: 'p1',
                      name: 'BillingPricingRead',
                      statements: [{ effect: 'Allow', actions: ['a'], resources: ['r'] }],
                    },
                  },
                ],
              },
            ]),
        },
      }),
    );
    const roles = await repo.findByIds(['r1']);
    expect(roles[0].policies[0].name).toBe('BillingPricingRead');
  });

  it('membership rows flatten to roleIds', async () => {
    const repo = new PrismaMembershipRepository(
      stub({
        membership: {
          findMany: () =>
            Promise.resolve([
              {
                principalId: 'u1',
                accountId: 'a1',
                roles: [{ roleId: 'r1' }, { roleId: 'r2' }],
              },
            ]),
        },
      }),
    );
    const ms = await repo.findByPrincipalId('u1');
    expect(ms[0].roleIds).toEqual(['r1', 'r2']);
  });
});
