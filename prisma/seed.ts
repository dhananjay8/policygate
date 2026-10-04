/**
 * Seed script: npm run db:seed
 * Requires DATABASE_URL and `npm run db:generate` + `npm run db:push` first.
 * Loads the same demo scenario the in-memory fixtures use.
 */
import { PrismaClient } from '@prisma/client';
import { buildDemoSeed } from '../packages/policygate/src/demo/fixtures';

const prisma = new PrismaClient();

async function main(): Promise<void> {
  const seed = buildDemoSeed();

  for (const p of seed.policies) {
    await prisma.policy.upsert({
      where: { id: p.id },
      update: { name: p.name, statements: p.statements },
      create: { id: p.id, name: p.name, statements: p.statements },
    });
  }

  for (const r of seed.roles) {
    await prisma.role.upsert({
      where: { id: r.id },
      update: {
        name: r.name,
        systemDefault: r.systemDefault,
        unauthenticatedSystemDefault: r.unauthenticatedSystemDefault,
        internalAgentOnly: r.internalAgentOnly,
      },
      create: {
        id: r.id,
        name: r.name,
        systemDefault: r.systemDefault,
        unauthenticatedSystemDefault: r.unauthenticatedSystemDefault,
        internalAgentOnly: r.internalAgentOnly,
      },
    });
    await prisma.rolePolicy.deleteMany({ where: { roleId: r.id } });
    for (const p of r.policies) {
      await prisma.rolePolicy.create({ data: { roleId: r.id, policyId: p.id } });
    }
  }

  for (const acct of ['account-123', 'account-456']) {
    await prisma.account.upsert({
      where: { id: acct },
      update: {},
      create: { id: acct, name: acct },
    });
  }

  for (const p of seed.principals) {
    await prisma.principal.upsert({
      where: { id: p.id },
      update: { type: p.type, metadata: p.metadata ?? null },
      create: { id: p.id, type: p.type, metadata: p.metadata ?? null },
    });
  }

  for (const m of seed.memberships) {
    const membership = await prisma.membership.upsert({
      where: { principalId_accountId: { principalId: m.principalId, accountId: m.accountId } },
      update: {},
      create: { principalId: m.principalId, accountId: m.accountId },
    });
    await prisma.membershipRole.deleteMany({ where: { membershipId: membership.id } });
    for (const roleId of m.roleIds) {
      await prisma.membershipRole.create({
        data: { membershipId: membership.id, roleId },
      });
    }
  }

  for (const [principalId, policyIds] of Object.entries(seed.directPolicies)) {
    await prisma.directPolicy.deleteMany({ where: { principalId } });
    for (const policyId of policyIds) {
      await prisma.directPolicy.create({ data: { principalId, policyId } });
    }
  }

  console.log('Seeded demo authorization data.');
}

main()
  .catch((err) => {
    console.error(err);
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
