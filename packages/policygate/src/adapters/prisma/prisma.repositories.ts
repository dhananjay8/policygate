import type {
  Membership,
  Policy,
  PolicyStatement,
  Principal,
  Role,
} from '../../authorization/authorization.types';
import { AuthorizationConfigurationException } from '../../exceptions/authorization.exceptions';
import type {
  DirectPolicyRepository,
  MembershipRepository,
  PolicyRepository,
  PrincipalRepository,
  RoleRepository,
} from '../repositories';

/**
 * Structural typing over the generated PrismaClient so this package does
 * NOT depend on @prisma/client at compile time. Pass your app's generated
 * client — the shapes below match prisma/schema.prisma.
 */
export interface PrismaClientLike {
  role: {
    findMany(args: unknown): Promise<PrismaRoleRow[]>;
  };
  policy: {
    findMany(args: unknown): Promise<PrismaPolicyRow[]>;
    findUnique(args: unknown): Promise<PrismaPolicyRow | null>;
  };
  membership: {
    findMany(args: unknown): Promise<PrismaMembershipRow[]>;
  };
  directPolicy: {
    findMany(args: unknown): Promise<{ policyId: string }[]>;
  };
  principal: {
    findUnique(args: unknown): Promise<PrismaPrincipalRow | null>;
  };
}

interface PrismaPolicyRow {
  id: string;
  name: string;
  statements: unknown; // Json
}
interface PrismaRoleRow {
  id: string;
  name: string;
  systemDefault: boolean;
  unauthenticatedSystemDefault: boolean;
  internalAgentOnly: boolean;
  policies: { policy: PrismaPolicyRow }[];
}
interface PrismaMembershipRow {
  principalId: string;
  accountId: string;
  roles: { roleId: string }[];
}
interface PrismaPrincipalRow {
  id: string;
  type: string;
  metadata: unknown;
}

function isStatement(v: unknown): v is PolicyStatement {
  if (typeof v !== 'object' || v === null) return false;
  const s = v as Record<string, unknown>;
  return (
    (s.effect === 'Allow' || s.effect === 'Deny') &&
    Array.isArray(s.actions) &&
    s.actions.every((a) => typeof a === 'string') &&
    Array.isArray(s.resources) &&
    s.resources.every((r) => typeof r === 'string')
  );
}

/** Malformed persisted policy = configuration error, fail closed. */
function toPolicy(row: PrismaPolicyRow): Policy {
  if (!Array.isArray(row.statements) || !row.statements.every(isStatement)) {
    throw new AuthorizationConfigurationException(
      `Policy '${row.id}' ('${row.name}') contains malformed statements`,
    );
  }
  return { id: row.id, name: row.name, statements: row.statements as PolicyStatement[] };
}

function toRole(row: PrismaRoleRow): Role {
  return {
    id: row.id,
    name: row.name,
    systemDefault: row.systemDefault,
    unauthenticatedSystemDefault: row.unauthenticatedSystemDefault,
    internalAgentOnly: row.internalAgentOnly,
    policies: row.policies.map((rp) => toPolicy(rp.policy)),
  };
}

const ROLE_INCLUDE = { include: { policies: { include: { policy: true } } } } as const;

export class PrismaRoleRepository implements RoleRepository {
  constructor(private readonly prisma: PrismaClientLike) {}

  async findByIds(ids: string[]): Promise<Role[]> {
    const rows = await this.prisma.role.findMany({ where: { id: { in: ids } }, ...ROLE_INCLUDE });
    return rows.map(toRole);
  }
  async findSystemDefaults(): Promise<Role[]> {
    const rows = await this.prisma.role.findMany({
      where: { systemDefault: true },
      ...ROLE_INCLUDE,
    });
    return rows.map(toRole);
  }
  async findUnauthenticatedDefaults(): Promise<Role[]> {
    const rows = await this.prisma.role.findMany({
      where: { unauthenticatedSystemDefault: true },
      ...ROLE_INCLUDE,
    });
    return rows.map(toRole);
  }
}

export class PrismaPolicyRepository implements PolicyRepository {
  constructor(private readonly prisma: PrismaClientLike) {}
  async findByIds(ids: string[]): Promise<Policy[]> {
    const rows = await this.prisma.policy.findMany({ where: { id: { in: ids } } });
    return rows.map(toPolicy);
  }
  async findById(id: string): Promise<Policy | undefined> {
    const row = await this.prisma.policy.findUnique({ where: { id } });
    return row ? toPolicy(row) : undefined;
  }
}

export class PrismaMembershipRepository implements MembershipRepository {
  constructor(private readonly prisma: PrismaClientLike) {}
  async findByPrincipalId(principalId: string): Promise<Membership[]> {
    const rows = await this.prisma.membership.findMany({
      where: { principalId },
      include: { roles: true },
    });
    return rows.map((r) => ({
      principalId: r.principalId,
      accountId: r.accountId,
      roleIds: r.roles.map((mr) => mr.roleId),
    }));
  }
}

export class PrismaDirectPolicyRepository implements DirectPolicyRepository {
  constructor(private readonly prisma: PrismaClientLike) {}
  async findByPrincipalId(principalId: string): Promise<string[]> {
    const rows = await this.prisma.directPolicy.findMany({ where: { principalId } });
    return rows.map((r) => r.policyId);
  }
}

export class PrismaPrincipalRepository implements PrincipalRepository {
  constructor(private readonly prisma: PrismaClientLike) {}
  async findById(id: string): Promise<Principal | undefined> {
    const row = await this.prisma.principal.findUnique({ where: { id } });
    if (!row) return undefined;
    return {
      id: row.id,
      type: row.type as Principal['type'],
      authenticated: true,
      metadata: (row.metadata ?? undefined) as Record<string, unknown> | undefined,
    };
  }
}
