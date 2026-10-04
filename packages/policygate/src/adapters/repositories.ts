import type { Membership, Policy, Principal, Role } from '../authorization/authorization.types';

/**
 * Persistence boundary. The authorization engine depends only on these
 * interfaces — never on Prisma, SQL, Redis, etc.
 */
export interface RoleRepository {
  findByIds(ids: string[]): Promise<Role[]>;
  /** Roles that auto-apply to every authenticated principal. */
  findSystemDefaults(): Promise<Role[]>;
  /** Roles that may apply to unauthenticated requests. */
  findUnauthenticatedDefaults(): Promise<Role[]>;
}

export interface PolicyRepository {
  findByIds(ids: string[]): Promise<Policy[]>;
  findById(id: string): Promise<Policy | undefined>;
}

export interface MembershipRepository {
  /** All account memberships for a principal. */
  findByPrincipalId(principalId: string): Promise<Membership[]>;
}

/** Policies attached directly to a principal (service/API principals). */
export interface DirectPolicyRepository {
  findByPrincipalId(principalId: string): Promise<string[]>;
}

export interface PrincipalRepository {
  findById(id: string): Promise<Principal | undefined>;
}
