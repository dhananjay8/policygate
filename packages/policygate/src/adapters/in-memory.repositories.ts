import { Injectable } from '@nestjs/common';
import type { Membership, Policy, Principal, Role } from '../authorization/authorization.types';
import type {
  DirectPolicyRepository,
  MembershipRepository,
  PolicyRepository,
  PrincipalRepository,
  RoleRepository,
} from './repositories';

/**
 * In-memory repositories for unit tests, local development and demos.
 * Reads hit live object state on every call — no caching, so revocations
 * are visible on the next request.
 */
@Injectable()
export class InMemoryPolicyRepository implements PolicyRepository {
  private readonly policies = new Map<string, Policy>();

  constructor(initial: Policy[] = []) {
    for (const p of initial) this.policies.set(p.id, p);
  }

  async findByIds(ids: string[]): Promise<Policy[]> {
    return ids.map((id) => this.policies.get(id)).filter((p): p is Policy => p !== undefined);
  }

  async findById(id: string): Promise<Policy | undefined> {
    return this.policies.get(id);
  }

  save(policy: Policy): void {
    this.policies.set(policy.id, policy);
  }

  delete(id: string): void {
    this.policies.delete(id);
  }

  all(): Policy[] {
    return [...this.policies.values()];
  }
}

@Injectable()
export class InMemoryRoleRepository implements RoleRepository {
  private readonly roles = new Map<string, Role>();

  constructor(initial: Role[] = []) {
    for (const r of initial) this.roles.set(r.id, r);
  }

  async findByIds(ids: string[]): Promise<Role[]> {
    return ids.map((id) => this.roles.get(id)).filter((r): r is Role => r !== undefined);
  }

  async findSystemDefaults(): Promise<Role[]> {
    return [...this.roles.values()].filter((r) => r.systemDefault);
  }

  async findUnauthenticatedDefaults(): Promise<Role[]> {
    return [...this.roles.values()].filter((r) => r.unauthenticatedSystemDefault);
  }

  save(role: Role): void {
    this.roles.set(role.id, role);
  }

  delete(id: string): void {
    this.roles.delete(id);
  }
}

@Injectable()
export class InMemoryMembershipRepository implements MembershipRepository {
  private readonly memberships = new Map<string, Membership[]>();

  constructor(initial: Membership[] = []) {
    for (const m of initial) this.add(m);
  }

  async findByPrincipalId(principalId: string): Promise<Membership[]> {
    return this.memberships.get(principalId) ?? [];
  }

  add(m: Membership): void {
    const list = this.memberships.get(m.principalId) ?? [];
    this.memberships.set(m.principalId, [...list, m]);
  }

  remove(principalId: string, accountId: string): void {
    const list = (this.memberships.get(principalId) ?? []).filter((m) => m.accountId !== accountId);
    this.memberships.set(principalId, list);
  }
}

@Injectable()
export class InMemoryDirectPolicyRepository implements DirectPolicyRepository {
  private readonly direct = new Map<string, string[]>();

  constructor(initial: Record<string, string[]> = {}) {
    for (const [pid, ids] of Object.entries(initial)) this.direct.set(pid, ids);
  }

  async findByPrincipalId(principalId: string): Promise<string[]> {
    return this.direct.get(principalId) ?? [];
  }

  set(principalId: string, policyIds: string[]): void {
    this.direct.set(principalId, policyIds);
  }
}

@Injectable()
export class InMemoryPrincipalRepository implements PrincipalRepository {
  private readonly principals = new Map<string, Principal>();

  constructor(initial: Principal[] = []) {
    for (const p of initial) this.principals.set(p.id, p);
  }

  async findById(id: string): Promise<Principal | undefined> {
    return this.principals.get(id);
  }

  save(p: Principal): void {
    this.principals.set(p.id, p);
  }
}
