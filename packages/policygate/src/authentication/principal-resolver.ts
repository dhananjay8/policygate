import { Injectable, type ExecutionContext } from '@nestjs/common';
import type { IncomingMessage } from 'node:http';
import type { Principal, PrincipalType } from '../authorization/authorization.types';
import { UnauthenticatedException } from '../exceptions/authorization.exceptions';

/**
 * Identity resolution boundary. Implement this to plug in JWT/session/
 * portal-token/API-key verification. Authentication does NOT imply
 * authorization — this only produces a normalized Principal.
 */
export interface PrincipalResolver {
  resolve(context: ExecutionContext): Promise<Principal>;
}

interface HeaderCarrier {
  headers: Record<string, string | string[] | undefined>;
}

function header(req: HeaderCarrier, name: string): string | undefined {
  const v = req.headers[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

/**
 * Development/demo resolver that derives identity from trusted edge headers:
 *   x-principal-id, x-principal-type (USER|AGENT|SERVICE)
 * Any missing/invalid header yields an UNAUTHENTICATED principal (still
 * eligible for unauthenticated-default policies) rather than throwing —
 * the PDP decides whether unauthenticated access is allowed.
 *
 * For production, implement PrincipalResolver against your IdP/JWKS.
 */
@Injectable()
export class HeaderPrincipalResolver implements PrincipalResolver {
  async resolve(context: ExecutionContext): Promise<Principal> {
    const req = context.switchToHttp().getRequest<IncomingMessage & HeaderCarrier>();
    const id = header(req, 'x-principal-id');
    const typeRaw = (header(req, 'x-principal-type') ?? 'USER').toUpperCase();
    const type: PrincipalType =
      typeRaw === 'AGENT' || typeRaw === 'SERVICE' ? (typeRaw as PrincipalType) : 'USER';
    if (!id) {
      return { id: 'anonymous', type: 'USER', authenticated: false };
    }
    return { id, type, authenticated: true };
  }
}

/** Resolver that fails closed when credentials are missing entirely. */
@Injectable()
export class StrictHeaderPrincipalResolver implements PrincipalResolver {
  async resolve(context: ExecutionContext): Promise<Principal> {
    const req = context.switchToHttp().getRequest<IncomingMessage & HeaderCarrier>();
    const id = header(req, 'x-principal-id');
    if (!id) throw new UnauthenticatedException();
    const typeRaw = (header(req, 'x-principal-type') ?? 'USER').toUpperCase();
    const type: PrincipalType =
      typeRaw === 'AGENT' || typeRaw === 'SERVICE' ? (typeRaw as PrincipalType) : 'USER';
    return { id, type, authenticated: true };
  }
}

/** Normalized claims a token verifier may return. */
export interface VerifiedClaims {
  /** Subject / principal id. Required. */
  sub: string;
  /** USER | AGENT | SERVICE — defaults to USER. */
  type?: string;
  /** Additional claims carried into principal.metadata. */
  [claim: string]: unknown;
}

/**
 * Token verifier seam. Implement against your IdP: JWKS-backed JWT
 * verification, opaque portal-token introspection, session lookup, etc.
 * Return the normalized claims, or null when the token is invalid/expired.
 * Verification failures should THROW only for unrecoverable infra errors
 * (fail-closed); an invalid credential returns null.
 */
export type TokenVerifier = (token: string) => Promise<VerifiedClaims | null>;

export interface BearerPrincipalResolverOptions {
  /** Authorization header name (default 'authorization'). */
  headerName?: string;
  /** Scheme prefix (default 'Bearer'). Case-insensitive. */
  scheme?: string;
  /** Principal type default when the verifier omits claims.type. */
  defaultType?: PrincipalType;
  /** Map claim string -> PrincipalType (case-insensitive). */
  typeMap?: Record<string, PrincipalType>;
}

const ANONYMOUS: Principal = { id: 'anonymous', type: 'USER', authenticated: false };

function toPrincipal(claims: VerifiedClaims, opts: BearerPrincipalResolverOptions): Principal {
  const typeClaim = (claims.type ?? '').toUpperCase();
  const type: PrincipalType =
    opts.typeMap?.[typeClaim] ??
    (typeClaim === 'AGENT' || typeClaim === 'SERVICE'
      ? (typeClaim as PrincipalType)
      : (opts.defaultType ?? 'USER'));
  const { sub: _sub, type: _type, ...metadata } = claims;
  return { id: claims.sub, type, authenticated: true, metadata };
}

/**
 * Bearer-token resolver for customer JWTs, internal support/operations
 * tokens, and portal tokens — any credential presented as
 * `Authorization: Bearer <token>`. The `TokenVerifier` owns signature/
 * expiry/audience checks; this resolver only normalizes the result into
 * a Principal. Invalid or absent credentials yield the UNAUTHENTICATED
 * principal (still eligible for unauthenticated-default policies) rather
 * than throwing — the PDP decides whether anonymous access is allowed.
 */
@Injectable()
export class BearerTokenPrincipalResolver implements PrincipalResolver {
  constructor(
    private readonly verifier: TokenVerifier,
    private readonly options: BearerPrincipalResolverOptions = {},
  ) {}

  async resolve(context: ExecutionContext): Promise<Principal> {
    const req = context.switchToHttp().getRequest<IncomingMessage & HeaderCarrier>();
    const raw = header(req, this.options.headerName ?? 'authorization');
    const scheme = this.options.scheme ?? 'Bearer';
    if (!raw) return ANONYMOUS;
    const match = raw.match(new RegExp(`^${scheme}\\s+(.+)$`, 'i'));
    if (!match) return ANONYMOUS;
    const claims = await this.verifier(match[1]);
    if (!claims?.sub) return ANONYMOUS;
    return toPrincipal(claims, this.options);
  }
}

/** Lookup seam for API-key credentials. Return null for unknown keys. */
export type ApiKeyLookup = (
  apiKey: string,
) => Promise<Pick<Principal, 'id' | 'type' | 'metadata'> | null>;

/**
 * API-key resolver for service/API principals. Reads a configurable header
 * (default `x-api-key`) and normalizes the lookup result into a Principal.
 * Unknown/absent keys yield the UNAUTHENTICATED principal.
 */
@Injectable()
export class ApiKeyPrincipalResolver implements PrincipalResolver {
  constructor(
    private readonly lookup: ApiKeyLookup,
    private readonly headerName = 'x-api-key',
  ) {}

  async resolve(context: ExecutionContext): Promise<Principal> {
    const req = context.switchToHttp().getRequest<IncomingMessage & HeaderCarrier>();
    const key = header(req, this.headerName);
    if (!key) return ANONYMOUS;
    const found = await this.lookup(key);
    if (!found) return ANONYMOUS;
    return { ...found, authenticated: true };
  }
}

/**
 * Ordered chain over multiple authentication mechanisms. The first
 * resolver producing an AUTHENTICATED principal wins; resolvers that
 * yield the anonymous principal or throw UnauthenticatedException are
 * skipped. If every mechanism is absent/invalid, the anonymous principal
 * is returned — authentication failure never implies authorization.
 *
 * Unexpected verifier errors propagate (fail closed): a broken identity
 * provider must not silently become anonymous traffic.
 */
@Injectable()
export class CompositePrincipalResolver implements PrincipalResolver {
  constructor(private readonly resolvers: PrincipalResolver[]) {}

  async resolve(context: ExecutionContext): Promise<Principal> {
    for (const resolver of this.resolvers) {
      try {
        const principal = await resolver.resolve(context);
        if (principal?.authenticated) return principal;
      } catch (err) {
        if (err instanceof UnauthenticatedException) continue;
        throw err;
      }
    }
    return ANONYMOUS;
  }
}
