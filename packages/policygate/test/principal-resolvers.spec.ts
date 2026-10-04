import type { ExecutionContext } from '@nestjs/common';
import {
  ApiKeyPrincipalResolver,
  BearerTokenPrincipalResolver,
  CompositePrincipalResolver,
  HeaderPrincipalResolver,
  StrictHeaderPrincipalResolver,
} from '../src/authentication/principal-resolver';
import { UnauthenticatedException } from '../src/exceptions/authorization.exceptions';

function httpCtx(headers: Record<string, string>): ExecutionContext {
  const req = { headers };
  return {
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
}

describe('BearerTokenPrincipalResolver', () => {
  const resolver = new BearerTokenPrincipalResolver(async (token) =>
    token === 'good-token' ? { sub: 'user-123', type: 'user', iss: 'demo-idp' } : null,
  );

  it('normalizes a verified bearer token into a Principal', async () => {
    const p = await resolver.resolve(httpCtx({ authorization: 'Bearer good-token' }));
    expect(p).toMatchObject({ id: 'user-123', type: 'USER', authenticated: true });
    expect(p.metadata).toMatchObject({ iss: 'demo-idp' });
  });

  it('maps claim types (AGENT/SERVICE)', async () => {
    const r = new BearerTokenPrincipalResolver(async () => ({ sub: 'agent-ops', type: 'AGENT' }));
    const p = await r.resolve(httpCtx({ authorization: 'Bearer t' }));
    expect(p.type).toBe('AGENT');
  });

  it('unknown token -> anonymous (still unauthenticated-default eligible)', async () => {
    const p = await resolver.resolve(httpCtx({ authorization: 'Bearer bad' }));
    expect(p.authenticated).toBe(false);
  });

  it('missing/wrong scheme -> anonymous', async () => {
    await expect(resolver.resolve(httpCtx({}))).resolves.toMatchObject({
      authenticated: false,
    });
    await expect(resolver.resolve(httpCtx({ authorization: 'Basic abc' }))).resolves.toMatchObject({
      authenticated: false,
    });
  });

  it('verifier errors propagate (fail closed, not anonymous)', async () => {
    const broken = new BearerTokenPrincipalResolver(async () => {
      throw new Error('IdP unreachable');
    });
    await expect(broken.resolve(httpCtx({ authorization: 'Bearer t' }))).rejects.toThrow(
      'IdP unreachable',
    );
  });
});

describe('ApiKeyPrincipalResolver', () => {
  const resolver = new ApiKeyPrincipalResolver(async (key) =>
    key === 'demo-reporting-key' ? { id: 'svc-reporting', type: 'SERVICE' } : null,
  );

  it('known key -> authenticated SERVICE principal', async () => {
    const p = await resolver.resolve(httpCtx({ 'x-api-key': 'demo-reporting-key' }));
    expect(p).toMatchObject({ id: 'svc-reporting', type: 'SERVICE', authenticated: true });
  });

  it('unknown/missing key -> anonymous', async () => {
    await expect(resolver.resolve(httpCtx({ 'x-api-key': 'wrong' }))).resolves.toMatchObject({
      authenticated: false,
    });
    await expect(resolver.resolve(httpCtx({}))).resolves.toMatchObject({
      authenticated: false,
    });
  });
});

describe('CompositePrincipalResolver', () => {
  it('first authenticated mechanism wins', async () => {
    const composite = new CompositePrincipalResolver([
      new ApiKeyPrincipalResolver(async () => ({ id: 'svc-reporting', type: 'SERVICE' })),
      new HeaderPrincipalResolver(),
    ]);
    const p = await composite.resolve(httpCtx({ 'x-api-key': 'k', 'x-principal-id': 'user-123' }));
    expect(p.id).toBe('svc-reporting');
  });

  it('falls through to the next mechanism when the first yields anonymous', async () => {
    const composite = new CompositePrincipalResolver([
      new ApiKeyPrincipalResolver(async () => null),
      new HeaderPrincipalResolver(),
    ]);
    const p = await composite.resolve(httpCtx({ 'x-principal-id': 'user-123' }));
    expect(p.id).toBe('user-123');
  });

  it('all mechanisms absent -> anonymous', async () => {
    const composite = new CompositePrincipalResolver([
      new ApiKeyPrincipalResolver(async () => null),
      new HeaderPrincipalResolver(),
    ]);
    const p = await composite.resolve(httpCtx({}));
    expect(p.authenticated).toBe(false);
  });

  it('skips resolvers that throw UnauthenticatedException', async () => {
    const composite = new CompositePrincipalResolver([
      new StrictHeaderPrincipalResolver(),
      new HeaderPrincipalResolver(),
    ]);
    const p = await composite.resolve(httpCtx({}));
    expect(p.authenticated).toBe(false);
  });

  it('unexpected resolver errors propagate', async () => {
    const composite = new CompositePrincipalResolver([
      new ApiKeyPrincipalResolver(async () => {
        throw new Error('key store down');
      }),
      new HeaderPrincipalResolver(),
    ]);
    await expect(composite.resolve(httpCtx({ 'x-api-key': 'k' }))).rejects.toThrow(
      'key store down',
    );
  });
});

describe('UnauthenticatedException isolation', () => {
  it('StrictHeaderPrincipalResolver throws when identity headers are missing', async () => {
    const strict = new StrictHeaderPrincipalResolver();
    await expect(strict.resolve(httpCtx({}))).rejects.toBeInstanceOf(UnauthenticatedException);
  });
});
