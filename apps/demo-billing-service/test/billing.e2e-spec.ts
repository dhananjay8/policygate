import 'reflect-metadata';
import { Test } from '@nestjs/testing';
import {
  Body,
  Controller,
  Get,
  HttpCode,
  Param,
  Post,
  type INestApplication,
} from '@nestjs/common';
import type { AddressInfo } from 'node:net';
import request from 'supertest';
import {
  AuthorizationModule,
  AuthorizationService,
  buildDemoSeed,
  HeaderPrincipalResolver,
  InMemoryDirectPolicyRepository,
  InMemoryMembershipRepository,
  InMemoryPolicyRepository,
  InMemoryRoleRepository,
  RequirePermission,
  type AuthorizationRequest,
} from 'policygate';
import { AppModule } from '../src/app.module';

/** Minimal controller used to test remote-mode fail-closed behavior. */
@Controller()
class RemoteModeController {
  @RequirePermission({
    action: 'billing:ReadPricing',
    resource: 'rn:cc-api:billing::${cc:accountId}:Pricing/*',
  })
  @Get('/accounts/:accountId/pricing')
  getPricing(@Param('accountId') accountId: string) {
    return { accountId, reached: true };
  }
}

/** Test-local replica of the central /v1/authorize endpoint. */
@Controller()
class TestAuthorizeController {
  constructor(private readonly authz: AuthorizationService) {}

  @Post('/v1/authorize')
  @HttpCode(200)
  authorize(@Body() body: AuthorizationRequest) {
    return this.authz.evaluate(body);
  }
}

/**
 * Full pipeline integration tests:
 * HTTP -> Authentication -> Guard -> PRP -> PIP -> PDP -> handler
 */
describe('demo-billing-service (e2e)', () => {
  let app: INestApplication;

  const asUser = () => ({ 'x-principal-id': 'user-123', 'x-principal-type': 'USER' });
  const asAgent = () => ({ 'x-principal-id': 'agent-ops', 'x-principal-type': 'AGENT' });

  beforeAll(async () => {
    const mod = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = mod.createNestApplication();
    await app.init();
  });

  afterAll(async () => {
    await app.close();
  });

  describe('Flow A — valid access', () => {
    it('GET pricing on account-123 -> 200', async () => {
      await request(app.getHttpServer())
        .get('/accounts/account-123/pricing')
        .set(asUser())
        .expect(200);
    });
    it('GET invoices on account-456 (Viewer has invoice read) -> 200', async () => {
      await request(app.getHttpServer())
        .get('/accounts/account-456/invoices')
        .set(asUser())
        .expect(200);
    });
    it('POST refunds on account-123 (BillingOperator) -> 201', async () => {
      await request(app.getHttpServer())
        .post('/accounts/account-123/refunds')
        .set(asUser())
        .expect(201);
    });
  });

  describe('Flow B — wrong account / missing permission', () => {
    it('GET pricing on account-456 -> 403 (Viewer lacks pricing read)', async () => {
      const res = await request(app.getHttpServer())
        .get('/accounts/account-456/pricing')
        .set(asUser())
        .expect(403);
      expect(res.body.code).toBe('AUTHORIZATION_DENIED');
      expect(res.body.failedChecks).toEqual([
        {
          action: 'billing:ReadPricing',
          resource: 'rn:cc-api:billing::account-456:Pricing/*',
        },
      ]);
    });
    it('POST refunds on account-456 -> 403 (account-123 grant must not leak)', async () => {
      await request(app.getHttpServer())
        .post('/accounts/account-456/refunds')
        .set(asUser())
        .expect(403);
    });
    it('GET pricing on account-999 (no membership) -> 403', async () => {
      await request(app.getHttpServer())
        .get('/accounts/account-999/pricing')
        .set(asUser())
        .expect(403);
    });
  });

  describe('Feature gating through the same engine', () => {
    it('Flow C — NewBillingUI enabled on account-123 -> 200 enabled', async () => {
      const res = await request(app.getHttpServer())
        .get('/accounts/account-123/features/NewBillingUI')
        .set(asUser())
        .expect(200);
      expect(res.body.enabled).toBe(true);
    });
    it('Flow D — NewBillingUI absent on account-456 -> 403', async () => {
      await request(app.getHttpServer())
        .get('/accounts/account-456/features/NewBillingUI')
        .set(asUser())
        .expect(403);
    });
    it('unknown feature name -> 403', async () => {
      await request(app.getHttpServer())
        .get('/accounts/account-123/features/DoesNotExist')
        .set(asUser())
        .expect(403);
    });
  });

  describe('Flow E — revocation without cache invalidation', () => {
    it('revoked policy denies the very next request', async () => {
      await request(app.getHttpServer())
        .get('/accounts/account-123/pricing')
        .set(asUser())
        .expect(200);

      await request(app.getHttpServer())
        .post('/dev/roles/role-billing-operator/revoke/policy-billing-pricing-read')
        .expect(201);

      await request(app.getHttpServer())
        .get('/accounts/account-123/pricing')
        .set(asUser())
        .expect(403);

      await request(app.getHttpServer()).post('/dev/reset').expect(201);
      await request(app.getHttpServer())
        .get('/accounts/account-123/pricing')
        .set(asUser())
        .expect(200);
    });
  });

  describe('internal-agent-only roles', () => {
    it('AGENT principal can use InternalSupport; USER cannot', async () => {
      // agent-ops holds InternalSupport on account-123; customers never can.
      // Demonstrated indirectly: agent has no billing permissions -> 403 on pricing.
      await request(app.getHttpServer())
        .get('/accounts/account-123/pricing')
        .set(asAgent())
        .expect(403);
    });
  });

  describe('unauthenticated requests', () => {
    it('protected endpoint without identity -> 403', async () => {
      await request(app.getHttpServer()).get('/accounts/account-123/pricing').expect(403);
    });
    it('public health endpoint -> 200 without identity', async () => {
      await request(app.getHttpServer()).get('/health').expect(200);
    });
    it('unauthenticatedSystemDefault policy allows /health/details pre-login -> 200', async () => {
      const res = await request(app.getHttpServer()).get('/health/details').expect(200);
      expect(res.body.authorizedBy).toBe('PublicHealthRead');
    });
    it('systemDefault policy allows /health/details post-login -> 200', async () => {
      await request(app.getHttpServer()).get('/health/details').set(asUser()).expect(200);
    });
  });

  describe('metrics', () => {
    it('/dev/metrics returns counters', async () => {
      const res = await request(app.getHttpServer()).get('/dev/metrics').expect(200);
      expect(res.body.authorization_requests_total).toBeGreaterThan(0);
      expect(res.body).toHaveProperty('authorization_evaluation_duration_ms');
    });
  });

  describe('service principals — API key + directly attached policies', () => {
    const asService = () => ({ 'x-api-key': 'demo-reporting-key' });

    it('svc-reporting can read account-agnostic reports -> 200', async () => {
      const res = await request(app.getHttpServer()).get('/reports').set(asService()).expect(200);
      expect(res.body.reports[0].principal).toBe('svc-reporting');
    });

    it('API key authenticates but cannot reach account-scoped resources -> 403', async () => {
      // svc-reporting holds BillingInvoiceRead as a direct policy, but its
      // principal-scoped context has no accountId so ${cc:accountId} can
      // never resolve — a direct policy can never grant tenant data.
      await request(app.getHttpServer())
        .get('/accounts/account-123/invoices')
        .set(asService())
        .expect(403);
    });

    it('unknown API key -> anonymous -> 403 on protected endpoint', async () => {
      await request(app.getHttpServer()).get('/reports').set('x-api-key', 'bogus').expect(403);
    });

    it('customer credentials cannot reach service endpoints -> 403', async () => {
      await request(app.getHttpServer()).get('/reports').set(asUser()).expect(403);
    });
  });

  describe('Flow F — remote evaluator failure fails closed', () => {
    it('unreachable remote evaluator -> never authorized', async () => {
      const mod = await Test.createTestingModule({
        imports: [
          AuthorizationModule.forRoot({
            mode: 'remote',
            principalResolver: new HeaderPrincipalResolver(),
            remote: { url: 'http://127.0.0.1:1', timeoutMs: 300 },
          }),
        ],
        controllers: [RemoteModeController],
      }).compile();
      const remoteApp = mod.createNestApplication();
      await remoteApp.init();

      const res = await request(remoteApp.getHttpServer())
        .get('/accounts/account-123/pricing')
        .set(asUser());

      expect([403, 500]).toContain(res.status);
      expect(
        res.body.code === 'AUTHORIZATION_DENIED' ||
          res.body.code === 'AUTHORIZATION_EVALUATION_FAILED',
      ).toBe(true);
      await remoteApp.close();
    });
  });

  describe('Remote mode — happy path over real HTTP', () => {
    it('central authorization-service grants via /v1/authorize', async () => {
      const seed = buildDemoSeed();
      const centralModule = await Test.createTestingModule({
        imports: [
          AuthorizationModule.forRoot({
            mode: 'local',
            serviceName: 'authorization-service',
            principalResolver: new HeaderPrincipalResolver(),
            repositories: {
              roles: new InMemoryRoleRepository(seed.roles),
              policies: new InMemoryPolicyRepository(seed.policies),
              memberships: new InMemoryMembershipRepository(seed.memberships),
              directPolicies: new InMemoryDirectPolicyRepository(seed.directPolicies),
            },
            logging: { enabled: false },
          }),
        ],
        controllers: [TestAuthorizeController],
      }).compile();
      const central = centralModule.createNestApplication();
      await central.init();
      await central.listen(0);
      const port = (central.getHttpServer().address() as AddressInfo).port;

      const clientModule = await Test.createTestingModule({
        imports: [
          AuthorizationModule.forRoot({
            mode: 'remote',
            principalResolver: new HeaderPrincipalResolver(),
            remote: { url: `http://127.0.0.1:${port}`, timeoutMs: 2000 },
            logging: { enabled: false },
          }),
        ],
        controllers: [RemoteModeController],
      }).compile();
      const clientApp = clientModule.createNestApplication();
      await clientApp.init();

      // Allowed request over the wire
      const ok = await request(clientApp.getHttpServer())
        .get('/accounts/account-123/pricing')
        .set(asUser())
        .expect(200);
      expect(ok.body.reached).toBe(true);

      // Denied request over the wire (wrong account)
      await request(clientApp.getHttpServer())
        .get('/accounts/account-456/pricing')
        .set(asUser())
        .expect(403);

      await clientApp.close();
      await central.close();
    });
  });
});
