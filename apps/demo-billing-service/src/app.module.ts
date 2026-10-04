import { Module } from '@nestjs/common';
import {
  ApiKeyPrincipalResolver,
  AuthorizationModule,
  type AuthorizationModuleOptions,
  CompositePrincipalResolver,
  HeaderPrincipalResolver,
  type Principal,
} from 'policygate';
import { BillingController } from './billing.controller';
import { DevAdminController } from './dev-admin.controller';
import { DemoState, DemoStateModule } from './demo-state';

/**
 * Demo API keys -> service principals. In production this lookup would hit
 * a key store; here it demonstrates that API-key callers, header-injected
 * customer/agent identities, and (in production) JWT/portal tokens all
 * normalize into the same Principal and flow through the same pipeline.
 */
const DEMO_API_KEYS: Record<string, Pick<Principal, 'id' | 'type'>> = {
  'demo-reporting-key': { id: 'svc-reporting', type: 'SERVICE' },
};

export const demoPrincipalResolver = new CompositePrincipalResolver([
  new ApiKeyPrincipalResolver(async (key) => DEMO_API_KEYS[key] ?? null),
  new HeaderPrincipalResolver(),
]);

/**
 * AUTHZ_MODE=local  -> embedded PRP/PIP/PDP over in-memory repos
 * AUTHZ_MODE=remote -> delegates to AUTHZ_EVALUATOR_URL
 */
export function authorizationOptions(state: DemoState): AuthorizationModuleOptions {
  const base: AuthorizationModuleOptions = {
    mode: 'local',
    serviceName: 'demo-billing-service',
    principalResolver: demoPrincipalResolver,
    repositories: {
      roles: state.roles,
      policies: state.policies,
      memberships: state.memberships,
      directPolicies: state.directPolicies,
      principals: state.principals,
    },
    logging: { enabled: process.env.AUTHZ_DECISION_LOGGING !== 'false' },
  };
  if (process.env.AUTHZ_MODE === 'remote') {
    return {
      ...base,
      mode: 'remote',
      remote: {
        url: process.env.AUTHZ_EVALUATOR_URL ?? 'http://localhost:3100',
        timeoutMs: Number(process.env.AUTHZ_EVALUATOR_TIMEOUT_MS ?? 2000),
      },
      repositories: undefined,
    };
  }
  return base;
}

@Module({
  imports: [
    DemoStateModule,
    AuthorizationModule.forRootAsync({
      imports: [DemoStateModule],
      inject: [DemoState],
      useFactory: (state: DemoState) => authorizationOptions(state),
    }),
  ],
  controllers: [BillingController, DevAdminController],
})
export class AppModule {}
