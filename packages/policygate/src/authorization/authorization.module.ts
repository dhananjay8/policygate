import {
  DynamicModule,
  Module,
  type FactoryProvider,
  type InjectionToken,
  type ModuleMetadata,
  type Provider,
  type Type,
} from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import {
  ACCOUNT_CONTEXT_RESOLVER,
  AUTHORIZATION_EVALUATOR,
  AUTHORIZATION_METRICS,
  AUTHORIZATION_OPTIONS,
  CONDITION_EVALUATOR,
  DECISION_LOGGER,
  DIRECT_POLICY_REPOSITORY,
  MEMBERSHIP_REPOSITORY,
  POLICY_DECISION_POINT,
  POLICY_INFORMATION_POINT,
  POLICY_RETRIEVAL_POINT,
  POLICY_REPOSITORY,
  PRINCIPAL_REPOSITORY,
  PRINCIPAL_RESOLVER,
  ROLE_REPOSITORY,
  VARIABLE_RESOLVER,
} from './authorization.constants';
import type {
  AuthorizationModuleAsyncOptions,
  AuthorizationModuleOptions,
} from './authorization.options';
import { AuthorizationGuard } from '../guard/authorization.guard';
import { AuthorizationService } from './authorization.service';
import {
  LocalAuthorizationEvaluator,
  RemoteAuthorizationEvaluator,
} from './authorization-evaluator';
import { DefaultPolicyRetrievalPoint } from '../prp/policy-retrieval-point';
import { DefaultPolicyInformationPoint } from '../pip/policy-information-point';
import { DefaultPolicyDecisionPoint } from '../pdp/policy-decision-point';
import { DefaultAccountContextResolver } from '../guard/account-context-resolver';
import { DefaultVariableResolver } from '../variables/variable-resolver';
import { DefaultConditionEvaluator } from '../conditions/condition-evaluator';
import { ConsoleDecisionLogger, NoopDecisionLogger } from '../logging/decision-logger';
import { InMemoryAuthorizationMetrics } from '../metrics/authorization-metrics';
import { AuthorizationConfigurationException } from '../exceptions/authorization.exceptions';

type Impl<T> = T | Type<T>;

/**
 * Bind `token` to a custom class/instance or a default. Custom classes are
 * instantiated with the token's standard `deps`. For adapters needing other
 * injected collaborators, pass a constructed instance (or rebind the token
 * in your own module, which shadows the global default).
 */
function resolvable<T>(
  token: symbol,
  pick: (o: AuthorizationModuleOptions) => Impl<T> | undefined,
  makeDefault: (o: AuthorizationModuleOptions, ...deps: unknown[]) => T | undefined,
  deps: InjectionToken[] = [],
  requiredForLocal?: string,
): FactoryProvider {
  return {
    provide: token,
    useFactory: (opts: AuthorizationModuleOptions, ...args: unknown[]) => {
      const impl = pick(opts);
      if (impl !== undefined) {
        if (typeof impl === 'function') return new (impl as Type<T>)(...(args as never[]));
        return impl;
      }
      if (requiredForLocal !== undefined && opts.mode === 'local') {
        throw new AuthorizationConfigurationException(
          `mode='local' requires repositories.${requiredForLocal} ` +
            `(or a custom provider for ${token.description ?? 'this token'})`,
        );
      }
      return makeDefault(opts, ...args);
    },
    inject: [AUTHORIZATION_OPTIONS, ...deps],
  };
}

/**
 * Plug-and-play authorization module.
 *
 *   AuthorizationModule.forRoot({
 *     mode: 'local',
 *     principalResolver: MyResolver,
 *     repositories: { roles, policies, memberships, directPolicies },
 *   })
 */
@Module({})
export class AuthorizationModule {
  static forRoot(options: AuthorizationModuleOptions): DynamicModule {
    return this.build([{ provide: AUTHORIZATION_OPTIONS, useValue: options }], []);
  }

  static forRootAsync(asyncOptions: AuthorizationModuleAsyncOptions): DynamicModule {
    const optionsProvider: FactoryProvider = {
      provide: AUTHORIZATION_OPTIONS,
      useFactory: asyncOptions.useFactory,
      inject: asyncOptions.inject ?? [],
    };
    return this.build([optionsProvider], asyncOptions.imports ?? []);
  }

  private static build(
    optionProviders: Provider[],
    imports: ModuleMetadata['imports'],
  ): DynamicModule {
    const providers: Provider[] = [
      ...optionProviders,
      AuthorizationService,

      // Identity
      resolvable(
        PRINCIPAL_RESOLVER,
        (o) => o.principalResolver,
        () => {
          throw new AuthorizationConfigurationException(
            'AuthorizationModule requires a principalResolver',
          );
        },
      ),
      resolvable(
        ACCOUNT_CONTEXT_RESOLVER,
        (o) => o.accountContextResolver,
        () => new DefaultAccountContextResolver(),
      ),

      // Pure evaluation primitives
      resolvable(
        VARIABLE_RESOLVER,
        (o) => o.variableResolver,
        () => new DefaultVariableResolver(),
      ),
      resolvable(
        CONDITION_EVALUATOR,
        (o) => o.conditionEvaluator,
        (_o, vr) => new DefaultConditionEvaluator(vr as never),
        [VARIABLE_RESOLVER],
      ),
      resolvable(
        POLICY_DECISION_POINT,
        (o) => o.policyDecisionPoint,
        (_o, vr, ce) => new DefaultPolicyDecisionPoint(vr as never, ce as never),
        [VARIABLE_RESOLVER, CONDITION_EVALUATOR],
      ),

      // Repositories (required in local mode)
      resolvable(
        ROLE_REPOSITORY,
        (o) => o.repositories?.roles,
        () => undefined,
        [],
        'roles',
      ),
      resolvable(
        POLICY_REPOSITORY,
        (o) => o.repositories?.policies,
        () => undefined,
        [],
        'policies',
      ),
      resolvable(
        MEMBERSHIP_REPOSITORY,
        (o) => o.repositories?.memberships,
        () => undefined,
        [],
        'memberships',
      ),
      resolvable(
        DIRECT_POLICY_REPOSITORY,
        (o) => o.repositories?.directPolicies,
        () => undefined,
        [],
        'directPolicies',
      ),
      resolvable(
        PRINCIPAL_REPOSITORY,
        (o) => o.repositories?.principals,
        () => undefined,
      ),

      // Retrieval / information points
      {
        provide: POLICY_RETRIEVAL_POINT,
        useFactory: (opts: AuthorizationModuleOptions, memberships, directPolicies, roles) => {
          if (opts.policyRetrievalPoint) {
            const impl = opts.policyRetrievalPoint;
            return typeof impl === 'function'
              ? new (impl as Type<never>)(memberships, directPolicies, roles)
              : impl;
          }
          if (opts.mode === 'remote') return undefined;
          if (!memberships || !directPolicies || !roles) {
            throw new AuthorizationConfigurationException(
              'Local mode requires memberships/directPolicies/roles repositories',
            );
          }
          return new DefaultPolicyRetrievalPoint(memberships, directPolicies, roles);
        },
        inject: [
          AUTHORIZATION_OPTIONS,
          { token: MEMBERSHIP_REPOSITORY, optional: true },
          { token: DIRECT_POLICY_REPOSITORY, optional: true },
          { token: ROLE_REPOSITORY, optional: true },
        ],
      } as FactoryProvider,
      {
        provide: POLICY_INFORMATION_POINT,
        useFactory: (opts: AuthorizationModuleOptions, roles, policies) => {
          if (opts.policyInformationPoint) {
            const impl = opts.policyInformationPoint;
            return typeof impl === 'function' ? new (impl as Type<never>)(roles, policies) : impl;
          }
          if (opts.mode === 'remote') return undefined;
          if (!roles || !policies) {
            throw new AuthorizationConfigurationException(
              'Local mode requires roles/policies repositories',
            );
          }
          return new DefaultPolicyInformationPoint(roles, policies);
        },
        inject: [
          AUTHORIZATION_OPTIONS,
          { token: ROLE_REPOSITORY, optional: true },
          { token: POLICY_REPOSITORY, optional: true },
        ],
      } as FactoryProvider,

      // Evaluator: local embedded or remote HTTP
      {
        provide: AUTHORIZATION_EVALUATOR,
        useFactory: (opts: AuthorizationModuleOptions, prp, pip, pdp) => {
          if (opts.mode === 'remote') {
            return new RemoteAuthorizationEvaluator({
              url: opts.remote?.url ?? opts.evaluatorUrl ?? '',
              timeoutMs: opts.remote?.timeoutMs,
              serviceToken: opts.remote?.serviceToken,
              fetchImpl: opts.remote?.fetchImpl,
            });
          }
          if (!prp || !pip || !pdp) {
            throw new AuthorizationConfigurationException(
              'Local evaluator requires PRP, PIP and PDP',
            );
          }
          return new LocalAuthorizationEvaluator(prp, pip, pdp);
        },
        inject: [
          AUTHORIZATION_OPTIONS,
          { token: POLICY_RETRIEVAL_POINT, optional: true },
          { token: POLICY_INFORMATION_POINT, optional: true },
          { token: POLICY_DECISION_POINT, optional: true },
        ],
      } as FactoryProvider,

      // Observability
      {
        provide: DECISION_LOGGER,
        useFactory: (opts: AuthorizationModuleOptions) => {
          if (opts.logging?.enabled === false) return new NoopDecisionLogger();
          const custom = opts.logging?.logger;
          if (custom !== undefined) {
            return typeof custom === 'function' ? new (custom as Type<never>)() : custom;
          }
          return new ConsoleDecisionLogger();
        },
        inject: [AUTHORIZATION_OPTIONS],
      },
      {
        provide: AUTHORIZATION_METRICS,
        useFactory: (opts: AuthorizationModuleOptions) => {
          const custom = opts.metrics;
          if (custom !== undefined) {
            return typeof custom === 'function' ? new (custom as Type<never>)() : custom;
          }
          return new InMemoryAuthorizationMetrics();
        },
        inject: [AUTHORIZATION_OPTIONS],
      },

      // Guard — only activates where @RequirePermission(s) metadata exists
      { provide: APP_GUARD, useClass: AuthorizationGuard },
    ];

    return {
      module: AuthorizationModule,
      global: true,
      imports,
      providers,
      exports: [
        AuthorizationService,
        AUTHORIZATION_EVALUATOR,
        AUTHORIZATION_OPTIONS,
        AUTHORIZATION_METRICS,
        DECISION_LOGGER,
      ],
    };
  }
}
