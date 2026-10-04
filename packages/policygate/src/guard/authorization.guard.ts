import { CanActivate, ExecutionContext, Inject, Injectable, Optional } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type {
  AuthorizationRequest,
  RequiredAuthorizationMetadata,
} from '../authorization/authorization.types';
import {
  ACCOUNT_CONTEXT_RESOLVER,
  PRINCIPAL_RESOLVER,
  REQUIRED_AUTHORIZATION_KEY,
  VARIABLE_RESOLVER,
} from '../authorization/authorization.constants';
import type { PrincipalResolver } from '../authentication/principal-resolver';
import type { AccountContextResolver } from './account-context-resolver';
import { DefaultAccountContextResolver } from './account-context-resolver';
import type { VariableResolver } from '../variables/variable-resolver';
import { DefaultVariableResolver } from '../variables/variable-resolver';
import { AuthorizationService } from '../authorization/authorization.service';
import {
  AuthorizationDeniedException,
  AuthorizationEvaluationException,
} from '../exceptions/authorization.exceptions';

/**
 * Global guard (registered via APP_GUARD unless globalGuard=false).
 *
 * Pipeline: principal -> metadata -> trusted account context -> resolve
 * resource template -> evaluator (PRP/PIP/PDP or remote) -> allow/deny.
 * The handler never runs unless every required check (per `match` mode)
 * succeeds. All failures are fail-closed.
 */
@Injectable()
export class AuthorizationGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly authorizationService: AuthorizationService,
    @Inject(PRINCIPAL_RESOLVER) private readonly principalResolver: PrincipalResolver,
    @Optional()
    @Inject(ACCOUNT_CONTEXT_RESOLVER)
    accountContextResolver: AccountContextResolver | null,
    @Optional()
    @Inject(VARIABLE_RESOLVER)
    variableResolver: VariableResolver | null,
  ) {
    this.accountContextResolver = accountContextResolver ?? new DefaultAccountContextResolver();
    this.variableResolver = variableResolver ?? new DefaultVariableResolver();
  }

  private readonly accountContextResolver: AccountContextResolver;
  private readonly variableResolver: VariableResolver;

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const metadata = this.reflector.getAllAndOverride<RequiredAuthorizationMetadata | undefined>(
      REQUIRED_AUTHORIZATION_KEY,
      [context.getHandler(), context.getClass()],
    );
    // Endpoints without authorization metadata are not protected by this guard.
    if (!metadata || metadata.checks.length === 0) return true;

    const principal = await this.principalResolver.resolve(context);
    this.attachPrincipal(context, principal);
    const accountContext = await this.accountContextResolver.resolve(context, principal);

    const correlationId = this.correlationId(context);
    const failedChecks: { action: string; resource: string }[] = [];
    const matchAll = metadata.match === 'ALL';
    let anyAllowed = false;
    let evaluationError: unknown;

    for (const check of metadata.checks) {
      const variables = { ...accountContext.variables };
      const resource = this.variableResolver.resolve(check.resource, variables);
      const action = this.variableResolver.resolve(check.action, variables);

      const request: AuthorizationRequest = {
        principal,
        action,
        resource,
        accountId: accountContext.accountId,
        variables,
        requestContext: { correlationId },
      };

      try {
        const decision = await this.authorizationService.evaluate(request);
        if (decision.allowed) {
          anyAllowed = true;
          if (!matchAll) return true;
        } else {
          failedChecks.push({ action, resource });
          if (matchAll) break;
        }
      } catch (err) {
        // Denied exceptions from evaluate() are impossible (decision-driven),
        // but evaluation failures must fail closed regardless.
        if (err instanceof AuthorizationDeniedException) {
          failedChecks.push({ action: check.action, resource });
          if (matchAll) break;
          continue;
        }
        const wrapped =
          err instanceof AuthorizationEvaluationException
            ? err
            : new AuthorizationEvaluationException('Authorization evaluation failed', err);
        if (matchAll) {
          // ALL: one failed check means the requirement cannot be met.
          throw wrapped;
        }
        // ANY: this check cannot grant access, but another check may still
        // independently authorize the request — the error is deferred.
        evaluationError = wrapped;
        failedChecks.push({ action, resource });
        continue;
      }
    }

    if (matchAll && failedChecks.length === 0 && metadata.checks.length > 0) return true;
    if (!matchAll && anyAllowed) return true;

    // No check authorized. If the only reason was an evaluation failure,
    // surface the error (fail closed) rather than a plain 403 — operators
    // must see a broken evaluator, not a silent deny.
    if (evaluationError !== undefined) throw evaluationError;
    throw new AuthorizationDeniedException(failedChecks);
  }

  /** Exposes the resolved principal to handlers via request.authzPrincipal. */
  private attachPrincipal(context: ExecutionContext, principal: unknown): void {
    try {
      const req = context.switchToHttp().getRequest<Record<string, unknown>>();
      if (req && typeof req === 'object') req['authzPrincipal'] = principal;
    } catch {
      /* non-HTTP transport */
    }
  }

  private correlationId(context: ExecutionContext): string | undefined {
    try {
      const req = context
        .switchToHttp()
        .getRequest<{ headers?: Record<string, string | string[] | undefined> }>();
      const v = req?.headers?.['x-correlation-id'] ?? req?.headers?.['x-request-id'];
      return Array.isArray(v) ? v[0] : v;
    } catch {
      return undefined;
    }
  }
}
