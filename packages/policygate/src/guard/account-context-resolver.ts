import { Injectable, type ExecutionContext } from '@nestjs/common';
import type { AccountAuthorizationContext, Principal } from '../authorization/authorization.types';

/**
 * Resolves the *requested* account context from the incoming request and
 * exposes safe interpolation variables. The account id extracted here is
 * NEVER trusted as authorization — it is only used to select which
 * server-side membership context the PDP may evaluate.
 */
export interface AccountContextResolver {
  resolve(context: ExecutionContext, principal: Principal): Promise<AccountAuthorizationContext>;
}

interface HttpRequestShape {
  params?: Record<string, string>;
  query?: Record<string, unknown>;
  headers?: Record<string, string | string[] | undefined>;
}

/**
 * Default resolver: reads `params.accountId` (route param) and exposes all
 * route params as `cc:<paramName>` variables, plus `cc:principalId`.
 * Route-param variables are interpolated into resource templates; the
 * `cc:accountId` variable used inside policy statements always comes from
 * the trusted evaluation context (set by the PDP), never from the client.
 */
@Injectable()
export class DefaultAccountContextResolver implements AccountContextResolver {
  async resolve(
    context: ExecutionContext,
    principal: Principal,
  ): Promise<AccountAuthorizationContext> {
    const req = context.switchToHttp().getRequest<HttpRequestShape>();
    const params = req.params ?? {};
    const variables: Record<string, unknown> = { 'cc:principalId': principal.id };
    for (const [key, value] of Object.entries(params)) {
      variables[`cc:${key}`] = value;
    }
    const accountId = params['accountId'];
    if (accountId !== undefined) variables['cc:accountId'] = accountId;
    return { accountId, variables };
  }
}
