import { Body, Controller, Get, HttpCode, Post } from '@nestjs/common';
import { AuthorizationService, type AuthorizationRequest } from 'policygate';
import { AuthorizeRequestDto } from './authorize.dto';

@Controller()
export class AuthorizeController {
  constructor(private readonly authorization: AuthorizationService) {}

  @Get('/health')
  health(): { status: string } {
    return { status: 'ok' };
  }

  /**
   * Central policy evaluation endpoint.
   * Returns the PDP decision verbatim; this service's own AuthorizationGuard
   * only protects endpoints carrying @RequirePermission metadata, so this
   * route stays open (guard it behind service-token middleware in prod).
   */
  @Post('/v1/authorize')
  @HttpCode(200)
  async authorize(@Body() body: AuthorizeRequestDto) {
    const request: AuthorizationRequest = {
      principal: {
        id: body.principal.id,
        type: body.principal.type,
        authenticated: body.principal.authenticated ?? true,
        metadata: body.principal.metadata,
      },
      action: body.action,
      resource: body.resource,
      accountId: body.accountId,
      variables: body.variables,
      requestContext: body.requestContext,
    };
    const decision = await this.authorization.evaluate(request);
    return {
      allowed: decision.allowed,
      reasons: decision.reasons,
      evaluatedContexts: decision.evaluatedContexts,
      matchedStatements: decision.matchedStatements,
      matchedPolicies: decision.matchedPolicies,
      grantedByContextId: decision.grantedByContextId,
    };
  }
}
