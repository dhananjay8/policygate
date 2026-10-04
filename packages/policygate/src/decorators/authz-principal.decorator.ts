import { createParamDecorator, type ExecutionContext } from '@nestjs/common';
import type { Principal } from '../authorization/authorization.types';
import { UnauthenticatedException } from '../exceptions/authorization.exceptions';

/**
 * Injects the Principal resolved by the AuthorizationGuard.
 *   getFeature(@AuthzPrincipal() principal: Principal)
 * Throws UnauthenticatedException if the guard never ran.
 */
export const AuthzPrincipal = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): Principal => {
    const req = ctx.switchToHttp().getRequest<{ authzPrincipal?: Principal }>();
    if (!req.authzPrincipal) {
      throw new UnauthenticatedException(
        'No resolved principal on request — is the AuthorizationGuard active?',
      );
    }
    return req.authzPrincipal;
  },
);
