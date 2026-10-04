import { SetMetadata } from '@nestjs/common';
import { REQUIRED_AUTHORIZATION_KEY } from '../authorization/authorization.constants';
import type {
  RequiredAuthorizationMetadata,
  RequiredPermission,
} from '../authorization/authorization.types';

/**
 * Single required check.
 *   @RequirePermission({ action: 'billing:ReadPricing',
 *                        resource: 'rn:cc-api:billing::${cc:accountId}:Pricing/*' })
 */
export const RequirePermission = (check: RequiredPermission) =>
  SetMetadata(REQUIRED_AUTHORIZATION_KEY, {
    checks: [check],
    match: 'ALL',
  } satisfies RequiredAuthorizationMetadata);

export interface RequirePermissionsOptions {
  /**
   * ANY (default): at least one check must independently allow.
   * ALL: every check must allow.
   */
  match?: 'ANY' | 'ALL';
}

/**
 * Multiple independent checks. Defaults to ANY semantics:
 *   @RequirePermissions([{action, resource}, {action, resource}])
 * or explicitly:
 *   @RequirePermissions([{...}, {...}], { match: 'ALL' })
 */
export const RequirePermissions = (
  checks: RequiredPermission[],
  options?: RequirePermissionsOptions,
) => {
  const match = options?.match ?? 'ANY';
  return SetMetadata(REQUIRED_AUTHORIZATION_KEY, {
    checks,
    match,
  } satisfies RequiredAuthorizationMetadata);
};
