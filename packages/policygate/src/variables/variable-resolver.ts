import { Injectable } from '@nestjs/common';
import type { AuthorizationVariables } from '../authorization/authorization.types';

const PLACEHOLDER = /\$\{([^}]+)\}/g;

export interface VariableResolver {
  resolve(expression: string, context: AuthorizationVariables): string;
}

/**
 * Deterministic `${key}` interpolation. Unresolved placeholders are kept
 * verbatim — a literal like `${cc:accountId}` can never equal a real
 * account segment, so the statement simply fails to match (fail-safe,
 * never fail-open).
 */
@Injectable()
export class DefaultVariableResolver implements VariableResolver {
  resolve(expression: string, context: AuthorizationVariables): string {
    return expression.replace(PLACEHOLDER, (raw, key: string) => {
      const value = context[key.trim()];
      if (value === undefined || value === null) return raw;
      return String(value);
    });
  }

  /** Whether an expression still contains unresolved placeholders. */
  hasUnresolved(expression: string): boolean {
    return PLACEHOLDER.test(expression);
  }
}
