import { Injectable } from '@nestjs/common';
import type { AuthorizationVariables } from '../authorization/authorization.types';
import { segmentWildcardMatch } from '../resources/pattern-matcher';
import type { VariableResolver } from '../variables/variable-resolver';
import { DefaultVariableResolver } from '../variables/variable-resolver';

/**
 * Pluggable operator contract. Add operators by registering a new
 * ConditionOperator — the PDP never changes.
 */
export interface ConditionOperator {
  readonly name: string;
  evaluate(actual: unknown, expected: unknown, keyExists: boolean): boolean;
}

function asArray(expected: unknown): unknown[] {
  return Array.isArray(expected) ? expected : [expected];
}

function toNumber(value: unknown): number | undefined {
  const n = typeof value === 'number' ? value : Number(value);
  return Number.isFinite(n) ? n : undefined;
}

class StringEqualsOp implements ConditionOperator {
  readonly name = 'StringEquals';
  evaluate(actual: unknown, expected: unknown): boolean {
    return asArray(expected).some((e) => String(actual) === String(e));
  }
}
class StringNotEqualsOp implements ConditionOperator {
  readonly name = 'StringNotEquals';
  evaluate(actual: unknown, expected: unknown): boolean {
    return asArray(expected).every((e) => String(actual) !== String(e));
  }
}
class StringLikeOp implements ConditionOperator {
  readonly name = 'StringLike';
  evaluate(actual: unknown, expected: unknown): boolean {
    return asArray(expected).some((e) => segmentWildcardMatch(String(e), String(actual)));
  }
}
class StringNotLikeOp implements ConditionOperator {
  readonly name = 'StringNotLike';
  evaluate(actual: unknown, expected: unknown): boolean {
    return asArray(expected).every((e) => !segmentWildcardMatch(String(e), String(actual)));
  }
}
class NumericEqualsOp implements ConditionOperator {
  readonly name = 'NumericEquals';
  evaluate(actual: unknown, expected: unknown): boolean {
    const a = toNumber(actual);
    return a !== undefined && asArray(expected).some((e) => toNumber(e) === a);
  }
}
class NumericGreaterThanOp implements ConditionOperator {
  readonly name = 'NumericGreaterThan';
  evaluate(actual: unknown, expected: unknown): boolean {
    const a = toNumber(actual);
    const e = toNumber(asArray(expected)[0]);
    return a !== undefined && e !== undefined && a > e;
  }
}
class NumericLessThanOp implements ConditionOperator {
  readonly name = 'NumericLessThan';
  evaluate(actual: unknown, expected: unknown): boolean {
    const a = toNumber(actual);
    const e = toNumber(asArray(expected)[0]);
    return a !== undefined && e !== undefined && a < e;
  }
}
class ExistsOp implements ConditionOperator {
  readonly name = 'Exists';
  evaluate(_actual: unknown, expected: unknown, keyExists: boolean): boolean {
    return keyExists === Boolean(asArray(expected)[0]);
  }
}

export interface ConditionEvaluator {
  /** All operator blocks ANDed; all keys within an operator block ANDed. */
  evaluate(
    conditions: Record<string, Record<string, unknown>> | undefined,
    variables: AuthorizationVariables,
  ): boolean;
}

@Injectable()
export class DefaultConditionEvaluator implements ConditionEvaluator {
  private readonly operators = new Map<string, ConditionOperator>();
  private readonly variableResolver: VariableResolver;

  constructor(variableResolver?: VariableResolver, extraOperators: ConditionOperator[] = []) {
    this.variableResolver = variableResolver ?? new DefaultVariableResolver();
    for (const op of [
      new StringEqualsOp(),
      new StringNotEqualsOp(),
      new StringLikeOp(),
      new StringNotLikeOp(),
      new NumericEqualsOp(),
      new NumericGreaterThanOp(),
      new NumericLessThanOp(),
      new ExistsOp(),
      ...extraOperators,
    ]) {
      this.operators.set(op.name, op);
    }
  }

  evaluate(
    conditions: Record<string, Record<string, unknown>> | undefined,
    variables: AuthorizationVariables,
  ): boolean {
    if (!conditions || Object.keys(conditions).length === 0) return true;
    for (const [operatorName, block] of Object.entries(conditions)) {
      const operator = this.operators.get(operatorName);
      if (!operator) return false; // unknown operator => condition cannot be satisfied
      for (const [key, rawExpected] of Object.entries(block)) {
        const keyExists = variables[key] !== undefined && variables[key] !== null;
        const expected =
          typeof rawExpected === 'string'
            ? this.variableResolver.resolve(rawExpected, variables)
            : rawExpected;
        if (!operator.evaluate(variables[key], expected, keyExists)) return false;
      }
    }
    return true;
  }
}
