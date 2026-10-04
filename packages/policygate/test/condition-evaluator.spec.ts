import {
  DefaultConditionEvaluator,
  type ConditionOperator,
} from '../src/conditions/condition-evaluator';

describe('DefaultConditionEvaluator', () => {
  const ce = new DefaultConditionEvaluator();
  const vars = {
    'cc:accountId': 'account-123',
    'cc:region': 'us-east-1',
    'cc:amount': 500,
  };

  it('empty conditions always pass', () => {
    expect(ce.evaluate(undefined, vars)).toBe(true);
    expect(ce.evaluate({}, vars)).toBe(true);
  });

  it('StringEquals', () => {
    expect(ce.evaluate({ StringEquals: { 'cc:accountId': 'account-123' } }, vars)).toBe(true);
    expect(ce.evaluate({ StringEquals: { 'cc:accountId': 'account-456' } }, vars)).toBe(false);
    expect(
      ce.evaluate({ StringEquals: { 'cc:accountId': ['account-456', 'account-123'] } }, vars),
    ).toBe(true);
  });
  it('StringNotEquals', () => {
    expect(ce.evaluate({ StringNotEquals: { 'cc:accountId': 'account-456' } }, vars)).toBe(true);
    expect(ce.evaluate({ StringNotEquals: { 'cc:accountId': 'account-123' } }, vars)).toBe(false);
  });
  it('StringLike', () => {
    expect(ce.evaluate({ StringLike: { 'cc:region': 'us-*' } }, vars)).toBe(true);
    expect(ce.evaluate({ StringLike: { 'cc:region': 'eu-*' } }, vars)).toBe(false);
  });
  it('StringNotLike', () => {
    expect(ce.evaluate({ StringNotLike: { 'cc:region': 'eu-*' } }, vars)).toBe(true);
    expect(ce.evaluate({ StringNotLike: { 'cc:region': 'us-*' } }, vars)).toBe(false);
  });
  it('numeric operators', () => {
    expect(ce.evaluate({ NumericEquals: { 'cc:amount': 500 } }, vars)).toBe(true);
    expect(ce.evaluate({ NumericEquals: { 'cc:amount': '500' } }, vars)).toBe(true);
    expect(ce.evaluate({ NumericGreaterThan: { 'cc:amount': 100 } }, vars)).toBe(true);
    expect(ce.evaluate({ NumericGreaterThan: { 'cc:amount': 500 } }, vars)).toBe(false);
    expect(ce.evaluate({ NumericLessThan: { 'cc:amount': 1000 } }, vars)).toBe(true);
    expect(ce.evaluate({ NumericLessThan: { 'cc:amount': 500 } }, vars)).toBe(false);
    expect(ce.evaluate({ NumericEquals: { 'cc:amount': 'abc' } }, vars)).toBe(false);
  });
  it('Exists', () => {
    expect(ce.evaluate({ Exists: { 'cc:accountId': true } }, vars)).toBe(true);
    expect(ce.evaluate({ Exists: { 'cc:missing': true } }, vars)).toBe(false);
    expect(ce.evaluate({ Exists: { 'cc:missing': false } }, vars)).toBe(true);
  });
  it('interpolates expected values', () => {
    expect(ce.evaluate({ StringEquals: { 'cc:accountId': '${cc:accountId}' } }, vars)).toBe(true);
  });
  it('ANDs operators and keys', () => {
    expect(
      ce.evaluate(
        {
          StringEquals: { 'cc:accountId': 'account-123' },
          NumericGreaterThan: { 'cc:amount': 100 },
        },
        vars,
      ),
    ).toBe(true);
    expect(
      ce.evaluate(
        {
          StringEquals: { 'cc:accountId': 'account-123' },
          NumericGreaterThan: { 'cc:amount': 999 },
        },
        vars,
      ),
    ).toBe(false);
  });
  it('unknown operator fails closed', () => {
    expect(ce.evaluate({ HolographicEquals: { 'cc:accountId': 'x' } }, vars)).toBe(false);
  });
  it('extensible: custom operator can be registered without touching the PDP', () => {
    class StartsWithOp implements ConditionOperator {
      readonly name = 'StartsWith';
      evaluate(actual: unknown, expected: unknown): boolean {
        return String(actual).startsWith(String(expected));
      }
    }
    const custom = new DefaultConditionEvaluator(undefined, [new StartsWithOp()]);
    expect(custom.evaluate({ StartsWith: { 'cc:region': 'us' } }, vars)).toBe(true);
    expect(custom.evaluate({ StartsWith: { 'cc:region': 'eu' } }, vars)).toBe(false);
  });
});
