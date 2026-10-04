import { DefaultVariableResolver } from '../src/variables/variable-resolver';

describe('DefaultVariableResolver', () => {
  const resolver = new DefaultVariableResolver();
  const vars = { 'cc:accountId': 'account-123', 'cc:principalId': 'user-123' };

  it('interpolates a single placeholder', () => {
    expect(resolver.resolve('rn:cc-api:billing::${cc:accountId}:Pricing/*', vars)).toBe(
      'rn:cc-api:billing::account-123:Pricing/*',
    );
  });
  it('interpolates multiple placeholders', () => {
    expect(resolver.resolve('${cc:principalId}@${cc:accountId}', vars)).toBe(
      'user-123@account-123',
    );
  });
  it('leaves unknown placeholders verbatim (fail-safe non-match)', () => {
    expect(resolver.resolve('x:${cc:missing}:y', vars)).toBe('x:${cc:missing}:y');
  });
  it('is deterministic and leaves literals untouched', () => {
    expect(resolver.resolve('no placeholders', vars)).toBe('no placeholders');
  });
  it('stringifies non-string values', () => {
    expect(resolver.resolve('n=${n}', { n: 42 })).toBe('n=42');
  });
});
