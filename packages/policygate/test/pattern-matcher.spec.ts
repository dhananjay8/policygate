import { matchAnyPattern, segmentWildcardMatch } from '../src/resources/pattern-matcher';

describe('segmentWildcardMatch', () => {
  describe('actions', () => {
    it('exact match', () => {
      expect(segmentWildcardMatch('billing:ReadPricing', 'billing:ReadPricing')).toBe(true);
    });
    it('segment wildcard matches same-segment suffix', () => {
      expect(segmentWildcardMatch('billing:*', 'billing:ReadPricing')).toBe(true);
      expect(segmentWildcardMatch('billing:*', 'billing:ReadInvoice')).toBe(true);
    });
    it('wildcard does not cross segment boundary', () => {
      expect(segmentWildcardMatch('billing:*', 'billing:x:y')).toBe(false);
      expect(segmentWildcardMatch('billing:Read*', 'billing:ReadPricing')).toBe(true);
      expect(segmentWildcardMatch('billing:Read*', 'billing:ReadPricing:x')).toBe(false);
    });
    it('mismatch', () => {
      expect(segmentWildcardMatch('billing:ReadPricing', 'billing:CreateRefund')).toBe(false);
      expect(segmentWildcardMatch('billing:*', 'orders:Read')).toBe(false);
    });
    it('bare * matches everything', () => {
      expect(segmentWildcardMatch('*', 'anything:at:all')).toBe(true);
    });
    it('does not substring-match', () => {
      expect(segmentWildcardMatch('billing:Read', 'billing:ReadPricing')).toBe(false);
    });
  });

  describe('resources', () => {
    const rn = (acct: string, rest: string) => `rn:cc-api:billing::${acct}:${rest}`;
    it('exact match', () => {
      expect(
        segmentWildcardMatch(
          rn('account-123', 'Pricing/current'),
          rn('account-123', 'Pricing/current'),
        ),
      ).toBe(true);
    });
    it('trailing wildcard matches resource identifier', () => {
      expect(
        segmentWildcardMatch(rn('account-123', 'Pricing/*'), rn('account-123', 'Pricing/current')),
      ).toBe(true);
    });
    it('account segment mismatch does not match', () => {
      expect(
        segmentWildcardMatch(rn('account-123', 'Pricing/*'), rn('account-456', 'Pricing/current')),
      ).toBe(false);
    });
    it('wildcard cannot cross colon into another account', () => {
      // `*` is confined to its own segment — it can't swallow 'acct:rest'
      expect(
        segmentWildcardMatch('rn:cc-api:billing::*', rn('account-456', 'Pricing/current')),
      ).toBe(false);
      // account-position wildcard + resource wildcard matches
      expect(
        segmentWildcardMatch('rn:cc-api:billing::*:*', rn('account-456', 'Pricing/current')),
      ).toBe(true);
      expect(
        segmentWildcardMatch(rn('account-*', 'Pricing/*'), rn('account-456', 'Pricing/x')),
      ).toBe(true); // prefix wildcard ok
      expect(segmentWildcardMatch(rn('account-123', '*'), rn('account-123:x', 'Pricing/x'))).toBe(
        false,
      );
    });
    it('literal colons must align', () => {
      expect(segmentWildcardMatch('rn:a:b::acct:X/1', 'rn:a:b::acct:X/1')).toBe(true);
      expect(segmentWildcardMatch('rn:a:b::acct:X/1', 'rn:a:c::acct:X/1')).toBe(false);
    });
  });

  describe('matchAnyPattern', () => {
    it('true when any pattern matches', () => {
      expect(matchAnyPattern(['billing:ReadInvoice', 'billing:*'], 'billing:ReadPricing')).toBe(
        true,
      );
    });
    it('false when none match', () => {
      expect(matchAnyPattern(['a:b', 'c:*'], 'billing:ReadPricing')).toBe(false);
    });
  });
});
