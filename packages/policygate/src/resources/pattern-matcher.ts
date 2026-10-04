/**
 * Segment-aware wildcard matcher shared by actions and resources.
 *
 * `*` matches zero or more characters *within* a `:`-separated segment.
 * It never crosses a `:` boundary, so `billing:*` matches
 * `billing:ReadPricing` but not `billing:x:y`, and
 * `rn:a:b::acct:Pricing/*` cannot match a different account segment.
 * This avoids unsafe substring matching.
 */
export function segmentWildcardMatch(pattern: string, value: string): boolean {
  if (pattern === '*') return true;
  if (!pattern.includes('*')) return pattern === value;

  let regex = '^';
  for (const ch of pattern) {
    if (ch === '*') {
      regex += '[^:]*';
    } else {
      regex += escapeRegExp(ch);
    }
  }
  regex += '$';
  return new RegExp(regex).test(value);
}

export function matchAnyPattern(patterns: readonly string[], value: string): boolean {
  return patterns.some((p) => segmentWildcardMatch(p, value));
}

function escapeRegExp(ch: string): string {
  return /[.+?^${}()|[\]\\]/.test(ch) ? `\\${ch}` : ch;
}
