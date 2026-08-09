/**
 * Unit tests — stemmer.ts (Signal Decision 2)
 * Porter stemmer, NFC normalisation, set-intersection match
 */
import { stemKeyword, stemKeywords, keywordsMatch } from '../../src/services/stemmer';

describe('stemKeyword', () => {
  test.each([
    ['traveling', 'travel'],
    ['hotels', 'hotel'],
    ['booking', 'book'],
    ['financial', 'financi'],
    ['TRAVEL', 'travel'],         // case-insensitive
    ['travel', 'travel'],         // idempotent
  ])('stems "%s" → "%s"', (input, expected) => {
    expect(stemKeyword(input)).toBe(expected);
  });

  test('NFC-normalises unicode before stemming', () => {
    // café with combining accent vs precomposed — should match
    const a = stemKeyword('caf\u00E9');    // precomposed é
    const b = stemKeyword('cafe\u0301');   // combining accent
    expect(a).toBe(b);
  });
});

describe('stemKeywords', () => {
  test('deduplicates stemmed results', () => {
    const result = stemKeywords(['travel', 'traveling', 'travels']);
    expect(result.filter((k) => k === 'travel').length).toBe(1);
  });

  test('returns sorted array for determinism', () => {
    const result = stemKeywords(['hotel', 'airline', 'travel']);
    expect(result).toEqual([...result].sort());
  });
});

describe('keywordsMatch — Signal Decision 2: set intersection ≥1', () => {
  test('matches when one stemmed keyword intersects', () => {
    expect(keywordsMatch(['travel', 'hotel'], ['hotel', 'resort'])).toBe(true);
  });

  test('no match when sets are disjoint', () => {
    expect(keywordsMatch(['financi', 'invest'], ['travel', 'hotel'])).toBe(false);
  });

  test('match is case-insensitive (stems already lowercased)', () => {
    expect(keywordsMatch(['travel'], ['travel'])).toBe(true);
  });

  test('empty request keywords → no match', () => {
    expect(keywordsMatch([], ['travel'])).toBe(false);
  });

  test('empty campaign keywords → no match', () => {
    expect(keywordsMatch(['travel'], [])).toBe(false);
  });

  test('stemmed form matches: "traveling" stems → matches "travel" campaign keyword', () => {
    const requestStemmed = stemKeywords(['traveling', 'booking']);
    const campaignStemmed = ['travel', 'hotel'];
    expect(keywordsMatch(requestStemmed, campaignStemmed)).toBe(true);
  });
});
