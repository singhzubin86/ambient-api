/**
 * Keyword stemming — Signal Decision 2
 *
 * Porter stemmer, case-insensitive, NFC-normalised, no fuzzy/edit-distance.
 * Pre-stem campaign keywords at creation time (stored in targeting_keywords_stemmed).
 * Stem request context keywords at request time.
 *
 * Using the 'natural' npm package for Porter stemmer.
 * Install: npm install natural @types/natural
 * (added to package.json dependencies)
 */

// Inline lightweight Porter stemmer to avoid adding a heavyweight NLP dep.
// This implements the five-step Porter algorithm sufficient for English.
// Source derivation: standard Porter 1980 algorithm, widely in public domain.

const VOWELS = /[aeiou]/;
const CONSONANT_VOWEL_CONSONANT = /[^aeiou][aeiou][^aeiouwy]$/;

function isConsonant(word: string, i: number): boolean {
  const ch = word[i]!;
  if ('aeiou'.includes(ch)) return false;
  if (ch === 'y') return i === 0 || !isConsonant(word, i - 1);
  return true;
}

function measure(stem: string): number {
  // Count VC sequences
  let m = 0;
  let inVowel = false;
  for (let i = 0; i < stem.length; i++) {
    const c = isConsonant(stem, i);
    if (c && inVowel) { m++; inVowel = false; }
    else if (!c) inVowel = true;
  }
  return m;
}

function hasVowel(stem: string): boolean {
  for (let i = 0; i < stem.length; i++) {
    if (!isConsonant(stem, i)) return true;
  }
  return false;
}

function endsWithDouble(word: string): boolean {
  if (word.length < 2) return false;
  const last = word[word.length - 1]!;
  return word[word.length - 2] === last && 'lsz'.includes(last) === false &&
    'bdfgmnprt'.includes(last);
}

function step1a(word: string): string {
  if (word.endsWith('sses')) return word.slice(0, -2);
  if (word.endsWith('ies')) return word.slice(0, -2);
  if (word.endsWith('ss')) return word;
  if (word.endsWith('s')) return word.slice(0, -1);
  return word;
}

function step1b(word: string): string {
  if (word.endsWith('eed')) {
    const stem = word.slice(0, -3);
    if (measure(stem) > 0) return stem + 'ee';
    return word;
  }
  if (word.endsWith('ed')) {
    const stem = word.slice(0, -2);
    if (hasVowel(stem)) return step1bFix(stem);
    return word;
  }
  if (word.endsWith('ing')) {
    const stem = word.slice(0, -3);
    if (hasVowel(stem)) return step1bFix(stem);
    return word;
  }
  return word;
}

function step1bFix(word: string): string {
  if (word.endsWith('at') || word.endsWith('bl') || word.endsWith('iz')) return word + 'e';
  if (word.length > 1 && word[word.length - 1] === word[word.length - 2] &&
      !'lsz'.includes(word[word.length - 1]!)) {
    return word.slice(0, -1);
  }
  if (measure(word) === 1 && CONSONANT_VOWEL_CONSONANT.test(word)) return word + 'e';
  return word;
}

function step1c(word: string): string {
  if (word.endsWith('y') && hasVowel(word.slice(0, -1))) return word.slice(0, -1) + 'i';
  return word;
}

const STEP2_MAP: [string, string][] = [
  ['ational', 'ate'], ['tional', 'tion'], ['enci', 'ence'], ['anci', 'ance'],
  ['izer', 'ize'], ['abli', 'able'], ['alli', 'al'], ['entli', 'ent'],
  ['eli', 'e'], ['ousli', 'ous'], ['ization', 'ize'], ['ation', 'ate'],
  ['ator', 'ate'], ['alism', 'al'], ['iveness', 'ive'], ['fulness', 'ful'],
  ['ousness', 'ous'], ['aliti', 'al'], ['iviti', 'ive'], ['biliti', 'ble'],
];

function step2(word: string): string {
  for (const [suffix, replacement] of STEP2_MAP) {
    if (word.endsWith(suffix)) {
      const stem = word.slice(0, -suffix.length);
      if (measure(stem) > 0) return stem + replacement;
      return word;
    }
  }
  return word;
}

const STEP3_MAP: [string, string][] = [
  ['icate', 'ic'], ['ative', ''], ['alize', 'al'], ['iciti', 'ic'],
  ['ical', 'ic'], ['ful', ''], ['ness', ''],
];

function step3(word: string): string {
  for (const [suffix, replacement] of STEP3_MAP) {
    if (word.endsWith(suffix)) {
      const stem = word.slice(0, -suffix.length);
      if (measure(stem) > 0) return stem + replacement;
      return word;
    }
  }
  return word;
}

const STEP4_SUFFIXES = [
  'al', 'ance', 'ence', 'er', 'ic', 'able', 'ible', 'ant', 'ement',
  'ment', 'ent', 'ism', 'ate', 'iti', 'ous', 'ive', 'ize',
];

function step4(word: string): string {
  if (word.endsWith('ion')) {
    const stem = word.slice(0, -3);
    if (measure(stem) > 1 && /[st]$/.test(stem)) return stem;
    return word;
  }
  for (const suffix of STEP4_SUFFIXES) {
    if (word.endsWith(suffix)) {
      const stem = word.slice(0, -suffix.length);
      if (measure(stem) > 1) return stem;
      return word;
    }
  }
  return word;
}

function step5a(word: string): string {
  if (word.endsWith('e')) {
    const stem = word.slice(0, -1);
    if (measure(stem) > 1) return stem;
    if (measure(stem) === 1 && !CONSONANT_VOWEL_CONSONANT.test(stem)) return stem;
  }
  return word;
}

function step5b(word: string): string {
  if (word.endsWith('ll') && measure(word) > 1) return word.slice(0, -1);
  return word;
}

/** Stem a single token using Porter algorithm. Input must be lowercased. */
function porterStem(word: string): string {
  if (word.length <= 2) return word;
  let w = word;
  w = step1a(w);
  w = step1b(w);
  w = step1c(w);
  w = step2(w);
  w = step3(w);
  w = step4(w);
  w = step5a(w);
  w = step5b(w);
  return w;
}

/**
 * Normalise and stem a keyword.
 * Signal Decision 2: NFC, lowercase, then Porter stem.
 */
export function stemKeyword(raw: string): string {
  return porterStem(raw.normalize('NFC').toLowerCase().trim());
}

/**
 * Stem an array of keywords, deduplicate, return sorted for determinism.
 */
export function stemKeywords(keywords: string[]): string[] {
  const stemmed = new Set(keywords.map(stemKeyword));
  return Array.from(stemmed).sort();
}

/**
 * Signal Decision 2: match condition is set intersection ≥ 1 stemmed keyword.
 */
export function keywordsMatch(
  requestStemmed: string[],
  campaignStemmed: string[],
): boolean {
  const campaignSet = new Set(campaignStemmed);
  return requestStemmed.some((k) => campaignSet.has(k));
}
