import { normalize } from "./normalize.js";

export function matchLength(completion: string, token: string): number {
  const actual = normalize(completion), expected = normalize(token);
  let matched = 0;
  while (matched < expected.length && actual[matched] === expected[matched]) matched++;
  return matched;
}
/** Idealized random-character null model; not a measured model contamination probability. */
export const nullProbability = (matched: number): number => 26 ** -Math.min(matched, 2) * 16 ** -Math.max(matched - 2, 0);
export const adjusted = (p: number, comparisons: number): number => Math.min(1, p * comparisons);
