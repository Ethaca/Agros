export const normalize = (s: string): string => s.normalize("NFKC").replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]/g, "").replace(/[^a-z0-9]/gi, "").toLowerCase();

/** Mapping is per grapheme so compatibility characters and combining sequences retain original offsets. */
export function normalizedWithOffsets(s: string): { text: string; offsets: number[] } {
  let text = "";
  const offsets: number[] = [];
  for (const segment of new Intl.Segmenter("en", { granularity: "grapheme" }).segment(s)) {
    const part = normalize(segment.segment);
    text += part;
    for (let i = 0; i < part.length; i++) offsets.push(segment.index);
  }
  return { text, offsets };
}
