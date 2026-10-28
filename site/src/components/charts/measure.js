// Approximate rendered text widths (px) for sizing diagram boxes at build time.
// Average advance per character, measured on Inter and JetBrains Mono at the
// sizes the diagrams use; slightly generous so boxes never come out tight.
export const PAD = 18;  // inner padding of a node, left and right

export const sansW = (s, px, weight = 400) => s.length * px * (weight >= 600 ? 0.6 : 0.56);
export const monoW = (s, px = 9.5, tracking = 0.12) => s.length * px * (0.6 + tracking);

/** Width a node needs for its eyebrow, name (15px semibold) and role (12px). */
export function nodeW({ eyebrow = "", name = "", role = "" }) {
  return Math.ceil(Math.max(monoW(eyebrow.toUpperCase()), sansW(name, 15, 600), sansW(role, 12)) + 2 * PAD);
}
