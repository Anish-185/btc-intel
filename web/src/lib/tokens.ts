/** Cytoscape paints to a canvas and never sees CSS custom properties, so the
 *  few tokens the graph needs are resolved to literal colours once.
 *
 *  The field palette is not themed (see tokens.css), so one read is enough —
 *  but it is a read, not a copy: the stylesheet stays the single source. */
let cache: Record<string, string> = {};

export function token(name: string, fallback = "#7f9bd8"): string {
  if (cache[name]) return cache[name];
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  cache[name] = value || fallback;
  return cache[name];
}

/** Called when the theme changes; the field tokens do not move, but anything
 *  added later that does will pick the new value up. */
export const forgetTokens = () => {
  cache = {};
};
