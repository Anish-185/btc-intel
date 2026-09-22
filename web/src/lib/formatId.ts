/** One way to shorten an identifier, everywhere.
 *
 *  Bitcoin addresses and txids are 34 and 64 characters; drawn in full they
 *  wrap table rows, collide on a graph canvas and push a PDF figure off the
 *  page. Every place that shortens one now calls this, so a fix in one view is
 *  a fix in all of them — and so the *rule* is a thing a test can assert
 *  against rather than a habit each component re-invents.
 *
 *  The full value is never lost: it stays the element's title, the node's id,
 *  and what the copy button puts on the clipboard.
 *
 *  Kept in step with its Python twin, `api/format_id.py`, which does the same
 *  job for the PDF case report. If you change the defaults, change both.
 */

/** Leading characters kept. Enough to tell two addresses apart at a glance:
 *  the script prefix plus four. */
export const ID_HEAD = 6;
/** Trailing characters kept — what an investigator reads back from a note. */
export const ID_TAIL = 4;
/** The character between the two halves. One glyph, not three dots. */
export const ELLIPSIS = "…";

export interface IdFormat {
  head?: number;
  tail?: number;
}

/** The longest string `formatId` can return for a given setting. */
export const maxIdLength = ({ head = ID_HEAD, tail = ID_TAIL }: IdFormat = {}): number =>
  head + ELLIPSIS.length + tail;

/**
 * Middle-truncate an identifier: `bc1qdf…d061`.
 *
 * Values already short enough are returned untouched — shortening a 10-char
 * label to a 11-char one would be worse than leaving it, and an IP address
 * must never be cut, because a half IP is not an identifier at all.
 */
export function formatId(value: string, options: IdFormat = {}): string {
  const { head = ID_HEAD, tail = ID_TAIL } = options;
  const text = String(value ?? "");
  if (text.length <= maxIdLength(options)) return text;
  return `${text.slice(0, head)}${ELLIPSIS}${text.slice(-tail)}`;
}

/** True when `formatId` would leave the value alone. */
export const fitsWhole = (value: string, options: IdFormat = {}): boolean =>
  String(value ?? "").length <= maxIdLength(options);
