/** Export the current view as SVG, without a GPL dependency.
 *
 *  `cytoscape-svg` does this job but is GPL-3.0, which would put this MIT
 *  project's distribution under copyleft — see docs/vendor_notes.md. Walking
 *  the live model is a hundred lines and gives us two things the package
 *  cannot: output in our own design tokens, and a function the PDF case report
 *  can call so a report embeds the analyst's actual view rather than a
 *  screenshot of it.
 */
import type { Core } from "cytoscape";
import { readToken } from "./model";
import { formatId } from "../../lib/formatId";

const escape = (value: string) =>
  value.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]!);

function polygon(cx: number, cy: number, w: number, h: number, sides: "diamond" | "hexagon"): string {
  const rx = w / 2;
  const ry = h / 2;
  const points =
    sides === "diamond"
      ? [[cx, cy - ry], [cx + rx, cy], [cx, cy + ry], [cx - rx, cy]]
      : [
          [cx - rx, cy],
          [cx - rx / 2, cy - ry],
          [cx + rx / 2, cy - ry],
          [cx + rx, cy],
          [cx + rx / 2, cy + ry],
          [cx - rx / 2, cy + ry],
        ];
  return points.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(" ");
}

export interface SvgOptions {
  /** Drawn in the corner, so a report page says what it is showing. */
  caption?: string;
  padding?: number;
}

export function toSvg(cy: Core, options: SvgOptions = {}): string {
  const padding = options.padding ?? 24;
  const nodes = cy.nodes(":visible");
  const edges = cy.edges(":visible");

  const box = nodes.boundingBox();
  const width = Math.max(box.w + padding * 2, 200);
  const height = Math.max(box.h + padding * 2, 160) + (options.caption ? 26 : 0);
  const dx = padding - box.x1;
  const dy = padding - box.y1;

  const field = readToken("--field");
  const ink = readToken("--field-ink");
  const muted = readToken("--field-muted");

  const parts: string[] = [];
  parts.push(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width.toFixed(0)}" height="${height.toFixed(0)}" ` +
      `viewBox="0 0 ${width.toFixed(0)} ${height.toFixed(0)}" font-family="IBM Plex Mono, monospace">`,
  );
  parts.push(`<rect width="100%" height="100%" fill="${field}"/>`);
  parts.push(
    `<defs><marker id="a" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="5" markerHeight="5" ` +
      `orient="auto-start-reverse"><path d="M0 0 L8 4 L0 8 z" fill="${muted}"/></marker></defs>`,
  );

  for (const edge of edges) {
    const source = edge.source().position();
    const target = edge.target().position();
    const stroke = edge.hasClass("taint") ? readToken("--node-taint") : edge.style("line-color");
    const dash = edge.style("line-style") === "dashed" ? ' stroke-dasharray="6 4"' : "";
    parts.push(
      `<line x1="${(source.x + dx).toFixed(1)}" y1="${(source.y + dy).toFixed(1)}" ` +
        `x2="${(target.x + dx).toFixed(1)}" y2="${(target.y + dy).toFixed(1)}" ` +
        `stroke="${stroke}" stroke-width="${Number(edge.style("width").toString().replace("px", "")) || 1}"` +
        `${dash} marker-end="url(#a)" opacity="0.9"/>`,
    );
  }

  for (const node of nodes) {
    const { x, y } = node.position();
    const cx = x + dx;
    const cy2 = y + dy;
    const w = node.width();
    const h = node.height();
    const fill = node.style("background-color");
    const type = node.data("type");
    const outline = node.data("alerted")
      ? ` stroke="${readToken("--risk-node-critical")}" stroke-width="2.5"`
      : "";

    if (type === "transaction") {
      parts.push(`<polygon points="${polygon(cx, cy2, w, h, "diamond")}" fill="${fill}"${outline}/>`);
    } else if (type === "ip") {
      parts.push(`<polygon points="${polygon(cx, cy2, w, h, "hexagon")}" fill="${fill}"${outline}/>`);
    } else if (type === "aggregate") {
      parts.push(
        `<rect x="${(cx - w / 2).toFixed(1)}" y="${(cy2 - h / 2).toFixed(1)}" width="${w}" height="${h}" ` +
          `rx="4" fill="${fill}" stroke="${muted}"/>`,
      );
    } else {
      parts.push(`<circle cx="${cx.toFixed(1)}" cy="${cy2.toFixed(1)}" r="${(w / 2).toFixed(1)}" fill="${fill}"${outline}/>`);
    }

    const label = String(node.data("label") ?? node.id());
    parts.push(
      `<text x="${cx.toFixed(1)}" y="${(cy2 + h / 2 + 10).toFixed(1)}" fill="${ink}" font-size="9" ` +
        `text-anchor="middle" opacity="0.8">${escape(formatId(label))}</text>`,
    );
  }

  if (options.caption) {
    parts.push(
      `<text x="${padding}" y="${(height - 10).toFixed(0)}" fill="${muted}" font-size="10">` +
        `${escape(options.caption)}</text>`,
    );
  }

  parts.push("</svg>");
  return parts.join("\n");
}

/** PNG straight off the canvas Cytoscape already maintains. */
export function toPngBlob(cy: Core): Blob {
  const uri = cy.png({ full: true, scale: 2, bg: readToken("--field") });
  const binary = atob(uri.split(",")[1]);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return new Blob([bytes], { type: "image/png" });
}

export function download(content: Blob | string, filename: string, type = "image/svg+xml"): void {
  const blob = typeof content === "string" ? new Blob([content], { type }) : content;
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
