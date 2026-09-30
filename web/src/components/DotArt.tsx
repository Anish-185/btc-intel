/** A picture drawn as dots, squares or hex glyphs from a small greyscale ink
 *  map in public/art/ (built by scripts/build-art.sh). The canvas takes its
 *  colour from CSS `color`, so the same file works on paper, on cobalt and in
 *  both themes.
 *
 *  `reveal` sweeps the cells in from the left and right edges toward the
 *  middle, once, on first sight. Reduced motion draws the final frame. */
import { useEffect, useRef } from "react";
import { reducedMotion } from "../lib/motion";

type Mode = "dot" | "square" | "glyph";

const HEX = "0123456789abcdef";

export function DotArt({
  name,
  mode = "dot",
  cell = 7,
  reveal = false,
  glyphs = HEX,
  className,
}: {
  name: string;
  mode?: Mode;
  cell?: number;
  reveal?: boolean;
  glyphs?: string;
  className?: string;
}) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    let ink: Float32Array | null = null;
    let iw = 0;
    let ih = 0;
    let raf = 0;
    let revealed = !reveal || reducedMotion();
    const dpr = Math.min(devicePixelRatio || 1, 2);

    const draw = (progress = 1) => {
      if (!ink) return;
      const { width, height } = canvas.getBoundingClientRect();
      canvas.width = Math.max(1, Math.round(width * dpr));
      canvas.height = Math.max(1, Math.round(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, width, height);
      ctx.fillStyle = getComputedStyle(canvas).color;
      ctx.font = `${cell * 1.15}px "IBM Plex Mono", monospace`;
      ctx.textAlign = "center";
      ctx.textBaseline = "middle";

      // Contain: the whole picture, centred, on a whole number of cells.
      const cols = Math.floor(width / cell);
      const rows = Math.floor(height / cell);
      const scale = Math.min(cols / iw, rows / ih);
      const dw = Math.floor(iw * scale);
      const dh = Math.floor(ih * scale);
      const ox = Math.floor((cols - dw) / 2);
      const oy = Math.floor((rows - dh) / 2);

      // Box-average each cell's block of the source, so thin lines thin out
      // instead of disappearing between samples.
      const src = ink;
      const cellInk = (x: number, y: number) => {
        const x0 = Math.floor(x / scale);
        const y0 = Math.floor(y / scale);
        const x1 = Math.max(x0 + 1, Math.min(iw, Math.floor((x + 1) / scale)));
        const y1 = Math.max(y0 + 1, Math.min(ih, Math.floor((y + 1) / scale)));
        let sum = 0;
        for (let yy = y0; yy < y1; yy++) for (let xx = x0; xx < x1; xx++) sum += src[yy * iw + xx];
        return Math.pow(sum / ((x1 - x0) * (y1 - y0)), 0.7);
      };

      for (let y = 0; y < dh; y++) {
        for (let x = 0; x < dw; x++) {
          const v = cellInk(x, y);
          if (v < 0.12) continue;
          // Sweep from both edges toward the centre.
          const edge = Math.min(x, dw - 1 - x) / (dw / 2);
          if (edge > progress) continue;
          const cx = (ox + x + 0.5) * cell;
          const cy = (oy + y + 0.5) * cell;
          if (mode === "glyph") {
            ctx.globalAlpha = Math.min(1, v * 1.6);
            ctx.fillText(glyphs[(x * 7 + y * 13) % glyphs.length], cx, cy);
          } else if (mode === "square") {
            const s = Math.max(1, cell * 0.86 * Math.sqrt(v));
            ctx.fillRect(cx - s / 2, cy - s / 2, s, s);
          } else {
            ctx.beginPath();
            ctx.arc(cx, cy, Math.max(0.6, (cell / 2) * 0.92 * Math.sqrt(v)), 0, Math.PI * 2);
            ctx.fill();
          }
        }
      }
      ctx.globalAlpha = 1;
    };

    const animate = () => {
      const start = performance.now();
      const step = (now: number) => {
        const t = Math.min(1, (now - start) / 1400);
        draw(1 - Math.pow(1 - t, 3));
        if (t < 1) raf = requestAnimationFrame(step);
        else revealed = true;
      };
      raf = requestAnimationFrame(step);
    };

    const image = new Image();
    image.onload = () => {
      iw = image.naturalWidth;
      ih = image.naturalHeight;
      const off = document.createElement("canvas");
      off.width = iw;
      off.height = ih;
      const octx = off.getContext("2d");
      if (!octx) return;
      octx.drawImage(image, 0, 0);
      const px = octx.getImageData(0, 0, iw, ih).data;
      ink = new Float32Array(iw * ih);
      for (let i = 0; i < ink.length; i++) ink[i] = px[i * 4] / 255;
      if (revealed) draw();
      else seen.observe(canvas);
    };
    image.src = `${import.meta.env.BASE_URL}art/${name}.png`;

    const seen = new IntersectionObserver((entries) => {
      if (entries.some((e) => e.isIntersecting)) {
        seen.disconnect();
        animate();
      }
    });
    const resized = new ResizeObserver(() => revealed && draw());
    resized.observe(canvas);
    // The theme toggle changes the ink colour but not the size.
    const themed = new MutationObserver(() => revealed && draw());
    themed.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });

    return () => {
      cancelAnimationFrame(raf);
      seen.disconnect();
      resized.disconnect();
      themed.disconnect();
      image.onload = null;
    };
  }, [name, mode, cell, reveal, glyphs]);

  return <canvas ref={ref} className={className ?? "dot-art"} aria-hidden="true" />;
}
