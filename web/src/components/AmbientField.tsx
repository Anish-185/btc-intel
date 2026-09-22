/** The home header's field: a dithered grid of ordinary traffic with a few
 *  cells burning amber. It is the product in one picture — most of what
 *  crosses the network is nothing, and the job is the handful that is not.
 *
 *  Drawn procedurally on a canvas, so nothing is downloaded. Capped at 8 fps,
 *  paused when off-screen or when the tab is hidden, and never drawn at all
 *  when the reader asked for reduced motion. */
import { useEffect, useRef } from "react";
import { useReducedMotion } from "../lib/motion";

const CELL = 14;
const FPS = 8;

export function AmbientField({ anomalies = 3 }: { anomalies?: number }) {
  const ref = useRef<HTMLCanvasElement>(null);
  const reduced = useReducedMotion();

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let raf = 0;
    let last = 0;
    let visible = true;
    let frame = 0;

    const dpr = Math.min(devicePixelRatio || 1, 2);
    const resize = () => {
      const { width, height } = canvas.getBoundingClientRect();
      canvas.width = Math.max(1, Math.floor(width * dpr));
      canvas.height = Math.max(1, Math.floor(height * dpr));
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();

    const css = getComputedStyle(document.documentElement);
    const ink = css.getPropertyValue("--field-muted").trim() || "#7f9bd8";
    const hot = css.getPropertyValue("--risk-high").trim() || "#ff8f61";

    // Fixed hotspots: the anomaly is a fact about the picture, not a twinkle.
    const spots = Array.from({ length: anomalies }, (_, i) => ({
      x: 0.17 + i * 0.29,
      y: 0.32 + ((i * 7) % 5) * 0.11,
    }));

    const draw = (t: number) => {
      const { width, height } = canvas.getBoundingClientRect();
      ctx.clearRect(0, 0, width, height);
      const cols = Math.ceil(width / CELL);
      const rows = Math.ceil(height / CELL);
      const phase = frame * 0.06;

      for (let y = 0; y < rows; y += 1) {
        for (let x = 0; x < cols; x += 1) {
          // A cheap, stable value noise — enough texture to read as traffic.
          const n =
            Math.sin(x * 0.37 + phase) * Math.cos(y * 0.51 - phase * 0.7) * 0.5 +
            Math.sin((x + y) * 0.21 + phase * 0.4) * 0.5;
          const v = (n + 1) / 2;
          if (v < 0.42) continue;
          ctx.fillStyle = ink;
          ctx.globalAlpha = 0.1 + (v - 0.42) * 0.7;
          const size = v > 0.78 ? 3 : 2;
          ctx.fillRect(x * CELL, y * CELL, size, size);
        }
      }

      ctx.globalAlpha = 1;
      for (const spot of spots) {
        const cx = Math.floor((spot.x * width) / CELL) * CELL;
        const cy = Math.floor((spot.y * height) / CELL) * CELL;
        ctx.fillStyle = hot;
        ctx.globalAlpha = 0.85;
        ctx.fillRect(cx, cy, CELL - 3, CELL - 3);
        ctx.globalAlpha = 0.25;
        ctx.strokeStyle = hot;
        ctx.strokeRect(cx - CELL, cy - CELL, CELL * 3, CELL * 3);
      }
      ctx.globalAlpha = 1;
      void t;
    };

    const loop = (t: number) => {
      raf = requestAnimationFrame(loop);
      if (!visible || t - last < 1000 / FPS) return;
      last = t;
      frame += 1;
      draw(t);
    };

    draw(0);
    if (!reduced) raf = requestAnimationFrame(loop);

    const observer = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting && !document.hidden;
    });
    observer.observe(canvas);
    const onVisibility = () => {
      visible = !document.hidden;
    };
    document.addEventListener("visibilitychange", onVisibility);
    const onResize = () => {
      resize();
      draw(0);
    };
    addEventListener("resize", onResize);

    return () => {
      cancelAnimationFrame(raf);
      observer.disconnect();
      document.removeEventListener("visibilitychange", onVisibility);
      removeEventListener("resize", onResize);
    };
  }, [reduced, anomalies]);

  return <canvas ref={ref} aria-hidden="true" data-testid="ambient-field" data-animated={!reduced} />;
}
