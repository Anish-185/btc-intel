/** Motion primitives. Three rules, enforced here rather than per component:
 *  only transform and opacity animate, nothing waits on an animation, and
 *  prefers-reduced-motion turns all of it off.
 *
 *  No animation library: the two things that genuinely need scripting — a FLIP
 *  on re-sort and a count-up — are a dozen lines each on the Web Animations
 *  API, which is already in every browser this ships to. */
import { useEffect, useRef, useState } from "react";

export const reducedMotion = () =>
  typeof matchMedia === "function" && matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Live version: components that own an animation loop need to stop when the
 *  setting changes, not only when they mount. */
export function useReducedMotion(): boolean {
  const [reduced, setReduced] = useState(reducedMotion);
  useEffect(() => {
    if (typeof matchMedia !== "function") return;
    const query = matchMedia("(prefers-reduced-motion: reduce)");
    const update = () => setReduced(query.matches);
    query.addEventListener?.("change", update);
    return () => query.removeEventListener?.("change", update);
  }, []);
  return reduced;
}

/** Sections fade up once, staggered, when the page first paints. Once only:
 *  a queue that re-animates every time you sort it is a queue you cannot read. */
export function useEnter<T extends HTMLElement>(index = 0) {
  const ref = useRef<T>(null);
  useEffect(() => {
    const node = ref.current;
    if (!node || reducedMotion()) return;
    node.animate(
      [
        { opacity: 0, transform: "translateY(10px)" },
        { opacity: 1, transform: "none" },
      ],
      {
        duration: 400,
        delay: index * 40,
        easing: "cubic-bezier(.22, 1, .36, 1)",
        fill: "backwards",
      },
    );
  }, [index]);
  return ref;
}

/** Count a number up once, on mount. Returns the value to render; the final
 *  value is set immediately when motion is reduced. */
export function useCountUp(target: number, duration = 400): number {
  const [value, setValue] = useState(() => (reducedMotion() ? target : 0));
  useEffect(() => {
    if (reducedMotion()) {
      setValue(target);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const tick = (now: number) => {
      const t = Math.min((now - start) / duration, 1);
      // ease-out, matching --ease-out closely enough for a numeral
      setValue(target * (1 - Math.pow(1 - t, 3)));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, duration]);
  return value;
}
