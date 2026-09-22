/** Fitting the graph to its panel, safely.
 *
 *  `cy.fit()` is only meaningful when the container has a size. A graph
 *  mounted inside a collapsed section, a hidden tab or a panel that has not
 *  been laid out yet measures 0×0, and fitting then leaves a graph zoomed to
 *  nothing with no obvious cause. So a fit that cannot work now is remembered
 *  and run when the element is first both sized and on screen — and the same
 *  machinery re-fits when the panel is resized, which is the other way a
 *  carefully framed view silently breaks.
 */
import type { Core } from "cytoscape";

export interface Fitter {
  /** Fit now if that is possible, otherwise as soon as it is. */
  fit(): void;
  /** Stop observing. */
  dispose(): void;
}

const PADDING = 30;

export function createFitter(cy: Core, container: HTMLElement): Fitter {
  let pending = false;
  let hasFitted = false;

  const sized = () => {
    const rect = container.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };

  const doFit = () => {
    if (cy.destroyed?.()) return false;
    if (!sized() || cy.nodes().length === 0) return false;
    cy.resize();
    cy.fit(undefined, PADDING);
    hasFitted = true;
    pending = false;
    return true;
  };

  const fit = () => {
    if (!doFit()) pending = true;
  };

  // The panel changed size: re-measure and, if the view was fitted before,
  // keep it fitted. A view the analyst has panned and zoomed by hand is left
  // alone — only a pending or previously automatic fit is re-applied.
  const resize = new ResizeObserver(() => {
    if (cy.destroyed?.()) return;
    cy.resize();
    if (pending || hasFitted) doFit();
  });
  resize.observe(container);

  // The panel became visible: run the fit that could not happen while it was
  // hidden.
  const visible = new IntersectionObserver((entries) => {
    if (entries.some((entry) => entry.isIntersecting) && pending) doFit();
  });
  visible.observe(container);

  return {
    fit,
    dispose() {
      resize.disconnect();
      visible.disconnect();
    },
  };
}
