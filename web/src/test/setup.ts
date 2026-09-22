import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

/** jsdom has no layout engine, so the browser APIs the console leans on are
 *  stubbed here rather than guarded in the components. */

let reducedMotion = false;
export const setReducedMotion = (value: boolean) => {
  reducedMotion = value;
};

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: query.includes("prefers-reduced-motion") ? reducedMotion : false,
    media: query,
    onchange: null,
    addEventListener: () => {},
    removeEventListener: () => {},
    addListener: () => {},
    removeListener: () => {},
    dispatchEvent: () => false,
  }),
});

class Observer {
  observe() {}
  unobserve() {}
  disconnect() {}
  takeRecords() {
    return [];
  }
}
vi.stubGlobal("IntersectionObserver", Observer);
vi.stubGlobal("ResizeObserver", Observer);

// Element.animate is not implemented in jsdom; the console uses it for every
// entrance and the FLIP.
if (!Element.prototype.animate) {
  Element.prototype.animate = (() => ({
    finished: Promise.resolve(),
    cancel() {},
    finish() {},
  })) as never;
}

if (!HTMLDialogElement.prototype.showModal) {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.open = false;
  };
}

// jsdom has no canvas. The ambient field only needs a context object that
// swallows drawing calls; what the test checks is whether it starts a loop.
HTMLCanvasElement.prototype.getContext = (() => {
  const noop = () => {};
  return {
    setTransform: noop,
    clearRect: noop,
    fillRect: noop,
    strokeRect: noop,
    fillStyle: "",
    strokeStyle: "",
    globalAlpha: 1,
  };
}) as never;
