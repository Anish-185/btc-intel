/** The frame every page sits in: a left rail with the wordmark, the sections,
 *  an on-this-page list, and the theme toggle. Content to the right. */
import { useEffect, useState, type ReactNode } from "react";
import { NavLink, useLocation, useParams } from "react-router-dom";
import { useBuildCheck } from "../lib/useBuildCheck";
import { useTheme } from "../lib/theme";
import { forgetTokens } from "../lib/tokens";
import { CommandPalette } from "./CommandPalette";

/** ⌘ on a Mac, Ctrl everywhere else. Showing the wrong one teaches the wrong
 *  shortcut, which is worse than showing none. */
const MOD = typeof navigator !== "undefined" && /Mac|iP(hone|ad)/.test(navigator.platform)
  ? "\u2318K"
  : "Ctrl K";

const PAGES = [
  { to: "/", label: "Overview" },
  { to: "/alerts", label: "Alert queue" },
  { to: "/investigate", label: "Investigation graph" },
  { to: "/redteam", label: "Red team" },
];

export interface Anchor {
  id: string;
  label: string;
}

export function Shell({ anchors, children }: { anchors?: Anchor[]; children: ReactNode }) {
  const [theme, toggleTheme] = useTheme();
  const build = useBuildCheck();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [activeAnchor, setActiveAnchor] = useState<string | null>(null);
  const { pathname } = useLocation();
  const params = useParams();

  // A case and a transaction are places too. Showing the open one in the rail
  // is how a reader learns the console has more than two pages.
  const open = params.id
    ? { label: `Case ${params.id.slice(0, 10)}…`, to: pathname }
    : params.txid
      ? { label: `Transaction ${params.txid.slice(0, 8)}…`, to: pathname }
      : null;

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen(true);
      }
    };
    addEventListener("keydown", onKey);
    return () => removeEventListener("keydown", onKey);
  }, []);

  // Which section the reader is in. Observed, not computed on scroll, so the
  // rail never costs a frame while the table is being worked.
  useEffect(() => {
    if (!anchors?.length) return;
    setActiveAnchor(anchors[0].id);
    const observer = new IntersectionObserver(
      (entries) => {
        const seen = entries.filter((e) => e.isIntersecting);
        if (seen.length) setActiveAnchor(seen[0].target.id);
      },
      { rootMargin: "-10% 0px -70% 0px" },
    );
    for (const anchor of anchors) {
      const node = document.getElementById(anchor.id);
      if (node) observer.observe(node);
    }
    return () => observer.disconnect();
  }, [anchors, pathname]);

  return (
    <div className="shell">
      <header className="rail">
        <NavLink to="/" className="wordmark">
          <span className="wordmark-mark" aria-hidden="true" />
          btc-intel
        </NavLink>

        <nav className="rail-nav" aria-label="Sections">
          {PAGES.map((page) => (
            <NavLink key={page.to} to={page.to} end={page.to === "/"} className="rail-link">
              {page.label}
            </NavLink>
          ))}
          {open && (
            <NavLink to={open.to} className="rail-link" title={params.id ?? params.txid}>
              <span className="mono" style={{ fontSize: "var(--fs-small)" }}>{open.label}</span>
            </NavLink>
          )}
        </nav>

        {anchors?.length ? (
          <>
            <hr className="rail-divider" />
            <p className="label">On this page</p>
            <nav className="subnav" aria-label="On this page">
              {anchors.map((anchor) => (
                <a
                  key={anchor.id}
                  href={`#${anchor.id}`}
                  aria-current={activeAnchor === anchor.id}
                >
                  {anchor.label}
                </a>
              ))}
            </nav>
          </>
        ) : null}

        <div className="rail-foot">
          <button type="button" className="btn btn-ghost bracket" onClick={() => setPaletteOpen(true)}>
            Search <span className="muted">{MOD}</span>
          </button>
          <button
            type="button"
            className="btn btn-quiet"
            onClick={() => {
              forgetTokens();
              toggleTheme();
            }}
            aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
          >
            <span className="theme-swatch" aria-hidden="true" />
            {theme === "dark" ? "light" : "dark"}
          </button>
          <p className="label" style={{ marginTop: "var(--sp-2)" }}>
            Offline · synthetic data
          </p>
        </div>
      </header>

      <main className="content">
        {(build.mismatch || build.unreachable) && (
          <div className="notice build-notice" role="alert">
            <span aria-hidden="true">⚠</span>
            <div>
              <p className="label">
                {build.mismatch ? "The API is a different build" : "The API is not answering"}
              </p>
              <p className="soft" style={{ marginTop: "var(--sp-1)" }}>
                {build.mismatch ? (
                  <>
                    This page was built from <code className="mono">{build.ours}</code>; the
                    server at <code className="mono">{"/version"}</code> reports{" "}
                    <code className="mono">{build.theirs}</code>, started{" "}
                    {build.startedAt?.replace("T", " ").replace("+00:00", " UTC")}. Restart it
                    with <code className="mono">offline/run_offline.sh</code> before trusting
                    anything on screen.
                  </>
                ) : (
                  <>
                    Nothing answered <code className="mono">/version</code>. Either the API is
                    not running, or it is an older build without that endpoint — start it with{" "}
                    <code className="mono">offline/run_offline.sh</code>.
                  </>
                )}
              </p>
            </div>
          </div>
        )}
        {children}
      </main>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  );
}
