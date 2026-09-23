/** Jump straight to a thing: an entity id, a transaction id, an IP.
 *
 *  An investigator arrives with an identifier from somewhere else — a case
 *  file, an email, another tool — so the fastest path is a box that takes it
 *  and goes. Ctrl/⌘-K anywhere, arrows and Enter, Escape to leave. */
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { evidenceKind } from "../lib/format";

interface Target {
  label: string;
  hint: string;
  to: string;
}

function targetsFor(query: string): Target[] {
  const value = query.trim();
  if (!value) {
    return [
      { label: "Alert queue", hint: "page", to: "/alerts" },
      { label: "Overview", hint: "page", to: "/" },
      { label: "Red team", hint: "page", to: "/redteam" },
      { label: "Live monitor", hint: "page", to: "/monitor" },
      { label: "Chain of custody", hint: "page", to: "/custody" },
    ];
  }
  const kind = evidenceKind(value);
  const out: Target[] = [];
  if (kind === "transaction") {
    out.push({ label: value, hint: "transaction — propagation", to: `/tx/${value}` });
  }
  if (kind === "wallet" || kind === "note") {
    out.push({ label: value, hint: "entity or wallet", to: `/entities/${value}` });
  }
  if (kind === "ip") {
    out.push({ label: value, hint: "search alerts for this address", to: `/alerts?q=${value}` });
  }
  out.push({ label: value, hint: "open as entity id", to: `/entities/${value}` });
  return out.filter((t, i, all) => all.findIndex((o) => o.to === t.to) === i).slice(0, 5);
}

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const navigate = useNavigate();
  const targets = useMemo(() => targetsFor(query), [query]);

  useEffect(() => {
    const node = dialog.current;
    if (!node) return;
    if (open && !node.open) {
      node.showModal?.();
      setQuery("");
      setActive(0);
    }
    if (!open && node.open) node.close();
  }, [open]);

  const go = (target: Target) => {
    onClose();
    navigate(target.to);
  };

  return (
    <dialog
      ref={dialog}
      className="palette"
      aria-label="Go to"
      onClose={onClose}
      onClick={(event) => {
        if (event.target === dialog.current) onClose();
      }}
    >
      <input
        autoFocus
        type="search"
        value={query}
        placeholder="Entity, transaction id or IP address"
        aria-label="Entity, transaction id or IP address"
        onChange={(event) => {
          setQuery(event.target.value);
          setActive(0);
        }}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown") {
            event.preventDefault();
            setActive((i) => Math.min(i + 1, targets.length - 1));
          } else if (event.key === "ArrowUp") {
            event.preventDefault();
            setActive((i) => Math.max(i - 1, 0));
          } else if (event.key === "Enter" && targets[active]) {
            event.preventDefault();
            go(targets[active]);
          }
        }}
      />
      <ul>
        {targets.map((target, i) => (
          <li key={target.to} data-active={i === active}>
            <button type="button" onMouseEnter={() => setActive(i)} onClick={() => go(target)}>
              <span style={{ overflow: "hidden", textOverflow: "ellipsis" }}>{target.label}</span>
              <span className="muted">{target.hint}</span>
            </button>
          </li>
        ))}
      </ul>
      <p className="palette-foot label">↑ ↓ to choose · enter to open · esc to close</p>
    </dialog>
  );
}
