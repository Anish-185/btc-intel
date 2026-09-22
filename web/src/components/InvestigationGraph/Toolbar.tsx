/** The graph's controls: how it is laid out, what it shows, what mode the
 *  pointer is in, and how the view leaves the screen.
 *
 *  Everything here is one click away on purpose. A control that hides in a
 *  menu is a control an investigator does not use at two in the morning.
 */
import { useEffect, useState } from "react";
import { LAYOUT_HINTS, LAYOUT_LABELS, type LayoutName } from "./layouts";
import { DEFAULT_FILTERS, type Filters, type NodeType } from "./model";

export type Mode = "browse" | "path";

export interface TraceSettings {
  direction: "forward" | "backward";
  maxHops: number;
  minAmount: number;
}

export function Toolbar({
  layout,
  onLayout,
  mode,
  onMode,
  simplify,
  onSimplify,
  trace,
  onTrace,
  onSearch,
  onFit,
  onUndo,
  onRedo,
  canUndo,
  canRedo,
  onExport,
  onSave,
  filters,
  onFilters,
  showPruned,
  onShowPruned,
  prunedCount,
  busy,
}: {
  layout: LayoutName;
  onLayout: (name: LayoutName) => void;
  mode: Mode;
  onMode: (mode: Mode) => void;
  simplify: boolean;
  onSimplify: (value: boolean) => void;
  trace: TraceSettings;
  onTrace: (settings: TraceSettings) => void;
  onSearch: (query: string) => void;
  onFit: () => void;
  onUndo: () => void;
  onRedo: () => void;
  canUndo: boolean;
  canRedo: boolean;
  onExport: (kind: "png" | "svg") => void;
  onSave: () => void;
  filters: Filters;
  onFilters: (filters: Filters) => void;
  showPruned: boolean;
  onShowPruned: (value: boolean) => void;
  prunedCount: number;
  busy: boolean;
}) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);

  // Filter changes are debounced: dragging a slider must not re-style the
  // graph on every pixel.
  const [draft, setDraft] = useState(filters);
  useEffect(() => setDraft(filters), [filters]);
  useEffect(() => {
    const timer = setTimeout(() => {
      if (JSON.stringify(draft) !== JSON.stringify(filters)) onFilters(draft);
    }, 250);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft]);

  const setType = (type: NodeType, value: boolean) =>
    setDraft({ ...draft, types: { ...draft.types, [type]: value } });

  return (
    <div className="graph-toolbar">
      <div className="graph-toolbar-row">
        <span className="label">layout</span>
        <div className="graph-segment" role="group" aria-label="Layout">
          {(Object.keys(LAYOUT_LABELS) as LayoutName[]).map((name) => (
            <button
              key={name}
              type="button"
              className="btn btn-quiet field-btn"
              aria-pressed={layout === name}
              title={LAYOUT_HINTS[name]}
              onClick={() => onLayout(name)}
            >
              {LAYOUT_LABELS[name]}
            </button>
          ))}
        </div>

        <span className="graph-toolbar-gap" />

        <button
          type="button"
          className="btn btn-quiet field-btn"
          aria-pressed={simplify}
          title="Hide transaction nodes and join the wallets they connect. Lossy — the edge label says how many transactions each line stands for."
          onClick={() => onSimplify(!simplify)}
        >
          simplify connectors
        </button>

        <button
          type="button"
          className="btn btn-quiet field-btn"
          aria-pressed={mode === "path"}
          title="Pick two nodes to show the money-flow path between them"
          onClick={() => onMode(mode === "path" ? "browse" : "path")}
        >
          find path
        </button>

        {busy && <span className="label graph-busy">working…</span>}
      </div>

      <div className="graph-toolbar-row">
        <label className="field">
          <span className="label">find</span>
          <input
            type="search"
            value={query}
            placeholder="address, txid or IP"
            aria-label="Find a node"
            onChange={(event) => {
              setQuery(event.target.value);
              onSearch(event.target.value);
            }}
          />
        </label>

        <span className="label">trace</span>
        <select
          aria-label="Trace direction"
          value={trace.direction}
          onChange={(event) =>
            onTrace({ ...trace, direction: event.target.value as TraceSettings["direction"] })
          }
        >
          <option value="forward">forward</option>
          <option value="backward">backward</option>
        </select>
        <label className="field">
          <span className="label">hops</span>
          <input
            type="number"
            min={1}
            max={6}
            value={trace.maxHops}
            aria-label="Maximum hops"
            onChange={(event) => onTrace({ ...trace, maxHops: Number(event.target.value) })}
          />
        </label>
        <label className="field">
          <span className="label">min btc</span>
          <input
            type="number"
            min={0}
            step={0.01}
            value={trace.minAmount}
            aria-label="Minimum amount"
            onChange={(event) => onTrace({ ...trace, minAmount: Number(event.target.value) })}
          />
        </label>

        {prunedCount > 0 && (
          <button
            type="button"
            className="btn btn-quiet field-btn"
            aria-pressed={showPruned}
            onClick={() => onShowPruned(!showPruned)}
          >
            {showPruned ? "hide" : "show"} {prunedCount} pruned
          </button>
        )}

        <span className="graph-toolbar-gap" />

        <button type="button" className="btn btn-quiet field-btn" onClick={onUndo} disabled={!canUndo}>
          undo
        </button>
        <button type="button" className="btn btn-quiet field-btn" onClick={onRedo} disabled={!canRedo}>
          redo
        </button>
        <button type="button" className="btn btn-quiet field-btn" onClick={onFit} title="Fit to screen (F)">
          fit
        </button>
        <button
          type="button"
          className="btn btn-quiet field-btn"
          aria-pressed={open}
          onClick={() => setOpen(!open)}
        >
          filters
        </button>
        <button type="button" className="btn btn-quiet field-btn" onClick={() => onExport("png")}>
          png
        </button>
        <button type="button" className="btn btn-quiet field-btn" onClick={() => onExport("svg")}>
          svg
        </button>
        <button type="button" className="btn btn-quiet field-btn" onClick={onSave}>
          save
        </button>
      </div>

      {open && (
        <div className="graph-filters" role="group" aria-label="Filters">
          <div className="graph-filter-group">
            <span className="label">show</span>
            {(["wallet", "transaction", "ip", "aggregate"] as const).map((type) => (
              <label key={type} className="graph-check">
                <input
                  type="checkbox"
                  checked={draft.types[type]}
                  onChange={(event) => setType(type, event.target.checked)}
                />
                {type}
              </label>
            ))}
          </div>

          <label className="field">
            <span className="label">min risk</span>
            <input
              type="range"
              min={0}
              max={1}
              step={0.05}
              value={draft.minRisk}
              onChange={(event) => setDraft({ ...draft, minRisk: Number(event.target.value) })}
            />
            <span className="num">{draft.minRisk.toFixed(2)}</span>
          </label>

          <label className="field">
            <span className="label">min btc</span>
            <input
              type="number"
              min={0}
              step={0.01}
              value={draft.minAmount}
              onChange={(event) => setDraft({ ...draft, minAmount: Number(event.target.value) })}
            />
          </label>

          <label className="field">
            <span className="label">from</span>
            <input
              type="date"
              onChange={(event) =>
                setDraft({
                  ...draft,
                  from: event.target.value ? Date.parse(event.target.value) : null,
                })
              }
            />
          </label>
          <label className="field">
            <span className="label">to</span>
            <input
              type="date"
              onChange={(event) =>
                setDraft({
                  ...draft,
                  to: event.target.value ? Date.parse(event.target.value) + 86_400_000 : null,
                })
              }
            />
          </label>

          <label className="field">
            <span className="label">hide clusters under</span>
            <input
              type="number"
              min={0}
              value={draft.minClusterSize}
              onChange={(event) =>
                setDraft({ ...draft, minClusterSize: Number(event.target.value) })
              }
            />
          </label>

          <button
            type="button"
            className="btn btn-quiet field-btn"
            onClick={() => setDraft(DEFAULT_FILTERS)}
          >
            reset
          </button>
        </div>
      )}
    </div>
  );
}
