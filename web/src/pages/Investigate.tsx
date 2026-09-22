/** The investigation surface: one case, one graph, as much of it as the
 *  analyst chooses to pull in.
 *
 *  It opens on a node's immediate neighbourhood rather than on everything —
 *  a graph that starts at four thousand nodes has answered nothing and cost a
 *  minute of waiting. Everything else is one expand away. */
import { useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { InvestigationGraph } from "../components/InvestigationGraph";
import { graphApi } from "../components/InvestigationGraph/api";
import type { GraphPayload } from "../components/InvestigationGraph/model";
import { ErrorNote, Label, SkeletonRows } from "../components/ui";
import { Shell } from "../components/Shell";
import { useToast } from "../components/Toasts";
import { useApi } from "../lib/useApi";
import { formatId } from "../lib/formatId";

export function Investigate() {
  const [params] = useSearchParams();
  const focus = params.get("focus");
  const investigation = params.get("investigation") ?? undefined;
  const toast = useToast();
  const [notice, setNotice] = useState<string | null>(null);

  const seed = useApi(
    (signal) =>
      focus
        ? graphApi.neighbors(focus, { limit: 20 }, signal)
        : Promise.resolve(null as unknown as Awaited<ReturnType<typeof graphApi.neighbors>>),
    [focus],
  );

  const initial = useMemo<GraphPayload | undefined>(
    () => (seed.data ? { nodes: seed.data.nodes, edges: seed.data.edges } : undefined),
    [seed.data],
  );

  useEffect(() => {
    if (notice) {
      toast(notice);
      setNotice(null);
    }
  }, [notice, toast]);

  return (
    <Shell>
      <section className="section">
        <div className="section-head">
          <div>
            <Label>investigation graph</Label>
            <h1 style={{ marginTop: "var(--sp-2)" }}>
              {focus ? (
                <span className="mono" title={focus}>
                  {formatId(focus, { head: 20, tail: 8 })}
                </span>
              ) : investigation ? (
                "Saved investigation"
              ) : (
                "Pick somewhere to start"
              )}
            </h1>
          </div>
          {focus && (
            <Link to={`/entities/${encodeURIComponent(focus)}`} viewTransition>
              Back to the case →
            </Link>
          )}
        </div>

        {!focus && !investigation ? (
          <p className="soft measure">
            Open a case and choose <em>Investigate</em>, or press Ctrl K and paste a wallet,
            transaction or IP. The graph starts from one node and grows only where you expand it.
          </p>
        ) : seed.error ? (
          <ErrorNote error={seed.error} />
        ) : seed.loading && !investigation ? (
          <SkeletonRows rows={6} />
        ) : (
          <InvestigationGraph
            initial={initial}
            focusId={focus}
            investigationId={investigation}
            height={620}
            onNotice={setNotice}
          />
        )}

        <p className="muted" style={{ marginTop: "var(--sp-3)", fontSize: "var(--fs-small)" }}>
          Double-click a node to expand it · right-click (or long-press) for the menu · F fits the
          view, Esc clears the selection, Delete hides what is selected.
        </p>
      </section>
    </Shell>
  );
}
