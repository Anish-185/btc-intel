/** Is the page talking to the server it was built with?
 *
 *  A stale uvicorn cost an hour once: the console showed the new UI, every
 *  request went to a process started before the endpoints existed, and the
 *  symptom was a plain "Not Found" that looked like a frontend bug. The commit
 *  is stamped into both halves at build and start, so the answer is now one
 *  comparison rather than an investigation.
 */
import { useEffect, useState } from "react";
import { API_BASE } from "../api/client";

export interface BuildState {
  ours: string;
  theirs: string | null;
  startedAt: string | null;
  routes: number | null;
  /** Both sides known, and different. */
  mismatch: boolean;
  /** The API did not answer /version at all — an old build, or nothing running. */
  unreachable: boolean;
}

export function useBuildCheck(): BuildState {
  const ours = typeof __APP_COMMIT__ === "string" ? __APP_COMMIT__ : "unknown";
  const [state, setState] = useState<BuildState>({
    ours,
    theirs: null,
    startedAt: null,
    routes: null,
    mismatch: false,
    unreachable: false,
  });

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${API_BASE}/version`, { signal: controller.signal })
      .then((response) => (response.ok ? response.json() : Promise.reject(response.statusText)))
      .then((body: { commit: string; started_at: string; routes: number }) =>
        setState({
          ours,
          theirs: body.commit,
          startedAt: body.started_at,
          routes: body.routes,
          // "unknown" on either side means someone built without git; that is
          // not evidence of staleness, so it is not reported as such.
          mismatch:
            body.commit !== ours && body.commit !== "unknown" && ours !== "unknown",
          unreachable: false,
        }),
      )
      .catch(() => {
        if (controller.signal.aborted) return;
        setState((current) => ({ ...current, unreachable: true }));
      });
    return () => controller.abort();
  }, [ours]);

  return state;
}
