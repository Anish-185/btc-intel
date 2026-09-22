import { Suspense, lazy } from "react";
import { Route, Routes } from "react-router-dom";
import { ToastHost } from "./components/Toasts";
import { Home } from "./pages/Home";
import { Alerts } from "./pages/Alerts";
import { Entity } from "./pages/Entity";
import { Transaction } from "./pages/Transaction";

// The investigation graph pulls in Cytoscape and its extensions — the heaviest
// thing the console loads, and only this route needs it.
const Investigate = lazy(() =>
  import("./pages/Investigate").then((m) => ({ default: m.Investigate })),
);

export function App() {
  return (
    <ToastHost>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/entities/:id" element={<Entity />} />
        <Route path="/tx/:txid" element={<Transaction />} />
        <Route
          path="/investigate"
          element={
            <Suspense fallback={<div className="shell" aria-busy="true" />}>
              <Investigate />
            </Suspense>
          }
        />
        <Route path="*" element={<Home />} />
      </Routes>
    </ToastHost>
  );
}
