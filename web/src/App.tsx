import { Route, Routes } from "react-router-dom";
import { ToastHost } from "./components/Toasts";
import { Home } from "./pages/Home";
import { Alerts } from "./pages/Alerts";
import { Entity } from "./pages/Entity";
import { Transaction } from "./pages/Transaction";

export function App() {
  return (
    <ToastHost>
      <Routes>
        <Route path="/" element={<Home />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/entities/:id" element={<Entity />} />
        <Route path="/tx/:txid" element={<Transaction />} />
        <Route path="*" element={<Home />} />
      </Routes>
    </ToastHost>
  );
}
