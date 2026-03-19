import { HashRouter, Routes, Route } from "react-router-dom";
import { MainLayout } from "./components/layout/MainLayout";
import { Placeholder } from "./pages/Placeholder";

export function App() {
  return (
    <HashRouter>
      <Routes>
        <Route element={<MainLayout />}>
          <Route index element={<Placeholder name="Calculator" />} />
          <Route path="split" element={<Placeholder name="Splitter" />} />
          <Route path="contains" element={<Placeholder name="Contains" />} />
          <Route path="summarize" element={<Placeholder name="Summarize" />} />
          <Route path="from-range" element={<Placeholder name="From Range" />} />
          <Route path="ipam" element={<Placeholder name="IPAM Dashboard" />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}
