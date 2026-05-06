import { HashRouter, Routes, Route } from "react-router-dom";
import { MainLayout } from "./components/layout/MainLayout";
import { Calculator } from "./pages/Calculator";
import { Splitter } from "./pages/Splitter";
import { Contains } from "./pages/Contains";
import { Summarize } from "./pages/Summarize";
import { FromRange } from "./pages/FromRange";
import { Ipam } from "./pages/Ipam";
import { Visualizer } from "./pages/Visualizer";
import { AllowlistAdmin } from "./pages/AllowlistAdmin";
import { Tokens } from "./pages/Tokens";

export function App() {
  return (
    <HashRouter>
      <Routes>
        <Route element={<MainLayout />}>
          <Route index element={<Calculator />} />
          <Route path="split" element={<Splitter />} />
          <Route path="contains" element={<Contains />} />
          <Route path="summarize" element={<Summarize />} />
          <Route path="from-range" element={<FromRange />} />
          <Route path="visualizer" element={<Visualizer />} />
          <Route path="ipam" element={<Ipam />} />
          <Route path="tokens" element={<Tokens />} />
          <Route path="admin/allowlist" element={<AllowlistAdmin />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}
