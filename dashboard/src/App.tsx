import { HashRouter, Routes, Route } from "react-router-dom";
import { MainLayout } from "./components/layout/MainLayout";
import { Calculator } from "./pages/Calculator";
import { Splitter } from "./pages/Splitter";
import { Contains } from "./pages/Contains";
import { Summarize } from "./pages/Summarize";
import { FromRange } from "./pages/FromRange";
import { Placeholder } from "./pages/Placeholder";

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
          <Route path="ipam" element={<Placeholder name="IPAM Dashboard" />} />
        </Route>
      </Routes>
    </HashRouter>
  );
}
