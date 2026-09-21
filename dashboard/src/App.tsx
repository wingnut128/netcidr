import { HashRouter, Routes, Route } from "react-router-dom";
import { withSentryReactRouterV7Routing } from "@sentry/react";
import { MainLayout } from "./components/layout/MainLayout";
import { Calculator } from "./pages/Calculator";
import { Splitter } from "./pages/Splitter";
import { Contains } from "./pages/Contains";
import { Summarize } from "./pages/Summarize";
import { FromRange } from "./pages/FromRange";
import { Ipam } from "./pages/Ipam";
import { Hostnames } from "./pages/Hostnames";
import { Visualizer } from "./pages/Visualizer";
import { UsersAdmin } from "./pages/UsersAdmin";
import { Activity } from "./pages/Activity";
import { Tokens } from "./pages/Tokens";

// Names Sentry navigation transactions by route pattern instead of raw URL.
const SentryRoutes = withSentryReactRouterV7Routing(Routes);

export function App() {
  return (
    <HashRouter>
      <SentryRoutes>
        <Route element={<MainLayout />}>
          <Route index element={<Calculator />} />
          <Route path="split" element={<Splitter />} />
          <Route path="contains" element={<Contains />} />
          <Route path="summarize" element={<Summarize />} />
          <Route path="from-range" element={<FromRange />} />
          <Route path="visualizer" element={<Visualizer />} />
          <Route path="ipam" element={<Ipam />} />
          <Route path="hostnames" element={<Hostnames />} />
          <Route path="tokens" element={<Tokens />} />
          <Route path="admin/users" element={<UsersAdmin />} />
          <Route path="admin/activity" element={<Activity />} />
        </Route>
      </SentryRoutes>
    </HashRouter>
  );
}
