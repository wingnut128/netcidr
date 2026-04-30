import { useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { get } from "../../api";

interface Features {
  ipam: boolean;
  swagger: boolean;
}

export function MainLayout() {
  const [ipamEnabled, setIpamEnabled] = useState(false);
  const [swaggerEnabled, setSwaggerEnabled] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    get<Features>("/features")
      .then((f) => {
        setIpamEnabled(f.ipam);
        setSwaggerEnabled(f.swagger);
      })
      .catch(() => {
        setIpamEnabled(false);
        setSwaggerEnabled(false);
      });
  }, []);

  return (
    <div className="min-h-screen bg-bg">
      <Sidebar
        ipamEnabled={ipamEnabled}
        swaggerEnabled={swaggerEnabled}
        open={drawerOpen}
        onClose={() => setDrawerOpen(false)}
      />

      {/* Mobile top bar — hamburger + brand. Hidden on md:+. */}
      <div className="md:hidden sticky top-0 z-30 flex items-center justify-between px-4 h-14 bg-surface border-b border-border">
        <button
          type="button"
          onClick={() => setDrawerOpen(true)}
          aria-label="Open navigation"
          className="text-text-muted hover:text-text min-h-[44px] min-w-[44px] flex items-center justify-center"
        >
          <span aria-hidden className="text-xl">☰</span>
        </button>
        <span className="text-cyan text-base font-semibold tracking-tight">
          netcidr
        </span>
        <span className="w-11" aria-hidden />
      </div>

      {/* Backdrop — only rendered on mobile when drawer is open. */}
      {drawerOpen && (
        <div
          className="md:hidden fixed inset-0 bg-black/40 z-40"
          onClick={() => setDrawerOpen(false)}
          aria-hidden
        />
      )}

      <main className="md:ml-52 p-4 md:p-8 max-w-screen-2xl">
        <Outlet />
      </main>
    </div>
  );
}
