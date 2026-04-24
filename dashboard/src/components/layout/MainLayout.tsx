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
  const [sidebarOpen, setSidebarOpen] = useState(false);

  useEffect(() => {
    get<Features>("/features")
      .then((f) => setIpamEnabled(f.ipam))
      .catch(() => setIpamEnabled(false));
  }, []);

  return (
    <div className="min-h-screen bg-bg">
      <Sidebar
        ipamEnabled={ipamEnabled}
        mobileOpen={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />
      <header className="md:hidden sticky top-0 z-30 flex items-center justify-between px-3 py-2 border-b border-border bg-surface">
        <button
          type="button"
          aria-label="Open navigation"
          className="min-w-[44px] min-h-[44px] flex items-center justify-center text-text hover:text-cyan"
          onClick={() => setSidebarOpen(true)}
        >
          <svg
            width="22"
            height="22"
            viewBox="0 0 22 22"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="square"
            aria-hidden="true"
          >
            <line x1="3" y1="6" x2="19" y2="6" />
            <line x1="3" y1="11" x2="19" y2="11" />
            <line x1="3" y1="16" x2="19" y2="16" />
          </svg>
        </button>
        <h1 className="text-cyan text-sm font-bold tracking-wider">netcidr</h1>
        <div className="w-[44px]" aria-hidden="true" />
      </header>
      <main className="md:ml-48 p-4 md:p-6">
        <Outlet />
      </main>
    </div>
  );
}
