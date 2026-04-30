import { useEffect, useRef, useState } from "react";
import { NavLink, useLocation } from "react-router-dom";
import { useTheme } from "../../theme/ThemeProvider";
import { useAuth } from "../../auth/AuthContext";
import { get } from "../../api";

const baseNavItems = [
  { to: "/", label: "Calc" },
  { to: "/split", label: "Split" },
  { to: "/contains", label: "Contains" },
  { to: "/summarize", label: "Summarize" },
  { to: "/from-range", label: "Range" },
  { to: "/visualizer", label: "Visualize" },
];

interface SidebarProps {
  ipamEnabled: boolean;
  swaggerEnabled: boolean;
  /** Whether the mobile drawer is open. Ignored on `md:`+. */
  open: boolean;
  /** Called when the user dismisses the drawer (route change, backdrop, link tap). */
  onClose: () => void;
}

interface VersionResponse {
  name: string;
  version: string;
  commit: string;
  commit_full: string;
}

const REPO_URL = "https://github.com/wingnut128/netcidr";

export function Sidebar({
  ipamEnabled,
  swaggerEnabled,
  open,
  onClose,
}: SidebarProps) {
  const { theme, toggleTheme } = useTheme();
  const auth = useAuth();
  const location = useLocation();
  const [versionInfo, setVersionInfo] = useState<VersionResponse | null>(null);

  useEffect(() => {
    void get<VersionResponse>("/version")
      .then(setVersionInfo)
      .catch(() => setVersionInfo(null));
  }, []);

  // Auto-close the drawer on route change. Tracking the previous path with
  // a ref keeps the effect from firing on every render — `onClose` is a
  // fresh inline arrow on each parent render, so depending on it would
  // close the drawer the moment it's opened.
  const prevPath = useRef(location.pathname);
  useEffect(() => {
    if (prevPath.current !== location.pathname) {
      prevPath.current = location.pathname;
      onClose();
    }
  }, [location.pathname, onClose]);

  const navItems = ipamEnabled
    ? [...baseNavItems, { to: "/ipam", label: "IPAM" }]
    : baseNavItems;
  const adminItems = auth.isAdmin
    ? [{ to: "/admin/allowlist", label: "Allowlist" }]
    : [];

  return (
    <nav
      aria-label="Primary"
      className={`fixed left-0 top-0 h-full w-52 bg-surface border-r border-border flex flex-col z-50 transform transition-transform duration-200 md:translate-x-0 ${
        open ? "translate-x-0" : "-translate-x-full md:translate-x-0"
      }`}
    >
      <div className="px-5 py-5 border-b border-border">
        <h1 className="text-cyan text-lg font-semibold tracking-tight">
          netcidr
        </h1>
        <p className="text-text-muted text-xs mt-0.5">Subnet tools</p>
      </div>

      <div className="flex flex-col gap-0.5 p-2 flex-1">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `relative block pl-4 pr-3 py-3 md:py-2 text-base md:text-sm rounded-md transition-colors ${
                isActive
                  ? "text-text font-semibold bg-surface2 before:content-[''] before:absolute before:left-0 before:top-2 before:bottom-2 md:before:top-1.5 md:before:bottom-1.5 before:w-0.5 before:rounded-r before:bg-cyan"
                  : "text-text-muted hover:text-text hover:bg-surface2/60"
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
        {adminItems.length > 0 && (
          <>
            <p className="text-text-muted text-xs px-4 mt-4 mb-1">Admin</p>
            {adminItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                className={({ isActive }) =>
                  `relative block pl-4 pr-3 py-3 md:py-2 text-base md:text-sm rounded-md transition-colors ${
                    isActive
                      ? "text-text font-semibold bg-surface2 before:content-[''] before:absolute before:left-0 before:top-2 before:bottom-2 md:before:top-1.5 md:before:bottom-1.5 before:w-0.5 before:rounded-r before:bg-cyan"
                      : "text-text-muted hover:text-text hover:bg-surface2/60"
                  }`
                }
              >
                {item.label}
              </NavLink>
            ))}
          </>
        )}
      </div>

      {auth.status === "authenticated" && auth.email && (
        <div className="px-4 py-3 border-t border-border">
          <p className="text-text text-xs truncate" title={auth.email}>
            {auth.email}
          </p>
          <button
            type="button"
            onClick={() => auth.signOut()}
            className="mt-1 text-xs text-text-muted hover:text-cyan cursor-pointer min-h-[44px] md:min-h-0"
          >
            Sign out
          </button>
        </div>
      )}

      <div className="border-t border-border">
        {swaggerEnabled && (
          <a
            href="/swagger-ui"
            target="_blank"
            rel="noopener noreferrer"
            className="block px-4 py-3 md:py-2 text-sm text-text-muted hover:text-text hover:bg-surface2/60 transition-colors"
          >
            API Docs ↗
          </a>
        )}
        <div className="px-4 py-2.5 flex items-center justify-between border-t border-border">
          <button
            type="button"
            onClick={toggleTheme}
            aria-label="Toggle theme"
            title="Toggle theme (⌘+J)"
            className="text-text-muted hover:text-text text-xs cursor-pointer flex items-center gap-1.5 min-h-[44px] md:min-h-0"
          >
            <span aria-hidden>{theme === "dark" ? "☾" : "☀"}</span>
            <span>{theme === "dark" ? "Dark" : "Light"}</span>
          </button>
          {versionInfo && (
            <p
              className="text-text-muted text-xs font-mono tabular-nums flex items-center gap-1.5"
              title={`netcidr v${versionInfo.version} (${versionInfo.commit_full})`}
            >
              <span>v{versionInfo.version}</span>
              {versionInfo.commit && versionInfo.commit !== "unknown" && (
                <>
                  <span aria-hidden>·</span>
                  <a
                    href={`${REPO_URL}/commit/${versionInfo.commit_full}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:text-text"
                  >
                    {versionInfo.commit}
                  </a>
                </>
              )}
            </p>
          )}
        </div>
      </div>
    </nav>
  );
}
