import { NavLink } from "react-router-dom";
import { useTheme } from "../../theme/ThemeProvider";
import { useAuth } from "../../auth/AuthContext";

const baseNavItems = [
  { to: "/", label: "CALC" },
  { to: "/split", label: "SPLIT" },
  { to: "/contains", label: "CONTAINS" },
  { to: "/summarize", label: "SUMMARIZE" },
  { to: "/from-range", label: "RANGE" },
  { to: "/visualizer", label: "VISUALIZE" },
];

interface SidebarProps {
  ipamEnabled: boolean;
  swaggerEnabled: boolean;
}

export function Sidebar({ ipamEnabled, swaggerEnabled }: SidebarProps) {
  const { theme, toggleTheme } = useTheme();
  const auth = useAuth();
  const navItems = ipamEnabled
    ? [...baseNavItems, { to: "/ipam", label: "IPAM" }]
    : baseNavItems;
  return (
    <nav className="fixed left-0 top-0 h-full w-48 bg-surface border-r border-border flex flex-col z-50">
      <div className="px-4 py-5 border-b border-border">
        <h1 className="text-cyan text-lg font-bold tracking-wider">netcidr</h1>
        <p className="text-text-muted text-[10px] uppercase tracking-widest mt-1">
          subnet tools
        </p>
      </div>
      <div className="flex flex-col gap-0.5 p-2 flex-1">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) =>
              `block px-3 py-2 text-xs tracking-wider uppercase border border-transparent transition-colors ${
                isActive
                  ? "text-bg bg-cyan border-cyan font-bold"
                  : "text-text-muted hover:text-cyan hover:border-border"
              }`
            }
          >
            {item.label}
          </NavLink>
        ))}
      </div>
      {swaggerEnabled && (
        <div className="px-2 pb-2">
          <a
            href="/swagger-ui"
            target="_blank"
            rel="noopener noreferrer"
            className="block px-3 py-2 text-xs tracking-wider uppercase border border-transparent text-text-muted hover:text-cyan hover:border-border transition-colors"
          >
            API Docs ↗
          </a>
        </div>
      )}
      {auth.status === "authenticated" && auth.email && (
        <div className="px-3 py-2 border-t border-border">
          <p
            className="text-text text-[10px] truncate"
            title={auth.email}
          >
            {auth.email}
          </p>
          <button
            type="button"
            onClick={() => void auth.signOut()}
            className="mt-1 text-[10px] uppercase tracking-widest text-text-muted hover:text-cyan cursor-pointer"
          >
            Sign out
          </button>
        </div>
      )}
      <div className="px-3 py-3 border-t border-border flex items-center justify-between">
        <button
          type="button"
          onClick={toggleTheme}
          aria-label="Toggle theme"
          title="Toggle theme (⌘+J)"
          className="text-text-muted hover:text-cyan text-[10px] uppercase tracking-widest cursor-pointer flex items-center gap-1.5"
        >
          <span aria-hidden>{theme === "dark" ? "☾" : "☀"}</span>
          <span>{theme === "dark" ? "Dark" : "Light"}</span>
        </button>
        <p className="text-text-muted text-[10px]" id="version-display">
          &nbsp;
        </p>
      </div>
    </nav>
  );
}
