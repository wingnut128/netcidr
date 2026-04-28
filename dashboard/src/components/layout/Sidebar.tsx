import { NavLink } from "react-router-dom";
import { useTheme } from "../../theme/ThemeProvider";
import { useAuth } from "../../auth/AuthContext";

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
}

export function Sidebar({ ipamEnabled, swaggerEnabled }: SidebarProps) {
  const { theme, toggleTheme } = useTheme();
  const auth = useAuth();
  const navItems = ipamEnabled
    ? [...baseNavItems, { to: "/ipam", label: "IPAM" }]
    : baseNavItems;
  return (
    <nav className="fixed left-0 top-0 h-full w-52 bg-surface border-r border-border flex flex-col z-50">
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
              `relative block pl-4 pr-3 py-2 text-sm rounded-md transition-colors ${
                isActive
                  ? "text-text font-semibold bg-surface2 before:content-[''] before:absolute before:left-0 before:top-1.5 before:bottom-1.5 before:w-0.5 before:rounded-r before:bg-cyan"
                  : "text-text-muted hover:text-text hover:bg-surface2/60"
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
            className="block px-4 py-2 text-sm rounded-md text-text-muted hover:text-text hover:bg-surface2/60 transition-colors"
          >
            API Docs ↗
          </a>
        </div>
      )}
      {auth.status === "authenticated" && auth.email && (
        <div className="px-4 py-3 border-t border-border">
          <p className="text-text text-xs truncate" title={auth.email}>
            {auth.email}
          </p>
          <button
            type="button"
            onClick={() => void auth.signOut()}
            className="mt-1 text-xs text-text-muted hover:text-cyan cursor-pointer"
          >
            Sign out
          </button>
        </div>
      )}
      <div className="px-4 py-3 border-t border-border flex items-center justify-between">
        <button
          type="button"
          onClick={toggleTheme}
          aria-label="Toggle theme"
          title="Toggle theme (⌘+J)"
          className="text-text-muted hover:text-text text-xs cursor-pointer flex items-center gap-1.5"
        >
          <span aria-hidden>{theme === "dark" ? "☾" : "☀"}</span>
          <span>{theme === "dark" ? "Dark" : "Light"}</span>
        </button>
        <p className="text-text-muted text-xs" id="version-display">
          &nbsp;
        </p>
      </div>
    </nav>
  );
}
