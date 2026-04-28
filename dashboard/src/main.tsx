import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { AuthProvider } from "./auth/AuthContext";
import { ThemeProvider } from "./theme/ThemeProvider";
import { userManager } from "./auth/oidc";
import "./index.css";

/**
 * OIDC redirect handling sits *outside* React because the dashboard uses
 * HashRouter (URLs like `/#/ipam`), but Google's OAuth redirect URI must be
 * a real path (e.g., `/auth/callback`). When Google posts back to
 * `/auth/callback#id_token=…`, HashRouter would never match it. We catch
 * those paths here, hand the fragment to `userManager`, and bounce the
 * browser to the hash-routed app.
 */
async function handleOidcRedirect(): Promise<boolean> {
  if (!userManager) return false;
  const path = window.location.pathname;
  if (path === "/auth/callback") {
    try {
      await userManager.signinRedirectCallback();
    } catch (e) {
      console.error("OIDC callback failed", e);
    }
    window.location.replace("/#/ipam");
    return true;
  }
  if (path === "/auth/silent-callback") {
    try {
      await userManager.signinSilentCallback();
    } catch {
      // Reported via UserManager events to the parent window's AuthContext.
    }
    return true;
  }
  return false;
}

void (async () => {
  const handled = await handleOidcRedirect();
  if (handled) return;

  const root = document.getElementById("root");
  if (!root) throw new Error("Root element not found");

  createRoot(root).render(
    <StrictMode>
      <ThemeProvider>
        <AuthProvider>
          <App />
        </AuthProvider>
      </ThemeProvider>
    </StrictMode>,
  );
})();
