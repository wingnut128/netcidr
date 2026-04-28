import { GoogleLogin } from "@react-oauth/google";
import { useAuth } from "../../auth/AuthContext";
import { isAuthConfigured } from "../../auth/oidc";
import { useTheme } from "../../theme/ThemeProvider";

export function SignInCard() {
  const auth = useAuth();
  const { theme } = useTheme();

  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="bg-surface border border-border rounded-lg shadow-[0_1px_2px_rgba(15,23,42,0.04)] p-8 max-w-md w-full text-center">
        <h2 className="text-text text-lg font-semibold mb-2">
          Sign in to IPAM
        </h2>
        <p className="text-text-muted text-sm mb-6 leading-relaxed">
          The IPAM dashboard and the allocation Visualizer are restricted to
          allowlisted Google accounts. The calculator tools (Calc, Split,
          Contains, Summarize, Range) are available without signing in.
        </p>
        {isAuthConfigured ? (
          <div className="flex justify-center">
            <GoogleLogin
              onSuccess={(cred) => {
                if (cred.credential) {
                  auth.acceptCredential(cred.credential);
                } else {
                  auth.reportError(
                    "Google sign-in returned no credential — try again.",
                  );
                }
              }}
              onError={() => {
                auth.reportError(
                  "Google sign-in was cancelled or rejected. Confirm the account is on the allowlist.",
                );
              }}
              theme={theme === "dark" ? "filled_black" : "outline"}
              size="large"
              text="signin_with"
              shape="rectangular"
              useOneTap={false}
            />
          </div>
        ) : (
          <p className="text-red text-sm">
            Sign-in is not configured for this build (missing
            VITE_OAUTH_WEB_CLIENT_ID).
          </p>
        )}
        {auth.error && (
          <p className="mt-4 text-red text-sm border border-red/30 bg-red/10 rounded-md px-3 py-2 text-left">
            {auth.error}
          </p>
        )}
      </div>
    </div>
  );
}
