import { GoogleLogin } from "@react-oauth/google";
import { useAuth } from "../../auth/AuthContext";
import { useTheme } from "../../theme/ThemeProvider";

interface SignInControlProps {
  width?: string | number;
}

/** Shared Google sign-in control for both public and protected surfaces. */
export function SignInControl({ width }: SignInControlProps) {
  const auth = useAuth();
  const { theme } = useTheme();

  if (auth.status === "disabled") {
    return (
      <p className="text-red text-xs" role="status">
        Sign-in unavailable for this deployment.
      </p>
    );
  }

  return (
    <div>
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
        click_listener={auth.clearError}
        theme={theme === "dark" ? "filled_black" : "outline"}
        size="large"
        text="signin_with"
        shape="rectangular"
        useOneTap={false}
        width={width}
      />
      {auth.error && (
        <p
          className="mt-3 text-red text-xs border border-red/30 bg-red/10 rounded-md px-3 py-2 text-left"
          role="alert"
        >
          {auth.error}
        </p>
      )}
    </div>
  );
}
