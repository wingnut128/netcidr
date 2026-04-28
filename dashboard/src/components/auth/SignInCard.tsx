interface SignInCardProps {
  onSignIn: () => void;
  configured: boolean;
  error?: string | null;
}

export function SignInCard({ onSignIn, configured, error }: SignInCardProps) {
  const handleClick = (e: React.MouseEvent<HTMLButtonElement>) => {
    e.preventDefault();
    console.info("[SignInCard] button clicked");
    onSignIn();
  };

  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="bg-surface border border-border rounded-lg shadow-sm p-8 max-w-md w-full text-center">
        <h2 className="text-text text-lg font-semibold mb-2">
          Sign in to IPAM
        </h2>
        <p className="text-text-muted text-sm mb-6 leading-relaxed">
          The IPAM dashboard is restricted to allowlisted Google accounts.
          The other tools (Calc, Split, Contains, Summarize, Range, Visualize)
          are available without signing in.
        </p>
        {configured ? (
          <button
            type="button"
            onClick={handleClick}
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 border border-cyan text-cyan hover:bg-cyan hover:text-bg transition-colors text-sm font-medium rounded-md cursor-pointer"
          >
            <GoogleGlyph />
            Sign in with Google
          </button>
        ) : (
          <p className="text-red text-sm">
            Sign-in is not configured for this build (missing
            VITE_OAUTH_WEB_CLIENT_ID).
          </p>
        )}
        {error && (
          <p className="mt-4 text-red text-sm border border-red/30 bg-red/10 rounded-md px-3 py-2 text-left">
            {error}
          </p>
        )}
      </div>
    </div>
  );
}

function GoogleGlyph() {
  return (
    <svg
      width="14"
      height="14"
      viewBox="0 0 48 48"
      aria-hidden="true"
      focusable="false"
    >
      <path
        fill="#EA4335"
        d="M24 9.5c3.54 0 6.71 1.22 9.21 3.6l6.85-6.85C35.9 2.38 30.47 0 24 0 14.62 0 6.51 5.38 2.56 13.22l7.98 6.19C12.43 13.72 17.74 9.5 24 9.5z"
      />
      <path
        fill="#4285F4"
        d="M46.98 24.55c0-1.57-.15-3.09-.38-4.55H24v9.02h12.94c-.58 2.96-2.26 5.48-4.78 7.18l7.73 6c4.51-4.18 7.09-10.36 7.09-17.65z"
      />
      <path
        fill="#FBBC05"
        d="M10.53 28.59A14.5 14.5 0 0 1 9.5 24c0-1.6.27-3.15.74-4.59l-7.98-6.19A23.94 23.94 0 0 0 0 24c0 3.87.93 7.52 2.56 10.78l7.97-6.19z"
      />
      <path
        fill="#34A853"
        d="M24 48c6.48 0 11.93-2.13 15.89-5.81l-7.73-6c-2.15 1.45-4.92 2.3-8.16 2.3-6.26 0-11.57-4.22-13.47-9.91l-7.98 6.19C6.51 42.62 14.62 48 24 48z"
      />
      <path fill="none" d="M0 0h48v48H0z" />
    </svg>
  );
}
