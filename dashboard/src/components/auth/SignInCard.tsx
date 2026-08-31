import { SignInControl } from "./SignInControl";

export function SignInCard() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="bg-surface border border-border rounded-lg shadow-[0_1px_2px_rgba(15,23,42,0.04)] p-8 max-w-md w-full text-center">
        <h2 className="text-text text-lg font-semibold mb-2">
          Sign in to netcidr
        </h2>
        <p className="text-text-muted text-sm mb-6 leading-relaxed">
          IPAM, Visualize, and Hostnames are restricted to allowlisted Google
          accounts. Calc, Split, Contains, Summarize, and Range remain
          available without signing in.
        </p>
        <div className="flex justify-center">
          <SignInControl width={280} />
        </div>
      </div>
    </div>
  );
}
