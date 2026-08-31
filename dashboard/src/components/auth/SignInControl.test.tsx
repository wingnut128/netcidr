import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthContextValue, AuthStatus } from "../../auth/AuthContext";
import { SignInControl } from "./SignInControl";

const mocks = vi.hoisted(() => ({
  auth: null as AuthContextValue | null,
}));

vi.mock("../../auth/AuthContext", () => ({
  useAuth: () => mocks.auth,
}));

vi.mock("../../theme/ThemeProvider", () => ({
  useTheme: () => ({ theme: "dark", toggleTheme: vi.fn() }),
}));

vi.mock("@react-oauth/google", () => ({
  GoogleLogin: ({
    onSuccess,
    onError,
  }: {
    onSuccess: (credential: { credential?: string }) => void;
    onError?: () => void;
  }) => (
    <div>
      <button type="button" onClick={() => onSuccess({})}>
        Missing credential
      </button>
      <button type="button" onClick={onError}>
        Reject sign in
      </button>
    </div>
  ),
}));

function authState(status: AuthStatus): AuthContextValue {
  return {
    status,
    email: null,
    name: null,
    picture: null,
    isAdmin: false,
    isPlatformAdmin: false,
    adminContact: null,
    error: null,
    acceptCredential: vi.fn(),
    signOut: vi.fn(),
    reportError: vi.fn(),
    clearError: vi.fn(),
  };
}

describe("SignInControl", () => {
  beforeEach(() => {
    mocks.auth = authState("anonymous");
  });

  it("reports a successful response that contains no credential", () => {
    render(<SignInControl />);
    fireEvent.click(screen.getByRole("button", { name: "Missing credential" }));

    expect(mocks.auth?.reportError).toHaveBeenCalledWith(
      "Google sign-in returned no credential — try again.",
    );
  });

  it("reports a rejected sign-in", () => {
    render(<SignInControl />);
    fireEvent.click(screen.getByRole("button", { name: "Reject sign in" }));

    expect(mocks.auth?.reportError).toHaveBeenCalledWith(
      "Google sign-in was cancelled or rejected. Confirm the account is on the allowlist.",
    );
  });

  it("renders an accessible unavailable state when auth is disabled", () => {
    mocks.auth = authState("disabled");
    render(<SignInControl />);

    expect(screen.getByRole("status")).toHaveTextContent(
      "Sign-in unavailable for this deployment.",
    );
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
  });
});
