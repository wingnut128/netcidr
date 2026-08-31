import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthContextValue, AuthStatus } from "../../auth/AuthContext";
import { AuthGate } from "./AuthGate";

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
  GoogleLogin: ({ onSuccess }: { onSuccess: (value: { credential: string }) => void }) => (
    <button type="button" onClick={() => onSuccess({ credential: "test-jwt" })}>
      Sign in
    </button>
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

function protectedDeepLink() {
  return (
    <MemoryRouter initialEntries={["/visualizer"]}>
      <Routes>
        <Route
          path="/visualizer"
          element={
            <AuthGate>
              <h1>Allocation Map</h1>
            </AuthGate>
          }
        />
      </Routes>
    </MemoryRouter>
  );
}

describe("AuthGate protected deep links", () => {
  beforeEach(() => {
    mocks.auth = authState("anonymous");
  });

  it("reveals the requested protected page in place after login", () => {
    const view = render(protectedDeepLink());

    expect(screen.getByRole("heading", { name: "Sign in to netcidr" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(mocks.auth?.acceptCredential).toHaveBeenCalledWith("test-jwt");

    mocks.auth = authState("authenticated");
    view.rerender(protectedDeepLink());

    expect(screen.getByRole("heading", { name: "Allocation Map" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Sign in to netcidr" })).not.toBeInTheDocument();
  });
});
