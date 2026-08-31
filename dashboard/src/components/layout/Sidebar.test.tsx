import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AuthContextValue, AuthStatus } from "../../auth/AuthContext";
import { Sidebar } from "./Sidebar";

const mocks = vi.hoisted(() => ({
  auth: null as AuthContextValue | null,
  get: vi.fn(),
}));

vi.mock("../../auth/AuthContext", () => ({
  useAuth: () => mocks.auth,
}));

vi.mock("../../theme/ThemeProvider", () => ({
  useTheme: () => ({ theme: "dark", toggleTheme: vi.fn() }),
}));

vi.mock("../../api", () => ({
  get: mocks.get,
}));

vi.mock("@react-oauth/google", () => ({
  GoogleLogin: ({
    onSuccess,
    click_listener,
  }: {
    onSuccess: (credential: { credential?: string }) => void;
    click_listener?: () => void;
  }) => (
    <button
      type="button"
      onClick={() => {
        click_listener?.();
        onSuccess({ credential: "test-jwt" });
      }}
    >
      Sign in
    </button>
  ),
}));

function authState(
  status: AuthStatus,
  overrides: Partial<AuthContextValue> = {},
): AuthContextValue {
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
    ...overrides,
  };
}

function sidebar(ipamEnabled = true, open = true) {
  return (
    <MemoryRouter>
      <Sidebar
        ipamEnabled={ipamEnabled}
        swaggerEnabled={false}
        open={open}
        onClose={vi.fn()}
      />
    </MemoryRouter>
  );
}

const publicLinks = ["Calc", "Split", "Contains", "Summarize", "Range"];
const protectedLinks = ["IPAM", "Visualize", "Hostnames"];

describe("Sidebar auth-aware navigation", () => {
  beforeEach(() => {
    mocks.auth = authState("anonymous");
    mocks.get.mockResolvedValue({
      name: "netcidr",
      version: "0.28.3",
      commit: "abc1234",
      commit_full: "abc123456789",
    });
  });

  it("shows public tools and sign-in, but no protected services, anonymously", () => {
    render(sidebar());

    for (const label of publicLinks) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
    for (const label of protectedLinks) {
      expect(screen.queryByRole("link", { name: label })).not.toBeInTheDocument();
    }
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
  });

  it("does not flash login or protected services while auth is loading", () => {
    mocks.auth = authState("loading", {
      isAdmin: true,
      isPlatformAdmin: true,
    });
    render(sidebar());

    expect(screen.getByRole("status")).toHaveTextContent("Checking sign-in");
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument();
    for (const label of protectedLinks) {
      expect(screen.queryByRole("link", { name: label })).not.toBeInTheDocument();
    }
    expect(screen.queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Activity" })).not.toBeInTheDocument();
  });

  it("reveals services immediately after successful authentication", () => {
    const view = render(sidebar());
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(mocks.auth?.clearError).toHaveBeenCalledOnce();
    expect(mocks.auth?.acceptCredential).toHaveBeenCalledWith("test-jwt");

    mocks.auth = authState("authenticated", { email: "user@example.com" });
    view.rerender(sidebar());

    for (const label of protectedLinks) {
      expect(screen.getByRole("link", { name: label })).toBeInTheDocument();
    }
    expect(screen.getByRole("link", { name: "Tokens" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument();
  });

  it("keeps IPAM services hidden when the feature is disabled", () => {
    mocks.auth = authState("authenticated", { email: "user@example.com" });
    render(sidebar(false));

    for (const label of protectedLinks) {
      expect(screen.queryByRole("link", { name: label })).not.toBeInTheDocument();
    }
    expect(screen.getByRole("link", { name: "Tokens" })).toBeInTheDocument();
  });

  it("shows pending access and sign-out without protected links", () => {
    const signOut = vi.fn();
    mocks.auth = authState("unallowlisted", {
      email: "pending@example.com",
      signOut,
    });
    render(sidebar());

    expect(screen.getByText("pending@example.com")).toBeInTheDocument();
    expect(screen.getByText("Access pending")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
    expect(signOut).toHaveBeenCalledOnce();
    for (const label of protectedLinks) {
      expect(screen.queryByRole("link", { name: label })).not.toBeInTheDocument();
    }
  });

  it("removes protected links when a session expires", () => {
    mocks.auth = authState("authenticated", { email: "user@example.com" });
    const view = render(sidebar());
    expect(screen.getByRole("link", { name: "IPAM" })).toBeInTheDocument();

    mocks.auth = authState("anonymous");
    view.rerender(sidebar());

    expect(screen.queryByRole("link", { name: "IPAM" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign in" })).toBeInTheDocument();
  });

  it("surfaces sign-in configuration and authentication errors", () => {
    mocks.auth = authState("disabled");
    const view = render(sidebar());
    expect(screen.getByRole("status")).toHaveTextContent("Sign-in unavailable");

    mocks.auth = authState("anonymous", { error: "Authentication failed" });
    view.rerender(sidebar());
    expect(screen.getByRole("alert")).toHaveTextContent("Authentication failed");
  });

  it("keeps the primary navigation and login keyboard accessible in the mobile drawer", async () => {
    const user = userEvent.setup();
    const { rerender } = render(sidebar(true, false));
    expect(screen.getByRole("navigation", { name: "Primary" })).toHaveClass(
      "-translate-x-full",
    );

    rerender(sidebar(true, true));
    expect(screen.getByRole("navigation", { name: "Primary" })).toHaveClass(
      "translate-x-0",
    );

    for (let index = 0; index < 6; index += 1) {
      await user.tab();
    }
    expect(screen.getByRole("button", { name: "Sign in" })).toHaveFocus();
  });
});
