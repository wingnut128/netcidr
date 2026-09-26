import { beforeEach, describe, expect, it, vi } from "vitest";

function token(exp: number): string {
  const payload = btoa(JSON.stringify({ sub: "user", exp, iat: 1 }));
  return `header.${payload}.signature`;
}

describe("ID token lifetime and storage boundary", () => {
  beforeEach(() => {
    window.localStorage.clear();
    vi.resetModules();
  });

  it("discards a legacy persisted token without authenticating from it", async () => {
    window.localStorage.setItem("netcidr.idToken", token(Date.now() / 1000 + 3600));
    const auth = await import("./oidc");
    expect(auth.getCurrentIdToken()).toBeNull();
    expect(window.localStorage.getItem("netcidr.idToken")).toBeNull();
  });

  it("never persists a new token and loses it on page module reload", async () => {
    const jwt = token(Date.now() / 1000 + 3600);
    const write = vi.spyOn(Storage.prototype, "setItem");
    const auth = await import("./oidc");
    expect(auth.setIdToken(jwt)?.sub).toBe("user");
    expect(auth.getCurrentIdToken()).toBe(jwt);
    expect(write).not.toHaveBeenCalled();
    vi.resetModules();
    const reloaded = await import("./oidc");
    expect(reloaded.getCurrentIdToken()).toBeNull();
    write.mockRestore();
  });

  it("refuses malformed and expired credentials before caching them", async () => {
    const auth = await import("./oidc");
    expect(auth.setIdToken("invalid")).toBeNull();
    expect(auth.getCurrentIdToken()).toBeNull();
    expect(auth.setIdToken(token(Date.now() / 1000 - 60))).toBeNull();
    expect(auth.getCurrentIdToken()).toBeNull();
  });
});
