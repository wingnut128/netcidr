import { useCallback, useEffect, useState } from "react";
import {
  type CreateTokenResponse,
  type TokenSummary,
  createToken,
  listTokens,
  revokeToken,
} from "../auth/tokens";
import { getErrorMessage } from "../lib/errors";

export function useTokens() {
  const [tokens, setTokens] = useState<TokenSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [createOpen, setCreateOpen] = useState(false);
  const [mintedToken, setMintedToken] = useState<CreateTokenResponse | null>(
    null,
  );
  const [pendingRevoke, setPendingRevoke] = useState<TokenSummary | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const r = await listTokens();
      setTokens(r.tokens);
    } catch (e: unknown) {
      setError(getErrorMessage(e, "Failed to load tokens"));
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const create = useCallback(
    async (name: string, expiresInDays: number) => {
      setBusy(true);
      try {
        const minted = await createToken({
          name,
          expires_in_days: expiresInDays,
        });
        setCreateOpen(false);
        setMintedToken(minted);
        await refresh();
      } catch (e: unknown) {
        setError(getErrorMessage(e, "Failed to create token"));
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  const revokePending = useCallback(async () => {
    if (!pendingRevoke) return;
    setBusy(true);
    try {
      await revokeToken(pendingRevoke.id);
      setPendingRevoke(null);
      await refresh();
    } catch (e: unknown) {
      setError(getErrorMessage(e, "Failed to revoke token"));
    } finally {
      setBusy(false);
    }
  }, [pendingRevoke, refresh]);

  return {
    tokens,
    error,
    busy,
    createOpen,
    mintedToken,
    pendingRevoke,
    clearError: () => setError(null),
    openCreate: () => setCreateOpen(true),
    closeCreate: () => setCreateOpen(false),
    create,
    dismissMinted: () => setMintedToken(null),
    openRevoke: setPendingRevoke,
    closeRevoke: () => setPendingRevoke(null),
    revokePending,
  };
}
