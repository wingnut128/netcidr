import { AuthGate } from "../components/auth/AuthGate";
import { ErrorBanner } from "../components/ui/ErrorBanner";
import { PageHeader } from "../components/ui/PageHeader";
import { CreateTokenModal } from "../components/tokens/CreateTokenModal";
import { RevealTokenModal } from "../components/tokens/RevealTokenModal";
import { RevokeTokenModal } from "../components/tokens/RevokeTokenModal";
import { TokenTable } from "../components/tokens/TokenTable";
import { useTokens } from "../hooks/useTokens";

export function Tokens() {
  return (
    <AuthGate>
      <TokensDashboard />
    </AuthGate>
  );
}

function TokensDashboard() {
  const tokens = useTokens();

  return (
    <div>
      <PageHeader
        title="Personal access tokens"
        subtitle="Mint long-lived tokens to call netcidr APIs from CLIs, scripts, and CI."
      />

      <ErrorBanner message={tokens.error} onDismiss={tokens.clearError} />

      <TokenTable
        tokens={tokens.tokens}
        onCreateClick={tokens.openCreate}
        onRevokeClick={tokens.openRevoke}
      />

      <CreateTokenModal
        open={tokens.createOpen}
        busy={tokens.busy}
        onClose={tokens.closeCreate}
        onSubmit={tokens.create}
      />

      <RevealTokenModal
        token={tokens.mintedToken}
        onDismiss={tokens.dismissMinted}
      />

      <RevokeTokenModal
        token={tokens.pendingRevoke}
        busy={tokens.busy}
        onCancel={tokens.closeRevoke}
        onConfirm={tokens.revokePending}
      />
    </div>
  );
}
