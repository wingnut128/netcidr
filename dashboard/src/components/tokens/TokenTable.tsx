import type { TokenSummary } from "../../auth/tokens";
import { TABLE_HEADER } from "../../lib/styles";
import { Panel } from "../ui/Panel";
import { formatTokenDate, tokenStatus } from "./tokenDisplay";

interface TokenTableProps {
  tokens: TokenSummary[] | null;
  onCreateClick: () => void;
  onRevokeClick: (token: TokenSummary) => void;
}

export function TokenTable({
  tokens,
  onCreateClick,
  onRevokeClick,
}: TokenTableProps) {
  return (
    <Panel
      title="Your tokens"
      actions={
        <button
          type="button"
          className="inline-flex items-center justify-center px-4 py-2 min-h-[44px] md:min-h-0 text-sm font-medium bg-cyan text-bg rounded-md cursor-pointer hover:bg-text transition-colors"
          onClick={onCreateClick}
        >
          Create token
        </button>
      }
    >
      {!tokens ? (
        <p className="text-text-muted text-sm">Loading...</p>
      ) : tokens.length === 0 ? (
        <p className="text-text-muted text-sm">
          No tokens yet. Create one to mint your first token.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr>
                <th className={TABLE_HEADER}>Name</th>
                <th className={TABLE_HEADER}>Prefix</th>
                <th className={TABLE_HEADER}>Created</th>
                <th className={TABLE_HEADER}>Expires</th>
                <th className={TABLE_HEADER}>Last used</th>
                <th className={TABLE_HEADER}>Status</th>
                <th className={TABLE_HEADER}></th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => (
                <TokenRow
                  key={token.id}
                  token={token}
                  onRevoke={() => onRevokeClick(token)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}

function TokenRow({
  token,
  onRevoke,
}: {
  token: TokenSummary;
  onRevoke: () => void;
}) {
  const status = tokenStatus(token);

  return (
    <tr className="border-b border-border last:border-b-0 hover:bg-cyan/[0.03] transition-colors">
      <td className="px-3 py-2">{token.name}</td>
      <td className="px-3 py-2 font-mono">{token.prefix}...</td>
      <td className="px-3 py-2 font-mono">
        {formatTokenDate(token.created_at)}
      </td>
      <td className="px-3 py-2 font-mono">
        {formatTokenDate(token.expires_at)}
      </td>
      <td className="px-3 py-2 font-mono">
        {token.last_used_at ? formatTokenDate(token.last_used_at) : "-"}
      </td>
      <td className="px-3 py-2">
        <span
          className={`inline-block px-2 py-0.5 text-xs font-medium capitalize rounded-md border ${status.className}`}
        >
          {status.label}
        </span>
      </td>
      <td className="px-3 py-2 text-right">
        {!token.revoked_at && (
          <button
            type="button"
            className="text-xs text-red hover:underline cursor-pointer"
            onClick={onRevoke}
          >
            Revoke
          </button>
        )}
      </td>
    </tr>
  );
}
