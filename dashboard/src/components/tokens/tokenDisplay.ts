import type { TokenSummary } from "../../auth/tokens";

export interface TokenStatus {
  label: "active" | "expired" | "revoked";
  className: string;
}

export function tokenStatus(token: TokenSummary): TokenStatus {
  if (token.revoked_at) {
    return { label: "revoked", className: "border-red/40 bg-red/10 text-red" };
  }
  if (new Date(token.expires_at).getTime() < Date.now()) {
    return {
      label: "expired",
      className: "border-text-muted bg-text-muted/30 text-text-muted",
    };
  }
  return {
    label: "active",
    className: "border-green/40 bg-green/10 text-green",
  };
}

export function formatTokenDate(rfc3339: string): string {
  const d = new Date(rfc3339);
  if (isNaN(d.getTime())) return rfc3339;
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}
