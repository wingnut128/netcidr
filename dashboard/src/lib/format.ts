/** Format a number with locale separators (e.g., 1,234,567). */
export function fmtNum(n: number | string): string {
  const num = Number(n);
  if (isNaN(num)) return String(n);
  return num.toLocaleString();
}

/** Format a number with compact suffix (e.g., 1.2K, 3.4M). */
export function fmtSize(n: number | string): string {
  const num = Number(n);
  if (isNaN(num)) return String(n);
  if (num >= 1e9) return (num / 1e9).toFixed(1) + "B";
  if (num >= 1e6) return (num / 1e6).toFixed(1) + "M";
  if (num >= 1e3) return (num / 1e3).toFixed(1) + "K";
  return String(num);
}

/** Format an ISO date string to locale date + time. */
export function fmtDate(s: string | null | undefined): string {
  if (!s) return "-";
  const d = new Date(s);
  if (isNaN(d.getTime())) return s.slice(0, 19);
  return (
    d.toLocaleDateString() +
    " " +
    d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })
  );
}
