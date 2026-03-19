/** Format a number with locale separators (e.g., 1,234,567). */
export function fmtNum(n: number | string): string {
  const num = Number(n);
  if (isNaN(num)) return String(n);
  return num.toLocaleString();
}
