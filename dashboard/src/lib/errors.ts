/** Extract a human-readable message from an unknown caught value. */
export function getErrorMessage(err: unknown, fallback = "Unknown error"): string {
  return err instanceof Error ? err.message : fallback;
}
