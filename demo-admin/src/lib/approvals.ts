import { ApiStatusError } from "../api/client";

/** One row of the argument table. Values are text only: nothing here is ever interpreted as HTML. */
export type PreviewRow = { key: string; value: string; kind: "text" | "json" | "empty" };

/** Strings render as text, null as an em dash, and everything else (objects, arrays, numbers, booleans) as formatted JSON. */
export function previewRows(preview: Record<string, unknown>): PreviewRow[] {
  return Object.entries(preview).map(([key, value]) => {
    if (value === null || value === undefined) return { key, value: "—", kind: "empty" };
    if (typeof value === "string") return { key, value, kind: "text" };
    return { key, value: JSON.stringify(value, null, 2), kind: "json" };
  });
}

/** Human copy for a failed decision or read. Read from the status alone, never from a response body. */
export function approvalErrorMessage(exception: unknown): string {
  if (exception instanceof ApiStatusError) {
    switch (exception.status) {
      case 403: return "This approval belongs to someone else, so you can’t decide it.";
      case 404: return "This request no longer exists. It may have been cleaned up.";
      case 409: return "This request was already decided.";
      case 410: return "This request expired. The agent can ask again.";
      case 503: return "Approvals are unavailable right now. Nothing was decided; try again in a moment.";
    }
  }
  return exception instanceof Error ? exception.message : "The decision could not be saved. Try again.";
}

/** "in 12 minutes", "3 minutes ago", "just now". */
export function relativeTime(value: string, now: number = Date.now()): string {
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return "—";
  const seconds = Math.round((time - now) / 1000);
  const abs = Math.abs(seconds);
  if (abs < 45) return "just now";
  const [amount, unit] = abs < 3600 ? [Math.round(abs / 60), "minute"] : abs < 86400 ? [Math.round(abs / 3600), "hour"] : [Math.round(abs / 86400), "day"];
  const label = `${amount} ${unit}${amount === 1 ? "" : "s"}`;
  return seconds > 0 ? `in ${label}` : `${label} ago`;
}
