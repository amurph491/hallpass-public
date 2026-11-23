/** Per-browser convenience state only. Storage can be unavailable; callers always get a fallback. */
export function readJson(key: string): unknown {
  try {
    return JSON.parse(window.localStorage.getItem(key) || "null");
  } catch {
    return null;
  }
}

export function writeJson(key: string, value: unknown): void {
  try {
    window.localStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Losing a remembered path or selection is acceptable.
  }
}
