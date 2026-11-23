export function formatDate(value?: string): string {
  const date = value ? new Date(value) : undefined;
  return date && Number.isFinite(date.getTime())
    ? date.toLocaleString([], { dateStyle: "medium", timeStyle: "short" })
    : "—";
}

export function initials(name: string): string {
  return name.split(" ").map(word => word[0]).join("").slice(0, 2);
}
