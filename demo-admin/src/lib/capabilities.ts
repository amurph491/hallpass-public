/** Plain-language names for known capabilities. The capability ID stays visible next to them. */
const LABELS: Record<string, string> = {
  "Slack.Message.Read": "Read Slack messages",
  "Slack.Message.Send": "Send Slack messages"
};

/** "Slack.Message.Read" -> "Read Slack messages"; unknown IDs fall back to readable words. */
export function capabilityLabel(name: string): string {
  if (LABELS[name]) return LABELS[name];
  const parts = name.split(".").filter(Boolean);
  if (parts.length < 2) return name;
  const action = parts[parts.length - 1];
  return `${action} ${parts.slice(0, -1).join(" ")}`;
}
