/** Value allowlists on grants: `constraints.value_in[factKey] = [allowed values]`. Mirrors the server bounds. */
export type ValueIn = Record<string, string[]>;
export type Constraints = { value_in?: ValueIn };

export type FactOption = { key: string; label: string; hint: string };

/** Known fact keys per capability name. Providers add entries (for example Gmail recipients, HubSpot properties). */
export const FACTS_BY_CAPABILITY: Record<string, FactOption[]> = {
  "Google.Mail.Send": [{ key: "gmail.recipients", label: "Recipients the agent may email", hint: "One email address per line" }],
  "HubSpot.Deal.Update": [{ key: "hubspot.properties", label: "Deal properties the agent may change", hint: "One internal property name per line, e.g. dealstage" }]
};

export const FACT_KEY_PATTERN = /^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,4}$/;
export const MAX_VALUE_LENGTH = 512;
export const MAX_VALUES_PER_KEY = 200;
export const MAX_KEYS = 20;

/** One editable row: a fact key and the allowed values, one per line. */
export type ConstraintDraftRow = { key: string; text: string };

export type DraftResult = { ok: true; constraints?: Constraints } | { ok: false; errors: string[] };

// eslint-disable-next-line no-control-regex
const CONTROL = new RegExp("[\\u0000-\\u001f\\u007f-\\u009f\\u2028\\u2029]");

/** Fact options offered for the given capability names, de-duplicated by key. */
export function factsFor(capabilityNames: string[], registry: Record<string, FactOption[]> = FACTS_BY_CAPABILITY): FactOption[] {
  const seen = new Map<string, FactOption>();
  for (const name of capabilityNames) for (const fact of registry[name] ?? []) if (!seen.has(fact.key)) seen.set(fact.key, fact);
  return [...seen.values()];
}

/** Validates a draft and builds the `constraints` payload. Fully blank rows are ignored; no values at all yields no constraints. */
export function buildConstraints(rows: ConstraintDraftRow[]): DraftResult {
  const errors: string[] = [];
  const valueIn: ValueIn = {};
  for (const row of rows) {
    const key = row.key.trim();
    const hasText = row.text.trim().length > 0;
    if (!key && !hasText) continue;
    if (!FACT_KEY_PATTERN.test(key)) { errors.push(`"${key}" is not a valid key. Use lowercase words separated by dots, such as gmail.recipients.`); continue; }
    if (Object.prototype.hasOwnProperty.call(valueIn, key)) { errors.push(`${key} is listed more than once.`); continue; }
    const values = row.text.split(/\r\n|\n|\r/).map(line => line.trim()).filter(line => line.length > 0);
    if (!values.length) { errors.push(`${key} needs at least one allowed value.`); continue; }
    if (values.length > MAX_VALUES_PER_KEY) { errors.push(`${key} allows at most ${MAX_VALUES_PER_KEY} values.`); continue; }
    if (values.some(value => CONTROL.test(value))) { errors.push(`${key} has a value with control characters.`); continue; }
    if (values.some(value => value.length > MAX_VALUE_LENGTH)) { errors.push(`${key} has a value longer than ${MAX_VALUE_LENGTH} characters.`); continue; }
    if (new Set(values).size !== values.length) { errors.push(`${key} has duplicate values.`); continue; }
    valueIn[key] = values;
  }
  if (Object.keys(valueIn).length > MAX_KEYS) errors.push(`At most ${MAX_KEYS} keys are allowed.`);
  if (errors.length) return { ok: false, errors };
  return Object.keys(valueIn).length ? { ok: true, constraints: { value_in: valueIn } } : { ok: true };
}

/** Request body for one grant; `constraints` is present only when a value list exists. */
export function delegationPayload(base: { agentId: string; capabilityId: string; resourceId?: string; expiresAt?: string }, constraints?: Constraints) {
  const valueIn = constraints?.value_in;
  return valueIn && Object.keys(valueIn).length > 0 ? { ...base, constraints: { value_in: valueIn } } : { ...base };
}

export const COLLAPSE_AFTER = 5;

/** Plain-text summaries, one per key: "key ∈ {a, b, and N more}". Callers must render as text, never HTML. */
export function describeConstraints(constraints: Constraints | undefined): string[] {
  const valueIn = constraints?.value_in ?? {};
  return Object.entries(valueIn).filter(([, values]) => values.length > 0).map(([key, values]) => {
    const shown = values.slice(0, COLLAPSE_AFTER).join(", ");
    const more = values.length - COLLAPSE_AFTER;
    return `${key} ∈ {${shown}${more > 0 ? `, and ${more} more` : ""}}`;
  });
}
