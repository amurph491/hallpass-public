import { useState } from "react";
import { Button } from "../../ui/Button";
import { ConstraintDraftRow, FactOption, buildConstraints, describeConstraints } from "../../lib/constraints";
import type { Constraints } from "../../lib/constraints";

const CUSTOM = "__custom__";

type Props = { rows: ConstraintDraftRow[]; onChange: (rows: ConstraintDraftRow[]) => void; facts: FactOption[] };

/** Optional "Limit values" section: pick a known fact (or an advanced custom key) and list allowed values, one per line. */
export function LimitValues({ rows, onChange, facts }: Props) {
  const [customRows, setCustomRows] = useState<ReadonlySet<number>>(new Set());
  const result = buildConstraints(rows);
  const update = (index: number, patch: Partial<ConstraintDraftRow>) => onChange(rows.map((row, i) => i === index ? { ...row, ...patch } : row));
  const isCustom = (index: number) => customRows.has(index) || (rows[index].key !== "" && !facts.some(fact => fact.key === rows[index].key));
  return (
    <fieldset className="limit-values">
      <legend className="field-label">Limit values (optional)</legend>
      <span className="field-hint">Restrict this access to the listed values. Anything else is denied. Applies to every grant in this step.</span>
      {rows.map((row, index) => (
        <div key={index} className="limit-row">
          <label>
            <span className="field-label">Fact</span>
            <select className="input" value={isCustom(index) ? CUSTOM : row.key} onChange={event => {
              const next = new Set(customRows);
              if (event.target.value === CUSTOM) { next.add(index); setCustomRows(next); update(index, { key: "" }); }
              else { next.delete(index); setCustomRows(next); update(index, { key: event.target.value }); }
            }}>
              <option value="">Choose a fact…</option>
              {facts.map(fact => <option key={fact.key} value={fact.key}>{fact.label}</option>)}
              <option value={CUSTOM}>Advanced: custom key</option>
            </select>
          </label>
          {isCustom(index) && (
            <label>
              <span className="field-label">Custom key</span>
              <input className="input mono" value={row.key} placeholder="gmail.recipients" onChange={event => update(index, { key: event.target.value })} />
            </label>
          )}
          <label>
            <span className="field-label">Allowed values, one per line</span>
            <textarea className="input mono" rows={4} value={row.text} onChange={event => update(index, { text: event.target.value })} />
          </label>
          {facts.find(fact => fact.key === row.key)?.hint && <span className="field-hint">{facts.find(fact => fact.key === row.key)?.hint}</span>}
          <Button size="sm" onClick={() => { setCustomRows(new Set()); onChange(rows.filter((_, i) => i !== index)); }}>Remove limit</Button>
        </div>
      ))}
      <Button size="sm" onClick={() => onChange([...rows, { key: "", text: "" }])}>Add limit</Button>
      {!result.ok && result.errors.map(message => <p key={message} className="field-error" role="alert">{message}</p>)}
    </fieldset>
  );
}

/** Renders "Limited to: key ∈ {…}" lines as escaped text. */
export function ConstraintSummary({ constraints }: { constraints: Constraints | undefined }) {
  const lines = describeConstraints(constraints);
  if (!lines.length) return null;
  return <>{lines.map(line => <small key={line} className="mono">Limited to: {line}</small>)}</>;
}
