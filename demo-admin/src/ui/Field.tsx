import { ReactElement, ReactNode, cloneElement, useId } from "react";

type Props = { label: string; hint?: ReactNode; error?: string; children: ReactElement<{ id?: string; "aria-describedby"?: string }> };

/** Labels one control and wires its hint and error for assistive technology. */
export function Field({ label, hint, error, children }: Props) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  const describedBy = [hint && hintId, error && errorId].filter(Boolean).join(" ") || undefined;
  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>{label}</label>
      {cloneElement(children, { id, "aria-describedby": describedBy })}
      {hint && <span className="field-hint" id={hintId}>{hint}</span>}
      {error && <span className="field-error" id={errorId} role="alert">{error}</span>}
    </div>
  );
}
