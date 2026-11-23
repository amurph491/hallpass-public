import { CopyButton } from "../../ui/CopyButton";

/** A copyable command or configuration block. */
export function Command({ value, label }: { value: string; label: string }) {
  return (
    <div className="command">
      <pre className="code-block" aria-label={label} tabIndex={0}><code>{value}</code></pre>
      <CopyButton getText={() => value} />
    </div>
  );
}
