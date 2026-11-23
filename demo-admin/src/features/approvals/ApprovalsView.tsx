import { ShieldCheck } from "lucide-react";
import type { Approval, ApprovalDecision } from "../../api/client";
import { PreviewRow, previewRows, relativeTime } from "../../lib/approvals";
import { Button } from "../../ui/Button";
import { Card } from "../../ui/Card";
import { EmptyState } from "../../ui/Feedback";

export function ApprovalCallout() {
  return (
    <div className="callout" role="note">
      <ShieldCheck aria-hidden />
      <span><strong>Approving allows exactly this request, once, until its displayed expiry.</strong> The agent must then retry the same request. A different request, or the same one after it expires, needs a new approval.</span>
    </div>
  );
}

/** Argument table. Every value is a React text child, so markup in a value is shown, never run. */
export function PreviewTable({ preview }: { preview: Record<string, unknown> }) {
  const rows: PreviewRow[] = previewRows(preview);
  if (!rows.length) return <p className="muted">This request has no arguments.</p>;
  return (
    <dl className="kv" aria-label="Request arguments">
      {rows.map(row => (
        <div key={row.key}>
          <dt>{row.key}</dt>
          <dd>{row.kind === "empty" ? row.value : <pre className="approval-preview">{row.value}</pre>}</dd>
        </div>
      ))}
    </dl>
  );
}

export type ApprovalCardProps = {
  approval: Approval;
  agentName: string;
  resourceName: string;
  now?: number;
  busy: boolean;
  error?: string;
  onDecide: (approval: Approval, decision: ApprovalDecision) => void;
};

export function ApprovalCard({ approval, agentName, resourceName, now, busy, error, onDecide }: ApprovalCardProps) {
  return (
    <Card>
      <div className="stack">
        <div className="approval-meta">
          <strong>{agentName}</strong>
          <span>wants to run <code>{approval.tool}</code></span>
          <span>on {resourceName}</span>
          <span>requested {relativeTime(approval.requestedAt, now)}</span>
          <span>expires {relativeTime(approval.expiresAt, now)}</span>
        </div>
        <PreviewTable preview={approval.preview} />
        {error && <div className="callout callout-warning" role="alert">{error}</div>}
        <div className="row">
          <Button variant="primary" disabled={busy} onClick={() => onDecide(approval, "approve")}>Approve</Button>
          <Button disabled={busy} onClick={() => onDecide(approval, "deny")}>Deny</Button>
        </div>
      </div>
    </Card>
  );
}

export type ApprovalsViewProps = Omit<ApprovalCardProps, "approval" | "agentName" | "resourceName" | "error"> & {
  approvals: Approval[];
  agentName: (id: string) => string;
  resourceName: (id: string) => string;
  errors: Record<string, string | undefined>;
};

export function ApprovalsView({ approvals, agentName, resourceName, errors, ...rest }: ApprovalsViewProps) {
  return (
    <div className="stack">
      <ApprovalCallout />
      {approvals.length === 0
        ? <Card><EmptyState title="Nothing is waiting for you">When an agent asks for something that needs approval, it appears here.</EmptyState></Card>
        : approvals.map(approval => (
          <ApprovalCard key={approval.id} approval={approval} agentName={agentName(approval.agentId)} resourceName={resourceName(approval.resourceId)} error={errors[approval.id]} {...rest} />
        ))}
    </div>
  );
}
