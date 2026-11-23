import { useState } from "react";
import { useQueries, useQueryClient } from "@tanstack/react-query";
import { Approval, ApprovalDecision, controlPlaneApi } from "../../api/client";
import { queryKeys, useApprovals } from "../../api/queries";
import { useAdmin } from "../../app/AdminContext";
import { approvalErrorMessage } from "../../lib/approvals";
import { Button } from "../../ui/Button";
import { Dialog } from "../../ui/Dialog";
import { ErrorState, LoadingState } from "../../ui/Feedback";
import { ApprovalsView, PreviewTable } from "./ApprovalsView";

export function ApprovalsPage() {
  const { data, notify } = useAdmin();
  const client = useQueryClient();
  const approvals = useApprovals(true);
  const [confirming, setConfirming] = useState<{ approval: Approval; decision: ApprovalDecision }>();
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Record<string, string | undefined>>({});

  // Selected resources are named by their connection's listing; the catalog covers provider-level resources.
  const listings = useQueries({ queries: data.connections.map(connection => ({ queryKey: ["connections", connection.id, "resources"], queryFn: () => controlPlaneApi.connectionResources(connection.id) })) });
  const resourceNames = new Map<string, string>(data.resources.map(item => [item.id, item.name]));
  listings.forEach(listing => listing.data?.resources.forEach(item => resourceNames.set(item.id, item.name)));
  const agentName = (id: string) => data.agents.find(agent => agent.id === id)?.name ?? id;
  const resourceName = (id: string) => resourceNames.get(id) ?? id;

  async function decide() {
    if (!confirming) return;
    const { approval, decision } = confirming;
    setBusy(true);
    try {
      await controlPlaneApi.decideApproval(approval.id, decision);
      setErrors(current => ({ ...current, [approval.id]: undefined }));
      notify(decision === "approve" ? "Approved. The agent can now retry the same request." : "Denied.");
    } catch (exception) {
      setErrors(current => ({ ...current, [approval.id]: approvalErrorMessage(exception) }));
    } finally {
      setBusy(false);
      setConfirming(undefined);
      await client.invalidateQueries({ queryKey: queryKeys.approvals });
    }
  }

  if (approvals.isPending) return <LoadingState>Loading approvals…</LoadingState>;
  if (approvals.isError) return <ErrorState message={approvalErrorMessage(approvals.error)} retry={() => void approvals.refetch()} />;

  return (
    <>
      <ApprovalsView approvals={approvals.data} agentName={agentName} resourceName={resourceName} errors={errors} busy={busy} onDecide={(approval, decision) => setConfirming({ approval, decision })} />
      {confirming && (
        <Dialog
          title={confirming.decision === "approve" ? "Approve this request?" : "Deny this request?"}
          description={confirming.decision === "approve" ? "This allows exactly the request below, once, until its displayed expiry. The agent must retry it before that deadline." : "The agent’s request will be refused."}
          onClose={() => setConfirming(undefined)}
          footer={<>
            <Button onClick={() => setConfirming(undefined)} autoFocus>Cancel</Button>
            <Button variant={confirming.decision === "approve" ? "primary" : "danger-solid"} disabled={busy} onClick={() => void decide()}>{busy ? "Working…" : confirming.decision === "approve" ? "Approve" : "Deny"}</Button>
          </>}
        >
          <p><strong>{agentName(confirming.approval.agentId)}</strong> · <code>{confirming.approval.tool}</code> · {resourceName(confirming.approval.resourceId)}</p>
          <PreviewTable preview={confirming.approval.preview} />
        </Dialog>
      )}
    </>
  );
}
