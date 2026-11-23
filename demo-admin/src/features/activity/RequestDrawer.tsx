import { Link } from "react-router";
import { useRequestEvents } from "../../api/queries";
import { useAdmin } from "../../app/AdminContext";
import { agentPath } from "../../app/routes";
import { formatDate } from "../../lib/format";
import { authorizationSourceLabel } from "../../lib/labels";
import { buildRequests, requestAction, requestExplanation, requestTimeline } from "../../lib/requests";
import { Button } from "../../ui/Button";
import { CopyButton } from "../../ui/CopyButton";
import { Dialog } from "../../ui/Dialog";
import { EmptyState, Spinner } from "../../ui/Feedback";
import { Pill } from "../../ui/Pill";

/** What happened to one request: the result in plain words, its timeline, then the evidence. */
export function RequestDrawer({ requestId, onClose }: { requestId: string; onClose: () => void }) {
  const { data } = useAdmin();
  const events = useRequestEvents(requestId);
  const decision = data.decisions.find(item => item.requestId === requestId);
  // Wait for the lifecycle before showing a result, so an allowed call never flashes as "Allowed" before "Succeeded".
  const loading = events.isPending;
  const [request] = loading ? [] : buildRequests(decision ? [decision] : [], events.data ?? []);

  if (!request) {
    return (
      <Dialog variant="drawer" title={loading ? "Loading request…" : events.isError ? "Execution history unavailable" : "Request not found"} onClose={onClose} footer={<><span className="spacer" /><Button onClick={onClose}>Close</Button></>}>
        {loading
          ? <div className="state" role="status"><Spinner />Loading request…</div>
          : <EmptyState title={events.isError ? "Couldn’t load this request" : "Nothing recorded for this request"}>
              {events.isError ? "Execution history is unavailable. The execution outcome could not be loaded." : "It may be older than the history Hallpass keeps loaded, or the link is wrong."}
            </EmptyState>}
        {events.isError && <Button onClick={() => void events.refetch()}>Retry</Button>}
      </Dialog>
    );
  }

  const agent = data.agents.find(item => item.id === request.agentId);
  const action = requestAction(request, data.tools);
  const timeline = requestTimeline(request);
  const executionUnavailable = request.source !== "test" && events.isError;
  const executionLoading = request.source !== "test" && events.isPending;
  const correlationId = decision?.correlationId || request.events[0]?.correlationId;
  const resource = decision?.resource && (data.resources.find(item => item.id === decision.resource)?.name || decision.resource);

  return (
    <Dialog
      variant="drawer"
      className="request-drawer"
      eyebrow={<Pill tone={executionUnavailable ? "warning" : executionLoading ? "muted" : request.result.tone}>{executionUnavailable ? "Execution history unavailable" : executionLoading ? "Loading execution history…" : request.result.label}</Pill>}
      title={action.label}
      description={`${agent?.name ?? "Unknown agent"} · ${request.source === "test" ? "Access test" : request.source === "agent" ? "Agent call" : "Unknown source"} · ${formatDate(request.at)}`}
      onClose={onClose}
      footer={<>
        {agent && <Link className="btn btn-secondary" to={agentPath(agent.id, "activity")}>View {agent.name}</Link>}
        <span className="spacer" />
        <Button onClick={onClose}>Close</Button>
      </>}
    >
      {executionUnavailable ? <div role="alert"><p className="request-summary">The authorization decision is recorded, but the execution outcome could not be loaded.</p><Button onClick={() => void events.refetch()}>Retry</Button></div>
        : executionLoading ? <p className="request-summary" role="status">Loading execution evidence…</p>
        : <p className="request-summary">{requestExplanation(request)}</p>}

      <section className="drawer-section">
        <h3>Timeline</h3>
        <ol className="timeline">
          {timeline.map(step => (
            <li key={step.key} className={`timeline-step timeline-${step.tone}`}>
              <span className="timeline-dot" aria-hidden />
              <div>
                <strong>{step.label}</strong>
                {step.detail && <p>{step.detail}</p>}
              </div>
              {step.at && <time dateTime={step.at}>{new Date(step.at).toLocaleTimeString([], { hour: "numeric", minute: "2-digit", second: "2-digit" })}</time>}
            </li>
          ))}
        </ol>
        {events.isError && <p className="field-error" role="alert">Call events couldn’t be loaded, so this timeline may be incomplete.</p>}
      </section>

      <section className="drawer-section">
        <h3>Evidence</h3>
        <dl className="kv">
          {decision && <div><dt>Authorization decision</dt><dd>{decision.decision === "allow" ? "Allowed" : decision.decision === "require_approval" ? "Requires approval" : "Denied"}</dd></div>}
          <div><dt>Agent</dt><dd>{agent ? <Link to={agentPath(agent.id)}>{agent.name}</Link> : <span className="mono">{request.agentId ?? "Unknown"}</span>}</dd></div>
          <div><dt>Capability</dt><dd>{action.capability ? <span className="mono">{action.capability}</span> : "None (unmapped tools are always blocked)"}</dd></div>
          {request.tool && <div><dt>Tool</dt><dd className="mono">{request.tool}</dd></div>}
          {resource && <div><dt>Resource</dt><dd>{resource}</dd></div>}
          {decision?.policy && <div><dt>Policy</dt><dd className="mono">{decision.policy}</dd></div>}
          {decision?.delegation && <div><dt>Access grant</dt><dd className="mono">{decision.delegation}</dd></div>}
          <div><dt>Source</dt><dd>{authorizationSourceLabel(decision?.authorizationSource ?? request.events[0]?.authorizationSource)}</dd></div>
          <div><dt>Request ID</dt><dd className="kv-copy"><span className="mono">{request.requestId}</span><CopyButton getText={() => request.requestId} label="Copy" /></dd></div>
          {correlationId && <div><dt>Correlation ID</dt><dd className="kv-copy"><span className="mono">{correlationId}</span><CopyButton getText={() => correlationId} label="Copy" /></dd></div>}
        </dl>
      </section>
    </Dialog>
  );
}
