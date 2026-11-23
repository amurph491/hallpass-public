import type { Agent, Tool } from "../../api/client";
import { formatDate } from "../../lib/format";
import { ActivityRequest, SOURCES, requestAction } from "../../lib/requests";
import { Pill } from "../../ui/Pill";

type Props = {
  requests: ActivityRequest[];
  agents: Agent[];
  tools: Tool[];
  caption: string;
  onOpen: (requestId: string) => void;
  showAgent?: boolean;
};

/** One row per request, newest first. Rows open the request's detail. */
export function ActivityTable({ requests, agents, tools, caption, onOpen, showAgent = true }: Props) {
  const agentName = (id?: string) => agents.find(agent => agent.id === id)?.name;
  return (
    <div className="table-wrap">
      <table className="table table-interactive activity-table">
        <caption className="visually-hidden">{caption}</caption>
        <thead>
          <tr><th>Time</th>{showAgent && <th>Agent</th>}<th>Action</th><th>Result</th><th>Source</th></tr>
        </thead>
        <tbody>
          {requests.map(request => {
            const action = requestAction(request, tools);
            return (
              <tr key={request.requestId}>
                <td className="cell-muted cell-nowrap col-time">{formatDate(request.at)}</td>
                {showAgent && <td className="cell-nowrap col-agent">{agentName(request.agentId) || <span className="faint">Unknown agent</span>}</td>}
                <td className="col-action">
                  <span className="cell-primary">
                    <button type="button" className="row-link" onClick={() => onOpen(request.requestId)}>{action.label}</button>
                    {request.tool && <small className="mono">{request.tool}</small>}
                  </span>
                </td>
                <td className="col-result"><Pill tone={request.result.tone}>{request.result.label}</Pill></td>
                <td className="cell-muted cell-nowrap col-source">{SOURCES[request.source]}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
