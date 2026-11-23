import { Link } from "react-router";
import type { Agent } from "../../api/client";
import { useActivity } from "../../api/queries";
import { useAdmin } from "../../app/AdminContext";
import { sectionPath } from "../../app/routes";
import { Card } from "../../ui/Card";
import { EmptyState, Spinner } from "../../ui/Feedback";
import { ActivityTable } from "../activity/ActivityTable";
import { useRequestParam } from "../activity/requestParam";

export function ActivityTab({ agent }: { agent: Agent }) {
  const { data } = useAdmin();
  const activity = useActivity(agent.id);
  const { open } = useRequestParam();
  return (
    <Card
      className="table-card"
      title="Activity"
      description="This agent’s calls and access tests, newest first."
      actions={<Link className="btn btn-ghost btn-sm" to={`${sectionPath("activity")}?agent=${encodeURIComponent(agent.id)}`}>Open in Activity</Link>}
    >
      {activity.error && <div className="card-body"><p className="field-error" role="alert">Some activity could not be loaded.</p></div>}
      {activity.requests.length
        ? <ActivityTable requests={activity.requests} agents={data.agents} tools={data.tools} caption={`Activity for ${agent.name}`} onOpen={open} showAgent={false} />
        : activity.error ? null
        : activity.loading
          ? <div className="state" role="status"><Spinner />Loading activity…</div>
          : <EmptyState title="No activity yet">Calls and tests for this agent show up here.</EmptyState>}
    </Card>
  );
}
