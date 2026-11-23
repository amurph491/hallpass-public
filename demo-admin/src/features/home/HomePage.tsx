import { ReactNode } from "react";
import { Link } from "react-router";
import { ArrowRight, CircleAlert, CircleCheck, CircleDashed } from "lucide-react";
import { useActivity, useExecutionSummary } from "../../api/queries";
import { useAdmin } from "../../app/AdminContext";
import { agentPath, appPath, sectionPath } from "../../app/routes";
import { activeGrants, lastUsed } from "../../lib/agents";
import { currentCredential } from "../../lib/access";
import type { App } from "../../lib/apps";
import { formatDate } from "../../lib/format";
import { AttentionItem, SetupStep, attentionItems, setupSteps } from "../../lib/home";
import { credentialStatus } from "../../lib/labels";
import { Button } from "../../ui/Button";
import { Card } from "../../ui/Card";
import { EmptyState, ErrorState, LoadingState } from "../../ui/Feedback";
import { Pill } from "../../ui/Pill";
import { ActivityTable } from "../activity/ActivityTable";
import { useRequestParam } from "../activity/requestParam";
import { clientFor } from "../agents/clients";

type Props = { apps: App[]; onAddAgent: () => void };

const activityPath = sectionPath("activity");

function StepRow({ step, next, onAddAgent, connectSlack, slackApp }: { step: SetupStep; next: boolean; onAddAgent: () => void; connectSlack: () => void; slackApp?: App }) {
  const agentName = step.agent?.name ?? "your agent";
  const copy: Record<SetupStep["key"], { title: string; done: string; detail: string; action?: ReactNode }> = {
    connect: {
      title: "Connect Slack",
      done: "Slack is connected",
      detail: "Hallpass keeps the Slack credential on the server. Agents never see it.",
      action: slackApp?.connection
        ? <Link className="btn btn-primary btn-sm" to={appPath(slackApp.id)}>Reconnect Slack</Link>
        : <Button variant="primary" size="sm" onClick={connectSlack}>Connect Slack</Button>
    },
    agent: {
      title: "Add an agent",
      done: "Agent added",
      detail: "One per client, such as Codex CLI or Claude Code. Each gets its own key and access.",
      action: <Button variant="primary" size="sm" onClick={onAddAgent}>Add agent</Button>
    },
    access: {
      title: "Give it access",
      done: "Access given",
      detail: "Choose what the agent may do, such as reading Slack messages.",
      action: step.agent && <Link className="btn btn-primary btn-sm" to={agentPath(step.agent.id)}>Give {agentName} access</Link>
    },
    key: {
      title: "Create its key and connect the client",
      done: "Key created",
      detail: "Three commands on the agent’s Client setup tab. The key is shown once.",
      action: step.agent && <Link className="btn btn-primary btn-sm" to={agentPath(step.agent.id, "setup")}>Set up {agentName}</Link>
    },
    call: {
      title: "Make a first call",
      done: "First call succeeded",
      detail: "Ask the agent to search Slack. This turns green once Slack answers.",
      action: step.agent && <Link className="btn btn-primary btn-sm" to={agentPath(step.agent.id, "setup")}>Open client setup</Link>
    }
  };
  const item = copy[step.key];
  return (
    <li className={`setup-step setup-step-${step.done ? "done" : "todo"}`}>
      {step.done ? <CircleCheck aria-hidden className="setup-step-icon" /> : <CircleDashed aria-hidden className="setup-step-icon" />}
      <div className="setup-step-row">
        <div className="setup-step-body">
          <strong>{step.done ? item.done : item.title}<span className="visually-hidden"> ({step.done ? "done" : "to do"})</span></strong>
          {!step.done && <p className="muted">{item.detail}</p>}
        </div>
        {next && item.action}
      </div>
    </li>
  );
}

function attentionCopy(item: AttentionItem): { text: string; to: string; action: string } {
  switch (item.kind) {
    case "key": return { text: `${item.agent?.name}’s key has expired`, to: agentPath(item.agent?.id ?? "", "key"), action: "Replace key" };
    case "app": return { text: `${item.app?.name} is ${item.app?.status.key === "expired" ? "expired" : "disconnected"}`, to: appPath(item.app?.id ?? ""), action: "View app" };
    case "blocked": return { text: `${item.count} blocked ${item.count === 1 ? "call" : "calls"} from agents in the loaded history for the last 24 hours`, to: `${activityPath}?result=blocked&source=agent&range=24h`, action: "Review" };
    case "failed": return { text: `${item.count} failed ${item.count === 1 ? "call" : "calls"} from agents in the loaded history for the last 24 hours`, to: `${activityPath}?result=failed&source=agent&range=24h`, action: "Review" };
    case "unknown": return { text: `${item.count} ${item.count === 1 ? "call" : "calls"} with an unknown outcome in the loaded history for the last 24 hours`, to: `${activityPath}?result=unknown&source=agent&range=24h`, action: "Review" };
  }
}

export function HomePage({ apps, onAddAgent }: Props) {
  const { data, clientOf, connectSlack } = useAdmin();
  const { open } = useRequestParam();
  const activity = useActivity();
  const { requests, loading, error } = activity;
  const summary = useExecutionSummary();
  const input = { apps, agents: data.agents, delegations: data.delegations, credentialsByAgent: data.credentialsByAgent, requests, hasCompletedExecution: summary.data?.hasCompletedExecution ?? false };
  const steps = setupSteps(input);
  const next = steps.findIndex(step => !step.done);
  const slackApp = apps.find(app => app.provider === "Slack");
  // A succeeded call proves setup happened; later problems, such as a disconnect, go under Needs attention.
  const setUp = steps.some(step => step.key === "call" && step.done);

  // Wait for durable setup evidence; a failed history read must not look like unfinished setup.
  if (loading || summary.isPending) return <LoadingState>Loading your workspace…</LoadingState>;
  if (summary.isError || error) return <ErrorState message="Execution history could not be loaded. Try again in a moment." retry={() => { void summary.refetch(); activity.refetch(); }} />;

  if (!setUp) return (
    <Card title="Get set up" description={`${steps.filter(step => step.done).length} of ${steps.length} done. Each step turns green when Hallpass sees it happen.`}>
      <div className="card-body">
        <ol className="setup-steps">
          {steps.map((step, index) => <StepRow key={step.key} step={step} next={index === next} onAddAgent={onAddAgent} connectSlack={connectSlack} slackApp={slackApp} />)}
        </ol>
      </div>
    </Card>
  );

  const attention = attentionItems(input);
  return (
    <div className="stack">
      <Card title="Needs attention" className={attention.length ? undefined : "card-quiet"}>
        {attention.length ? (
          <ul className="attention-list">
            {attention.map(item => {
              const text = attentionCopy(item);
              return (
                <li key={item.key}>
                  <CircleAlert aria-hidden />
                  <span>{text.text}</span>
                  <Link className="btn btn-secondary btn-sm" to={text.to}>{text.action}</Link>
                </li>
              );
            })}
          </ul>
        ) : <div className="card-body"><p className="all-clear"><CircleCheck aria-hidden />Nothing needs you right now.</p></div>}
      </Card>

      <Card title="Agents" actions={<Button size="sm" onClick={onAddAgent}>Add agent</Button>}>
        <div className="agent-strip">
          {data.agents.map(agent => {
            const key = credentialStatus(currentCredential(data.credentialsByAgent[agent.id]));
            const grants = activeGrants(data.delegations, agent.id).length;
            const last = lastUsed(data.credentialsByAgent[agent.id]);
            return (
              <Link key={agent.id} to={agentPath(agent.id)} className="agent-tile">
                <span className="agent-tile-head">
                  <strong>{agent.name}</strong>
                  <Pill tone={key.tone}>{key.badge}</Pill>
                </span>
                <small>{clientFor(clientOf(agent)).title}</small>
                <small>{grants ? `${grants} ${grants === 1 ? "capability" : "capabilities"}` : "No access"}</small>
                <small>{last ? `Last active ${formatDate(last)}` : "Never active"}</small>
              </Link>
            );
          })}
        </div>
      </Card>

      <Card
        className="table-card"
        title="Recent activity"
        actions={<Link className="btn btn-ghost btn-sm" to={activityPath}>View all<ArrowRight aria-hidden /></Link>}
      >
        {requests.length
          ? <ActivityTable requests={requests.slice(0, 5)} agents={data.agents} tools={data.tools} caption="Recent activity" onOpen={open} />
          : <EmptyState title="No activity yet" />}
      </Card>
    </div>
  );
}
