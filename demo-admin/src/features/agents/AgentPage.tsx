import { ReactNode, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { ChevronLeft, FlaskConical } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { queryKeys } from "../../api/queries";
import { useAdmin } from "../../app/AdminContext";
import { AgentTab, agentPath, parseAgentTab, sectionPath } from "../../app/routes";
import { activeGrants } from "../../lib/agents";
import { currentCredential } from "../../lib/access";
import { credentialStatus } from "../../lib/labels";
import { Button } from "../../ui/Button";
import { Dialog } from "../../ui/Dialog";
import { EmptyState } from "../../ui/Feedback";
import { Pill } from "../../ui/Pill";
import { Tabs, tabPanelProps } from "../../ui/Tabs";
import { TestAccessForm } from "./TestAccessForm";
import { AccessTab } from "./AccessTab";
import { ActivityTab } from "./ActivityTab";
import { clientFor } from "./clients";
import { KeyTab } from "./KeyTab";
import { SetupTab } from "./SetupTab";

export function AgentPage({ agentId }: { agentId: string }) {
  const { data, clientOf } = useAdmin();
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [testing, setTesting] = useState(false);
  const tab = parseAgentTab(params.get("tab"));
  const agent = data.agents.find(item => item.id === agentId);

  if (!agent) return (
    <div className="card">
      <EmptyState title="Agent not found" action={<Link className="btn btn-secondary" to={sectionPath("agents")}>Back to agents</Link>}>
        It may have been removed, or the link is wrong.
      </EmptyState>
    </div>
  );

  const key = credentialStatus(currentCredential(data.credentialsByAgent[agent.id]));
  const grants = activeGrants(data.delegations, agent.id);
  const tabs: Array<{ id: AgentTab; label: ReactNode }> = [
    { id: "access", label: <>Access<span className="tab-count">{grants.length}</span></> },
    { id: "key", label: "Key" },
    { id: "setup", label: "Client setup" },
    { id: "activity", label: "Activity" }
  ];

  return (
    <>
      <Link className="back-link" to={sectionPath("agents")}><ChevronLeft aria-hidden />Agents</Link>
      <div className="page-header">
        <div>
          <h1>{agent.name}</h1>
          <div className="meta-row">
            <span>{clientFor(clientOf(agent)).title}</span>
            <Pill tone={key.tone}>{key.badge}</Pill>
            <span className="mono faint">{agent.id}</span>
          </div>
          {agent.description && <p>{agent.description}</p>}
        </div>
        <div className="page-header-actions">
          <Button icon={<FlaskConical aria-hidden />} onClick={() => setTesting(true)}>Test access</Button>
        </div>
      </div>
      <Tabs label="Agent sections" tabs={tabs} active={tab} onChange={next => navigate(agentPath(agent.id, next), { replace: true })} />
      <div {...tabPanelProps(tab)}>
        {tab === "access" && <AccessTab agent={agent} />}
        {tab === "key" && <KeyTab agent={agent} />}
        {tab === "setup" && <SetupTab agent={agent} />}
        {tab === "activity" && <ActivityTab agent={agent} />}
      </div>
      {testing && (
        <Dialog className="dialog-wide" title={`Test ${agent.name}’s access`} description="Checks what this agent may do right now. Nothing is sent to Slack." onClose={() => setTesting(false)}>
          <TestAccessForm agents={data.agents} tools={data.tools} agentId={agent.id} onChecked={() => void queryClient.invalidateQueries({ queryKey: queryKeys.decisions })} />
        </Dialog>
      )}
    </>
  );
}
