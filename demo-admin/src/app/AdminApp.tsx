import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { useQueryClient } from "@tanstack/react-query";
import { Plus, Search } from "lucide-react";
import { Agent, Connection, connectionStartMessage, controlPlaneApi } from "../api/client";
import { queryKeys, useApprovals, useControlPlane, useRefetchAll } from "../api/queries";
import { currentCredential } from "../lib/access";
import { buildApps } from "../lib/apps";
import { capabilityLabel } from "../lib/capabilities";
import { ActivityPage } from "../features/activity/ActivityPage";
import { RequestDrawer } from "../features/activity/RequestDrawer";
import { useRequestParam } from "../features/activity/requestParam";
import { AddAgentDialog } from "../features/agents/AddAgentDialog";
import { AgentCredentialDialog } from "../features/agents/AgentCredentialDialog";
import { AgentPage } from "../features/agents/AgentPage";
import { AgentsPage } from "../features/agents/AgentsPage";
import { ClientKey, clientOf as guessClient, loadAgentClients, saveAgentClients } from "../features/agents/clients";
import { AppPage } from "../features/apps/AppPage";
import { ApprovalsPage } from "../features/approvals/ApprovalsPage";
import { AppsPage } from "../features/apps/AppsPage";
import { HomePage } from "../features/home/HomePage";
import { Button } from "../ui/Button";
import { ErrorState, LoadingState } from "../ui/Feedback";
import { PageHeader } from "../ui/PageHeader";
import { Toast, useToast } from "../ui/Toast";
import { AdminContext, AdminContextValue, MutationOptions } from "./AdminContext";
import { AdminSidebar, AdminTopbar, SearchItem } from "./AdminChrome";
import { useManagementSession } from "./ManagementSession";
import { AdminRoute, Section, agentPath, appPath, sectionCopy, sectionPath } from "./routes";

function errorMessage(exception: unknown, fallback: string): string {
  return exception instanceof Error ? exception.message : fallback;
}

/** UI state that only applies to the screen it was opened on, so back/forward navigation drops it. */
type Scoped<T> = { screen: string; value: T };

export function AdminApp({ route }: { route: Exclude<AdminRoute, { kind: "redirect" }> }) {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const queryClient = useQueryClient();
  const refetchAll = useRefetchAll();
  const data = useControlPlane();
  const { agents, credentialsByAgent, tools } = data;
  const { message: toast, notify } = useToast();
  const openRequest = useRequestParam();

  const section: Section = route.kind === "agent" ? "agents" : route.kind === "app" ? "apps" : route.section;
  const screen = route.kind === "agent" ? `agent:${route.agentId}` : route.kind === "app" ? `app:${route.appId}` : route.section;
  const [queryState, setQueryState] = useState<Scoped<string>>();
  const [agentClients, setAgentClients] = useState<Record<string, ClientKey>>(loadAgentClients);
  const [keyTarget, setKeyTarget] = useState<Agent>();
  const [busy, setBusy] = useState(false);

  const query = queryState?.screen === screen ? queryState.value : "";
  const setQuery = (value: string) => setQueryState({ screen, value });
  const adding = route.kind === "section" && route.section === "agents" && params.get("new") === "1";
  const apps = buildApps(data);
  const agent = route.kind === "agent" ? agents.find(item => item.id === route.agentId) : undefined;
  const app = route.kind === "app" ? apps.find(item => item.id === route.appId) : undefined;
  const title = agent?.name ?? app?.name ?? sectionCopy[section].title;

  useEffect(() => saveAgentClients(agentClients), [agentClients]);
  useEffect(() => { document.title = `${title} · Hallpass`; }, [title]);

  const pendingApprovals = useApprovals().data?.length ?? 0;
  const counts: Partial<Record<Section, number>> = { agents: agents.length, apps: apps.length, approvals: pendingApprovals };

  async function mutate<T>(action: () => Promise<T>, keys: ReadonlyArray<readonly unknown[]>, options: MutationOptions): Promise<{ value: T } | undefined> {
    setBusy(true);
    try {
      const value = await action();
      await Promise.all(keys.map(queryKey => queryClient.invalidateQueries({ queryKey })));
      notify(options.success);
      return { value };
    } catch (exception) {
      const message = errorMessage(exception, options.failure);
      if (options.onError) options.onError(message); else notify(message);
      // A partial multi-step write may have landed; show the server's current state.
      await Promise.all(keys.map(queryKey => queryClient.invalidateQueries({ queryKey })));
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  async function connectProvider(providerKey: string): Promise<string | undefined> {
    setBusy(true);
    try {
      window.location.assign(await controlPlaneApi.startConnection(providerKey));
      return undefined;
    } catch (exception) {
      const message = connectionStartMessage(providerKey, exception);
      notify(message);
      return message;
    } finally {
      setBusy(false);
    }
  }

  async function reconnect(connection: Connection) {
    setBusy(true);
    try {
      window.location.assign(await controlPlaneApi.reauthorizeConnection(connection.id));
    } catch (exception) {
      notify(errorMessage(exception, `${connection.provider} reconnection could not start.`));
    } finally {
      setBusy(false);
    }
  }

  async function disconnect(connection: Connection): Promise<boolean> {
    return Boolean(await mutate(() => controlPlaneApi.disconnect(connection.id), [queryKeys.connections], { success: `${connection.provider} disconnected. Calls that need it are blocked.`, failure: `${connection.provider} connection could not be disconnected.` }));
  }

  const session = useManagementSession();
  const context: AdminContextValue = {
    data,
    busy,
    adminOrigin: window.location.origin,
    agentApiUrl: session?.session.agentApiUrl,
    mutate,
    notify,
    openKeyDialog: setKeyTarget,
    clientOf: item => guessClient(item, agentClients),
    setClient: (agentId, client) => setAgentClients(current => ({ ...current, [agentId]: client })),
    connectSlack: () => void connectProvider("slack"),
    connectProvider,
    reconnect: connection => void reconnect(connection),
    disconnect
  };

  function openAddAgent() {
    navigate(`${sectionPath("agents")}?new=1`);
  }
  function closeAddAgent() {
    const next = new URLSearchParams(params);
    next.delete("new");
    setParams(next, { replace: true });
  }

  const searchable: SearchItem[] = [
    ...agents.map(item => ({ key: `agent-${item.id}`, name: item.name, meta: item.description || item.id, kind: "Agent", open: () => navigate(agentPath(item.id)) })),
    ...data.delegations.filter(item => item.status === "active").map(item => {
      const grantee = agents.find(candidate => candidate.id === item.granteeId)?.name || item.grantee;
      return { key: `grant-${item.id}`, name: `${capabilityLabel(item.capability)} · ${grantee}`, meta: item.capability, kind: "Access", open: () => navigate(agentPath(item.granteeId)) };
    }),
    ...apps.map(item => ({ key: `app-${item.id}`, name: item.name, meta: `${item.provider} · ${item.status.label}`, kind: "App", open: () => navigate(appPath(item.id)) })),
    ...tools.map(item => {
      const owner = apps.find(candidate => candidate.id === item.resourceId);
      return { key: `tool-${item.name}`, name: item.label || item.name, meta: item.name, kind: "Tool", open: () => navigate(owner ? appPath(owner.id) : sectionPath("apps")) };
    })
  ];

  const slackConnected = apps.some(item => item.provider === "Slack" && item.status.key === "connected");
  const headerAction =
    route.kind === "section" && section === "apps" && !slackConnected ? <Button variant="primary" icon={<Plus aria-hidden />} disabled={busy} onClick={() => void connectProvider("slack")}>Connect Slack</Button>
    : route.kind === "section" && section === "agents" && agents.length > 0 ? <Button variant="primary" icon={<Plus aria-hidden />} onClick={openAddAgent}>Add agent</Button>
    : undefined;

  function renderScreen() {
    if (data.loading) return <LoadingState>Loading your workspace…</LoadingState>;
    if (data.error) return <ErrorState message={data.error} retry={() => void refetchAll()} />;
    if (route.kind === "agent") return <AgentPage key={route.agentId} agentId={route.agentId} />;
    if (route.kind === "app") return <AppPage key={route.appId} app={app} />;
    switch (route.section) {
      case "home":
        return <HomePage apps={apps} onAddAgent={openAddAgent} />;
      case "agents":
        return (
          <>
            {agents.length > 0 && (
              <div className="toolbar">
                <div className="search">
                  <Search aria-hidden />
                  <input className="input" type="search" value={query} onChange={event => setQuery(event.target.value)} placeholder="Filter agents…" aria-label="Filter agents" />
                </div>
                <span className="toolbar-count">{agents.length} total</span>
              </div>
            )}
            <AgentsPage query={query} addButton={<Button variant="primary" icon={<Plus aria-hidden />} onClick={openAddAgent}>Add agent</Button>} />
          </>
        );
      case "apps":
        return <AppsPage apps={apps} />;
      case "approvals":
        return <ApprovalsPage />;
      case "activity":
        return <ActivityPage />;
    }
  }

  return (
    <AdminContext.Provider value={context}>
      <a className="skip-link" href="#main">Skip to content</a>
      <div className="shell">
        <AdminSidebar section={section} counts={counts} />
        <div className="main">
          <AdminTopbar title={title} searchable={searchable} />
          <main className="content" id="main" tabIndex={-1}>
            {route.kind === "section" && <PageHeader title={sectionCopy[section].title} description={sectionCopy[section].subtitle} actions={headerAction} />}
            {renderScreen()}
          </main>
        </div>
        {openRequest.requestId && !data.loading && <RequestDrawer key={openRequest.requestId} requestId={openRequest.requestId} onClose={openRequest.close} />}
        {keyTarget && (
          <AgentCredentialDialog
            agent={keyTarget}
            credential={currentCredential(credentialsByAgent[keyTarget.id])}
            client={context.clientOf(keyTarget)}
            onClose={() => setKeyTarget(undefined)}
            onChanged={() => void queryClient.invalidateQueries({ queryKey: queryKeys.agentCredentials(keyTarget.id) })}
          />
        )}
        {adding && <AddAgentDialog onClose={closeAddAgent} onDone={created => navigate(agentPath(created.id, "setup"), { replace: true })} />}
        <Toast message={toast} />
      </div>
    </AdminContext.Provider>
  );
}
