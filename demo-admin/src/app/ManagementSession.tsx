import { ReactNode, createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { QueryClientProvider } from "@tanstack/react-query";
import { ManagementSession, SESSION_EXPIRED_EVENT, invalidateSessionRequests, bootstrapAdminSession, loadManagementSession, loginMethods, selectTenant, signOut } from "../api/client";
import { createQueryClient } from "../api/queries";
import { SessionState, sessionGate } from "../lib/session";
import { SessionGate } from "./SessionGate";

type SessionActions = { session: ManagementSession; switchTenant: () => void; signOut: () => Promise<void> };
const SessionContext = createContext<SessionActions | undefined>(undefined);
export function useManagementSession() { return useContext(SessionContext); }

// Remount at every session/workspace boundary. Late responses can only reach the
// retired cache; neither cached records nor transient UI survive a switch.
function WorkspaceQueries({ children }: { children: ReactNode }) {
  const [client] = useState(createQueryClient);
  useEffect(() => () => { client.clear(); }, [client]);
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

export function ManagementSessionGate({ children }: { children: ReactNode }) {
  const [gate, setGate] = useState<SessionState>();
  const [error, setError] = useState<string>();
  const [busy, setBusy] = useState(false);
  const pending = useRef(false);
  const generation = useRef(0);
  const refresh = useCallback(async () => {
    const current = ++generation.current;
    setError(undefined);
    try {
      const [session, methods] = await Promise.all([loadManagementSession(), loginMethods()]);
      if (current === generation.current) setGate(sessionGate(session, methods, new URLSearchParams(window.location.search).get("login")));
    } catch (exception) {
      if (current === generation.current) setError(exception instanceof Error ? exception.message : "The management session could not be loaded.");
    }
  }, []);
  useEffect(() => {
    void refresh();
    function expired() {
      invalidateSessionRequests();
      setGate(undefined);
      void refresh();
    }
    window.addEventListener(SESSION_EXPIRED_EVENT, expired);
    return () => { ++generation.current; window.removeEventListener(SESSION_EXPIRED_EVENT, expired); };
  }, [refresh]);

  async function run(action: () => Promise<void>, leaveWorkspace = false) {
    if (pending.current) return;
    pending.current = true;
    invalidateSessionRequests();
    if (leaveWorkspace) setGate(undefined);
    setBusy(true); setError(undefined);
    try { await action(); await refresh(); }
    catch (exception) {
      // Restore verified session state even when logout or selection fails.
      await refresh();
      setError(exception instanceof Error ? exception.message : "The request could not be completed.");
    } finally { pending.current = false; setBusy(false); }
  }

  if (gate?.kind === "ready") {
    const actions: SessionActions = {
      session: gate.session,
      switchTenant: () => { invalidateSessionRequests(); setGate({ kind: "choose-tenant", session: gate.session }); },
      signOut: () => run(signOut, true)
    };
    return <SessionContext.Provider value={actions}><WorkspaceQueries key={`${gate.session.userId}:${gate.session.tenant!.tenantId}`}>{children}</WorkspaceQueries></SessionContext.Provider>;
  }
  return <SessionGate gate={gate} error={error} busy={busy} onRetry={refresh} onBootstrap={value => run(() => bootstrapAdminSession(value))} onSelect={tenantId => run(() => selectTenant(tenantId))} onSignOut={() => run(signOut)} />;
}
