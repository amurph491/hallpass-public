import { FormEvent, useState } from "react";
import { oidcStartPath } from "../api/client";
import type { SessionState } from "../lib/session";
import { Button } from "../ui/Button";
import { Field } from "../ui/Field";
import { Wordmark } from "./AdminChrome";

export type SessionGateProps = { gate?: SessionState; error?: string; busy: boolean; onRetry: () => Promise<void>; onBootstrap: (value: string) => Promise<void>; onSelect: (tenantId: string) => Promise<void>; onSignOut: () => Promise<void> };
export function SessionGate({ gate, error, busy, onRetry, onBootstrap, onSelect, onSignOut }: SessionGateProps) {
  const [bootstrap, setBootstrap] = useState("");
  async function submit(event: FormEvent) {
    event.preventDefault();
    const value = bootstrap; setBootstrap("");
    await onBootstrap(value);
  }
  return <main className="signin"><div className="signin-card"><Wordmark />
    {!gate && <><h1>Loading management session…</h1>{error && <Button onClick={() => void onRetry()}>Retry</Button>}</>}
    {gate?.kind === "sign-in" && <>
      <h1>Sign in to your workspace</h1><p>Access follows your current workspace membership.</p>
      {gate.notice && <p className="field-error" role="alert">{gate.notice}</p>}
      <div className="card signin-form">
        {gate.methods.oidc && <a className="btn btn-primary" href={oidcStartPath}>Sign in with single sign-on</a>}
        {gate.methods.developmentBootstrap && <form className="signin-form" onSubmit={submit}>
          <Field label="Local development bootstrap value" hint={<>Find it in <code>.secrets/admin_bootstrap</code>. It is exchanged for a browser session and cleared from this form.</>}><input className="input" type="password" autoComplete="off" value={bootstrap} onChange={event => setBootstrap(event.target.value)} required disabled={busy} /></Field>
          <Button type="submit" variant="primary" disabled={busy}>{busy ? "Signing in…" : "Open development session"}</Button>
        </form>}
        {!gate.methods.oidc && !gate.methods.developmentBootstrap && <p>No sign-in method is configured on this server.</p>}
      </div>
    </>}
    {gate?.kind === "choose-tenant" && <>
      <h1>Choose a workspace</h1><p>You need administrator access to manage this workspace.</p>
      <div className="card signin-form">{gate.session.memberships.map(m => <Button key={m.tenantId} disabled={busy || m.role !== "ADMIN"} onClick={() => void onSelect(m.tenantId)}>{m.name || m.tenantId} · {m.breakGlass ? "Emergency administrator (time-boxed)" : m.role === "ADMIN" ? "Administrator" : "Member"}</Button>)}
      {!gate.session.memberships.length && <p>Your account has no active workspace membership.</p>}
      <Button disabled={busy} onClick={() => void onSignOut()}>Sign out</Button></div>
    </>}
    {error && <p className="field-error" role="alert">{error}</p>}
  </div></main>;
}
