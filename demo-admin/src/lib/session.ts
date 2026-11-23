import type { LoginMethods, ManagementSession } from "../api/client";

export type SessionState =
  | { kind: "sign-in"; methods: LoginMethods; notice?: string }
  | { kind: "choose-tenant"; session: ManagementSession }
  | { kind: "ready"; session: ManagementSession };

export function loginNotice(value: string | null): string | undefined {
  if (value === "no_access") return "Your account does not have access to any Hallpass workspace.";
  if (value === "unavailable") return "Sign-in is temporarily unavailable. Existing sessions are unaffected.";
  if (value === "failed") return "Sign-in could not be completed. Please try again.";
  return undefined;
}

export function sessionGate(session: ManagementSession | undefined, methods: LoginMethods, notice: string | null = null): SessionState {
  if (!session) return { kind: "sign-in", methods, notice: loginNotice(notice) };
  if (!session.tenant || session.tenant.role !== "ADMIN") return { kind: "choose-tenant", session };
  return { kind: "ready", session };
}
