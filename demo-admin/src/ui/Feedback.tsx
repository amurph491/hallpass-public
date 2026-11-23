import type { ReactNode } from "react";
import { Button } from "./Button";

export function Spinner({ label }: { label?: string }) {
  return <span className="spinner" role={label ? "status" : undefined} aria-label={label} />;
}

export function LoadingState({ children = "Loading…" }: { children?: ReactNode }) {
  return <div className="card state" role="status"><Spinner />{children}</div>;
}

export function ErrorState({ message, retry }: { message: string; retry: () => void }) {
  return (
    <div className="card state state-error" role="alert">
      <strong>Couldn’t load this workspace</strong>
      <p className="muted">{message}</p>
      <Button onClick={retry}>Try again</Button>
    </div>
  );
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}
