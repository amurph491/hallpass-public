import type { ReactNode } from "react";
import { Button } from "./Button";
import { Dialog } from "./Dialog";

type Props = {
  title: string;
  /** What happens, stated plainly, e.g. "Its next call will be blocked." */
  children: ReactNode;
  confirmLabel: string;
  busy: boolean;
  onConfirm: () => void;
  onCancel: () => void;
};

export function ConfirmDialog({ title, children, confirmLabel, busy, onConfirm, onCancel }: Props) {
  return (
    <Dialog
      title={title}
      onClose={onCancel}
      footer={<>
        <Button onClick={onCancel} autoFocus>Cancel</Button>
        <Button variant="danger-solid" onClick={onConfirm} disabled={busy}>{busy ? "Working…" : confirmLabel}</Button>
      </>}
    >
      <p className="muted">{children}</p>
    </Dialog>
  );
}
