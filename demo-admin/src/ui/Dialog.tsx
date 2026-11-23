import { FormEvent, ReactNode, useEffect, useId, useRef } from "react";
import { X } from "lucide-react";

type Props = {
  title: ReactNode;
  description?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  /** Renders inside `.dialog-footer`. */
  footer?: ReactNode;
  /** Wraps body and footer in a form so Enter submits. */
  onSubmit?: (event: FormEvent) => void;
  /** When false, Esc and backdrop clicks are ignored; only explicit buttons close. */
  dismissible?: boolean;
  variant?: "dialog" | "drawer";
  className?: string;
  /** Content above the title, such as a status pill in a drawer. */
  eyebrow?: ReactNode;
};

/**
 * Modal built on the native <dialog>: the browser supplies the focus trap,
 * inert background, top layer and Esc handling.
 */
export function Dialog({ title, description, onClose, children, footer, onSubmit, dismissible = true, variant = "dialog", className, eyebrow }: Props) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descriptionId = useId();

  useEffect(() => {
    const dialog = ref.current;
    if (dialog && !dialog.open) dialog.showModal();
    return () => dialog?.close();
  }, []);

  const drawer = variant === "drawer";
  const header = (
    <div className={drawer ? "drawer-header" : "dialog-header"}>
      <div>
        {eyebrow}
        <h2 id={titleId}>{title}</h2>
        {description && <p id={descriptionId}>{description}</p>}
      </div>
      {dismissible && <button type="button" className="btn btn-ghost btn-icon" onClick={onClose} aria-label="Close"><X /></button>}
    </div>
  );
  const body = <div className={drawer ? "drawer-body" : "dialog-body"}>{children}</div>;
  const foot = footer && <div className={drawer ? "drawer-footer" : "dialog-footer"}>{footer}</div>;

  return (
    <dialog
      ref={ref}
      className={[drawer ? "drawer" : "dialog", className].filter(Boolean).join(" ")}
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
      onCancel={event => { event.preventDefault(); if (dismissible) onClose(); }}
      onClick={event => { if (dismissible && event.target === ref.current) onClose(); }}
    >
      {onSubmit
        ? <form className="dialog-form" onSubmit={onSubmit}>{header}{body}{foot}</form>
        : <>{header}{body}{foot}</>}
    </dialog>
  );
}
