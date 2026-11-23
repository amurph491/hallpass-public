import type { ReactNode } from "react";

type Props = { title?: ReactNode; description?: ReactNode; actions?: ReactNode; className?: string; children?: ReactNode; titleId?: string };

/** A bordered surface with an optional header. Children render unpadded; wrap them in `.card-body` when needed. */
export function Card({ title, description, actions, className, children, titleId }: Props) {
  return (
    <section className={["card", className].filter(Boolean).join(" ")} aria-labelledby={titleId}>
      {(title || actions) && (
        <div className="card-header">
          <div>
            {title && <h2 id={titleId}>{title}</h2>}
            {description && <p>{description}</p>}
          </div>
          {actions && <div className="card-header-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}
