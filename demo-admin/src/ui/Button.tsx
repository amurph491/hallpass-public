import type { ButtonHTMLAttributes, ReactNode } from "react";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "danger-solid" | "link";

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: Variant;
  size?: "md" | "sm";
  icon?: ReactNode;
};

export function Button({ variant = "secondary", size = "md", icon, className, children, type = "button", ...rest }: Props) {
  const classes = ["btn", `btn-${variant}`, size === "sm" && "btn-sm", className].filter(Boolean).join(" ");
  return <button type={type} className={classes} {...rest}>{icon}{children}</button>;
}
