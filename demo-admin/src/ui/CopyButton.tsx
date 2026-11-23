import { useEffect, useRef, useState } from "react";
import { Check, Copy } from "lucide-react";
import { Button } from "./Button";

/** Copies text produced on demand, so callers can keep secrets out of props until the click. */
export function CopyButton({ getText, label = "Copy", size = "sm", onError }: { getText: () => string | undefined; label?: string; size?: "sm" | "md"; onError?: () => void }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<number>();
  useEffect(() => () => window.clearTimeout(timer.current), []);
  async function copy() {
    const text = getText();
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 1600);
    } catch {
      onError?.();
    }
  }
  return <Button size={size} onClick={() => void copy()} icon={copied ? <Check aria-hidden /> : <Copy aria-hidden />}>{copied ? "Copied" : label}</Button>;
}
