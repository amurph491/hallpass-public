import { useEffect, useRef, useState } from "react";
import { CircleCheck } from "lucide-react";

export function useToast(durationMs = 3200) {
  const [message, setMessage] = useState<string>();
  const timer = useRef<number>();
  useEffect(() => () => window.clearTimeout(timer.current), []);
  function notify(next: string) {
    window.clearTimeout(timer.current);
    setMessage(next);
    timer.current = window.setTimeout(() => setMessage(undefined), durationMs);
  }
  return { message, notify };
}

export function Toast({ message }: { message?: string }) {
  return (
    <div role="status" aria-live="polite">
      {message && <div className="toast"><CircleCheck aria-hidden />{message}</div>}
    </div>
  );
}
