import { useSearchParams } from "react-router";

/** The open request lives in `?request=<id>`, so any screen can open it and the link can be shared. */
export function useRequestParam(): { requestId?: string; open: (requestId: string) => void; close: () => void } {
  const [params, setParams] = useSearchParams();
  function update(requestId?: string) {
    const next = new URLSearchParams(params);
    if (requestId) next.set("request", requestId); else next.delete("request");
    setParams(next, { replace: !requestId });
  }
  return { requestId: params.get("request") || undefined, open: update, close: () => update() };
}
