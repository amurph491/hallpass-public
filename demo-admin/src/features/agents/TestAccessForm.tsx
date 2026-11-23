import { FormEvent, useEffect, useRef, useState } from "react";
import { Agent, CheckResult, Tool, controlPlaneApi } from "../../api/client";
import { RESULTS, reasonLabel, requestAction } from "../../lib/requests";
import { Button } from "../../ui/Button";
import { Field } from "../../ui/Field";
import { Pill } from "../../ui/Pill";

export const UNKNOWN_TOOL = "unknown_demo_tool";

type Props = {
  agents: Agent[];
  tools: Tool[];
  /** Fixes the agent and hides its picker. */
  agentId?: string;
  onChecked: () => void;
};

/** Runs a human authorization preview. It records a decision but never calls the provider. */
export function TestAccessForm({ agents, tools, agentId: fixedAgent, onChecked }: Props) {
  const [agentChoice, setAgentId] = useState("");
  const [toolChoice, setTool] = useState("");
  const agentId = fixedAgent || agentChoice || agents[0]?.id || "";
  const tool = toolChoice || tools[0]?.name || "";
  const [result, setResult] = useState<{ response: CheckResult; agentId: string; tool: string }>();
  const generation = useRef(0);
  const pending = useRef(false);
  useEffect(() => {
    ++generation.current; pending.current = false;
    setResult(undefined); setError(undefined); setBusy(false); setTool("");
    return () => { ++generation.current; };
  }, [fixedAgent]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (pending.current) return;
    pending.current = true;
    const current = ++generation.current;
    const submitted = { agentId, tool };
    setResult(undefined);
    setBusy(true);
    setError(undefined);
    try {
      const response = await controlPlaneApi.check(submitted);
      if (current === generation.current) { setResult({ response, ...submitted }); onChecked(); }
    } catch (exception) {
      if (current === generation.current) setError(exception instanceof Error ? exception.message : "The check did not complete.");
    } finally {
      if (current === generation.current) { pending.current = false; setBusy(false); }
    }
  }

  const outcome = result?.response.decision === "allow" ? RESULTS.allowed : result?.response.decision === "require_approval" ? RESULTS.approval : RESULTS.blocked;

  return (
    <div>
      <form className={`preview-form${fixedAgent ? " preview-form-single" : ""}`} onSubmit={submit}>
        {!fixedAgent && (
          <Field label="Agent">
            <select className="select" disabled={busy} value={agentId} onChange={event => { setAgentId(event.target.value); setResult(undefined); }}>
              {agents.map(agent => <option value={agent.id} key={agent.id}>{agent.name}</option>)}
            </select>
          </Field>
        )}
        <Field label="Tool">
          <select className="select" disabled={busy} value={tool} onChange={event => { setTool(event.target.value); setResult(undefined); }}>
            {tools.map(item => <option value={item.name} key={item.name}>{item.label || item.name}</option>)}
            <option value={UNKNOWN_TOOL}>Unknown tool (always denied)</option>
          </select>
        </Field>
        <Button type="submit" variant="primary" className="btn-field" disabled={!agentId || !tool || busy}>{busy ? "Checking…" : "Run test"}</Button>
        {error && <p className="field-error" role="alert">{error}</p>}
      </form>
      <div aria-live="polite">
        {result && (
          <div className="result">
            <div><Pill tone={outcome.tone}>{outcome.label}</Pill></div>
            <h3>{requestAction({ tool: result.tool }, tools).label}</h3>
            <p>{reasonLabel(result.response.reason)}</p>
            <dl className="kv">
              <div><dt>Agent</dt><dd>{agents.find(agent => agent.id === result.agentId)?.name || result.agentId}</dd></div>
              <div><dt>Tool</dt><dd className="mono">{result.tool}</dd></div>
              {result.response.capability && <div><dt>Capability</dt><dd>{result.response.capability}</dd></div>}
              {result.response.policy && <div><dt>Policy</dt><dd className="mono">{result.response.policy}</dd></div>}
              {result.response.delegation && <div><dt>Delegation</dt><dd className="mono">{result.response.delegation}</dd></div>}
            </dl>
          </div>
        )}
      </div>
    </div>
  );
}
