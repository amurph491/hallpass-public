import { Link, useSearchParams } from "react-router";
import { RefreshCw } from "lucide-react";
import { HISTORY_LIMIT, useActivity } from "../../api/queries";
import { useAdmin } from "../../app/AdminContext";
import { sectionPath } from "../../app/routes";
import { ActivityFilters, RANGES, RESULTS, SOURCES, filterRequests, parseFilters } from "../../lib/requests";
import { Button } from "../../ui/Button";
import { Card } from "../../ui/Card";
import { EmptyState, LoadingState, Spinner } from "../../ui/Feedback";
import { ActivityTable } from "./ActivityTable";
import { useRequestParam } from "./requestParam";

export function ActivityPage() {
  const { data } = useAdmin();
  const [params, setParams] = useSearchParams();
  const { open } = useRequestParam();
  const activity = useActivity();
  const filters = parseFilters(params);
  const rows = filterRequests(activity.requests, filters);
  const filtered = Object.values(filters).some(Boolean);

  function setFilter(key: keyof ActivityFilters, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value); else next.delete(key);
    setParams(next, { replace: true });
  }
  function clearFilters() {
    const next = new URLSearchParams(params);
    (["agent", "result", "source", "range"] as const).forEach(key => next.delete(key));
    setParams(next, { replace: true });
  }

  if (activity.loading) return <LoadingState>Loading activity…</LoadingState>;

  return (
    <div className="stack">
      <Card className="table-card">
        <div className="filters">
          <select className="select" aria-label="Agent" value={filters.agent ?? ""} onChange={event => setFilter("agent", event.target.value)}>
            <option value="">All agents</option>
            {data.agents.map(agent => <option key={agent.id} value={agent.id}>{agent.name}</option>)}
          </select>
          <select className="select" aria-label="Result" value={filters.result ?? ""} onChange={event => setFilter("result", event.target.value)}>
            <option value="">Any result</option>
            {Object.values(RESULTS).map(result => <option key={result.key} value={result.key}>{result.label}</option>)}
          </select>
          <select className="select" aria-label="Source" value={filters.source ?? ""} onChange={event => setFilter("source", event.target.value)}>
            <option value="">Agents and tests</option>
            {Object.entries(SOURCES).map(([key, label]) => <option key={key} value={key}>{label === "Agent" ? "Agent calls" : label === "Test" ? "Tests" : "Unknown source"}</option>)}
          </select>
          <select className="select" aria-label="Time" value={filters.range ?? ""} onChange={event => setFilter("range", event.target.value)}>
            <option value="">Any time</option>
            {Object.entries(RANGES).map(([key, range]) => <option key={key} value={key}>{range.label}</option>)}
          </select>
          {filtered && <Button variant="ghost" size="sm" onClick={clearFilters}>Clear filters</Button>}
          <span className="filters-end">
            <span className="toolbar-count">{rows.length} {rows.length === 1 ? "request" : "requests"}</span>
            <Button size="sm" disabled={activity.fetching} onClick={activity.refetch} icon={activity.fetching ? <Spinner /> : <RefreshCw aria-hidden />}>Refresh</Button>
          </span>
        </div>
        {activity.error && <div className="card-body"><p className="field-error" role="alert">Some activity could not be loaded. Refresh to try again.</p></div>}
        {rows.length
          ? <ActivityTable requests={rows} agents={data.agents} tools={data.tools} caption="Activity" onOpen={open} />
          : activity.error ? null
          : filtered
            ? <EmptyState title="No matching requests" action={<Button onClick={clearFilters}>Clear filters</Button>}>Try a wider time range or another result.</EmptyState>
            : <EmptyState title="No activity yet" action={<Link className="btn btn-secondary" to={sectionPath("agents")}>Go to agents</Link>}>Calls from your agents and access tests show up here.</EmptyState>}
      </Card>
      <p className="footnote">Shows this workspace’s latest 50 access checks and {HISTORY_LIMIT} call events.</p>
    </div>
  );
}
