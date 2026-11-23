import type { Capability, Resource } from "../../api/client";
import { capabilityLabel } from "../../lib/capabilities";

type Props = {
  capabilities: Capability[];
  resources: Resource[];
  catalogResources: Resource[];
  selected: string[];
  onChange: (ids: string[]) => void;
  held?: string[];
};

/** Lets the administrator bind each capability grant to an addressable provider root or selected child. */
export function AccessPicker({ capabilities, resources, catalogResources, selected, onChange, held = [] }: Props) {
  const groups = new Map<string, Capability[]>();
  for (const capability of capabilities) {
    const key = capability.resourceId ?? "";
    groups.set(key, [...(groups.get(key) ?? []), capability]);
  }
  const resourceName = (id: string) => catalogResources.find(resource => resource.id === id)?.name || "Provider";
  const providerOf = (resourceId: string) => catalogResources.find(resource => resource.id === resourceId)?.provider?.toLowerCase();
  function toggle(key: string, checked: boolean) {
    onChange(checked ? [...selected, key] : selected.filter(item => item !== key));
  }
  return (
    <div className="access-picker">
      {[...groups.entries()].map(([catalogResourceId, items]) => {
        const provider = providerOf(catalogResourceId);
        const targets = resources.filter(resource => provider && resource.provider?.toLowerCase() === provider);
        return (
          <fieldset key={catalogResourceId} className="access-group">
            <legend>{resourceName(catalogResourceId)}</legend>
            {items.map(capability => targets.map(target => {
              const key = `${capability.id}|${target.id}`;
              const isHeld = held.includes(key);
              return (
                <label key={key} className="check-row">
                  <input type="checkbox" checked={isHeld || selected.includes(key)} disabled={isHeld} onChange={event => toggle(key, event.target.checked)} />
                  <span>
                    <strong>{capabilityLabel(capability.name)} · {target.name}</strong>
                    <small className="mono">{capability.name} · {target.type}{target.externalId ? ` · ${target.externalId}` : ""}{isHeld ? " · already granted" : ""}</small>
                  </span>
                </label>
              );
            }))}
          </fieldset>
        );
      })}
    </div>
  );
}
