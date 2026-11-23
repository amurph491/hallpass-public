import { useQueries } from "@tanstack/react-query";
import { controlPlaneApi, type Connection, type Resource } from "../../api/client";

/** Both grant dialogs use the same currently addressable connection roots and selected children. */
export function useGrantResources(connections: Connection[], catalogResources: Resource[]): Resource[] {
  const active = connections.filter(connection => connection.status === "active");
  const listings = useQueries({ queries: active.map(connection => ({
    queryKey: ["connections", connection.id, "resources"],
    queryFn: () => controlPlaneApi.connectionResources(connection.id)
  })) });
  const connectedProviders = new Set(active.map(connection => connection.provider.toLowerCase()));
  return [
    ...catalogResources.filter(resource => resource.type.toLowerCase() === "provider" && !connectedProviders.has((resource.provider ?? "").toLowerCase())),
    ...active.flatMap((connection, index) => (listings[index]?.data?.resources ?? []).map(resource => ({
      id: resource.id, name: resource.name, type: resource.root ? "account" : resource.kind,
      provider: connection.provider, externalId: resource.externalId
    })))
  ];
}
