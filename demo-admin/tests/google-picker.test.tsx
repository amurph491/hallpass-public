import assert from "node:assert/strict";
import test from "node:test";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router";
import { QueryClientProvider } from "@tanstack/react-query";
import { controlPlaneApi, type Connection, type Resource } from "../src/api/client.ts";
import { createQueryClient } from "../src/api/queries.ts";
import { AdminContext, type AdminContextValue } from "../src/app/AdminContext.tsx";
import { AppPage, CONNECTABLE_PROVIDERS, providerKey } from "../src/features/apps/AppPage.tsx";
import { DRIVE_FILE_SCOPE, GAPI_SCRIPT_URL, GSI_SCRIPT_URL, PickerError, pickDriveFiles, type GoogleGlobals, type PickerConfig, type PickerLoader } from "../src/features/apps/googlePicker.ts";
import { appStatus, type App } from "../src/lib/apps.ts";

const config: PickerConfig = { clientId: "client-1", apiKey: "key-1", appId: "app-1", scope: DRIVE_FILE_SCOPE };
const SECRET_TOKEN = "browser-token-value";

type Harness = { loader: PickerLoader; scopes: string[]; tokens: string[]; scripts: string[]; multiselect: boolean[]; developerKeys: string[]; appIds: string[] };
type PickerCallback = (response: { action?: string; docs?: Array<{ id?: string }> }) => void;

function harness(action: "PICKED" | "CANCEL" | "ERROR", docs: Array<{ id: string }> = [], tokenOk = true, precedingActions: string[] = []): Harness {
  const h: Harness = { loader: undefined as never, scopes: [], tokens: [], scripts: [], multiselect: [], developerKeys: [], appIds: [] };
  class Builder {
    private callback: PickerCallback = () => {};
    addView() { return this; }
    enableFeature(f: unknown) { h.multiselect.push(f === "multi"); return this; }
    setOAuthToken(t: string) { h.tokens.push(t); return this; }
    setDeveloperKey(k: string) { h.developerKeys.push(k); return this; }
    setAppId(a: string) { h.appIds.push(a); return this; }
    setCallback(c: PickerCallback) { this.callback = c; return this; }
    build() { return { setVisible: () => { for (const precedingAction of precedingActions) this.callback({ action: precedingAction }); this.callback({ action: action.toLowerCase(), docs }); } }; }
  }
  const google: GoogleGlobals = {
    accounts: { oauth2: { initTokenClient: init => { h.scopes.push(init.scope); assert.equal(init.include_granted_scopes, false, "Picker must not inherit other scopes granted to the same OAuth client"); return { requestAccessToken: () => init.callback(tokenOk ? { access_token: SECRET_TOKEN } : { error: "denied" }) }; } } },
    picker: { Action: { PICKED: "picked", CANCEL: "cancel", ERROR: "error" }, Feature: { MULTISELECT_ENABLED: "multi" }, DocsView: class {}, PickerBuilder: Builder }
  };
  h.loader = { loadScript: async url => { h.scripts.push(url); }, loadPickerLibrary: async () => {}, google: () => google };
  return h;
}

test("picker requests drive.file only, enables multiselect, and returns picked IDs without using fetch", async t => {
  const fetchCalls: unknown[] = [];
  t.mock.method(globalThis, "fetch", async (...args: unknown[]) => { fetchCalls.push(args); return new Response("{}"); });
  const h = harness("PICKED", [{ id: "f1" }, { id: "f2" }]);
  const result = await pickDriveFiles(config, h.loader);
  assert.deepEqual(result, { status: "picked", ids: ["f1", "f2"] });
  assert.deepEqual(h.scopes, ["https://www.googleapis.com/auth/drive.file"]);
  assert.deepEqual(h.scripts, [GSI_SCRIPT_URL, GAPI_SCRIPT_URL]);
  assert.deepEqual(h.multiselect, [true]);
  assert.deepEqual(h.developerKeys, ["key-1"]);
  assert.deepEqual(h.appIds, ["app-1"]);
  assert.deepEqual(h.tokens, [SECRET_TOKEN]);
  assert.equal(fetchCalls.length, 0);
  assert.equal(JSON.stringify(result).includes(SECRET_TOKEN), false);
});

test("cancel returns no IDs and leaves no token in the result", async () => {
  const result = await pickDriveFiles(config, harness("CANCEL").loader);
  assert.deepEqual(result, { status: "cancelled" });
  assert.equal(JSON.stringify(result).includes(SECRET_TOKEN), false);
});

test("Picker API errors reject instead of leaving the selection flow pending", async () => {
  await assert.rejects(pickDriveFiles(config, harness("ERROR").loader), error => error instanceof PickerError && /Picker encountered an error/.test(error.message));
});

test("nonterminal Picker actions do not prevent a later file selection", async () => {
  const result = await pickDriveFiles(config, harness("PICKED", [{ id: "f1" }], true, ["loaded"]).loader);
  assert.deepEqual(result, { status: "picked", ids: ["f1"] });
});

test("script load failure and a denied token are clear errors", async () => {
  const failing = harness("PICKED");
  failing.loader.loadScript = async () => { throw new Error("network"); };
  await assert.rejects(pickDriveFiles(config, failing.loader), error => error instanceof PickerError && /could not be loaded/.test(error.message));
  const denied = harness("PICKED", [], false);
  await assert.rejects(pickDriveFiles(config, denied.loader), error => error instanceof PickerError && /did not grant/.test(error.message));
  assert.deepEqual(denied.tokens, []);
});

function googleApp(connection?: Connection): App {
  const resource: Resource = { id: "google-provider", name: "Google", type: "provider", provider: "GOOGLE" };
  return { id: resource.id, name: "Google", provider: "Google", resource, connection, connections: connection ? [connection] : [], status: appStatus(connection), capabilities: [], blockedTools: [] };
}

function render(app: App, withPicker: boolean) {
  const client = createQueryClient();
  if (withPicker) client.setQueryData(["connections", "google", "picker-config"], config);
  const admin = { busy: false, connectProvider: async () => undefined, disconnect: async () => true, mutate: async () => undefined } as unknown as AdminContextValue;
  return renderToStaticMarkup(
    <QueryClientProvider client={client}>
      <MemoryRouter><AdminContext.Provider value={admin}><AppPage app={app} /></AdminContext.Provider></MemoryRouter>
    </QueryClientProvider>
  );
}

const connection: Connection = { id: "conn-g", resourceId: "google-provider", provider: "GOOGLE", status: "active", accountLabel: "me@example.com", createdAt: "2026-09-29T12:00:00Z" };

test("Add files button shows only for a Google connection with picker-config", () => {
  assert.match(render(googleApp(connection), true), /Add files from Google Drive/);
  assert.doesNotMatch(render(googleApp(connection), false), /Add files from Google Drive/);
  const slack: Resource = { id: "s", name: "Slack", type: "provider", provider: "SLACK" };
  const slackConnection: Connection = { ...connection, id: "conn-s", provider: "SLACK" };
  const slackApp: App = { id: "s", name: "Slack", provider: "Slack", resource: slack, connection: slackConnection, connections: [slackConnection], status: appStatus(slackConnection), capabilities: [], blockedTools: [] };
  assert.doesNotMatch(render(slackApp, true), /Add files from Google Drive/);
});

test("Google connect posts to the google start route and the callout explains the setup", async t => {
  assert.ok(CONNECTABLE_PROVIDERS.includes("Google"));
  const calls: Array<[string, string | undefined]> = [];
  t.mock.method(globalThis, "fetch", async (path: string, init?: RequestInit) => { calls.push([path, init?.method]); return new Response(JSON.stringify({ authorizationUrl: "https://accounts.google.com/o/oauth2" })); });
  await controlPlaneApi.startConnection(providerKey(googleApp()));
  assert.deepEqual(calls, [["/api/connections/google/start", "POST"]]);
  const html = render(googleApp(), false);
  assert.match(html, /Connect Google account/);
  assert.match(html, /HALLPASS_GOOGLE_DRIVE_CLIENT_ID/);
  assert.match(html, /google_drive_client_secret/);
  assert.match(html, /Only the files you pick/);
  assert.match(html, /personal Drive: only you can grant agents access/);
});

test("picker-config 404 means Picker is unavailable", async t => {
  t.mock.method(globalThis, "fetch", async () => new Response("{}", { status: 404 }));
  assert.equal(await controlPlaneApi.googlePickerConfig(), null);
});
