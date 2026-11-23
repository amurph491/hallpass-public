/**
 * Google Picker support for the admin UI.
 *
 * Invariant: the server never sends a provider token to the browser. The Picker uses its own short-lived
 * browser token (Google Identity Services token client, drive.file only) for the same OAuth client. That token
 * is held in a local variable for the Picker session, never sent to Hallpass, never logged, never stored, and
 * dropped as soon as the Picker closes.
 */

export const DRIVE_FILE_SCOPE = "https://www.googleapis.com/auth/drive.file";
export const GSI_SCRIPT_URL = "https://accounts.google.com/gsi/client";
export const GAPI_SCRIPT_URL = "https://apis.google.com/js/api.js";

export type PickerConfig = { clientId: string; apiKey: string; appId: string; scope: string };

type TokenResponse = { access_token?: string; error?: string };
type PickerDoc = { id?: string };
type PickerResponse = { action?: string; docs?: PickerDoc[] };
type PickerInstance = { setVisible(visible: boolean): void };
type PickerBuilderInstance = {
  addView(view: unknown): PickerBuilderInstance;
  enableFeature(feature: unknown): PickerBuilderInstance;
  setOAuthToken(token: string): PickerBuilderInstance;
  setDeveloperKey(key: string): PickerBuilderInstance;
  setAppId(appId: string): PickerBuilderInstance;
  setCallback(callback: (response: PickerResponse) => void): PickerBuilderInstance;
  build(): PickerInstance;
};

/** The subset of the Google globals this module uses. */
export type GoogleGlobals = {
  accounts: { oauth2: { initTokenClient(config: {
    client_id: string; scope: string; include_granted_scopes: boolean; callback: (response: TokenResponse) => void; error_callback?: (error: unknown) => void;
  }): { requestAccessToken(overrides?: { prompt?: string }): void } } };
  picker: {
    PickerBuilder: new () => PickerBuilderInstance;
    DocsView: new () => unknown;
    Feature: { MULTISELECT_ENABLED: unknown };
    Action: { PICKED: string; CANCEL: string; ERROR: string };
  };
};

/** Injectable seams so the flow runs without the network. */
export type PickerLoader = {
  loadScript(url: string): Promise<void>;
  /** Loads the Picker library of the already-loaded api.js (`gapi.load("picker")`). */
  loadPickerLibrary(): Promise<void>;
  google(): GoogleGlobals;
};

export type PickResult = { status: "picked"; ids: string[] } | { status: "cancelled" };

export class PickerError extends Error {}

const scriptLoads = new Map<string, Promise<void>>();

/** Appends a script tag once per URL, at click time. A failed load can be retried. */
export function loadScriptOnce(url: string): Promise<void> {
  const existing = scriptLoads.get(url);
  if (existing) return existing;
  const promise = new Promise<void>((resolve, reject) => {
    const script = document.createElement("script");
    script.src = url;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => { scriptLoads.delete(url); script.remove(); reject(new PickerError("Google scripts could not be loaded.")); };
    document.head.appendChild(script);
  });
  scriptLoads.set(url, promise);
  return promise;
}

type WindowWithGoogle = { google?: GoogleGlobals; gapi?: { load(name: string, callback: () => void): void } };

export const browserLoader: PickerLoader = {
  loadScript: loadScriptOnce,
  loadPickerLibrary: () => new Promise<void>((resolve, reject) => {
    const gapi = (window as unknown as WindowWithGoogle).gapi;
    if (!gapi) return reject(new PickerError("Google scripts could not be loaded."));
    gapi.load("picker", () => resolve());
  }),
  google() {
    const google = (window as unknown as WindowWithGoogle).google;
    if (!google) throw new PickerError("Google scripts could not be loaded.");
    return google;
  }
};

/**
 * Opens the Picker and returns the picked file IDs. Requests only the drive.file scope. The browser token is
 * a local that is cleared when the Picker reports PICKED or CANCEL (or anything fails).
 */
export async function pickDriveFiles(config: PickerConfig, loader: PickerLoader = browserLoader): Promise<PickResult> {
  try {
    await loader.loadScript(GSI_SCRIPT_URL);
    await loader.loadScript(GAPI_SCRIPT_URL);
    await loader.loadPickerLibrary();
  } catch (error) {
    throw error instanceof PickerError ? error : new PickerError("Google scripts could not be loaded.");
  }
  const google = loader.google();
  let token: string | undefined;
  try {
    token = await new Promise<string>((resolve, reject) => {
      const client = google.accounts.oauth2.initTokenClient({
        client_id: config.clientId,
        scope: DRIVE_FILE_SCOPE,
        // GIS otherwise includes prior grants, including Gmail send on the same client.
        include_granted_scopes: false,
        callback: response => response.access_token && !response.error ? resolve(response.access_token) : reject(new PickerError("Google did not grant access to pick files.")),
        error_callback: () => reject(new PickerError("Google sign-in was closed or blocked."))
      });
      client.requestAccessToken();
    });
    const accessToken = token;
    return await new Promise<PickResult>((resolve, reject) => {
      const view = new google.picker.DocsView();
      const picker = new google.picker.PickerBuilder()
        .addView(view)
        .enableFeature(google.picker.Feature.MULTISELECT_ENABLED)
        .setOAuthToken(accessToken)
        .setDeveloperKey(config.apiKey)
        .setAppId(config.appId)
        .setCallback(response => {
          if (response.action === google.picker.Action.PICKED) {
            token = undefined;
            resolve({ status: "picked", ids: (response.docs ?? []).map(doc => doc.id).filter((id): id is string => typeof id === "string" && id.length > 0) });
          } else if (response.action === google.picker.Action.CANCEL) {
            token = undefined;
            resolve({ status: "cancelled" });
          } else if (response.action === google.picker.Action.ERROR) {
            reject(new PickerError("Google Picker encountered an error."));
          }
        })
        .build();
      picker.setVisible(true);
    });
  } finally {
    token = undefined;
  }
}

export function pickerErrorMessage(error: unknown): string {
  return error instanceof PickerError ? error.message : "Google Picker could not be opened.";
}
