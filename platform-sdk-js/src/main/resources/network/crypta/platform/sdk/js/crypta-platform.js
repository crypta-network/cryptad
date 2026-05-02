(function (window) {
  "use strict";

  if (window.CryptaPlatform) {
    return;
  }

  const defaultPlatformApiRoot = "/api/v1/";
  const bootstrapResourcePath = ".well-known/cryptad-bootstrap.json";
  const bootstrapNonceHeader = "X-Crypta-App-Bootstrap-Nonce";
  const bootstrapNonceFragmentParameter = "cryptadBootstrapNonce";
  const removedElementSelector =
    "script, style, template, iframe, frame, frameset, object, embed, link, meta, base";
  const urlAttributeNames = new Set(["href", "src", "action", "formaction"]);
  const appIdPattern = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;

  let currentBootstrap = null;
  let currentAppId = null;
  let currentBrowserSessionToken = "";
  let currentBootstrapNonce = "";
  let loadingAppId = null;
  let loadingBootstrap = null;

  async function loadBootstrap(options) {
    const rawAppId = explicitAppId(options) || inferAppId();
    const requestedAppId = rawAppId ? normalizeAppId(rawAppId) : null;

    const force = !!(options && options.force);
    if (!force && currentBootstrap && bootstrapMatchesRequest(currentBootstrap, requestedAppId)) {
      return copyBootstrap(currentBootstrap);
    }
    if (
      !force &&
      loadingBootstrap &&
      (requestedAppId === null || loadingAppId === requestedAppId)
    ) {
      return loadingBootstrap.then(copyBootstrap);
    }

    loadingAppId = requestedAppId;
    const inFlightBootstrap = fetchBootstrap(requestedAppId)
      .then((bootstrap) => {
        currentBootstrap = bootstrap;
        currentAppId = bootstrap.appId;
        return bootstrap;
      })
      .finally(() => {
        if (loadingBootstrap === inFlightBootstrap) {
          loadingAppId = null;
          loadingBootstrap = null;
        }
      });
    loadingBootstrap = inFlightBootstrap;
    return inFlightBootstrap.then(copyBootstrap);
  }

  function current() {
    return currentBootstrap ? copyBootstrap(currentBootstrap) : null;
  }

  function currentId() {
    if (currentBootstrap && currentBootstrap.appId) {
      return currentBootstrap.appId;
    }
    const inferredAppId = inferAppId();
    return inferredAppId ? normalizeAppId(inferredAppId) : null;
  }

  async function fetchBootstrap(appId) {
    const urls = bootstrapUrls(appId);
    const headers = bootstrapHeaders();
    let lastResponse = null;
    let lastData = {};
    for (let index = 0; index < urls.length; index += 1) {
      const response = await fetch(urls[index], {
        headers,
        credentials: "omit",
      });
      const data = await readJson(response);
      if (response.ok) {
        return finishBootstrap(appId, data);
      }
      lastResponse = response;
      lastData = data;
      if (index + 1 >= urls.length) {
        break;
      }
    }
    throw new Error(responseErrorMessage(lastData, lastResponse));
  }

  function finishBootstrap(appId, data) {
    const bootstrap = sanitizeBootstrap(data);
    const browserSessionToken = sessionTokenFromBootstrap(data);
    if (bootstrap.appId) {
      bootstrap.appId = normalizeAppId(bootstrap.appId);
    }
    if (bootstrap.appId && appId && bootstrap.appId !== appId) {
      throw new Error("Bootstrap app id does not match the requested app.");
    }
    if (!bootstrap.appId && appId) {
      bootstrap.appId = appId;
    }
    if (!bootstrap.appId) {
      throw new Error("Bootstrap response did not include a Cryptad app id.");
    }
    currentBrowserSessionToken = browserSessionToken;
    return bootstrap;
  }

  function bootstrapHeaders() {
    const headers = { Accept: "application/json" };
    const nonce = bootstrapNonce();
    if (nonce) {
      headers[bootstrapNonceHeader] = nonce;
    }
    return headers;
  }

  function bootstrapNonce() {
    const nonce = bootstrapNonceFromHash(window.location.hash);
    if (nonce) {
      currentBootstrapNonce = nonce;
      return nonce;
    }
    return currentBootstrapNonce;
  }

  function bootstrapNonceFromHash(hash) {
    const value = typeof hash === "string" ? hash.trim() : "";
    if (!value || value === "#") {
      return "";
    }
    const params = new URLSearchParams(value.startsWith("#") ? value.substring(1) : value);
    const nonce = params.get(bootstrapNonceFragmentParameter);
    return typeof nonce === "string" ? nonce.trim() : "";
  }

  async function apiGet(path, options) {
    const requestOptions = options || {};
    if (requestOptions.bootstrap !== false) {
      await ensureBootstrap(requestOptions);
    }

    try {
      return await fetchApiGet(path, requestOptions);
    } catch (error) {
      if (!shouldRefreshAfterSessionError(error, requestOptions)) {
        throw error;
      }
      await refreshBootstrap(requestOptions);
      return fetchApiGet(path, requestOptions);
    }
  }

  async function fetchApiGet(path, requestOptions) {
    const url = apiUrl(path);
    applySearchParams(url, requestOptions.params || requestOptions.searchParams || requestOptions.query);

    const headers = appSessionHeaders(requestOptions.headers);
    const response = await fetch(url, {
      method: "GET",
      headers,
      signal: requestOptions.signal,
      credentials: "omit",
    });
    return readJsonOrThrow(response);
  }

  async function apiPostForm(path, formDataOrParams, options) {
    return submitFormMutation("POST", path, formDataOrParams, options);
  }

  async function apiDeleteForm(path, formDataOrParams, options) {
    return submitFormMutation("DELETE", path, formDataOrParams, options);
  }

  async function submitFormMutation(method, path, formDataOrParams, options) {
    const requestOptions = options || {};
    if (requestOptions.bootstrap !== false) {
      await refreshBootstrapForMutation(requestOptions);
    }

    const body = toUrlSearchParams(formDataOrParams);

    const headers = appSessionHeaders(requestOptions.headers);
    headers.set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
    const response = await fetch(apiUrl(path), {
      method,
      headers,
      body: body.toString(),
      signal: requestOptions.signal,
      credentials: "omit",
    });
    return readJsonOrThrow(response);
  }

  function apiUrl(path) {
    const root = normalizeLocalRoot(
      currentBootstrap && currentBootstrap.platformApiRoot,
      defaultPlatformApiRoot
    );
    const rootUrl = new URL(root, window.location.href);
    const url = coerceApiUrl(path, rootUrl);
    if (url.origin !== rootUrl.origin || !url.pathname.startsWith(rootUrl.pathname)) {
      throw new Error("Platform API URL must stay under the bootstrap API root.");
    }
    return url;
  }

  function queueSnapshot(options) {
    const snapshotOptions = options || {};
    const params = {
      page: snapshotOptions.page || "downloads",
    };
    if (snapshotOptions.sortBy) {
      params.sortBy = snapshotOptions.sortBy;
    }
    if (snapshotOptions.reversed) {
      params.reversed = "true";
    }
    if (snapshotOptions.advancedMode != null) {
      params.advancedMode = snapshotOptions.advancedMode ? "true" : "false";
    }
    return apiGet("queue", { params, signal: snapshotOptions.signal });
  }

  function directDownload(formDataOrParams, options) {
    return apiPostForm("queue/downloads", formDataOrParams, options);
  }

  function queueMutate(path, formDataOrParams, options) {
    if (typeof path !== "string" || !path.startsWith("queue/")) {
      throw new Error("Queue mutation paths must start with queue/.");
    }
    return apiPostForm(path, formDataOrParams, options);
  }

  function insertFile(formDataOrParams, options) {
    return apiPostForm("queue/inserts/file", formDataOrParams, options);
  }

  function insertDirectory(formDataOrParams, options) {
    return apiPostForm("queue/inserts/directory", formDataOrParams, options);
  }

  function sanitizeFragment(html, options) {
    const parser = new DOMParser();
    const parsed = parser.parseFromString(typeof html === "string" ? html : "", "text/html");
    sanitizeNode(parsed.body, options);
    const fragment = document.createDocumentFragment();
    fragment.append(...Array.from(parsed.body.childNodes));
    return fragment;
  }

  function sanitizeNode(root, options) {
    if (!root || typeof root.querySelectorAll !== "function") {
      return;
    }
    root.querySelectorAll(removedElementSelector).forEach((node) => {
      node.remove();
    });

    root.querySelectorAll("*").forEach((element) => {
      Array.from(element.attributes).forEach((attribute) => {
        const name = attribute.name.toLowerCase();
        if (name.startsWith("on") || name === "style" || name === "srcdoc") {
          element.removeAttribute(attribute.name);
          return;
        }
        if (urlAttributeNames.has(name) && !sameOrigin(attribute.value, options)) {
          element.removeAttribute(attribute.name);
        }
      });
    });
  }

  function sameOrigin(rawValue) {
    const value = typeof rawValue === "string" ? rawValue.trim() : "";
    if (!value || value.startsWith("#")) {
      return true;
    }
    if (value.startsWith("//")) {
      return false;
    }
    try {
      const url = new URL(value, window.location.href);
      return (
        (url.protocol === "http:" || url.protocol === "https:") &&
        url.origin === window.location.origin
      );
    } catch (error) {
      return false;
    }
  }

  function coerceApiUrl(path, rootUrl) {
    if (path instanceof URL) {
      return new URL(path.toString());
    }

    const value = path == null ? "" : String(path).trim();
    if (value.startsWith("//")) {
      throw new Error("Platform API paths must not be protocol-relative URLs.");
    }

    if (hasScheme(value)) {
      return new URL(value);
    }
    if (value.startsWith("/")) {
      return new URL(value, rootUrl);
    }
    return new URL(value, rootUrl);
  }

  function normalizeLocalRoot(value, fallback) {
    if (typeof value !== "string" || !value.trim() || value.trim().startsWith("//")) {
      return fallback;
    }
    try {
      const url = new URL(value.trim(), window.location.href);
      if (!localHttpOrigin(url) || url.search || url.hash || !url.pathname.startsWith("/api/v1/")) {
        return fallback;
      }
      url.pathname = url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
      return url.href;
    } catch (error) {
      return fallback;
    }
  }

  function localHttpOrigin(url) {
    const hostname = url.hostname.toLowerCase();
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      (hostname === "127.0.0.1" || hostname === "localhost" || hostname === "::1")
    );
  }

  function hasScheme(value) {
    return /^[A-Za-z][A-Za-z0-9+.-]*:/.test(value);
  }

  function applySearchParams(url, params) {
    if (!params) {
      return;
    }
    appendParams(url.searchParams, params, true);
  }

  function toUrlSearchParams(source) {
    const params = new URLSearchParams();
    appendParams(params, source, false);
    return params;
  }

  function appendParams(params, source, skipEmptyValues) {
    if (!source) {
      return;
    }

    if (typeof source.entries === "function") {
      for (const [key, value] of source.entries()) {
        appendParam(params, key, value, skipEmptyValues);
      }
      return;
    }

    if (Array.isArray(source)) {
      source.forEach((entry) => {
        if (Array.isArray(entry) && entry.length >= 2) {
          appendParam(params, entry[0], entry[1], skipEmptyValues);
        }
      });
      return;
    }

    if (typeof source === "object") {
      Object.keys(source).forEach((key) => {
        const value = source[key];
        if (Array.isArray(value)) {
          value.forEach((item) => appendParam(params, key, item, skipEmptyValues));
        } else {
          appendParam(params, key, value, skipEmptyValues);
        }
      });
    }
  }

  function appendParam(params, key, value, skipEmptyValues) {
    if (value == null || (skipEmptyValues && value === "")) {
      return;
    }
    if (typeof value === "string") {
      params.append(String(key), value);
    } else if (typeof value === "number" || typeof value === "boolean") {
      params.append(String(key), String(value));
    }
  }

  function jsonHeaders(headers) {
    const result = new Headers(headers || {});
    if (!result.has("Accept")) {
      result.set("Accept", "application/json");
    }
    return result;
  }

  function appSessionHeaders(headers) {
    const result = jsonHeaders(headers);
    if (!currentBrowserSessionToken) {
      throw new Error("App browser session is unavailable; reload the app UI.");
    }
    result.set("X-Crypta-App-Session", currentBrowserSessionToken);
    return result;
  }

  async function ensureBootstrap(options) {
    if (currentBootstrap && currentBrowserSessionToken && !(options && options.force)) {
      return currentBootstrap;
    }
    if (currentBootstrap && !currentBrowserSessionToken && !(options && options.force)) {
      return refreshBootstrap(options);
    }
    return loadBootstrap(options);
  }

  async function refreshBootstrap(options) {
    const appId = explicitAppId(options) || currentAppId || inferAppId();
    if (!appId) {
      return loadBootstrap(Object.assign({}, options, { force: true }));
    }
    return loadBootstrap(Object.assign({}, options, { appId, force: true }));
  }

  async function refreshBootstrapForMutation(options) {
    if (options && options.refreshBootstrap === false) {
      return ensureBootstrap(options);
    }
    if (!(options && options.force) && currentBrowserSessionLive()) {
      return ensureBootstrap(options);
    }
    return refreshBootstrap(options);
  }

  function currentBrowserSessionLive() {
    if (!currentBootstrap || !currentBrowserSessionToken) {
      return false;
    }
    const expiresAt = browserSessionExpiresAtMillis(currentBootstrap);
    return expiresAt == null || expiresAt > Date.now();
  }

  function browserSessionExpiresAtMillis(bootstrap) {
    const value =
      bootstrap && typeof bootstrap.browserSessionExpiresAt === "string"
        ? bootstrap.browserSessionExpiresAt.trim()
        : "";
    if (!value) {
      return null;
    }
    const parsed = Date.parse(value);
    return Number.isNaN(parsed) ? null : parsed;
  }

  async function readJsonOrThrow(response) {
    const data = await readJson(response);
    if (!response.ok) {
      throw responseError(data, response);
    }
    return data;
  }

  async function readJson(response) {
    return response.json().catch(() => ({}));
  }

  function responseErrorMessage(data, response) {
    const bodyMessage = responseBodyMessage(data);
    if (bodyMessage) {
      return bodyMessage;
    }
    if (response) {
      const status = response.status ? String(response.status) : "HTTP error";
      return response.statusText ? `${status} ${response.statusText}` : status;
    }
    return "Unknown error";
  }

  function responseError(data, response) {
    const code = responseErrorCode(data);
    const message =
      code === "invalid_app_browser_session"
        ? "App browser session expired; reload the app UI."
        : code === "origin_mismatch"
          ? "App browser session origin mismatch; reopen the app from Web Shell."
        : responseErrorMessage(data, response);
    if (code === "invalid_app_browser_session") {
      currentBrowserSessionToken = "";
    }
    const error = new Error(message);
    if (code) {
      error.code = code;
    }
    if (code === "invalid_app_browser_session") {
      error.sessionRefreshRequired = true;
    }
    return error;
  }

  function shouldRefreshAfterSessionError(error, options) {
    return (
      error &&
      error.code === "invalid_app_browser_session" &&
      !(options && options.bootstrap === false)
    );
  }

  function responseErrorCode(data) {
    if (data && typeof data === "object" && data.error && typeof data.error.code === "string") {
      return data.error.code;
    }
    return "";
  }

  function responseBodyMessage(data) {
    if (!data || typeof data !== "object") {
      return "";
    }
    if (typeof data.error === "string" && data.error.trim()) {
      return data.error.trim();
    }
    if (data.error && typeof data.error.message === "string" && data.error.message.trim()) {
      return data.error.message.trim();
    }
    if (typeof data.message === "string" && data.message.trim()) {
      return data.message.trim();
    }
    if (typeof data.detail === "string" && data.detail.trim()) {
      return data.detail.trim();
    }
    return "";
  }

  function errorMessage(error) {
    if (error instanceof Error && error.message) {
      return error.message;
    }
    if (typeof error === "string" && error) {
      return error;
    }
    const message = responseBodyMessage(error);
    return message || "Unknown error";
  }

  function explicitAppId(options) {
    const appId = options && typeof options.appId === "string" ? options.appId.trim() : "";
    return appId || "";
  }

  function inferAppId() {
    const segments = window.location.pathname.split("/");
    if (segments.length < 3 || segments[1] !== "apps") {
      return null;
    }
    try {
      return decodeURIComponent(segments[2]);
    } catch (error) {
      return null;
    }
  }

  function bootstrapUrls(appId) {
    const rootBootstrapUrl = `/${bootstrapResourcePath}`;
    if (!appId || !legacyAdminAppPath(appId)) {
      return [rootBootstrapUrl];
    }
    return [rootBootstrapUrl, `/apps/${encodeURIComponent(appId)}/${bootstrapResourcePath}`];
  }

  function bootstrapMatchesRequest(bootstrap, appId) {
    return !appId || (bootstrap && bootstrap.appId === appId);
  }

  function legacyAdminAppPath(appId) {
    const segments = window.location.pathname.split("/");
    if (segments.length < 3 || segments[1] !== "apps") {
      return false;
    }
    try {
      return normalizeAppId(decodeURIComponent(segments[2])) === appId;
    } catch (error) {
      return false;
    }
  }

  function normalizeAppId(appId) {
    if (typeof appId !== "string") {
      throw new Error("Cryptad app id must be a string.");
    }
    const normalized = appId.trim().toLowerCase();
    if (!appIdPattern.test(normalized)) {
      throw new Error("Cryptad app id must be one normalized local path segment.");
    }
    return normalized;
  }

  function sanitizeBootstrap(data) {
    const source = data && typeof data === "object" ? data : {};
    const bootstrap = {};
    copyStringField(source, bootstrap, "appId");
    copyStringField(source, bootstrap, "name");
    copyStringField(source, bootstrap, "uiRoot");
    copyStringField(source, bootstrap, "assetRoot");
    copyStringField(source, bootstrap, "platformApiRoot");
    copyStringField(source, bootstrap, "shellRoot");
    copyStringField(source, bootstrap, "uiOrigin");
    copyStringField(source, bootstrap, "uiOriginMode");
    copyStringField(source, bootstrap, "uiOriginStatus");
    copyStringField(source, bootstrap, "sameOriginFallbackUrl");
    copyStringField(source, bootstrap, "browserSessionExpiresAt");
    return bootstrap;
  }

  function sessionTokenFromBootstrap(data) {
    return data && typeof data.browserSessionToken === "string"
      ? data.browserSessionToken.trim()
      : "";
  }

  function copyStringField(source, target, name) {
    if (typeof source[name] === "string") {
      target[name] = source[name];
    }
  }

  function copyBootstrap(bootstrap) {
    return Object.assign({}, bootstrap);
  }

  window.CryptaPlatform = Object.freeze({
    bootstrap: Object.freeze({
      load: loadBootstrap,
      current,
    }),
    app: Object.freeze({
      currentId,
    }),
    api: Object.freeze({
      url: apiUrl,
      get: apiGet,
      postForm: apiPostForm,
      deleteForm: apiDeleteForm,
      errorMessage,
    }),
    queue: Object.freeze({
      snapshot: queueSnapshot,
      directDownload,
      mutate: queueMutate,
    }),
    content: Object.freeze({
      insertFile,
      insertDirectory,
    }),
    dom: Object.freeze({
      sanitizeFragment,
      sameOrigin,
    }),
  });
})(window);
