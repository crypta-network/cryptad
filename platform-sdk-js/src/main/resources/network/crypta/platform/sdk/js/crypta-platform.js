(function (window) {
  "use strict";

  if (window.CryptaPlatform) {
    return;
  }

  const defaultPlatformApiRoot = "/api/v1/";
  const bootstrapResourcePath = ".well-known/cryptad-bootstrap.json";
  const removedElementSelector =
    "script, style, template, iframe, frame, frameset, object, embed, link, meta, base";
  const urlAttributeNames = new Set(["href", "src", "action", "formaction"]);
  const appIdPattern = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;

  let currentBootstrap = null;
  let currentAppId = null;
  let loadingAppId = null;
  let loadingBootstrap = null;

  async function loadBootstrap(options) {
    const rawAppId = explicitAppId(options) || inferAppId();
    if (!rawAppId) {
      throw new Error("Unable to determine the current Cryptad app id.");
    }
    const requestedAppId = normalizeAppId(rawAppId);

    const force = !!(options && options.force);
    if (!force && currentBootstrap && currentAppId === requestedAppId) {
      return copyBootstrap(currentBootstrap);
    }
    if (!force && loadingBootstrap && loadingAppId === requestedAppId) {
      return loadingBootstrap.then(copyBootstrap);
    }

    loadingAppId = requestedAppId;
    loadingBootstrap = fetchBootstrap(requestedAppId)
      .then((bootstrap) => {
        currentBootstrap = bootstrap;
        currentAppId = bootstrap.appId || requestedAppId;
        return copyBootstrap(bootstrap);
      })
      .finally(() => {
        loadingAppId = null;
        loadingBootstrap = null;
      });
    return loadingBootstrap;
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
    const path = `/apps/${encodeURIComponent(appId)}/${bootstrapResourcePath}`;
    const response = await fetch(path, { headers: { Accept: "application/json" } });
    const data = await readJson(response);
    if (!response.ok) {
      throw new Error(responseErrorMessage(data, response));
    }
    const bootstrap = sanitizeBootstrap(data);
    if (bootstrap.appId) {
      bootstrap.appId = normalizeAppId(bootstrap.appId);
    }
    if (bootstrap.appId && bootstrap.appId !== appId) {
      throw new Error("Bootstrap app id does not match the requested app.");
    }
    if (!bootstrap.appId) {
      bootstrap.appId = appId;
    }
    return bootstrap;
  }

  async function apiGet(path, options) {
    const requestOptions = options || {};
    if (requestOptions.bootstrap !== false) {
      await ensureBootstrap(requestOptions);
    }
    const url = apiUrl(path);
    applySearchParams(url, requestOptions.params || requestOptions.searchParams || requestOptions.query);

    const headers = jsonHeaders(requestOptions.headers);
    const response = await fetch(url, {
      method: "GET",
      headers,
      signal: requestOptions.signal,
      credentials: "same-origin",
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
    const bootstrap =
      requestOptions.bootstrap === false
        ? currentBootstrap || {}
        : await refreshBootstrapForMutation(requestOptions);
    const formPassword = requestOptions.formPassword || bootstrap.formPassword || "";
    if (requestOptions.requireFormPassword !== false && !formPassword) {
      throw new Error(
        requestOptions.unavailableMessage ||
          "Mutating Platform API calls require a bootstrap formPassword."
      );
    }

    const body = toUrlSearchParams(formDataOrParams);
    if (formPassword) {
      body.set("formPassword", formPassword);
    }

    const headers = jsonHeaders(requestOptions.headers);
    headers.set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8");
    const response = await fetch(apiUrl(path), {
      method,
      headers,
      body: body.toString(),
      signal: requestOptions.signal,
      credentials: "same-origin",
    });
    return readJsonOrThrow(response);
  }

  function apiUrl(path) {
    const root = normalizeLocalRoot(
      currentBootstrap && currentBootstrap.platformApiRoot,
      defaultPlatformApiRoot
    );
    const rootUrl = new URL(root, window.location.origin);
    const url = coerceApiUrl(path, rootUrl);
    if (url.origin !== window.location.origin || !url.pathname.startsWith(rootUrl.pathname)) {
      throw new Error("Platform API URL must stay under the same-origin API root.");
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
      return new URL(value, window.location.origin);
    }
    return new URL(value, rootUrl);
  }

  function normalizeLocalRoot(value, fallback) {
    if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) {
      return fallback;
    }
    try {
      const url = new URL(value, window.location.origin);
      if (url.origin !== window.location.origin || url.search || url.hash) {
        return fallback;
      }
      return url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
    } catch (error) {
      return fallback;
    }
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

  async function ensureBootstrap(options) {
    if (currentBootstrap && !(options && options.force)) {
      return currentBootstrap;
    }
    return loadBootstrap(options);
  }

  async function refreshBootstrapForMutation(options) {
    if (options && options.refreshBootstrap === false) {
      return ensureBootstrap(options);
    }
    const appId = explicitAppId(options) || currentAppId || inferAppId();
    if (!appId) {
      return ensureBootstrap(options);
    }
    return loadBootstrap(Object.assign({}, options, { appId, force: true }));
  }

  async function readJsonOrThrow(response) {
    const data = await readJson(response);
    if (!response.ok) {
      throw new Error(responseErrorMessage(data, response));
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
    copyStringField(source, bootstrap, "formPassword");
    return bootstrap;
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
