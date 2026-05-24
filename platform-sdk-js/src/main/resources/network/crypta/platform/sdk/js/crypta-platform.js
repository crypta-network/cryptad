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
  const feedSnapshotType = "crypta.feed.snapshot.v1";
  const feedSnapshotContentType = "application/vnd.crypta.feed+json";
  const feedSnapshotTargetFilename = "feed.json";
  const feedSnapshotMaxEntries = 100;
  const trustStatementType = "crypta.trust.statement.v1";
  const trustStatementContentType = "application/vnd.crypta.trust+json";
  const trustStatementTargetFilename = "trust.json";

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
    try {
      return await fetchFormMutation(method, path, body, requestOptions);
    } catch (error) {
      if (!shouldRefreshAfterSessionError(error, requestOptions)) {
        throw error;
      }
      await refreshBootstrap(requestOptions);
      return fetchFormMutation(method, path, body, requestOptions);
    }
  }

  async function fetchFormMutation(method, path, body, requestOptions) {
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

  function fetchText(uriOrOptions, options) {
    return fetchContent("text", uriOrOptions, options);
  }

  function fetchBase64(uriOrOptions, options) {
    return fetchContent("base64", uriOrOptions, options);
  }

  function listContentSubscriptions(options) {
    return apiGet("content/subscriptions", options);
  }

  function createContentSubscription(options) {
    const source = requireOptionsObject(options, "Content subscription options");
    return apiPostForm(
      "content/subscriptions",
      normalizeContentSubscriptionCreate(source),
      requestOptionsFrom(source)
    );
  }

  function getContentSubscription(subscriptionIdOrOptions, options) {
    const request = contentSubscriptionRequest(
      subscriptionIdOrOptions,
      options,
      "Content subscription id"
    );
    return apiGet(`content/subscriptions/${encodeURIComponent(request.subscriptionId)}`, request.options);
  }

  function refreshContentSubscription(subscriptionIdOrOptions, options) {
    const request = contentSubscriptionRequest(
      subscriptionIdOrOptions,
      options,
      "Content subscription id"
    );
    return apiPostForm(
      `content/subscriptions/${encodeURIComponent(request.subscriptionId)}/refresh`,
      {},
      request.options
    );
  }

  function pauseContentSubscription(subscriptionIdOrOptions, options) {
    const request = contentSubscriptionRequest(
      subscriptionIdOrOptions,
      options,
      "Content subscription id"
    );
    return apiPostForm(
      `content/subscriptions/${encodeURIComponent(request.subscriptionId)}/pause`,
      {},
      request.options
    );
  }

  function resumeContentSubscription(subscriptionIdOrOptions, options) {
    const request = contentSubscriptionRequest(
      subscriptionIdOrOptions,
      options,
      "Content subscription id"
    );
    return apiPostForm(
      `content/subscriptions/${encodeURIComponent(request.subscriptionId)}/resume`,
      {},
      request.options
    );
  }

  function removeContentSubscription(subscriptionIdOrOptions, options) {
    const request = contentSubscriptionRequest(
      subscriptionIdOrOptions,
      options,
      "Content subscription id"
    );
    return apiDeleteForm(
      `content/subscriptions/${encodeURIComponent(request.subscriptionId)}`,
      {},
      request.options
    );
  }

  function insertAppDocument(options) {
    const source = requireOptionsObject(options, "App document insert options");
    return apiPostForm(
      "queue/inserts/app-document",
      normalizeAppDocumentInsert(source),
      requestOptionsFrom(source)
    );
  }

  function listVaultIdentities(options) {
    return apiGet("app-vault/identities", options);
  }

  function getVaultIdentity(identityId, options) {
    return apiGet(`app-vault/identities/${encodeURIComponent(vaultPathSegment(identityId))}`, options);
  }

  function createVaultIdentity(options) {
    const source = options && typeof options === "object" ? options : {};
    return apiPostForm(
      "app-vault/identities",
      normalizeVaultIdentityCreateOptions(source),
      requestOptionsFrom(source)
    );
  }

  function createProfileDocument(identityId, profile, options) {
    return apiPostForm(
      `app-vault/identities/${encodeURIComponent(vaultPathSegment(identityId))}/profile-document`,
      normalizeProfileDocument(profile),
      options
    );
  }

  function listVaultGrants(options) {
    return apiGet("app-vault/grants", options);
  }

  function requestVaultGrant(request, options) {
    return apiPostForm("app-vault/grants/request", normalizeVaultGrantRequest(request), options);
  }

  async function publishProfile(options) {
    const source = requireOptionsObject(options, "Profile publish options");
    const requestOptions = requestOptionsFrom(source);
    const profileDocumentResponse = await createProfileDocument(
      source.identityId,
      source.profile,
      requestOptions
    );
    const insertResponse = await insertAppDocument(
      profilePublishInsertOptions(source, profileDocumentFromResponse(profileDocumentResponse))
    );
    return {
      profileDocument: profileDocumentResponse,
      insert: insertResponse,
    };
  }

  function trustStatus(options) {
    return apiGet("trust-graph/status", options).then((response) =>
      unwrapField(response, "trustGraph")
    );
  }

  function listTrustAnchors(options) {
    return apiGet("trust-graph/anchors", options).then((response) =>
      unwrapField(response, "anchors")
    );
  }

  function addTrustAnchor(request, options) {
    return apiPostForm("trust-graph/anchors", normalizeTrustAnchor(request), options).then(
      (response) => unwrapField(response, "anchor")
    );
  }

  function removeTrustAnchor(fingerprintOrOptions, options) {
    const fingerprint =
      typeof fingerprintOrOptions === "string"
        ? fingerprintOrOptions
        : trustAnchorFingerprint(fingerprintOrOptions);
    return apiDeleteForm(
      `trust-graph/anchors/${encodeURIComponent(trimmedRequired(fingerprint, "issuerFingerprint"))}`,
      {},
      options
    ).then((response) => unwrapField(response, "anchor"));
  }

  function importTrustStatement(request, options) {
    return apiPostForm("trust-graph/import", normalizeTrustImport(request), options).then(
      (response) => unwrapField(response, "importResult")
    );
  }

  function trustSubjects(options) {
    return apiGet("trust-graph/subjects", options).then((response) =>
      unwrapField(response, "subjects")
    );
  }

  function trustStatements(request, options) {
    const source = request && typeof request === "object" ? request : {};
    const requestOptions = Object.assign({}, requestOptionsFrom(source), options || {});
    requestOptions.params = normalizeTrustQuery(source, false);
    return apiGet("trust-graph/statements", requestOptions).then((response) =>
      unwrapField(response, "statements")
    );
  }

  function trustScore(request, options) {
    const source = requireOptionsObject(request, "Trust score query");
    const requestOptions = Object.assign({}, requestOptionsFrom(source), options || {});
    requestOptions.params = normalizeTrustQuery(source, true);
    return apiGet("trust-graph/score", requestOptions).then((response) =>
      unwrapField(response, "score")
    );
  }

  function publishTrustStatement(options) {
    const source = requireOptionsObject(options, "Trust statement publish options");
    const insertOptions = Object.assign({}, source, {
      document: trustStatementDocument(source),
      contentType: trustStatementContentType,
      targetFilename: trustStatementTargetFilename,
    });
    return insertAppDocument(insertOptions);
  }

  function createTrustStatement(identityIdOrOptions, payload, options) {
    let identityId = identityIdOrOptions;
    let source = payload;
    let requestOptions = options;
    if (
      identityIdOrOptions &&
      typeof identityIdOrOptions === "object" &&
      !Array.isArray(identityIdOrOptions) &&
      typeof identityIdOrOptions.entries !== "function"
    ) {
      source = identityIdOrOptions;
      identityId = source.identityId || source.authorIdentity || source.authorIdentityId;
      requestOptions = requestOptionsFrom(source);
    }
    const request = requireOptionsObject(source, "Trust statement payload");
    return apiPostForm(
      `app-vault/identities/${encodeURIComponent(vaultPathSegment(identityId))}/trust-statement`,
      normalizeTrustStatementPayload(request),
      requestOptions || requestOptionsFrom(request)
    );
  }

  function parseFeedSnapshot(value) {
    const source = parseJsonObject(value, "Feed snapshot");
    const type = trimmedString(source.type);
    if (type !== feedSnapshotType) {
      throw new Error(`Feed snapshot type must be ${feedSnapshotType}.`);
    }
    const items = feedSnapshotItems(source);
    if (items.length > feedSnapshotMaxEntries) {
      throw new Error(`Feed snapshot must contain at most ${feedSnapshotMaxEntries} items.`);
    }

    const normalized = {
      type: feedSnapshotType,
      source: normalizeFeedSource(source.source),
      author: normalizeFeedAuthor(source.author),
    };
    copyFeedStringField(source, normalized, "title");
    copyFeedStringField(source, normalized, "updatedAt");
    normalized.items = items.map(normalizeFeedItem);
    return normalized;
  }

  async function fetchFeedSnapshot(uriOrOptions, options) {
    const response = await fetchText(uriOrOptions, options);
    const snapshot = parseFeedSnapshot(response.contentText || "");
    if (!snapshot.source.uri && response.requestedUri) {
      snapshot.source.uri = String(response.requestedUri);
    }
    if (!snapshot.source.resolvedUri && response.resolvedUri) {
      snapshot.source.resolvedUri = String(response.resolvedUri);
    }
    return { response, snapshot };
  }

  function publishFeedSnapshot(options) {
    const source = requireOptionsObject(options, "Feed publish options");
    const snapshot = parseFeedSnapshot(feedSnapshotDocument(source));
    return insertAppDocument(feedPublishInsertOptions(source, snapshot));
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
    const normalizedHostname =
      hostname.startsWith("[") && hostname.endsWith("]") ? hostname.slice(1, -1) : hostname;
    return (
      (url.protocol === "http:" || url.protocol === "https:") &&
      (normalizedHostname === "127.0.0.1" ||
        normalizedHostname === "localhost" ||
        normalizedHostname === "::1" ||
        normalizedHostname === "0:0:0:0:0:0:0:1")
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

  function requireOptionsObject(options, description) {
    if (
      !options ||
      typeof options !== "object" ||
      Array.isArray(options) ||
      typeof options.entries === "function"
    ) {
      throw new Error(`${description} must be an object.`);
    }
    return options;
  }

  function requestOptionsFrom(source) {
    const options = {};
    copyRequestOption(source, options, "appId");
    copyRequestOption(source, options, "signal");
    copyRequestOption(source, options, "headers");
    copyRequestOption(source, options, "bootstrap");
    copyRequestOption(source, options, "force");
    copyRequestOption(source, options, "refreshBootstrap");
    return options;
  }

  function fetchContent(format, uriOrOptions, options) {
    const source = contentFetchOptions(uriOrOptions, options);
    return apiPostForm(
      "content/fetch",
      normalizeContentFetchParams(source, format),
      requestOptionsFrom(source)
    );
  }

  function contentFetchOptions(uriOrOptions, options) {
    if (typeof uriOrOptions === "string") {
      if (options != null && (typeof options !== "object" || Array.isArray(options))) {
        throw new Error("Content fetch options must be an object.");
      }
      const source = Object.assign({}, options || {});
      source.uri = uriOrOptions;
      return source;
    }
    return requireOptionsObject(uriOrOptions, "Content fetch options");
  }

  function normalizeContentFetchParams(source, format) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "uri");
    copyStringParamAs(source, params, "key", "uri");
    copyPositiveIntegerParam(source, params, "maxBytes");
    copyPositiveIntegerParam(source, params, "timeoutMillis");
    copyStringParam(source, params, "purpose");
    if (!params.has("uri")) {
      throw new Error("Content fetch uri is required.");
    }
    params.set("format", format);
    return params;
  }

  function normalizeContentSubscriptionCreate(source) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "uri");
    copyStringParamAs(source, params, "sourceUri", "uri");
    copyStringParam(source, params, "label");
    copyPositiveIntegerParam(source, params, "pollIntervalSeconds");
    copyPositiveIntegerParam(source, params, "maxBytes");
    copyPositiveIntegerParam(source, params, "timeoutMillis");
    if (!params.has("uri")) {
      throw new Error("Content subscription uri is required.");
    }
    if (!params.has("label")) {
      throw new Error("Content subscription label is required.");
    }
    return params;
  }

  function contentSubscriptionRequest(subscriptionIdOrOptions, options, description) {
    if (
      subscriptionIdOrOptions &&
      typeof subscriptionIdOrOptions === "object" &&
      !Array.isArray(subscriptionIdOrOptions) &&
      typeof subscriptionIdOrOptions.entries !== "function"
    ) {
      const source = subscriptionIdOrOptions;
      return {
        subscriptionId: contentSubscriptionPathSegment(
          source.subscriptionId || source.id,
          description
        ),
        options: requestOptionsFrom(source),
      };
    }
    return {
      subscriptionId: contentSubscriptionPathSegment(subscriptionIdOrOptions, description),
      options: options || {},
    };
  }

  function copyRequestOption(source, target, name) {
    if (source && Object.prototype.hasOwnProperty.call(source, name)) {
      target[name] = source[name];
    }
  }

  function normalizeAppDocumentInsert(options) {
    const params = new URLSearchParams();
    copyStringParam(options, params, "insertUri");
    copyStringParam(options, params, "identifier");
    copyStringParam(options, params, "targetFilename");
    copyStringParam(options, params, "contentType");
    copyStringParam(options, params, "compatibilityMode");
    if (!params.has("contentType")) {
      copyStringParamAs(options, params, "mimeType", "contentType");
    }
    if (typeof options.compress === "boolean") {
      params.set("compress", options.compress ? "true" : "false");
    }
    const document = Object.prototype.hasOwnProperty.call(options, "document")
      ? options.document
      : options.profileDocument;
    params.set("documentBase64", jsonDocumentBase64(document, "App document"));
    return params;
  }

  function normalizeVaultIdentityCreateOptions(options) {
    const params = new URLSearchParams();
    copyStringParam(options, params, "kind");
    copyStringParam(options, params, "label");
    const scopes = normalizeVaultGrantScopes(options.scopes);
    if (scopes) {
      params.set("scopes", scopes);
    }
    return params;
  }

  function normalizeProfileDocument(profile) {
    const source = requireOptionsObject(profile, "Profile document");
    const params = new URLSearchParams();
    copyStringParam(source, params, "displayName");
    copyStringParam(source, params, "bio");
    copyStringParam(source, params, "website");
    copyStringParam(source, params, "avatarUri");
    copyStringParam(source, params, "contactUri");
    appendTagsParam(source.tags, params);
    return params;
  }

  function appendTagsParam(tags, params) {
    if (typeof tags === "string" && tags.trim()) {
      params.set("tags", tags.trim());
      return;
    }
    if (Array.isArray(tags)) {
      const normalized = tags
        .filter((tag) => typeof tag === "string" && tag.trim())
        .map((tag) => tag.trim());
      if (normalized.length > 0) {
        params.set("tags", normalized.join(","));
      }
    }
  }

  function copyStringParam(source, params, name) {
    const value = source && source[name];
    if (typeof value === "string" && value.trim()) {
      params.set(name, value.trim());
    }
  }

  function copyStringParamAs(source, params, sourceName, targetName) {
    const value = source && source[sourceName];
    if (typeof value === "string" && value.trim()) {
      params.set(targetName, value.trim());
    }
  }

  function copyPositiveIntegerParam(source, params, name) {
    if (!source || !Object.prototype.hasOwnProperty.call(source, name)) {
      return;
    }
    const value = source[name];
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value) || value <= 0) {
        throw new Error(`${name} must be a positive integer.`);
      }
      params.set(name, String(value));
      return;
    }
    if (typeof value === "string" && value.trim()) {
      const normalized = value.trim();
      if (!/^[1-9][0-9]*$/.test(normalized)) {
        throw new Error(`${name} must be a positive integer.`);
      }
      params.set(name, normalized);
    }
  }

  function jsonDocumentBase64(value, description) {
    let json;
    try {
      json = JSON.stringify(value);
    } catch (error) {
      throw new Error(`${description} must be JSON-serializable.`);
    }
    if (typeof json !== "string") {
      throw new Error(`${description} must be JSON-serializable.`);
    }
    return utf8Base64(json);
  }

  function utf8Base64(value) {
    if (typeof TextEncoder === "undefined" || typeof btoa !== "function") {
      throw new Error("JSON document encoding is unavailable in this browser.");
    }
    const bytes = new TextEncoder().encode(value);
    const chunkSize = 32768;
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      const chunk = bytes.subarray(offset, offset + chunkSize);
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
  }

  function profileDocumentFromResponse(response) {
    if (!response || typeof response !== "object") {
      return response;
    }
    if (response.profileDocument && typeof response.profileDocument === "object") {
      if (
        response.profileDocument.document &&
        typeof response.profileDocument.document === "object"
      ) {
        return response.profileDocument.document;
      }
      return response.profileDocument;
    }
    if (response.document && typeof response.document === "object") {
      return response.document;
    }
    return response;
  }

  function profilePublishInsertOptions(source, document) {
    const options = Object.assign({}, source, { document });
    if (!nonBlankString(options.identifier)) {
      options.identifier = `profile-${vaultPathSegment(source.identityId)}`;
    }
    if (!nonBlankString(options.targetFilename)) {
      options.targetFilename = "profile.json";
    }
    if (!nonBlankString(options.contentType)) {
      options.contentType = "application/vnd.crypta.profile+json";
    }
    return options;
  }

  function normalizeTrustAnchor(request) {
    const source = requireOptionsObject(request, "Trust anchor");
    const params = new URLSearchParams();
    params.set("issuerFingerprint", trimmedRequired(trustAnchorFingerprint(source), "issuerFingerprint"));
    copyStringParam(source, params, "label");
    copyStringParam(source, params, "source");
    return params;
  }

  function trustAnchorFingerprint(source) {
    if (typeof source === "string") {
      return source;
    }
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      throw new Error("Trust anchor issuer fingerprint is required.");
    }
    return (
      source.issuerFingerprint ||
      source.fingerprint ||
      source.identity ||
      source.identityId ||
      source.id
    );
  }

  function normalizeTrustImport(request) {
    const source = requireOptionsObject(request, "Trust import");
    const params = new URLSearchParams();
    params.set("document", trustStatementText(source));
    copyStringParam(source, params, "sourceUri");
    copyStringParamAs(source, params, "uri", "sourceUri");
    copyStringParam(source, params, "sourceLabel");
    copyStringParamAs(source, params, "label", "sourceLabel");
    return params;
  }

  function normalizeTrustQuery(source, requireSubject) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "subjectKind");
    copyStringParamAs(source, params, "kind", "subjectKind");
    copyStringParam(source, params, "subjectUri");
    copyStringParamAs(source, params, "uri", "subjectUri");
    copyStringParamAs(source, params, "subject", "subjectUri");
    copyStringParam(source, params, "context");
    copyStringParam(source, params, "issuerFingerprint");
    if (typeof source.includeEvidence === "boolean") {
      params.set("includeEvidence", source.includeEvidence ? "true" : "false");
    }
    if (
      requireSubject &&
      (!params.has("subjectKind") || !params.has("subjectUri") || !params.has("context"))
    ) {
      throw new Error("Trust score query requires subjectKind, subjectUri, and context.");
    }
    return params;
  }

  function normalizeTrustStatementPayload(source) {
    const params = new URLSearchParams();
    copyStringParam(source, params, "subjectKind");
    copyStringParamAs(source, params, "kind", "subjectKind");
    copyStringParam(source, params, "subjectUri");
    copyStringParamAs(source, params, "uri", "subjectUri");
    copyStringParamAs(source, params, "subject", "subjectUri");
    copyStringParamAs(source, params, "subjectIdentity", "subjectUri");
    copyStringParam(source, params, "subjectFingerprint");
    copyStringParam(source, params, "context");
    copyIntegerParam(source, params, "score");
    copyIntegerParamAs(source, params, "value", "score");
    copyIntegerParam(source, params, "confidence");
    copyStringParam(source, params, "reason");
    appendTagsParam(source.tags, params);
    copyStringParam(source, params, "expiresAt");
    copyStringParam(source, params, "profileUri");
    for (const requiredName of ["subjectKind", "subjectUri", "context", "score", "confidence"]) {
      if (!params.has(requiredName)) {
        throw new Error(`Trust statement payload requires ${requiredName}.`);
      }
    }
    return params;
  }

  function trustStatementDocument(source) {
    const value = Object.prototype.hasOwnProperty.call(source, "statement")
      ? source.statement
      : Object.prototype.hasOwnProperty.call(source, "trustStatement")
        ? source.trustStatement
        : source.document;
    let current = parseJsonObject(value, "Trust statement");
    for (let depth = 0; depth < 4; depth += 1) {
      if (current.type === trustStatementType) {
        return current;
      }
      if (typeof current.trustStatement === "string") {
        current = parseJsonObject(current.trustStatement, "Trust statement");
      } else if (
        current.trustStatement &&
        typeof current.trustStatement === "object" &&
        !Array.isArray(current.trustStatement)
      ) {
        current = current.trustStatement;
      } else {
        break;
      }
    }
    return current;
  }

  function trustStatementText(source) {
    const value = Object.prototype.hasOwnProperty.call(source, "document")
      ? source.document
      : Object.prototype.hasOwnProperty.call(source, "trustStatement")
        ? source.trustStatement
        : Object.prototype.hasOwnProperty.call(source, "statement")
          ? source.statement
          : source.text;
    if (typeof value === "string") {
      return trimmedRequired(value, "document");
    }
    if (value && typeof value === "object" && !Array.isArray(value)) {
      return JSON.stringify(trustStatementDocument({ document: value }));
    }
    throw new Error("Trust import document is required.");
  }

  function copyIntegerParam(source, params, name) {
    copyIntegerParamAs(source, params, name, name);
  }

  function copyIntegerParamAs(source, params, sourceName, targetName) {
    if (!source || !Object.prototype.hasOwnProperty.call(source, sourceName)) {
      return;
    }
    const value = source[sourceName];
    if (typeof value === "number") {
      if (!Number.isSafeInteger(value)) {
        throw new Error(`${sourceName} must be an integer.`);
      }
      params.set(targetName, String(value));
      return;
    }
    if (typeof value === "string" && value.trim()) {
      const normalized = value.trim();
      if (!/^-?[0-9]+$/.test(normalized)) {
        throw new Error(`${sourceName} must be an integer.`);
      }
      params.set(targetName, normalized);
    }
  }

  function trimmedRequired(value, name) {
    if (typeof value !== "string" || !value.trim()) {
      throw new Error(`${name} is required.`);
    }
    return value.trim();
  }

  function unwrapField(response, fieldName) {
    return response &&
      typeof response === "object" &&
      !Array.isArray(response) &&
      Object.prototype.hasOwnProperty.call(response, fieldName)
      ? response[fieldName]
      : response;
  }

  function parseJsonObject(value, description) {
    const source = typeof value === "string" ? parseJsonString(value, description) : value;
    if (!source || typeof source !== "object" || Array.isArray(source)) {
      throw new Error(`${description} must be a JSON object.`);
    }
    return source;
  }

  function parseJsonString(value, description) {
    try {
      return JSON.parse(value);
    } catch (error) {
      throw new Error(`${description} must be valid JSON.`);
    }
  }

  function feedSnapshotItems(source) {
    if (Array.isArray(source.items)) {
      return source.items;
    }
    if (Array.isArray(source.entries)) {
      return source.entries;
    }
    throw new Error("Feed snapshot items must be an array.");
  }

  function normalizeFeedSource(source) {
    const value = source && typeof source === "object" && !Array.isArray(source) ? source : {};
    const normalized = {};
    copyFeedStringField(value, normalized, "uri");
    copyFeedStringField(value, normalized, "resolvedUri");
    return normalized;
  }

  function normalizeFeedAuthor(author) {
    const value = author && typeof author === "object" && !Array.isArray(author) ? author : {};
    const normalized = {};
    copyFeedStringField(value, normalized, "name");
    copyFeedStringField(value, normalized, "profileUri");
    return normalized;
  }

  function normalizeFeedItem(item) {
    const source = parseJsonObject(item, "Feed item");
    const normalized = {};
    copyFeedStringField(source, normalized, "id");
    copyFeedStringField(source, normalized, "title");
    copyFeedStringField(source, normalized, "summary");
    copyFeedStringField(source, normalized, "uri");
    copyFeedStringField(source, normalized, "publishedAt");
    const tags = normalizeFeedTags(source.tags);
    if (tags.length > 0) {
      normalized.tags = tags;
    }
    return normalized;
  }

  function normalizeFeedTags(tags) {
    const source =
      typeof tags === "string"
        ? tags.split(",")
        : Array.isArray(tags)
          ? tags
        : [];
    const unique = new Set();
    source.forEach((tag) => {
      const normalized = trimmedString(tag);
      if (normalized) {
        unique.add(normalized);
      }
    });
    return Array.from(unique).sort();
  }

  function copyFeedStringField(source, target, name) {
    const value = trimmedString(source[name]);
    if (value) {
      target[name] = value;
    }
  }

  function trimmedString(value) {
    return typeof value === "string" ? value.trim() : "";
  }

  function feedSnapshotDocument(source) {
    if (Object.prototype.hasOwnProperty.call(source, "snapshot")) {
      return source.snapshot;
    }
    if (Object.prototype.hasOwnProperty.call(source, "feed")) {
      return source.feed;
    }
    if (Object.prototype.hasOwnProperty.call(source, "document")) {
      return source.document;
    }
    throw new Error("Feed publish options must include a snapshot.");
  }

  function feedPublishInsertOptions(source, snapshot) {
    const options = Object.assign({}, source, { document: snapshot });
    options.contentType = feedSnapshotContentType;
    options.targetFilename = feedSnapshotTargetFilename;
    return options;
  }

  function nonBlankString(value) {
    return typeof value === "string" && !!value.trim();
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

  function vaultPathSegment(value) {
    if (typeof value !== "string") {
      throw new Error("Vault identity id must be a string.");
    }
    const normalized = value.trim().toLowerCase();
    if (!/^[a-z0-9][a-z0-9._-]{0,191}$/.test(normalized)) {
      throw new Error("Vault identity id must be one normalized local path segment.");
    }
    return normalized;
  }

  function contentSubscriptionPathSegment(value, description) {
    if (typeof value !== "string") {
      throw new Error(`${description} must be a string.`);
    }
    const normalized = value.trim().toLowerCase();
    if (!/^[a-z0-9](?:[a-z0-9._-]{0,190}[a-z0-9])?$/.test(normalized)) {
      throw new Error(`${description} must be one normalized local path segment.`);
    }
    return normalized;
  }

  function normalizeVaultGrantRequest(request) {
    const source = request && typeof request === "object" ? request : {};
    const params = {
      identityId: vaultPathSegment(source.identityId),
      scopes: normalizeVaultGrantScopes(source.scopes),
    };
    if (typeof source.reason === "string" && source.reason.trim()) {
      params.reason = source.reason.trim();
    }
    return params;
  }

  function normalizeVaultGrantScopes(scopes) {
    if (typeof scopes === "string") {
      return scopes
        .split(",")
        .map((scope) => normalizeVaultGrantScope(scope))
        .join(",");
    }
    if (Array.isArray(scopes)) {
      return scopes.map((scope) => normalizeVaultGrantScope(scope)).join(",");
    }
    return "";
  }

  function normalizeVaultGrantScope(scope) {
    if (typeof scope !== "string") {
      throw new Error("Vault grant scopes must be strings.");
    }
    const normalized = scope.trim().toLowerCase();
    if (
      normalized !== "metadata.read" &&
      normalized !== "sign.domain-separated" &&
      normalized !== "publish.content" &&
      normalized !== "publish.profile" &&
      normalized !== "use.external-reference"
    ) {
      throw new Error("Unsupported vault grant scope.");
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
      fetchText,
      fetchBase64,
      insertFile,
      insertDirectory,
      insertAppDocument,
      subscriptions: Object.freeze({
        list: listContentSubscriptions,
        create: createContentSubscription,
        get: getContentSubscription,
        refresh: refreshContentSubscription,
        pause: pauseContentSubscription,
        resume: resumeContentSubscription,
        remove: removeContentSubscription,
      }),
    }),
    vault: Object.freeze({
      identities: Object.freeze({
        list: listVaultIdentities,
        get: getVaultIdentity,
        create: createVaultIdentity,
        createProfileDocument,
        createTrustStatement,
      }),
      grants: Object.freeze({
        list: listVaultGrants,
        request: requestVaultGrant,
      }),
    }),
    profile: Object.freeze({
      publish: publishProfile,
    }),
    feed: Object.freeze({
      parseSnapshot: parseFeedSnapshot,
      fetchSnapshot: fetchFeedSnapshot,
      publishSnapshot: publishFeedSnapshot,
    }),
    trust: Object.freeze({
      status: trustStatus,
      anchors: Object.freeze({
        list: listTrustAnchors,
        add: addTrustAnchor,
        remove: removeTrustAnchor,
      }),
      importStatement: importTrustStatement,
      subjects: trustSubjects,
      statements: trustStatements,
      score: trustScore,
      publishStatement: publishTrustStatement,
    }),
    dom: Object.freeze({
      sanitizeFragment,
      sameOrigin,
    }),
  });
})(window);
