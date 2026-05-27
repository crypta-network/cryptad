(() => {
  "use strict";

  const appId = "trust-graph";
  const maxStatementBytes = 65536;
  const dataNamespace = "ui-state";
  const dataStateKey = "preview-state";
  const dataSchemaVersion = 1;
  const state = {
    anchors: [],
    identities: [],
    lastStatementText: "",
    lastDraft: {},
    queueItems: [],
    recentImports: [],
    auditEvents: [],
    subscriptions: [],
    status: null,
  };

  const elements = {};

  document.addEventListener("DOMContentLoaded", () => {
    bindElements();
    bindEvents();
    startApp();
  });

  function bindElements() {
    elements.status = document.getElementById("status");
    elements.statusSummary = document.getElementById("status-summary");
    elements.identityList = document.getElementById("identity-list");
    elements.anchorList = document.getElementById("anchor-list");
    elements.statementPreview = document.getElementById("statement-preview");
    elements.scoreResult = document.getElementById("score-result");
    elements.publishResult = document.getElementById("publish-result");
    elements.queuePreview = document.getElementById("queue-preview");
    elements.auditList = document.getElementById("audit-list");
    elements.subscriptionList = document.getElementById("subscription-list");
    elements.refreshStatusButton = document.getElementById("refresh-status-button");
    elements.loadIdentitiesButton = document.getElementById("load-identities-button");
    elements.refreshAnchorsButton = document.getElementById("refresh-anchors-button");
    elements.refreshQueueButton = document.getElementById("refresh-queue-button");
    elements.refreshAuditButton = document.getElementById("refresh-audit-button");
    elements.refreshSubscriptionsButton = document.getElementById("refresh-subscriptions-button");
    elements.secondaryRefreshQueueButton =
      document.getElementById("secondary-refresh-queue-button");
    elements.identityForm = document.getElementById("identity-form");
    elements.anchorForm = document.getElementById("anchor-form");
    elements.fetchForm = document.getElementById("fetch-form");
    elements.scoreForm = document.getElementById("score-form");
    elements.publishForm = document.getElementById("publish-form");
    elements.subscriptionForm = document.getElementById("subscription-form");
  }

  function bindEvents() {
    elements.refreshStatusButton.addEventListener("click", refreshStatus);
    elements.loadIdentitiesButton.addEventListener("click", refreshIdentities);
    elements.refreshAnchorsButton.addEventListener("click", refreshAnchors);
    elements.refreshQueueButton.addEventListener("click", refreshQueue);
    elements.refreshAuditButton.addEventListener("click", refreshAudit);
    elements.refreshSubscriptionsButton.addEventListener("click", refreshSubscriptions);
    elements.secondaryRefreshQueueButton.addEventListener("click", refreshQueue);
    elements.identityForm.addEventListener("submit", createIdentity);
    elements.anchorForm.addEventListener("submit", addAnchor);
    elements.fetchForm.addEventListener("submit", fetchAndImportStatement);
    elements.scoreForm.addEventListener("submit", scoreSubject);
    elements.publishForm.addEventListener("submit", publishStatement);
    elements.subscriptionForm.addEventListener("submit", createSubscription);
  }

  async function startApp() {
    setStatus("Loading Trust Graph Preview.");
    try {
      if (CryptaPlatform.bootstrap && typeof CryptaPlatform.bootstrap.load === "function") {
        await CryptaPlatform.bootstrap.load({ appId });
      }
      await loadDurableState();
      restoreDraftForms();
      await Promise.all([
        refreshStatus(),
        refreshAnchors(),
        refreshIdentities(),
        refreshQueue(),
        refreshAudit(),
        refreshSubscriptions(),
      ]);
      setStatus("Trust Graph Preview is ready.");
    } catch (error) {
      setStatus(errorMessage(error));
    }
  }

  async function refreshStatus() {
    try {
      const status = await CryptaPlatform.trust.status();
      state.status = status;
      replaceChildren(elements.statusSummary, summaryNodes(status, "Trust status"));
      setStatus("Trust status refreshed.");
    } catch (error) {
      renderError(elements.statusSummary, error);
    }
  }

  async function refreshAnchors() {
    try {
      const response = await CryptaPlatform.trust.anchors.list();
      state.anchors = asArray(response.anchors || response.items || response);
      renderAnchors();
      setStatus("Trust anchors refreshed.");
    } catch (error) {
      renderError(elements.anchorList, error);
    }
  }

  async function refreshAudit() {
    try {
      const events = await CryptaPlatform.trust.audit.list({ limit: 12 });
      state.auditEvents = asArray(events.events || events.items || events);
      renderAudit();
      setStatus("Trust audit refreshed.");
    } catch (error) {
      renderError(elements.auditList, error);
    }
  }

  async function refreshSubscriptions() {
    try {
      const response = await CryptaPlatform.trust.exchange.subscriptions.list();
      state.subscriptions = asArray(response.subscriptions || response.items || response);
      renderSubscriptions();
      setStatus("Trust subscriptions refreshed.");
    } catch (error) {
      renderError(elements.subscriptionList, error);
    }
  }

  async function createSubscription(event) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const uri = textValue(formData, "uri");
    const label = textValue(formData, "label") || "Trust statement subscription";
    if (!uri) {
      setStatus("Enter a trust statement subscription URI.");
      return;
    }
    if (!isTrustSubscriptionUri(uri)) {
      setStatus("Subscription URI must start with USK@ or crypta:USK@.");
      return;
    }

    try {
      await CryptaPlatform.trust.exchange.subscriptions.create({
        uri,
        label,
        maxBytes: maxStatementBytes,
      });
      event.currentTarget.reset();
      await Promise.all([refreshSubscriptions(), refreshAudit()]);
      setStatus("Trust statement subscription created.");
    } catch (error) {
      renderError(elements.subscriptionList, error);
    }
  }

  async function refreshSubscription(subscriptionId) {
    await mutateSubscription(subscriptionId, CryptaPlatform.trust.exchange.subscriptions.refresh);
  }

  async function pauseSubscription(subscriptionId) {
    await mutateSubscription(subscriptionId, CryptaPlatform.trust.exchange.subscriptions.pause);
  }

  async function resumeSubscription(subscriptionId) {
    await mutateSubscription(subscriptionId, CryptaPlatform.trust.exchange.subscriptions.resume);
  }

  async function removeSubscription(subscriptionId) {
    await mutateSubscription(subscriptionId, CryptaPlatform.trust.exchange.subscriptions.remove);
  }

  async function mutateSubscription(subscriptionId, action) {
    if (!subscriptionId) {
      setStatus("Subscription id is unavailable.");
      return;
    }
    try {
      await action(subscriptionId);
      await Promise.all([refreshSubscriptions(), refreshAudit()]);
      setStatus("Trust subscription updated.");
    } catch (error) {
      renderError(elements.subscriptionList, error);
    }
  }

  async function addAnchor(event) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const identity = textValue(formData, "identity");
    const label = textValue(formData, "label");
    if (!identity) {
      setStatus("Enter an anchor identity.");
      return;
    }

    try {
      await CryptaPlatform.trust.anchors.add({
        issuerFingerprint: identity,
        label,
        source: "manual",
      });
      event.currentTarget.reset();
      await Promise.all([refreshAnchors(), refreshAudit(), refreshStatus()]);
      setStatus("Trust anchor added.");
    } catch (error) {
      setStatus(errorMessage(error));
    }
  }

  async function removeAnchor(identity) {
    try {
      await CryptaPlatform.trust.anchors.remove(identity);
      await Promise.all([refreshAnchors(), refreshAudit(), refreshStatus()]);
      setStatus("Trust anchor removed.");
    } catch (error) {
      setStatus(errorMessage(error));
    }
  }

  async function refreshIdentities() {
    try {
      const response = await CryptaPlatform.vault.identities.list();
      state.identities = asArray(response.identities || response.items || response);
      renderIdentities();
      setStatus("Identity metadata refreshed.");
    } catch (error) {
      renderError(elements.identityList, error);
    }
  }

  async function createIdentity(event) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const label = textValue(formData, "label");
    if (!label) {
      setStatus("Enter an identity label.");
      return;
    }

    try {
      const identity = await CryptaPlatform.vault.identities.create({
        label,
        purpose: "trust-statement",
      });
      event.currentTarget.reset();
      await refreshIdentities();
      replaceChildren(elements.publishResult, summaryNodes(identity, "Created identity"));
      setStatus("Identity creation requested.");
    } catch (error) {
      setStatus(errorMessage(error));
    }
  }

  async function fetchAndImportStatement(event) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const uri = textValue(formData, "uri");
    const documentText = textValue(formData, "document");
    const action = event.submitter ? event.submitter.value : "fetch";
    if (action === "import" || (!uri && documentText)) {
      await importStatementText("pasted", documentText, null);
      return;
    }
    if (!uri) {
      setStatus("Enter a statement URI or paste statement JSON.");
      return;
    }
    if (!isCryptaContentUri(uri)) {
      setStatus("Statement URI must start with CHK@, SSK@, USK@, KSK@, or crypta:.");
      return;
    }

    try {
      const imported = await CryptaPlatform.trust.exchange.fetchAndImport({
        uri,
        maxBytes: maxStatementBytes,
        sourceLabel: "Fetched statement",
      });
      state.lastStatementText = "";
      rememberImportSummary(
        "Fetched statement",
        uri,
        numberField(imported, "documentBytes", "bytes"),
        imported
      );
      renderImportSummary(uri, imported);
      await Promise.all([refreshStatus(), refreshAudit()]);
      setStatus("Statement fetched and imported.");
    } catch (error) {
      renderError(elements.statementPreview, error);
    }
  }

  async function importStatementText(label, text, sourceUri) {
    if (!text) {
      setStatus("Paste statement JSON before importing.");
      return;
    }
    if (byteLength(text) > maxStatementBytes) {
      setStatus("Trust statement JSON is too large.");
      return;
    }
    try {
      const request = { document: text, sourceLabel: label };
      if (sourceUri) {
        request.sourceUri = sourceUri;
      }
      const imported = await CryptaPlatform.trust.importStatement(request);
      state.lastStatementText = text;
      rememberImportSummary(label, sourceUri, byteLength(text || ""), imported);
      renderStatement(label, text, imported);
      await Promise.all([refreshStatus(), refreshAudit()]);
      setStatus("Statement imported.");
    } catch (error) {
      renderError(elements.statementPreview, error);
    }
  }

  async function scoreSubject(event) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const subjectKind = textValue(formData, "subjectKind") || "profile";
    const subject = textValue(formData, "subject");
    const context = textValue(formData, "context") || "general";
    if (!subject) {
      setStatus("Enter a subject URI or identity.");
      return;
    }

    try {
      const score = await CryptaPlatform.trust.score({
        subjectKind,
        subjectUri: subject,
        context,
        includeEvidence: true,
      });
      replaceChildren(elements.scoreResult, summaryNodes(score, "Trust score"));
      state.lastDraft.score = { subjectKind, subject, context };
      persistDurableState();
      setStatus("Trust score calculated.");
    } catch (error) {
      renderError(elements.scoreResult, error);
    }
  }

  async function publishStatement(event) {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);
    const authorIdentity = textValue(formData, "authorIdentity");
    const subjectKind = textValue(formData, "subjectKind") || "profile";
    const subjectIdentity = textValue(formData, "subjectIdentity");
    const value = Number(textValue(formData, "value"));
    const context = textValue(formData, "context") || "general";
    const reason = textValue(formData, "reason");
    const insertUri = textValue(formData, "insertUri");
    const identifier = textValue(formData, "identifier") || generatedIdentifier();

    if (!authorIdentity || !subjectIdentity || !insertUri || Number.isNaN(value)) {
      setStatus("Author, subject, trust value, and insert URI are required.");
      return;
    }

    try {
      const published = await CryptaPlatform.trust.exchange.publish({
        identityId: authorIdentity,
        subjectKind,
        subjectUri: subjectIdentity,
        context,
        score: value,
        confidence: 80,
        reason,
        insertUri,
        identifier,
      });
      await Promise.all([refreshQueue(), refreshStatus(), refreshAudit()]);
      state.lastDraft.publish = { authorIdentity, subjectKind, subjectIdentity, value, context, reason };
      persistDurableState();
      replaceChildren(
        elements.publishResult,
        summaryNodes(publicationSummary(published), "Published statement")
      );
      setStatus("Trust statement publication requested.");
    } catch (error) {
      renderError(elements.publishResult, error);
    }
  }

  async function refreshQueue() {
    try {
      const snapshot = await CryptaPlatform.queue.snapshot({ limit: 8 });
      state.queueItems = asArray(snapshot.items || snapshot.queue || snapshot);
      renderQueue(snapshot);
      setStatus("Queue preview refreshed.");
    } catch (error) {
      renderError(elements.queuePreview, error);
    }
  }

  async function loadDurableState() {
    if (!dataHelpersAvailable()) {
      return;
    }
    try {
      const stored = await CryptaPlatform.data.records.getJson(dataNamespace, dataStateKey);
      if (!stored || stored.schemaVersion !== dataSchemaVersion) {
        return;
      }
      state.lastDraft = normalizeLastDraft(stored.lastDraft);
      if (Array.isArray(stored.recentImports)) {
        state.recentImports = stored.recentImports.slice(0, 8).map(normalizeImportSummary);
      }
    } catch (error) {
      // First launch or older nodes may not have a saved preview record yet.
    }
  }

  async function persistDurableState() {
    if (!dataHelpersAvailable()) {
      return;
    }
    try {
      await CryptaPlatform.data.records.putJson({
        namespace: dataNamespace,
        key: dataStateKey,
        schemaVersion: dataSchemaVersion,
        value: {
          schemaVersion: dataSchemaVersion,
          lastDraft: normalizeLastDraft(state.lastDraft),
          recentImports: state.recentImports.slice(0, 8),
        },
      });
    } catch (error) {
      setStatus("Trust Graph Preview UI state could not be saved.");
    }
  }

  function dataHelpersAvailable() {
    return (
      CryptaPlatform.data &&
      CryptaPlatform.data.records &&
      typeof CryptaPlatform.data.records.getJson === "function" &&
      typeof CryptaPlatform.data.records.putJson === "function"
    );
  }

  function rememberImportSummary(label, sourceUri, bytes, imported) {
    const sourceKind = importSourceKind(sourceUri);
    state.recentImports.unshift({
      at: new Date().toISOString(),
      label: importSummaryLabel(label, sourceUri),
      sourceKind,
      bytes: Number(bytes) || 0,
      result: stringField(imported, "status", "outcome") || "imported",
    });
    state.recentImports = state.recentImports.slice(0, 8);
    state.lastDraft.import = { sourceKind };
    persistDurableState();
  }

  function normalizeImportSummary(summary) {
    if (!summary || typeof summary !== "object") {
      return {};
    }
    const sourceUri = String(summary.sourceUri || "");
    const label = String(summary.label || "");
    const sourceKind = sourceUri || isCryptaContentUri(label) ? "content-uri" : "pasted";
    return {
      at: String(summary.at || ""),
      label: importSummaryLabel(label, sourceUri),
      sourceKind: normalizeSourceKind(summary.sourceKind, sourceKind),
      bytes: Number(summary.bytes) || 0,
      result: String(summary.result || ""),
    };
  }

  function normalizeLastDraft(draft) {
    if (!draft || typeof draft !== "object") {
      return {};
    }
    const normalized = {};
    if (draft.score && typeof draft.score === "object") {
      normalized.score = draft.score;
    }
    if (draft.publish && typeof draft.publish === "object") {
      normalized.publish = draft.publish;
    }
    if (draft.import && typeof draft.import === "object") {
      const sourceKind = normalizeSourceKind(
        draft.import.sourceKind,
        draft.import.sourceUri ? "content-uri" : "",
      );
      if (sourceKind) {
        normalized.import = { sourceKind };
      }
    }
    return normalized;
  }

  function importSourceKind(sourceUri) {
    return sourceUri ? "content-uri" : "pasted";
  }

  function normalizeSourceKind(value, fallback) {
    const text = String(value || "");
    if (text === "content-uri" || text === "pasted") {
      return text;
    }
    return fallback || "";
  }

  function importSummaryLabel(label, sourceUri) {
    const text = String(label || "").trim();
    return sourceUri || isCryptaContentUri(text) ? "Fetched statement" : text || "Pasted statement";
  }

  function restoreDraftForms() {
    const score = state.lastDraft.score || {};
    setFormValue(elements.scoreForm, "subjectKind", score.subjectKind);
    setFormValue(elements.scoreForm, "subject", score.subject);
    setFormValue(elements.scoreForm, "context", score.context);
    const publish = state.lastDraft.publish || {};
    setFormValue(elements.publishForm, "authorIdentity", publish.authorIdentity);
    setFormValue(elements.publishForm, "subjectKind", publish.subjectKind);
    setFormValue(elements.publishForm, "subjectIdentity", publish.subjectIdentity);
    setFormValue(elements.publishForm, "value", publish.value);
    setFormValue(elements.publishForm, "context", publish.context);
    setFormValue(elements.publishForm, "reason", publish.reason);
  }

  function setFormValue(form, name, value) {
    const field = form.querySelector(`[name="${name}"]`);
    if (
      field instanceof HTMLInputElement ||
      field instanceof HTMLTextAreaElement ||
      field instanceof HTMLSelectElement
    ) {
      field.value = value == null ? "" : String(value);
    }
  }

  function renderAnchors() {
    if (state.anchors.length === 0) {
      replaceChildren(elements.anchorList, [emptyNode("No trust anchors returned.")]);
      return;
    }

    const nodes = state.anchors.map((anchor) => {
      const identity = stringField(anchor, "issuerFingerprint", "identity", "id", "subject");
      const item = document.createElement("article");
      item.className = "anchor-item";
      item.append(
        rowNode("Identity", identity || "Unknown"),
        rowNode("Label", stringField(anchor, "label", "name") || "Unlabeled"),
        rowNode(
          "Created",
          stringField(anchor, "createdAt", "addedAt", "updatedAt", "updated") || "Unknown"
        )
      );

      const actions = document.createElement("div");
      actions.className = "anchor-item__actions";
      const removeButton = document.createElement("button");
      removeButton.className = "cr-button cr-button--secondary";
      removeButton.type = "button";
      removeButton.textContent = "Remove";
      removeButton.addEventListener("click", () => removeAnchor(identity));
      removeButton.disabled = !identity;
      actions.append(removeButton);
      item.append(actions);
      return item;
    });
    replaceChildren(elements.anchorList, nodes);
  }

  function renderIdentities() {
    if (state.identities.length === 0) {
      replaceChildren(elements.identityList, [emptyNode("No identity metadata returned.")]);
      return;
    }

    const nodes = state.identities.map((identity) => {
      const item = document.createElement("article");
      item.className = "identity-item";
      item.append(
        rowNode("Label", stringField(identity, "label", "name") || "Unlabeled"),
        rowNode("Identity", stringField(identity, "identityId", "identity", "id") || "Unknown"),
        rowNode(
          "Fingerprint",
          stringField(identity, "fingerprint", "publicKeyFingerprint") || "Not shown"
        ),
        rowNode(
          "Scopes",
          compactValue(identity.usageScopes || identity.grants || identity.permissions || [])
        )
      );
      return item;
    });
    replaceChildren(elements.identityList, nodes);
  }

  function renderStatement(uri, text, imported) {
    const nodes = [
      rowNode("Source", importSummaryLabel(uri, "")),
      rowNode("Import", compactValue(imported)),
      textBlock("Statement text", text),
    ];
    replaceChildren(elements.statementPreview, nodes);
  }

  function renderImportSummary(uri, imported) {
    const summary = {
      source: "content-fetch",
      sourceSummary: redactedUri(uri),
      documentFingerprint: stringField(imported, "documentFingerprint"),
      payloadHash: stringField(imported, "payloadHash"),
      signatureVerified: stringField(imported, "signatureVerified"),
      importedAt: stringField(imported, "importedAt"),
      updatedAt: stringField(imported, "updatedAt"),
    };
    replaceChildren(elements.statementPreview, summaryNodes(summary, "Imported statement"));
  }

  function renderQueue(snapshot) {
    if (state.queueItems.length === 0) {
      replaceChildren(elements.queuePreview, summaryNodes(queueSnapshotSummary(snapshot), "Queue snapshot"));
      return;
    }

    const nodes = state.queueItems.map((item) => {
      const article = document.createElement("article");
      article.className = "queue-item";
      article.append(
        rowNode("Identifier", stringField(item, "identifier", "id") || "Unknown"),
        rowNode("State", stringField(item, "state", "status") || "Unknown"),
        rowNode("Request", stringField(item, "requestId", "request", "id") || "Not shown")
      );
      return article;
    });
    replaceChildren(elements.queuePreview, nodes);
  }

  function renderAudit() {
    if (state.auditEvents.length === 0) {
      replaceChildren(elements.auditList, [emptyNode("No trust graph audit entries returned.")]);
      return;
    }

    const nodes = state.auditEvents.map((event) => {
      const article = document.createElement("article");
      article.className = "audit-item";
      article.append(
        rowNode("Event", stringField(event, "eventType", "type") || "Unknown"),
        rowNode("Status", stringField(event, "statusCode", "status") || "ok"),
        rowNode("Document", stringField(event, "documentFingerprint") || "Not shown"),
        rowNode("Payload", stringField(event, "payloadHash") || "Not shown"),
        rowNode("Source", stringField(event, "sourceSummary", "source") || "Not shown"),
        rowNode("At", stringField(event, "timestamp", "at") || "Unknown")
      );
      return article;
    });
    replaceChildren(elements.auditList, nodes);
  }

  function renderSubscriptions() {
    if (state.subscriptions.length === 0) {
      replaceChildren(elements.subscriptionList, [
        emptyNode("No trust statement subscriptions returned."),
      ]);
      return;
    }

    const nodes = state.subscriptions.map((subscription) => {
      const subscriptionId = stringField(subscription, "subscriptionId", "id");
      const article = document.createElement("article");
      article.className = "subscription-item";
      article.append(
        rowNode("Label", stringField(subscription, "label", "name") || "Trust statement"),
        rowNode("URI", redactedUri(stringField(subscription, "uri", "sourceUri")) || "Not shown"),
        rowNode("Status", stringField(subscription, "state", "status") || "Unknown"),
        rowNode(
          "Edition",
          stringField(subscription, "lastKnownEdition", "lastEdition", "edition") || "Unknown"
        )
      );

      const actions = document.createElement("div");
      actions.className = "subscription-item__actions";
      actions.append(
        subscriptionButton("Refresh", () => refreshSubscription(subscriptionId), subscriptionId),
        subscriptionButton("Pause", () => pauseSubscription(subscriptionId), subscriptionId),
        subscriptionButton("Resume", () => resumeSubscription(subscriptionId), subscriptionId),
        subscriptionButton("Remove", () => removeSubscription(subscriptionId), subscriptionId)
      );
      article.append(actions);
      return article;
    });
    replaceChildren(elements.subscriptionList, nodes);
  }

  function subscriptionButton(label, action, subscriptionId) {
    const button = document.createElement("button");
    button.className = "cr-button cr-button--secondary";
    button.type = "button";
    button.textContent = label;
    button.disabled = !subscriptionId;
    button.addEventListener("click", action);
    return button;
  }

  function publicationSummary(published) {
    return {
      requestId: stringField(published, "requestId", "id"),
      documentFingerprint: stringField(published, "documentFingerprint"),
      payloadHash: stringField(published, "payloadHash"),
      signatureVerified: stringField(published, "signatureVerified"),
      source: stringField(published, "source") || "local-publish",
    };
  }

  function queueSnapshotSummary(snapshot) {
    return {
      count: Array.isArray(state.queueItems) ? state.queueItems.length : 0,
      page: stringField(snapshot, "page"),
      status: stringField(snapshot, "status"),
    };
  }

  function summaryNodes(value, title) {
    const item = document.createElement("article");
    item.className = "summary-item";
    const heading = document.createElement("p");
    heading.className = "summary-title";
    heading.append(strongText(title));
    item.append(heading);

    if (value && typeof value === "object" && !Array.isArray(value)) {
      const keys = Object.keys(value).slice(0, 8);
      if (keys.length === 0) {
        item.append(rowNode("Result", "No fields returned."));
      } else {
        keys.forEach((key) => item.append(rowNode(labelFromKey(key), compactValue(value[key]))));
      }
    } else {
      item.append(rowNode("Result", compactValue(value)));
    }

    return [item];
  }

  function rowNode(label, value) {
    const row = document.createElement("p");
    row.className = "summary-row";
    row.append(strongText(`${label}: `), document.createTextNode(value || ""));
    return row;
  }

  function textBlock(label, value) {
    const block = document.createElement("div");
    block.className = "summary-item";
    block.append(rowNode(label, ""));
    const text = document.createElement("p");
    text.className = "statement-text";
    text.textContent = value || "";
    block.append(text);
    return block;
  }

  function emptyNode(message) {
    const empty = document.createElement("p");
    empty.className = "cr-empty";
    empty.textContent = message;
    return empty;
  }

  function renderError(container, error) {
    replaceChildren(container, [emptyNode(errorMessage(error))]);
    setStatus(errorMessage(error));
  }

  function replaceChildren(container, nodes) {
    container.replaceChildren(...nodes);
  }

  function strongText(value) {
    const strong = document.createElement("strong");
    strong.textContent = value;
    return strong;
  }

  function textValue(formData, name) {
    return String(formData.get(name) || "").trim();
  }

  function asArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function stringField(value, ...keys) {
    if (!value || typeof value !== "object") {
      return "";
    }
    for (const key of keys) {
      if (value[key] !== undefined && value[key] !== null) {
        return String(value[key]);
      }
    }
    return "";
  }

  function numberField(value, ...keys) {
    if (!value || typeof value !== "object") {
      return 0;
    }
    for (const key of keys) {
      const number = Number(value[key]);
      if (Number.isFinite(number)) {
        return number;
      }
    }
    return 0;
  }

  function redactedUri(uri) {
    const value = String(uri || "").trim();
    if (!value) {
      return "";
    }
    const marker = value.startsWith("crypta:") ? "crypta:" : "";
    const remainder = marker ? value.slice(marker.length) : value;
    const separator = remainder.indexOf("@");
    const prefix = separator > 0 ? remainder.slice(0, separator + 1) : "";
    return `${marker}${prefix}redacted`;
  }

  function compactValue(value) {
    if (value === undefined || value === null || value === "") {
      return "None";
    }
    if (Array.isArray(value)) {
      return value.length === 0 ? "None" : value.map(compactValue).join(", ");
    }
    if (typeof value === "object") {
      return Object.entries(value)
        .slice(0, 6)
        .map(([key, entryValue]) => `${labelFromKey(key)}=${compactValue(entryValue)}`)
        .join("; ");
    }
    return String(value);
  }

  function labelFromKey(key) {
    return String(key)
      .replace(/([A-Z])/g, " $1")
      .replace(/[-_]/g, " ")
      .replace(/^./, (first) => first.toUpperCase());
  }

  function generatedIdentifier() {
    const timestamp = new Date().toISOString().replace(/[^0-9]/g, "").slice(0, 14);
    return `trust-graph-statement-${timestamp}`;
  }

  function isCryptaContentUri(uri) {
    return (
      uri.startsWith("CHK@") ||
      uri.startsWith("SSK@") ||
      uri.startsWith("USK@") ||
      uri.startsWith("KSK@") ||
      uri.startsWith("crypta:")
    );
  }

  function isTrustSubscriptionUri(uri) {
    const value = String(uri || "").trim();
    if (!value || /\s/.test(value) || value.includes("?") || value.includes("#")) {
      return false;
    }
    const runtimeUri = value.toLowerCase().startsWith("crypta:") ? value.slice(7).trim() : value;
    return runtimeUri.toUpperCase().startsWith("USK@");
  }

  function byteLength(value) {
    if (window.TextEncoder) {
      return new TextEncoder().encode(value).length;
    }
    return value.length;
  }

  function errorMessage(error) {
    if (
      CryptaPlatform.api &&
      typeof CryptaPlatform.api.errorMessage === "function"
    ) {
      return CryptaPlatform.api.errorMessage(error);
    }
    return error && error.message ? error.message : "Trust graph request failed.";
  }

  function setStatus(message) {
    elements.status.textContent = message;
  }
})();
