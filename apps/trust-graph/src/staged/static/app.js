(() => {
  "use strict";

  const appId = "trust-graph";
  const maxStatementBytes = 65536;
  const state = {
    anchors: [],
    identities: [],
    lastStatementText: "",
    queueItems: [],
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
    elements.refreshStatusButton = document.getElementById("refresh-status-button");
    elements.loadIdentitiesButton = document.getElementById("load-identities-button");
    elements.refreshAnchorsButton = document.getElementById("refresh-anchors-button");
    elements.refreshQueueButton = document.getElementById("refresh-queue-button");
    elements.secondaryRefreshQueueButton =
      document.getElementById("secondary-refresh-queue-button");
    elements.identityForm = document.getElementById("identity-form");
    elements.anchorForm = document.getElementById("anchor-form");
    elements.fetchForm = document.getElementById("fetch-form");
    elements.scoreForm = document.getElementById("score-form");
    elements.publishForm = document.getElementById("publish-form");
  }

  function bindEvents() {
    elements.refreshStatusButton.addEventListener("click", refreshStatus);
    elements.loadIdentitiesButton.addEventListener("click", refreshIdentities);
    elements.refreshAnchorsButton.addEventListener("click", refreshAnchors);
    elements.refreshQueueButton.addEventListener("click", refreshQueue);
    elements.secondaryRefreshQueueButton.addEventListener("click", refreshQueue);
    elements.identityForm.addEventListener("submit", createIdentity);
    elements.anchorForm.addEventListener("submit", addAnchor);
    elements.fetchForm.addEventListener("submit", fetchAndImportStatement);
    elements.scoreForm.addEventListener("submit", scoreSubject);
    elements.publishForm.addEventListener("submit", publishStatement);
  }

  async function startApp() {
    setStatus("Loading Trust Graph Preview.");
    try {
      if (CryptaPlatform.bootstrap && typeof CryptaPlatform.bootstrap.load === "function") {
        await CryptaPlatform.bootstrap.load({ appId });
      }
      await Promise.all([refreshStatus(), refreshAnchors(), refreshIdentities(), refreshQueue()]);
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
      await refreshAnchors();
      setStatus("Trust anchor added.");
    } catch (error) {
      setStatus(errorMessage(error));
    }
  }

  async function removeAnchor(identity) {
    try {
      await CryptaPlatform.trust.anchors.remove(identity);
      await refreshAnchors();
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
      const fetched = await CryptaPlatform.content.fetchText({ uri, maxBytes: maxStatementBytes });
      const text = fetched.contentText || fetched.text || fetched.content || String(fetched);
      state.lastStatementText = text;
      await importStatementText(uri, text, uri);
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
      renderStatement(label, text, imported);
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
      const statement = await CryptaPlatform.vault.identities.createTrustStatement(authorIdentity, {
        subjectKind,
        subjectUri: subjectIdentity,
        context,
        score: value,
        confidence: 80,
        reason,
      });
      const published = await CryptaPlatform.trust.publishStatement({
        insertUri,
        identifier,
        statement,
      });
      await refreshQueue();
      replaceChildren(elements.publishResult, summaryNodes(published, "Published statement"));
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
      rowNode("URI", uri),
      rowNode("Import", compactValue(imported)),
      textBlock("Statement text", text),
    ];
    replaceChildren(elements.statementPreview, nodes);
  }

  function renderQueue(snapshot) {
    if (state.queueItems.length === 0) {
      replaceChildren(elements.queuePreview, summaryNodes(snapshot, "Queue snapshot"));
      return;
    }

    const nodes = state.queueItems.map((item) => {
      const article = document.createElement("article");
      article.className = "queue-item";
      article.append(
        rowNode("Identifier", stringField(item, "identifier", "id") || "Unknown"),
        rowNode("State", stringField(item, "state", "status") || "Unknown"),
        rowNode("URI", stringField(item, "uri", "targetUri", "insertUri") || "Not shown")
      );
      return article;
    });
    replaceChildren(elements.queuePreview, nodes);
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
