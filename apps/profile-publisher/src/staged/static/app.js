(function () {
  "use strict";

  const appId = "profile-publisher";
  const defaultProfileContentType = "application/vnd.crypta.profile+json";
  const maxRecentActions = 5;
  const state = {
    draft: {},
    grants: [],
    identities: [],
    recentActions: [],
    selectedIdentityId: "",
    signedDocument: null,
    uploadQueueReversed: false,
    uploadQueueSortBy: null,
  };

  const elements = {
    documentPreview: document.getElementById("document-preview"),
    grantList: document.getElementById("grant-list"),
    identityForm: document.getElementById("identity-form"),
    identitySelect: document.getElementById("identity-select"),
    identitySummary: document.getElementById("identity-summary"),
    previewButton: document.getElementById("preview-button"),
    profileForm: document.getElementById("profile-form"),
    publishForm: document.getElementById("publish-form"),
    queuePreview: document.getElementById("queue-preview"),
    recentActions: document.getElementById("recent-actions"),
    refreshIdentitiesButton: document.getElementById("refresh-identities-button"),
    refreshQueueButton: document.getElementById("refresh-queue-button"),
    requestGrantButton: document.getElementById("request-grant-button"),
    secondaryRefreshQueueButton: document.getElementById("secondary-refresh-queue-button"),
    signButton: document.getElementById("sign-button"),
    status: document.getElementById("status"),
  };

  document.addEventListener("DOMContentLoaded", start);

  async function start() {
    bindControls();
    initializePublishForm();
    syncDraftFromForm();
    try {
      await CryptaPlatform.bootstrap.load({ appId });
      await Promise.all([refreshIdentities({ silent: true }), refreshUploadQueue({ silent: true })]);
      renderDocumentPreview(buildUnsignedProfilePreview());
      setStatus("Profile Publisher is ready.");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function bindControls() {
    elements.identityForm.addEventListener("submit", createIdentity);
    elements.identitySelect.addEventListener("change", selectIdentity);
    elements.previewButton.addEventListener("click", previewDocument);
    elements.profileForm.addEventListener("input", updateDraft);
    elements.publishForm.addEventListener("submit", publishDocument);
    elements.refreshIdentitiesButton.addEventListener("click", refreshIdentities);
    elements.refreshQueueButton.addEventListener("click", refreshUploadQueue);
    elements.requestGrantButton.addEventListener("click", requestSelectedGrant);
    elements.secondaryRefreshQueueButton.addEventListener("click", refreshUploadQueue);
    elements.signButton.addEventListener("click", signPreview);
    elements.queuePreview.addEventListener("click", interceptQueueClick);
    elements.queuePreview.addEventListener("submit", interceptQueueSubmit);
  }

  async function refreshIdentities(options) {
    const refreshOptions = options || {};
    try {
      if (!refreshOptions.silent) {
        setStatus("Loading profile identities...");
      }
      const identities = await CryptaPlatform.vault.identities.list();
      const grants = await CryptaPlatform.vault.grants.list();
      state.identities = normalizeIdentityList(identities);
      state.grants = normalizeGrantList(grants);
      if (!identityById(state.selectedIdentityId) && state.identities.length > 0) {
        setSelectedIdentityId(identityId(state.identities[0]));
      }
      renderIdentities();
      renderGrants();
      if (!refreshOptions.silent) {
        setStatus(`Loaded ${state.identities.length} profile identity record(s).`, "success");
      }
    } catch (error) {
      state.identities = [];
      state.grants = [];
      renderIdentities();
      renderGrants();
      if (!refreshOptions.silent) {
        setStatus(CryptaPlatform.api.errorMessage(error), "error");
      }
    }
  }

  async function createIdentity(event) {
    event.preventDefault();
    const label = fieldValue(elements.identityForm, "identityLabel") || "Profile Publisher identity";
    try {
      const data = await CryptaPlatform.vault.identities.create({
        label,
        scopes: ["metadata.read", "sign.domain-separated"],
      });
      const identity = data.identity || data;
      setSelectedIdentityId(identityId(identity));
      recordRecentAction("Identity", state.selectedIdentityId || label, "created");
      await refreshIdentities({ silent: true });
      setStatus("Profile identity created.", "success");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  async function requestSelectedGrant() {
    const identityIdValue = selectedIdentityId();
    if (!identityIdValue) {
      setStatus("Select an identity before requesting a grant.", "error");
      return;
    }
    try {
      const request = await CryptaPlatform.vault.grants.request({
        identityId: identityIdValue,
        scopes: ["metadata.read", "sign.domain-separated"],
        reason: "Sign Profile Publisher app documents.",
      });
      renderGrantRequest(request.grantRequest || request);
      recordRecentAction("Grant", identityIdValue, "operator review requested");
      setStatus("Identity grant request prepared for operator review.", "success");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  function selectIdentity() {
    setSelectedIdentityId(elements.identitySelect.value);
    renderSelectedIdentity();
    renderDocumentPreview(buildUnsignedProfilePreview());
  }

  function updateDraft() {
    syncDraftFromForm();
    state.signedDocument = null;
    renderDocumentPreview(buildUnsignedProfilePreview());
  }

  function previewDocument() {
    syncDraftFromForm();
    state.signedDocument = null;
    renderDocumentPreview(buildUnsignedProfilePreview());
    setStatus("Profile app-document preview refreshed.");
  }

  async function signPreview() {
    if (!selectedIdentityId()) {
      setStatus("Select an identity before signing the profile preview.", "error");
      return;
    }
    syncDraftFromForm();
    try {
      state.signedDocument = await createSignedProfileDocument();
      renderDocumentPreview(state.signedDocument);
      recordRecentAction("Signature", selectedIdentityId(), "signed preview");
      setStatus("Profile preview signed.", "success");
    } catch (error) {
      renderDocumentPreview(buildUnsignedProfilePreview());
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  async function publishDocument(event) {
    event.preventDefault();
    if (!selectedIdentityId()) {
      setStatus("Select an identity before publishing the profile document.", "error");
      return;
    }
    syncDraftFromForm();
    try {
      const documentData =
        cachedSignedDocumentForSelectedIdentity() || (await createSignedProfileDocument());
      state.signedDocument = documentData;
      renderDocumentPreview(documentData);
      const result = await CryptaPlatform.content.insertAppDocument(buildPublishOptions(documentData));
      renderPublishResult(result);
      await refreshUploadQueue({ silent: true });
      setStatus("Profile app-document publish queued.", "success");
    } catch (error) {
      setStatus(CryptaPlatform.api.errorMessage(error), "error");
    }
  }

  async function createSignedProfileDocument() {
    const response = await CryptaPlatform.vault.identities.createProfileDocument(
      selectedIdentityId(),
      buildProfilePayload(),
    );
    return profileDocumentFromResponse(response);
  }

  function cachedSignedDocumentForSelectedIdentity() {
    const documentData = state.signedDocument;
    if (!documentData || typeof documentData !== "object" || !documentData.identity) {
      return null;
    }
    return identityId(documentData.identity) === selectedIdentityId() ? documentData : null;
  }

  function buildPublishOptions(documentData) {
    const identifierField = elements.publishForm.querySelector('input[name="identifier"]');
    const identifier = fieldValue(elements.publishForm, "identifier") || generatedIdentifier("publish");
    if (identifierField instanceof HTMLInputElement) {
      identifierField.value = identifier;
    }
    return {
      document: documentData,
      insertUri: fieldValue(elements.publishForm, "insertUri"),
      identifier,
      contentType: fieldValue(elements.publishForm, "contentType") || defaultProfileContentType,
      targetFilename: fieldValue(elements.publishForm, "targetFilename") || "profile.json",
    };
  }

  async function refreshUploadQueue(options) {
    const refreshOptions = options || {};
    try {
      if (!refreshOptions.silent) {
        setStatus("Loading upload queue...");
      }
      const snapshot = await CryptaPlatform.queue.snapshot({
        page: "uploads",
        sortBy: state.uploadQueueSortBy,
        reversed: state.uploadQueueReversed,
      });
      renderQueue(snapshot.contentHtml);
      if (!refreshOptions.silent) {
        setStatus(uploadQueueStatusMessage());
      }
    } catch (error) {
      if (refreshOptions.silent) {
        renderQueue("");
      } else {
        setStatus(CryptaPlatform.api.errorMessage(error), "error");
      }
    }
  }

  function buildUnsignedProfilePreview() {
    return {
      schema: "crypta.profile.v1",
      profile: buildProfilePayload(),
      identity: selectedIdentitySummary(),
      signature: null,
    };
  }

  function buildProfilePayload() {
    const payload = {
      displayName: state.draft.displayName || "",
    };
    copyOptional(payload, "bio", state.draft.bio);
    copyOptional(payload, "website", state.draft.website);
    copyOptional(payload, "avatarUri", state.draft.avatarUri);
    copyOptional(payload, "contactUri", state.draft.contactUri);
    if (state.draft.tags.length > 0) {
      payload.tags = state.draft.tags;
    }
    return payload;
  }

  function selectedIdentitySummary() {
    const selectedIdentity = identityById(state.selectedIdentityId);
    if (!selectedIdentity) {
      return null;
    }
    return {
      identityId: identityId(selectedIdentity),
      label: identityLabel(selectedIdentity),
      fingerprint: stringValue(selectedIdentity.fingerprint),
      publicSummary: stringValue(selectedIdentity.publicSummary),
    };
  }

  function syncDraftFromForm() {
    state.draft = {
      avatarUri: fieldValue(elements.profileForm, "avatarUri"),
      bio: fieldValue(elements.profileForm, "bio"),
      contactUri: fieldValue(elements.profileForm, "contactUri"),
      displayName: fieldValue(elements.profileForm, "displayName"),
      tags: commaValues(fieldValue(elements.profileForm, "tags")),
      website: fieldValue(elements.profileForm, "website"),
    };
  }

  function initializePublishForm() {
    const identifier = elements.publishForm.querySelector('input[name="identifier"]');
    if (identifier instanceof HTMLInputElement && !identifier.value.trim()) {
      identifier.value = generatedIdentifier("publish");
    }
  }

  function renderIdentities() {
    elements.identitySelect.replaceChildren();
    if (state.identities.length === 0) {
      const option = document.createElement("option");
      option.value = "";
      option.textContent = "No granted identities";
      elements.identitySelect.append(option);
      elements.identitySelect.disabled = true;
      setSelectedIdentityId("");
      renderSelectedIdentity();
      return;
    }
    elements.identitySelect.disabled = false;
    for (const identity of state.identities) {
      const option = document.createElement("option");
      option.value = identityId(identity);
      option.textContent = identityLabel(identity);
      option.selected = option.value === state.selectedIdentityId;
      elements.identitySelect.append(option);
    }
    renderSelectedIdentity();
  }

  function setSelectedIdentityId(value) {
    const nextIdentityId = stringValue(value);
    if (state.selectedIdentityId !== nextIdentityId) {
      state.selectedIdentityId = nextIdentityId;
      state.signedDocument = null;
    }
  }

  function renderSelectedIdentity() {
    const identity = identityById(state.selectedIdentityId);
    if (!identity) {
      elements.identitySummary.replaceChildren(
        text("p", "cr-empty", "No granted identity metadata is available."),
      );
      return;
    }
    const panel = document.createElement("div");
    panel.className = "summary";
    panel.append(
      summaryRow("Identity", identityLabel(identity)),
      summaryRow("Identifier", identityId(identity)),
      summaryRow("Kind", identity.kind),
      summaryRow("Fingerprint", identity.fingerprint),
    );
    elements.identitySummary.replaceChildren(panel);
  }

  function renderGrants() {
    if (state.grants.length === 0) {
      elements.grantList.replaceChildren(text("p", "cr-empty", "No visible grants returned."));
      return;
    }
    const list = document.createElement("div");
    list.className = "grant-list";
    for (const grant of state.grants) {
      const item = document.createElement("div");
      item.className = "grant-item";
      item.append(
        summaryRow("Grant identity", grant.identityId || grant.id),
        summaryRow("Scopes", Array.isArray(grant.scopes) ? grant.scopes.join(", ") : grant.scopes),
        summaryRow("Status", grant.status),
      );
      list.append(item);
    }
    elements.grantList.replaceChildren(list);
  }

  function renderGrantRequest(request) {
    const panel = document.createElement("div");
    panel.className = "grant-list";
    const item = document.createElement("div");
    item.className = "grant-item";
    item.append(
      summaryRow("Grant request", request.status),
      summaryRow("Identity", request.identityId),
      summaryRow("Scopes", Array.isArray(request.scopes) ? request.scopes.join(", ") : request.scopes),
    );
    panel.append(item);
    elements.grantList.replaceChildren(panel);
  }

  function renderDocumentPreview(documentData) {
    elements.documentPreview.textContent = JSON.stringify(documentData, null, 2);
  }

  function renderPublishResult(data) {
    recordRecentAction("Publish", data.identifier, data.outcome || data.status || "queued");
  }

  function recordRecentAction(kind, subject, outcome) {
    state.recentActions.unshift({
      at: new Date().toLocaleTimeString(),
      kind: stringValue(kind),
      outcome: stringValue(outcome),
      subject: stringValue(subject),
    });
    state.recentActions = state.recentActions.slice(0, maxRecentActions);
    renderRecentActions();
  }

  function renderRecentActions() {
    if (state.recentActions.length === 0) {
      elements.recentActions.replaceChildren(
        text("p", "cr-empty", "Recent publish actions stay only in this page's memory."),
      );
      return;
    }
    const list = document.createElement("div");
    list.className = "recent-list";
    for (const action of state.recentActions) {
      const item = document.createElement("div");
      item.className = "recent-item";
      item.append(
        summaryRow("When", action.at),
        summaryRow("Action", action.kind),
        summaryRow("Subject", action.subject),
        summaryRow("Outcome", action.outcome),
      );
      list.append(item);
    }
    elements.recentActions.replaceChildren(list);
  }

  function renderQueue(contentHtml) {
    const container = document.createElement("div");
    container.className = "legacy-fragment";
    if (typeof contentHtml !== "string" || !contentHtml) {
      container.append(text("p", "cr-empty", "No upload queue content was returned."));
      elements.queuePreview.replaceChildren(container);
      return;
    }
    container.replaceChildren(CryptaPlatform.dom.sanitizeFragment(contentHtml));
    elements.queuePreview.replaceChildren(container);
  }

  function interceptQueueClick(event) {
    const target = event.target instanceof Element ? event.target : null;
    const anchor = target ? target.closest("a") : null;
    if (!anchor || !elements.queuePreview.contains(anchor)) {
      return;
    }
    if (updateUploadQueueSort(anchor.getAttribute("href") || "")) {
      event.preventDefault();
      return;
    }
    event.preventDefault();
    setStatus("Open Queue Manager for detailed queue actions.", "error");
  }

  function interceptQueueSubmit(event) {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    event.preventDefault();
    setStatus("Open Queue Manager for detailed queue actions.", "error");
  }

  function updateUploadQueueSort(rawHref) {
    if (typeof rawHref !== "string" || !rawHref.startsWith("?")) {
      return false;
    }
    const params = new URLSearchParams(rawHref.slice(1));
    if (!params.has("sortBy")) {
      return false;
    }
    state.uploadQueueSortBy = params.get("sortBy");
    state.uploadQueueReversed = params.get("reversed") === "true" || params.has("reversed");
    refreshUploadQueue();
    return true;
  }

  function profileDocumentFromResponse(response) {
    if (response && response.profileDocument && typeof response.profileDocument === "object") {
      return response.profileDocument;
    }
    return response;
  }

  function normalizeIdentityList(data) {
    if (Array.isArray(data)) {
      return data;
    }
    return data && Array.isArray(data.identities) ? data.identities : [];
  }

  function normalizeGrantList(data) {
    if (Array.isArray(data)) {
      return data;
    }
    return data && Array.isArray(data.grants) ? data.grants : [];
  }

  function selectedIdentityId() {
    return elements.identitySelect.disabled ? "" : state.selectedIdentityId;
  }

  function identityById(id) {
    return state.identities.find((identity) => identityId(identity) === id) || null;
  }

  function identityId(identity) {
    return stringValue(identity.identityId || identity.id);
  }

  function identityLabel(identity) {
    return stringValue(identity.label || identity.displayName || identityId(identity) || "Profile identity");
  }

  function uploadQueueStatusMessage() {
    if (!state.uploadQueueSortBy) {
      return "Showing upload queue progress.";
    }
    return `Showing upload queue sorted by ${state.uploadQueueSortBy}${
      state.uploadQueueReversed ? " descending" : ""
    }.`;
  }

  function generatedIdentifier(kind) {
    const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    const random = Math.random().toString(36).slice(2, 8);
    return `profile-publisher-${kind}-${timestamp}-${random}`;
  }

  function fieldValue(form, name) {
    const field = form.querySelector(`[name="${name}"]`);
    return field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement
      ? field.value.trim()
      : "";
  }

  function commaValues(value) {
    return stringValue(value)
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
  }

  function copyOptional(target, name, value) {
    if (typeof value === "string" && value) {
      target[name] = value;
    }
  }

  function summaryRow(label, value) {
    const row = document.createElement("p");
    const key = document.createElement("strong");
    key.textContent = `${label}: `;
    row.append(key, document.createTextNode(value == null || value === "" ? "Unavailable" : String(value)));
    return row;
  }

  function text(tagName, className, value) {
    const node = document.createElement(tagName);
    node.className = className;
    node.textContent = value;
    return node;
  }

  function stringValue(value) {
    return value == null ? "" : String(value);
  }

  function setStatus(message, tone) {
    elements.status.textContent = message || "";
    elements.status.className = statusClassName(tone);
  }

  function statusClassName(tone) {
    switch (tone) {
      case "success":
        return "cr-status cr-status--success";
      case "error":
        return "cr-status cr-status--danger";
      default:
        return "cr-status";
    }
  }
})();
