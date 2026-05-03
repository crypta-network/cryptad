(function () {
  "use strict";

  const bootstrapElement = document.getElementById("web-shell-bootstrap");
  const bootstrap = bootstrapElement
    ? JSON.parse(bootstrapElement.textContent || "{}")
    : {};

  const apiRoot = normalizeLocalRootPath(bootstrap.platformApiRoot, "/api/v1/");
  const shellRoot = normalizeLocalRootPath(bootstrap.shellRoot, "/app/node/");
  const apiRootUrl = new URL(apiRoot, window.location.origin);
  const shellRootUrl = new URL(shellRoot, window.location.origin);
  let formPassword = typeof bootstrap.formPassword === "string" ? bootstrap.formPassword : "";
  const legacyLinks = Array.isArray(bootstrap.legacyLinks) ? bootstrap.legacyLinks : [];
  const shellState = {
    alertsSnapshot: null,
    appCatalogsSnapshot: null,
    appsSnapshot: null,
    configSnapshot: null,
    diagnosticsSnapshot: null,
    securitySnapshot: null,
    updatesSnapshot: null,
    wizardSnapshot: null,
  };
  const directDownloadOperation = "create_direct_download";
  const isolatedLaunchParameter = "cryptadIsolatedLaunch";
  const isolatedOriginProbePath = "/.well-known/cryptad-origin.json";
  const publisherDefaultCompatibilityMode = "COMPAT_CURRENT";
  const queueState = {
    page: "downloads",
    advancedMode: false,
    sortBy: null,
    reversed: false,
    keysVisible: false,
  };
  let peerLoadGeneration = 0;
  let queueLoadGeneration = 0;
  let alertsLoadGeneration = 0;
  let appsLoadGeneration = 0;
  let diagnosticsLoadGeneration = 0;
  let securityLoadGeneration = 0;
  let updatesLoadGeneration = 0;
  let configLoadGeneration = 0;
  let wizardLoadGeneration = 0;
  const nativeQueueSubmitBypass = new WeakSet();

  const sections = {
    overview: document.getElementById("overview-body"),
    connectivity: document.getElementById("connectivity-body"),
    alerts: document.getElementById("alerts-body"),
    alertsStatus: document.getElementById("alerts-status"),
    alertsReadonlyHint: document.getElementById("alerts-readonly-hint"),
    apps: document.getElementById("apps-body"),
    appsStatus: document.getElementById("apps-status"),
    appsReadonlyHint: document.getElementById("apps-readonly-hint"),
    publisher: document.getElementById("publisher-body"),
    publisherStatus: document.getElementById("publisher-status"),
    publisherReadonlyHint: document.getElementById("publisher-readonly-hint"),
    diagnostics: document.getElementById("diagnostics-body"),
    diagnosticsStatus: document.getElementById("diagnostics-status"),
    security: document.getElementById("security-body"),
    securityStatus: document.getElementById("security-status"),
    securityReadonlyHint: document.getElementById("security-readonly-hint"),
    updates: document.getElementById("updates-body"),
    updatesStatus: document.getElementById("updates-status"),
    updatesReadonlyHint: document.getElementById("updates-readonly-hint"),
    config: document.getElementById("config-body"),
    configStatus: document.getElementById("config-status"),
    configReadonlyHint: document.getElementById("config-readonly-hint"),
    wizard: document.getElementById("wizard-body"),
    wizardStatus: document.getElementById("wizard-status"),
    wizardReadonlyHint: document.getElementById("wizard-readonly-hint"),
    peers: document.getElementById("peers-body"),
    peersStatus: document.getElementById("peers-status"),
    peersReadonlyHint: document.getElementById("peers-readonly-hint"),
    queue: document.getElementById("queue-body"),
    queueCount: document.getElementById("queue-count"),
    queueStatus: document.getElementById("queue-status"),
    queueKeys: document.getElementById("queue-key-export"),
    legacy: document.getElementById("legacy-links"),
  };
  const peerControls = {
    refreshButton: document.getElementById("peers-refresh-button"),
    createForm: document.getElementById("peer-create-form"),
    createReference: document.getElementById("peer-reference-text"),
    createSubmit: document.getElementById("peer-create-submit"),
  };
  const alertsControls = {
    refreshButton: document.getElementById("alerts-refresh-button"),
  };
  const appsControls = {
    refreshButton: document.getElementById("apps-refresh-button"),
    catalogSourceForm: document.getElementById("catalog-source-form"),
    catalogSourceInput: document.getElementById("catalog-source-input"),
  };
  const publisherControls = {
    fileForm: document.getElementById("publisher-file-form"),
    directoryForm: document.getElementById("publisher-directory-form"),
    queueLink: document.querySelector('#publisher .queue-toolbar a[href="#queue"]'),
  };
  const diagnosticsControls = {
    refreshButton: document.getElementById("diagnostics-refresh-button"),
  };
  const securityControls = {
    form: document.getElementById("security-form"),
    networkLevel: document.getElementById("security-network-level"),
    physicalLevel: document.getElementById("security-physical-level"),
  };
  const updatesControls = {
    refreshButton: document.getElementById("updates-refresh-button"),
    downloadButton: document.getElementById("updates-download-button"),
  };
  const configControls = {
    form: document.getElementById("config-form"),
    refreshButton: document.getElementById("config-refresh-button"),
    persistButton: document.getElementById("config-persist-button"),
    updaterEnabled: document.getElementById("config-updater-enabled"),
    updaterAutoupdate: document.getElementById("config-updater-autoupdate"),
    inputBandwidthLimit: document.getElementById("config-input-bandwidth-limit"),
    outputBandwidthLimit: document.getElementById("config-output-bandwidth-limit"),
  };
  const wizardControls = {
    form: document.getElementById("wizard-form"),
    refreshButton: document.getElementById("wizard-refresh-button"),
    knowSomeone: document.getElementById("wizard-know-someone"),
    connectToStrangers: document.getElementById("wizard-connect-to-strangers"),
    editBandwidth: document.getElementById("wizard-edit-bandwidth"),
    haveMonthlyLimit: document.getElementById("wizard-have-monthly-limit"),
    setPassword: document.getElementById("wizard-set-password"),
    downloadLimit: document.getElementById("wizard-download-limit"),
    uploadLimit: document.getElementById("wizard-upload-limit"),
    monthlyLimit: document.getElementById("wizard-monthly-limit"),
    storageLimit: document.getElementById("wizard-storage-limit"),
    password: document.getElementById("wizard-password"),
    confirmPassword: document.getElementById("wizard-confirm-password"),
    rateFields: document.getElementById("wizard-rate-fields"),
    monthlyLimitField: document.getElementById("wizard-monthly-limit-field"),
    passwordFields: document.getElementById("wizard-password-fields"),
  };
  const queueControls = {
    downloadsButton: document.getElementById("queue-downloads-button"),
    uploadsButton: document.getElementById("queue-uploads-button"),
    advancedToggle: document.getElementById("queue-advanced-toggle"),
    refreshButton: document.getElementById("queue-refresh-button"),
    keysButton: document.getElementById("queue-keys-button"),
    createForm: document.getElementById("queue-create-form"),
    createSubmit: document.getElementById("queue-download-submit"),
    createUri: document.getElementById("queue-download-uri"),
  };

  function apiUrl(path) {
    return new URL(path, apiRootUrl).toString();
  }

  function apiUrlWithQuery(path, query) {
    const url = new URL(path, apiRootUrl);
    for (const [key, value] of Object.entries(query || {})) {
      if (value == null || value === "") {
        continue;
      }
      url.searchParams.set(key, value);
    }
    return url.toString();
  }

  function normalizeLocalRootPath(value, fallback) {
    if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) {
      return fallback;
    }
    try {
      const url = new URL(value, window.location.origin);
      if (url.origin !== window.location.origin || url.search !== "" || url.hash !== "") {
        return fallback;
      }
      return url.pathname.endsWith("/") ? url.pathname : `${url.pathname}/`;
    } catch (error) {
      return fallback;
    }
  }

  function clear(node) {
    node.replaceChildren();
  }

  function text(tagName, className, value) {
    const node = document.createElement(tagName);
    if (className) {
      node.className = className;
    }
    node.textContent = value;
    return node;
  }

  function createPill(value, tone) {
    return text("span", "status-pill" + (tone ? " " + tone : ""), value);
  }

  function setStatus(message, tone) {
    setSectionStatus(sections.queueStatus, message, tone);
  }

  function setPeerStatus(message, tone) {
    setSectionStatus(sections.peersStatus, message, tone);
  }

  function setAlertsStatus(message, tone) {
    setSectionStatus(sections.alertsStatus, message, tone);
  }

  function setAppsStatus(message, tone) {
    setSectionStatus(sections.appsStatus, message, tone);
  }

  function setPublisherStatus(message, tone) {
    setSectionStatus(sections.publisherStatus, message, tone);
  }

  function setDiagnosticsStatus(message, tone) {
    setSectionStatus(sections.diagnosticsStatus, message, tone);
  }

  function setSectionStatus(container, message, tone) {
    clear(container);
    if (!message) {
      return;
    }
    container.append(text("p", tone ? `status-message ${tone}` : "status-message", message));
  }

  function setSecurityStatus(message, tone) {
    setSectionStatus(sections.securityStatus, message, tone);
  }

  function setUpdatesStatus(message, tone) {
    setSectionStatus(sections.updatesStatus, message, tone);
  }

  function setConfigStatus(message, tone) {
    setSectionStatus(sections.configStatus, message, tone);
  }

  function setWizardStatus(message, tone) {
    setSectionStatus(sections.wizardStatus, message, tone);
  }

  function definitionList(entries) {
    const list = document.createElement("div");
    list.className = "kv-list";
    for (const [label, value] of entries) {
      const row = document.createElement("div");
      row.className = "kv-row";

      const labelNode = text("div", "kv-label", label);
      const valueNode = document.createElement("div");
      valueNode.className = "kv-value";
      if (value instanceof Node) {
        valueNode.append(value);
      } else {
        valueNode.textContent = scalar(value);
      }

      row.append(labelNode, valueNode);
      list.append(row);
    }
    return list;
  }

  function scalar(value) {
    if (value == null) {
      return "Unavailable";
    }
    if (typeof value === "string") {
      return value;
    }
    if (typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
    if (Array.isArray(value)) {
      return `${value.length} item${value.length === 1 ? "" : "s"}`;
    }
    const entries = Object.entries(value);
    if (entries.length === 0) {
      return "Empty object";
    }
    return entries
      .slice(0, 4)
      .map(([key, entryValue]) => `${key}: ${scalar(entryValue)}`)
      .join(" • ");
  }

  function htmlToText(html) {
    if (typeof html !== "string" || !html) {
      return "";
    }
    const container = document.createElement("div");
    container.innerHTML = html;
    return (container.textContent || "").replace(/\s+/g, " ").trim();
  }

  function formatJson(value) {
    try {
      return JSON.stringify(value, null, 2);
    } catch (error) {
      return String(error);
    }
  }

  function summaryCard(title, values, tone) {
    const card = document.createElement("div");
    card.append(createPill(title, tone), definitionList(values));
    return card;
  }

  function topLevelFieldEntries(data, excludedKeys) {
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return [];
    }
    const excluded = new Set(Array.isArray(excludedKeys) ? excludedKeys : []);
    return Object.entries(data)
      .filter(([key]) => !excluded.has(key))
      .map(([key, value]) => [key, scalar(value)]);
  }

  function formatTimestampMillis(value) {
    if (typeof value === "number" && Number.isFinite(value)) {
      const date = new Date(value);
      if (!Number.isNaN(date.getTime())) {
        return date.toLocaleString();
      }
    }
    return scalar(value);
  }

  function formatPermissions(value) {
    if (!Array.isArray(value) || value.length === 0) {
      return "None";
    }
    return value
      .map((permission) => (typeof permission === "string" && permission ? permission : scalar(permission)))
      .join(", ");
  }

  function formatIsoTimestamp(value) {
    if (typeof value !== "string" || value.length === 0) {
      return "Unavailable";
    }
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) {
      return value;
    }
    return date.toLocaleString();
  }

  function severityTone(severity) {
    const normalized = typeof severity === "string" ? severity.toLowerCase() : "";
    if (normalized.includes("critical") || normalized.includes("error") || normalized.includes("high")) {
      return "is-error";
    }
    if (normalized.includes("warn") || normalized.includes("medium") || normalized.includes("moderate")) {
      return "is-warning";
    }
    return "";
  }

  function renderLegacyLinks() {
    clear(sections.legacy);
    for (const link of legacyLinks) {
      const path = normalizeLegacyLinkPath(link.path);
      if (!path) {
        continue;
      }
      const item = document.createElement("li");
      const anchor = document.createElement("a");
      anchor.pathname = path;
      anchor.search = "";
      anchor.hash = "";
      anchor.textContent = link.label;
      item.append(anchor);
      sections.legacy.append(item);
    }
  }

  function normalizeAppUiEntryHref(value, app) {
    if (typeof value !== "string" || value.length === 0) {
      return null;
    }
    try {
      const url = new URL(value, shellRootUrl);
      if (url.origin !== window.location.origin && !allowedAppUiOrigin(url, app)) {
        return null;
      }
      return url.origin === window.location.origin
        ? `${url.pathname}${url.search}${url.hash}`
        : url.href;
    } catch (error) {
      return null;
    }
  }

  function allowedAppUiOrigin(url, app) {
    if (!app || app.uiOriginMode !== "isolated-loopback" || app.uiOriginStatus !== "active") {
      return false;
    }
    if (typeof app.uiOrigin !== "string" || app.uiOrigin.length === 0) {
      return false;
    }
    const hostname = url.hostname.toLowerCase();
    return (
      url.origin === app.uiOrigin &&
      url.protocol === "http:" &&
      hostname === "127.0.0.1"
    );
  }

  function normalizeLegacyLinkPath(value) {
    if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) {
      return null;
    }
    try {
      const url = new URL(value, window.location.origin);
      if (
        url.origin !== window.location.origin ||
        url.search !== "" ||
        url.hash !== "" ||
        url.pathname !== value
      ) {
        return null;
      }
      return url.pathname;
    } catch (error) {
      return null;
    }
  }

  function renderOverview(data) {
    clear(sections.overview);
    sections.overview.append(
      summaryCard("Ready", [
        ["Node name", data.nodeName || "Unknown"],
        ["Version", data.versionString || "Unknown"],
        ["Build", scalar(data.buildNumber)],
        ["Revision", data.revision || "Unknown"],
        ["Testnet", scalar(data.testnetEnabled)],
        ["Compression", data.compressionCodecs || "Unknown"],
        ["Language", data.nodeLanguage || "Unknown"],
      ]),
    );
  }

  function renderConnectivity(data) {
    const sockets = Array.isArray(data.sockets) ? data.sockets : [];
    clear(sections.connectivity);
    sections.connectivity.append(
      summaryCard("Ports", [
        ["Darknet FNP", scalar(data.darknetFnpPort)],
        ["Opennet FNP", scalar(data.opennetFnpPort)],
        ["FProxy", scalar(data.fproxyListener && data.fproxyListener.port)],
        ["FCP", scalar(data.fcpListener && data.fcpListener.port)],
        ["Console", scalar(data.consoleListener && data.consoleListener.port)],
        ["Sockets", `${sockets.length}`],
      ]),
    );

    if (data.connectionTypeNotice && data.connectionTypeNotice.title) {
      sections.connectivity.append(
        summaryCard("Notice", [
          ["Title", data.connectionTypeNotice.title],
          ["Text", data.connectionTypeNotice.text || "No notice text"],
        ], "is-warning"),
      );
    }
  }

  function alertDismissPath(alertId) {
    return `alerts/${encodeURIComponent(alertId)}/dismiss`;
  }

  function renderAlertCard(alert, index) {
    const card = document.createElement("section");
    card.className = "alert-card";
    const title = typeof alert.title === "string" && alert.title ? alert.title : `Alert ${index + 1}`;
    const shortText =
      typeof alert.shortText === "string" && alert.shortText
        ? alert.shortText
        : "No short text provided.";
    const textBody = typeof alert.text === "string" && alert.text ? alert.text : "";

    const header = document.createElement("div");
    header.className = "alert-card-header";

    const heading = document.createElement("div");
    heading.className = "alert-card-heading";
    heading.append(text("h3", "alert-card-title", title), text("p", "alert-card-subtitle", shortText));

    const pills = document.createElement("div");
    pills.className = "alert-card-pills";
    if (alert.severity) {
      pills.append(createPill(String(alert.severity), severityTone(alert.severity)));
    }
    if (alert.eventNotification) {
      pills.append(createPill("Event notification", "is-warning"));
    }
    if (alert.dismissible === false) {
      pills.append(createPill("Not dismissible", "is-warning"));
    }

    header.append(heading, pills);
    card.append(header);

    if (textBody) {
      card.append(text("p", "alert-card-text", textBody));
    }

    card.append(
      definitionList([
        ["ID", scalar(alert.id)],
        ["Updated", formatTimestampMillis(alert.updatedTimeMillis)],
      ]),
    );

    const extraFields = topLevelFieldEntries(alert, [
      "id",
      "title",
      "shortText",
      "text",
      "severity",
      "dismissible",
      "dismissLabel",
      "eventNotification",
      "updatedTimeMillis",
    ]);
    if (extraFields.length) {
      card.append(definitionList(extraFields));
    }

    if (alert.dismissible !== false && formPassword) {
      const form = document.createElement("form");
      form.className = "alert-dismiss-form";
      form.dataset.alertId = alert.id == null ? "" : String(alert.id);

      const submit = document.createElement("button");
      submit.className = "button button-secondary";
      submit.type = "submit";
      submit.textContent =
        typeof alert.dismissLabel === "string" && alert.dismissLabel
          ? alert.dismissLabel
          : "Dismiss alert";
      form.append(submit);
      card.append(form);
    }

    return card;
  }

  function renderAlerts(data) {
    shellState.alertsSnapshot = data;
    updateAlertsToolbar();
    clear(sections.alerts);

    const alerts = Array.isArray(data.alerts) ? data.alerts : [];
    const summaryEntries = [["Alerts", `${alerts.length}`], ...topLevelFieldEntries(data, ["alerts"])];
    sections.alerts.append(summaryCard("Alerts summary", summaryEntries, alerts.length ? "" : "is-warning"));

    if (!alerts.length) {
      sections.alerts.append(text("p", "empty-state", "No alerts were returned."));
      return;
    }

    const list = document.createElement("div");
    list.className = "alert-card-list";
    alerts.forEach((alert, index) => {
      list.append(renderAlertCard(alert && typeof alert === "object" ? alert : {}, index));
    });
    sections.alerts.append(list);
  }

  function renderDiagnosticsSection(section, index) {
    const card = document.createElement("section");
    card.className = "diagnostics-section";
    const title =
      typeof section.title === "string" && section.title ? section.title : `Section ${index + 1}`;

    card.append(text("h3", "diagnostics-section-title", title));

    const lines = Array.isArray(section.lines) ? section.lines : [];
    if (!lines.length) {
      card.append(text("p", "empty-state", "No diagnostic lines were exported."));
    } else {
      const pre = document.createElement("pre");
      pre.className = "diagnostics-lines";
      pre.textContent = lines
        .map((line) => (typeof line === "string" ? line : formatJson(line)))
        .join("\n");
      card.append(pre);
    }

    const extraFields = topLevelFieldEntries(section, ["title", "lines"]);
    if (extraFields.length) {
      card.append(definitionList(extraFields));
    }

    return card;
  }

  function renderDiagnostics(data) {
    shellState.diagnosticsSnapshot = data;
    updateDiagnosticsToolbar();
    clear(sections.diagnostics);

    const sectionsList = Array.isArray(data.sections) ? data.sections : [];
    const summaryEntries = [
      ["Sections", `${sectionsList.length}`],
      ...topLevelFieldEntries(data, ["sections", "plainTextExport", "export", "textExport"]),
    ];
    sections.diagnostics.append(
      summaryCard("Diagnostics summary", summaryEntries, sectionsList.length ? "" : "is-warning"),
    );

    const exportText =
      typeof data.plainTextExport === "string"
        ? data.plainTextExport
        : typeof data.export === "string"
          ? data.export
          : typeof data.textExport === "string"
            ? data.textExport
            : null;
    if (exportText) {
      const exportDetails = document.createElement("details");
      exportDetails.className = "json-details";
      const summary = document.createElement("summary");
      summary.textContent = "Plain-text export";
      const pre = document.createElement("pre");
      pre.className = "json-code diagnostics-export";
      pre.textContent = exportText;
      exportDetails.append(summary, pre);
      sections.diagnostics.append(exportDetails);
    }

    if (!sectionsList.length) {
      sections.diagnostics.append(text("p", "empty-state", "No diagnostic sections were returned."));
      return;
    }

    const list = document.createElement("div");
    list.className = "diagnostics-section-list";
    sectionsList.forEach((section, index) => {
      list.append(renderDiagnosticsSection(section && typeof section === "object" ? section : {}, index));
    });
    sections.diagnostics.append(list);
  }

  function renderSecurity(data) {
    shellState.securitySnapshot = data;
    updateSecurityToolbar();
    clear(sections.security);
    sections.security.append(
      summaryCard("Threat levels", [
        ["Network", data.networkThreatLevel || "Unknown"],
        ["Physical", data.physicalThreatLevel || "Unknown"],
        ["Database", data.hasDatabase ? "Active" : "Inactive"],
        ["Master password file", data.masterPasswordFileExists ? "Present" : "Missing"],
        ["Password file path", data.masterPasswordFilePath || "Unavailable"],
      ]),
    );
    if (securityControls.networkLevel) {
      securityControls.networkLevel.value = data.networkThreatLevel || "NORMAL";
    }
    if (securityControls.physicalLevel) {
      securityControls.physicalLevel.value = data.physicalThreatLevel || "NORMAL";
    }
  }

  function renderUpdates(data) {
    shellState.updatesSnapshot = data;
    updateUpdatesToolbar();
    clear(sections.updates);
    sections.updates.append(
      summaryCard("Core updater", [
        ["Available", data.available ? "Yes" : "No"],
        ["Download action", data.downloadAllowed ? "Ready" : "Unavailable"],
      ], data.available ? "" : "is-warning"),
    );
  }

  function publisherSourceType(form) {
    return form instanceof HTMLFormElement && form.dataset.publisherSourceType === "directory"
      ? "directory"
      : "file";
  }

  function publisherLabel(sourceType) {
    return sourceType === "directory" ? "directory" : "file";
  }

  function publisherMutationPath(sourceType) {
    return sourceType === "directory" ? "queue/inserts/directory" : "queue/inserts/file";
  }

  function generatePublisherIdentifier(sourceType) {
    const timestamp = new Date().toISOString().replace(/[-:.TZ]/g, "").slice(0, 14);
    const randomToken = Math.random().toString(36).slice(2, 8);
    return `publisher-${publisherLabel(sourceType)}-${timestamp}-${randomToken}`;
  }

  function trimPublisherValue(form, fieldName) {
    const field = form.querySelector(`[name="${fieldName}"]`);
    return field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement
      ? field.value.trim()
      : "";
  }

  function initializePublisherForm(form) {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    const identifierField = form.querySelector('input[name="identifier"]');
    if (identifierField instanceof HTMLInputElement && identifierField.value.trim() === "") {
      identifierField.value = generatePublisherIdentifier(publisherSourceType(form));
    }
    const compatibilityField = form.querySelector('input[name="compatibilityMode"]');
    if (
      compatibilityField instanceof HTMLInputElement &&
      compatibilityField.value.trim() === ""
    ) {
      compatibilityField.value = publisherDefaultCompatibilityMode;
    }
  }

  function resetPublisherForm(form) {
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    form.reset();
    initializePublisherForm(form);
  }

  function buildPublisherFormData(form) {
    const sourceType = publisherSourceType(form);
    const formData = new FormData();
    const sourcePath = trimPublisherValue(form, "sourcePath");
    const insertUri = trimPublisherValue(form, "insertUri");
    let identifier = trimPublisherValue(form, "identifier");
    if (!identifier) {
      identifier = generatePublisherIdentifier(sourceType);
      const identifierField = form.querySelector('input[name="identifier"]');
      if (identifierField instanceof HTMLInputElement) {
        identifierField.value = identifier;
      }
    }
    const compatibilityMode =
      trimPublisherValue(form, "compatibilityMode") || publisherDefaultCompatibilityMode;

    formData.set("sourcePath", sourcePath);
    formData.set("insertUri", insertUri);
    formData.set("identifier", identifier);
    formData.set("compatibilityMode", compatibilityMode);

    const compressField = form.querySelector('input[name="compress"]');
    if (compressField instanceof HTMLInputElement && compressField.checked) {
      formData.set("compress", "on");
    }

    const contentType = trimPublisherValue(form, "contentType");
    if (contentType) {
      formData.set("contentType", contentType);
    }

    const targetFilename = trimPublisherValue(form, "targetFilename");
    if (targetFilename) {
      formData.set("targetFilename", targetFilename);
    }

    return formData;
  }

  function renderPublisherResult(data, sourceType) {
    clear(sections.publisher);

    const resolvedSourceType =
      typeof data.sourceType === "string" && data.sourceType ? data.sourceType : publisherLabel(sourceType);
    const insertAccepted = publisherInsertAccepted(data);
    const summaryEntries = [
      ["Operation", data.operation || `create_local_${resolvedSourceType}_insert`],
      ["Source type", resolvedSourceType],
      ["Source path", data.sourcePath || "Unavailable"],
      ["Insert URI", data.insertUri || "Unavailable"],
      ["Identifier", data.identifier || "Unavailable"],
      ["Outcome", data.outcome || "Unknown"],
    ];
    sections.publisher.append(
      summaryCard("Publisher result", summaryEntries, insertAccepted ? "is-success" : "is-warning"),
    );

    if (insertAccepted) {
      const actions = document.createElement("div");
      actions.className = "publisher-result-actions";
      const queueLink = document.createElement("a");
      queueLink.className = "button button-secondary";
      queueLink.href = "#queue";
      queueLink.textContent = "Open upload queue";
      queueLink.addEventListener("click", () => {
        showUploadQueueFromPublisher().catch((error) => {
          setStatus(error instanceof Error ? error.message : String(error), "is-error");
        });
      });
      actions.append(queueLink);
      sections.publisher.append(actions);
    }

    const extraFields = topLevelFieldEntries(data, [
      "operation",
      "sourceType",
      "sourcePath",
      "insertUri",
      "identifier",
      "outcome",
    ]);
    if (extraFields.length) {
      sections.publisher.append(definitionList(extraFields));
    }
  }

  function publisherInsertAccepted(data) {
    switch (publisherInsertOutcome(data)) {
      case "STARTED":
      case "IDENTIFIER_COLLISION":
      case "METADATA_UNRESOLVED":
        return true;
      default:
        return false;
    }
  }

  function publisherInsertOutcome(data) {
    return typeof data?.outcome === "string" && data.outcome ? data.outcome : "Unknown";
  }

  async function showUploadQueueFromPublisher() {
    queueState.page = "uploads";
    queueState.sortBy = null;
    queueState.reversed = false;
    queueState.keysVisible = false;
    setStatus("Refreshing upload queue.");
    await loadQueueSection();
  }

  async function submitPublisherForm(event) {
    event.preventDefault();
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (typeof form.reportValidity === "function" && !form.reportValidity()) {
      return;
    }

    const sourceType = publisherSourceType(form);
    const formData = buildPublisherFormData(form);

    try {
      const data = await postForm(
        publisherMutationPath(sourceType),
        formData,
        "Publisher actions unavailable in read-only mode.",
      );
      renderPublisherResult(data, sourceType);
      if (publisherInsertAccepted(data)) {
        resetPublisherForm(form);
        setPublisherStatus(
          `Local ${publisherLabel(sourceType)} insert handled: ${publisherInsertOutcome(data)}.`,
          "is-success",
        );
        await showUploadQueueFromPublisher();
      } else {
        setPublisherStatus(
          `Local ${publisherLabel(sourceType)} insert did not start: ${publisherInsertOutcome(data)}.`,
          "is-error",
        );
      }
    } catch (error) {
      setPublisherStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  function appDisplayName(app) {
    return typeof app.name === "string" && app.name ? app.name : typeof app.appId === "string" ? app.appId : "App";
  }

  function appMutationPath(appId, action) {
    if (typeof appId !== "string" || appId.length === 0) {
      return null;
    }
    const encodedAppId = encodeURIComponent(appId);
    switch (action) {
      case "start":
      case "stop":
        return `apps/${encodedAppId}/${action}`;
      case "uninstall":
        return `apps/${encodedAppId}`;
      default:
        return null;
    }
  }

  function appRuntimePath(appId) {
    return typeof appId === "string" && appId.length > 0
      ? `apps/${encodeURIComponent(appId)}/runtime`
      : null;
  }

  function appLogsPath(appId, maxBytes) {
    return typeof appId === "string" && appId.length > 0
      ? `apps/${encodeURIComponent(appId)}/logs?maxBytes=${encodeURIComponent(String(maxBytes))}`
      : null;
  }

  function appAuditPath(appId) {
    return typeof appId === "string" && appId.length > 0
      ? `apps/${encodeURIComponent(appId)}/audit`
      : null;
  }

  function catalogMutationPath(catalogId, appId, action) {
    if (typeof catalogId !== "string" || catalogId.length === 0) {
      return null;
    }
    const encodedCatalogId = encodeURIComponent(catalogId);
    if (action === "refresh") {
      return `app-catalogs/${encodedCatalogId}/refresh`;
    }
    if (action === "remove") {
      return `app-catalogs/${encodedCatalogId}`;
    }
    if (typeof appId !== "string" || appId.length === 0) {
      return null;
    }
    const encodedAppId = encodeURIComponent(appId);
    if (action === "install" || action === "update") {
      return `app-catalogs/${encodedCatalogId}/apps/${encodedAppId}/${action}`;
    }
    return null;
  }

  function appUiHref(app) {
    const isolatedFallbackHref = isolatedAppUiFallbackHref(app);
    if (isolatedFallbackHref || isolatedAppUiActive(app)) {
      return isolatedFallbackHref;
    }
    const explicitHref = normalizeAppUiEntryHref(app.uiUrl, app);
    if (explicitHref) {
      return explicitHref;
    }
    if (typeof app.uiUrl === "string" && app.uiUrl.length > 0) {
      return null;
    }
    if (app.uiMode === "static" && typeof app.appId === "string" && app.appId.length > 0) {
      return normalizeAppUiEntryHref(`/apps/${encodeURIComponent(app.appId)}/`, app);
    }
    return normalizeAppUiEntryHref(app.uiEntry, app);
  }

  function isolatedAppUiLaunchHref(app) {
    const fallbackHref = isolatedAppUiFallbackHref(app);
    if (!fallbackHref) {
      return null;
    }
    const url = new URL(fallbackHref, window.location.origin);
    url.searchParams.set(isolatedLaunchParameter, "1");
    return `${url.pathname}${url.search}${url.hash}`;
  }

  function isolatedAppUiFallbackHref(app) {
    if (!isolatedAppUiActive(app)) {
      return null;
    }
    return normalizeAppUiEntryHref(app.sameOriginFallbackUrl, app);
  }

  function isolatedAppUiProbeHref(app) {
    if (!isolatedAppUiActive(app) || typeof app.uiOrigin !== "string" || app.uiOrigin.length === 0) {
      return null;
    }
    try {
      const url = new URL(isolatedOriginProbePath, app.uiOrigin);
      if (!allowedAppUiOrigin(url, app)) {
        return null;
      }
      return url.href;
    } catch (error) {
      return null;
    }
  }

  function isolatedAppUiActive(app) {
    return app && app.uiOriginMode === "isolated-loopback" && app.uiOriginStatus === "active";
  }

  function appUiEntryNode(app) {
    const href = appUiHref(app);
    if (!href) {
      return null;
    }
    const container = document.createElement("span");
    container.className = "app-ui-entry";
    const link = document.createElement("a");
    link.className = "button button-secondary";
    link.href = href;
    link.textContent = "Open";
    const isolatedLaunchHref = isolatedAppUiLaunchHref(app);
    const isolatedProbeHref = isolatedAppUiProbeHref(app);
    if (
      isolatedLaunchHref &&
      isolatedProbeHref &&
      typeof app.appId === "string" &&
      app.appId.length > 0
    ) {
      link.dataset.isolatedLaunchHref = isolatedLaunchHref;
      link.dataset.isolatedProbeHref = isolatedProbeHref;
      link.dataset.isolatedAppId = app.appId;
    }
    container.append(link);
    return container;
  }

  function appUiLaunchClickTarget(event) {
    if (
      !(event instanceof MouseEvent) ||
      event.button !== 0 ||
      event.altKey ||
      event.ctrlKey ||
      event.metaKey ||
      event.shiftKey
    ) {
      return null;
    }
    const anchor = event.target instanceof Element
      ? event.target.closest("a[data-isolated-launch-href]")
      : null;
    return anchor instanceof HTMLAnchorElement ? anchor : null;
  }

  async function launchAppUiFromLink(link) {
    const fallbackHref = link.getAttribute("href") || "";
    const isolatedLaunchHref = link.dataset.isolatedLaunchHref || "";
    const probeHref = link.dataset.isolatedProbeHref || "";
    const expectedAppId = link.dataset.isolatedAppId || "";
    if (
      isolatedLaunchHref &&
      await isolatedAppOriginReachable(probeHref, expectedAppId)
    ) {
      window.location.assign(isolatedLaunchHref);
      return;
    }
    window.location.assign(fallbackHref);
  }

  async function isolatedAppOriginReachable(probeHref, expectedAppId) {
    if (!probeHref || !expectedAppId) {
      return false;
    }
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    const timeoutId = controller
      ? window.setTimeout(() => controller.abort(), 1000)
      : null;
    try {
      const probeOrigin = new URL(probeHref).origin;
      const response = await fetch(probeHref, {
        headers: { Accept: "application/json" },
        cache: "no-store",
        credentials: "omit",
        mode: "cors",
        signal: controller ? controller.signal : undefined,
      });
      const data = await response.json().catch(() => ({}));
      return (
        response.ok &&
        data &&
        data.appId === expectedAppId &&
        data.uiOrigin === probeOrigin &&
        data.uiOriginStatus === "active"
      );
    } catch (error) {
      return false;
    } finally {
      if (timeoutId != null) {
        window.clearTimeout(timeoutId);
      }
    }
  }

  function appSandboxStatus(app, runtime) {
    if (runtime && runtime.sandbox && typeof runtime.sandbox === "object") {
      return runtime.sandbox;
    }
    if (app && app.sandbox && typeof app.sandbox === "object") {
      return app.sandbox;
    }
    return null;
  }

  function sandboxLabel(status) {
    if (!status || typeof status !== "object") {
      return "Sandbox unavailable";
    }
    const mode = typeof status.mode === "string" ? status.mode : "";
    const supportLevel = typeof status.supportLevel === "string" ? status.supportLevel : "";
    if (supportLevel === "enforced") {
      return status.active === false ? inactiveEnforcedSandboxLabel(status) : "Enforced sandbox";
    }
    if (supportLevel === "best-effort") {
      return "Best-effort restricted process";
    }
    if (supportLevel === "unsupported") {
      return status.required ? "Unsupported required sandbox" : "Unsupported sandbox";
    }
    if (mode === "none" || supportLevel === "none") {
      return "No sandbox";
    }
    return scalar(mode || supportLevel || "unknown");
  }

  function inactiveEnforcedSandboxLabel(status) {
    const reason = typeof status.reason === "string" ? status.reason : "";
    const warnings = Array.isArray(status.warnings) ? status.warnings.join(" ") : "";
    const statusText = `${reason} ${warnings}`.toLowerCase();
    return statusText.includes("last launch")
      ? "Last launch enforced sandbox"
      : "Enforced sandbox available";
  }

  function sandboxTone(status) {
    if (!status || typeof status !== "object") {
      return "is-warning";
    }
    const supportLevel = typeof status.supportLevel === "string" ? status.supportLevel : "";
    if (supportLevel === "enforced") {
      return status.active === false ? "is-warning" : "is-success";
    }
    if (supportLevel === "unsupported" && status.required) {
      return "is-error";
    }
    return "is-warning";
  }

  function sandboxWarnings(status) {
    if (!status || !Array.isArray(status.warnings) || status.warnings.length === 0) {
      return "Unavailable";
    }
    return status.warnings.map((warning) => scalar(warning)).join("; ");
  }

  function appQuotaStatus(app, runtime) {
    if (runtime && runtime.quota && typeof runtime.quota === "object") {
      return runtime.quota;
    }
    if (app && app.quota && typeof app.quota === "object") {
      return app.quota;
    }
    return null;
  }

  function formatBytes(value) {
    if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
      return "Unavailable";
    }
    const units = ["bytes", "KiB", "MiB", "GiB", "TiB"];
    let scaled = value;
    let unitIndex = 0;
    while (scaled >= 1024 && unitIndex < units.length - 1) {
      scaled /= 1024;
      unitIndex += 1;
    }
    if (unitIndex === 0) {
      return `${value} bytes`;
    }
    return `${scaled.toFixed(scaled >= 10 ? 1 : 2)} ${units[unitIndex]}`;
  }

  function formatQuotaLimit(quota, effectiveKey, enforcedKey) {
    if (!quota || typeof quota !== "object") {
      return "Unavailable";
    }
    if (!quota[enforcedKey]) {
      return "Unlimited";
    }
    return formatBytes(quota[effectiveKey]);
  }

  function formatQuotaUsage(quota, usageKey, effectiveKey, enforcedKey) {
    if (!quota || typeof quota !== "object") {
      return "Unavailable";
    }
    const usage = formatBytes(quota[usageKey]);
    if (usage === "Unavailable") {
      return usage;
    }
    if (!quota[enforcedKey]) {
      return `${usage} of unlimited`;
    }
    return `${usage} of ${formatBytes(quota[effectiveKey])}`;
  }

  function quotaWarnings(quota, runtime) {
    const warnings = [];
    if (quota && Array.isArray(quota.warnings)) {
      quota.warnings.forEach((warning) => warnings.push(scalar(warning)));
    }
    if (runtime && Array.isArray(runtime.warnings)) {
      runtime.warnings.forEach((warning) => warnings.push(scalar(warning)));
    }
    const safeWarnings = warnings.filter((warning) => warning && warning !== "Unavailable");
    return safeWarnings.length ? safeWarnings.join("; ") : "Unavailable";
  }

  function buildAppActionForm(app, action, label) {
    const appId = typeof app.appId === "string" ? app.appId : "";
    const path = appMutationPath(appId, action);
    if (!path) {
      return null;
    }

    const form = document.createElement("form");
    form.className = "app-action-form";
    form.dataset.appId = appId;
    form.dataset.appAction = action;
    form.dataset.appName = appDisplayName(app);

    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = label;
    form.append(submit);
    return form;
  }

  function buildCatalogActionForm(catalog, app, action, label) {
    const catalogId = typeof catalog.catalogId === "string" ? catalog.catalogId : "";
    const appId = app && typeof app.appId === "string" ? app.appId : "";
    const path = catalogMutationPath(catalogId, appId, action);
    if (!path) {
      return null;
    }

    const form = document.createElement("form");
    form.className = "app-action-form";
    form.dataset.catalogId = catalogId;
    form.dataset.catalogAppId = appId;
    form.dataset.catalogAction = action;
    form.dataset.catalogAppName = app ? appDisplayName(app) : catalogId;

    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = label;
    form.append(submit);
    return form;
  }

  function stringList(value) {
    if (!Array.isArray(value)) {
      return [];
    }
    return value.filter((entry) => typeof entry === "string" && entry.length > 0);
  }

  function recordValue(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  }

  function normalizedStatus(value, fallback) {
    const raw = typeof value === "string" && value.length > 0 ? value : fallback;
    if (typeof raw !== "string" || raw.length === 0) {
      return "Unavailable";
    }
    return raw
      .replace(/[_-]+/g, " ")
      .toLowerCase()
      .replace(/\b\w/g, (letter) => letter.toUpperCase());
  }

  function safeMetadataUri(value) {
    if (typeof value !== "string" || value.length === 0) {
      return null;
    }
    try {
      const url = new URL(value);
      return url.protocol === "https:" || url.protocol === "http:" ? url.toString() : null;
    } catch (error) {
      return null;
    }
  }

  function metadataLinkNode(value, label) {
    const href = safeMetadataUri(value);
    if (!href) {
      return scalar(value);
    }
    const link = document.createElement("a");
    link.className = "metadata-link";
    link.href = href;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = typeof label === "string" && label ? label : value;
    return link;
  }

  function metadataLinkListNode(values) {
    const links = stringList(values);
    if (!links.length) {
      return "Unavailable";
    }
    const list = document.createElement("ul");
    list.className = "metadata-link-list";
    links.forEach((value, index) => {
      const item = document.createElement("li");
      item.append(metadataLinkNode(value, `Screenshot ${index + 1}`));
      list.append(item);
    });
    return list;
  }

  function chipListNode(values) {
    const entries = stringList(values);
    if (!entries.length) {
      return "Unavailable";
    }
    const list = document.createElement("span");
    list.className = "metadata-chip-list";
    entries.forEach((entry) => {
      list.append(text("span", "metadata-chip", entry));
    });
    return list;
  }

  function reviewTone(status) {
    const normalized = typeof status === "string" ? status.toLowerCase().replace(/[-\s]+/g, "_") : "";
    if (normalized.includes("reject") || normalized.includes("block") || normalized.includes("unsafe")) {
      return "is-error";
    }
    if (normalized.includes("unreview") || normalized.includes("not_review") || normalized.includes("pending")) {
      return "is-warning";
    }
    if (normalized.includes("review") || normalized.includes("approve") || normalized.includes("verified")) {
      return "is-success";
    }
    return "is-warning";
  }

  function compatibilityTone(compatibility) {
    if (!compatibility || Object.keys(compatibility).length === 0) {
      return "is-warning";
    }
    const status = typeof compatibility.status === "string" ? compatibility.status.toLowerCase() : "";
    if (status === "not_declared") {
      return "is-warning";
    }
    if (compatibility.satisfied === false) {
      return "is-error";
    }
    if (compatibility.satisfied === true) {
      return "is-success";
    }
    return status.includes("unsatisfied") || status.includes("unsupported") ? "is-error" : "is-warning";
  }

  function compatibilityLabel(compatibility) {
    if (!compatibility || Object.keys(compatibility).length === 0) {
      return "Compatibility unknown";
    }
    const status = typeof compatibility.status === "string" ? compatibility.status.toLowerCase() : "";
    if (status === "not_declared") {
      return "Compatibility not declared";
    }
    if (compatibility.satisfied === false) {
      return "Compatibility warning";
    }
    if (compatibility.satisfied === true) {
      return "Compatible";
    }
    return normalizedStatus(compatibility.status, "Compatibility advisory");
  }

  function versionTone(app) {
    if (app.updateAvailable || app.versionDifferent) {
      return "is-warning";
    }
    return app.installed ? "is-success" : "";
  }

  function versionLabel(app) {
    if (app.updateAvailable) {
      return "Update available";
    }
    if (app.versionDifferent) {
      return "Version differs";
    }
    if (app.installed) {
      return "Installed version";
    }
    return "Available";
  }

  function versionSummary(app) {
    const catalogVersion = typeof app.version === "string" && app.version ? app.version : "Unavailable";
    const installedVersion =
      typeof app.installedVersion === "string" && app.installedVersion ? app.installedVersion : "Unavailable";
    if (!app.installed) {
      return `Not installed; catalog version ${catalogVersion}`;
    }
    if (app.updateAvailable) {
      return `Update available: installed ${installedVersion}, catalog ${catalogVersion}`;
    }
    if (app.versionDifferent) {
      return `Installed ${installedVersion} differs from catalog ${catalogVersion}`;
    }
    if (typeof app.versionStatus === "string" && app.versionStatus.length > 0) {
      return normalizedStatus(app.versionStatus);
    }
    return `Installed ${installedVersion}; catalog ${catalogVersion}`;
  }

  function permissionDeltaStatus(permission, delta) {
    if (stringList(delta.added).includes(permission)) {
      return ["Added on install/update", "is-warning"];
    }
    if (stringList(delta.removed).includes(permission)) {
      return ["Removed by catalog version", "is-warning"];
    }
    if (stringList(delta.unchanged).includes(permission)) {
      return ["Already granted", "is-success"];
    }
    return null;
  }

  function permissionRationale(permission, rationales) {
    const value = rationales[permission];
    return typeof value === "string" && value.length > 0
      ? value
      : "No permission rationale supplied.";
  }

  function renderAppCard(app) {
    const card = document.createElement("article");
    card.className = "app-card";
    const runtime = app && app.runtime && typeof app.runtime === "object" ? app.runtime : null;
    const logs = app && app.logs && typeof app.logs === "object" ? app.logs : null;
    const audit = app && app.audit && typeof app.audit === "object" ? app.audit : null;
    const runtimeError = typeof app.runtimeError === "string" ? app.runtimeError : "";
    const runtimeState =
      runtime && typeof runtime.state === "string" && runtime.state ? runtime.state : app.running ? "RUNNING" : "STOPPED";
    const runtimeRunning = runtime ? !!runtime.running : !!app.running;
    const runtimeStoppable = runtimeRunning || runtimeState === "RESTARTING";
    const runtimePid = runtime ? runtime.pid : app.pid;
    const runtimeStartedAt = runtime ? runtime.startedAt : app.startedAt;
    const sandbox = appSandboxStatus(app, runtime);
    const quota = appQuotaStatus(app, runtime);

    const header = document.createElement("div");
    header.className = "app-card-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h3", "app-card-title", appDisplayName(app)),
      text("p", "app-card-subtitle", typeof app.appId === "string" && app.appId ? app.appId : "Unavailable"),
    );

    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill("Installed"));
    pills.append(createPill(runtimeState, runtimeRunning ? "is-success" : "is-warning"));
    pills.append(createPill(sandboxLabel(sandbox), sandboxTone(sandbox)));
    if (app.uiUrl || app.uiEntry) {
      pills.append(createPill(app.uiMode === "static" ? "Static UI" : "UI"));
    }
    if (app.uiOriginMode === "isolated-loopback" && app.uiOriginStatus === "active") {
      pills.append(createPill("Isolated origin", "is-success"));
    } else if (app.uiOriginMode === "same-origin-fallback") {
      pills.append(createPill("UI fallback", "is-warning"));
    }
    const deniedCount = audit && typeof audit.recentDeniedCount === "number"
      ? audit.recentDeniedCount
      : typeof app.recentDeniedCount === "number"
        ? app.recentDeniedCount
        : 0;
    if (deniedCount > 0) {
      pills.append(createPill(`${deniedCount} denied`, "is-error"));
    }
    if (quota && (quota.dataOverLimit || quota.cacheOverLimit)) {
      pills.append(createPill("Quota exceeded", "is-error"));
    } else if (
      (quota && Array.isArray(quota.warnings) && quota.warnings.length)
      || (runtime && Array.isArray(runtime.warnings) && runtime.warnings.length)
    ) {
      pills.append(createPill("Quota warning", "is-warning"));
    }
    header.append(heading, pills);
    card.append(header);

    const uiEntryNode = appUiEntryNode(app);
    const entries = [
      ["App ID", typeof app.appId === "string" && app.appId ? app.appId : "Unavailable"],
      ["Version", typeof app.version === "string" && app.version ? app.version : "Unavailable"],
      ["Permissions", formatPermissions(app.permissions)],
      ["UI mode", scalar(app.uiMode)],
      ["UI", uiEntryNode || scalar(app.uiUrl)],
      ["UI entry", scalar(app.uiEntry)],
      ["UI origin mode", scalar(app.uiOriginMode)],
      ["UI origin status", scalar(app.uiOriginStatus)],
      ["UI origin", scalar(app.uiOrigin)],
      ["Same-origin fallback", scalar(app.sameOriginFallbackUrl)],
      ["Sandbox", sandboxLabel(sandbox)],
      ["Sandbox required", sandbox && sandbox.required ? "Yes" : "No"],
      ["Sandbox provider", sandbox ? scalar(sandbox.provider) : "Unavailable"],
      ["Sandbox warnings", sandboxWarnings(sandbox)],
      ["Data usage", formatQuotaUsage(quota, "dataUsageBytes", "effectiveDataBytes", "dataQuotaEnforced")],
      ["Cache usage", formatQuotaUsage(quota, "cacheUsageBytes", "effectiveCacheBytes", "cacheQuotaEnforced")],
      ["Data limit", formatQuotaLimit(quota, "effectiveDataBytes", "dataQuotaEnforced")],
      ["Cache limit", formatQuotaLimit(quota, "effectiveCacheBytes", "cacheQuotaEnforced")],
      ["Quota warnings", quotaWarnings(quota, runtime)],
      ["Runtime state", runtimeState],
      ["Running", runtimeRunning ? "Yes" : "No"],
      ["PID", runtimeRunning ? scalar(runtimePid) : "Unavailable"],
      ["Started at", runtimeRunning ? formatIsoTimestamp(runtimeStartedAt) : "Unavailable"],
      ["Last exit code", runtime && runtime.lastExitCode != null ? scalar(runtime.lastExitCode) : "Unavailable"],
      ["Last exit at", runtime ? formatIsoTimestamp(runtime.lastExitAt) : "Unavailable"],
      ["Restart attempts", runtime ? scalar(runtime.currentRestartAttempt) : "Unavailable"],
      ["Denied app calls", scalar(deniedCount)],
      ["Process log size", logs && logs.available ? formatBytes(logs.sizeBytes) : formatBytes(runtime && runtime.logSizeBytes)],
      ["Process log limit", quota ? formatBytes(quota.processLogMaxBytes) : "Unavailable"],
      ["Process log tail limit", logs ? formatBytes(logs.maxBytes) : "Unavailable"],
      ["Process log truncated", logs && logs.truncated ? "Yes" : "No"],
      ["Runtime detail", runtimeError || (runtime ? "Available" : "Unavailable")],
    ];
    card.append(definitionList(entries));
    card.append(appPermissionsDetailsNode(app));
    card.append(appAuditDetailsNode(audit, app.auditError));
    const logDetails = appLogDetailsNode(logs, app.logsError);
    if (logDetails) {
      card.append(logDetails);
    }

    const actions = document.createElement("div");
    actions.className = "app-card-actions";
    if (formPassword) {
      const startForm = buildAppActionForm(
        app,
        runtimeStoppable ? "stop" : "start",
        runtimeStoppable ? "Stop" : "Start",
      );
      const uninstallForm = runtimeStoppable
        ? null
        : buildAppActionForm(app, "uninstall", "Uninstall");
      if (startForm) {
        actions.append(startForm);
      }
      if (uninstallForm) {
        actions.append(uninstallForm);
      }
    }
    if (actions.childNodes.length) {
      card.append(actions);
    }

    return card;
  }

  function appPermissionsDetailsNode(app) {
    const details = document.createElement("details");
    details.className = "json-details";
    const summary = document.createElement("summary");
    summary.textContent = "Declared permissions";
    details.append(summary);
    const permissions = Array.isArray(app.permissions) ? app.permissions : [];
    if (!permissions.length) {
      details.append(text("p", "empty-state", "No manifest permissions declared."));
      return details;
    }
    const list = document.createElement("ul");
    list.className = "permission-list";
    permissions.forEach((permission) => {
      list.append(text("li", "", scalar(permission)));
    });
    details.append(list);
    return details;
  }

  function appAuditDetailsNode(audit, auditError) {
    const details = document.createElement("details");
    details.className = "json-details";
    const summary = document.createElement("summary");
    summary.textContent = "Recent app audit";
    details.append(summary);
    if (auditError) {
      details.append(text("p", "error-state", auditError));
      return details;
    }
    const events = audit && Array.isArray(audit.events) ? audit.events : [];
    if (!events.length) {
      details.append(text("p", "empty-state", "No app-originated Platform API calls recorded."));
      return details;
    }
    const list = document.createElement("div");
    list.className = "app-audit-list";
    events.slice(0, 8).forEach((event) => {
      const safeEvent = event && typeof event === "object" ? event : {};
      const item = document.createElement("div");
      const denied = safeEvent.decision === "DENIED";
      item.className = "app-audit-event" + (denied ? " is-denied" : "");
      const header = document.createElement("div");
      header.className = "app-audit-event-header";
      header.append(
        createPill(scalar(safeEvent.decision), denied ? "is-error" : "is-success"),
        text("span", "app-audit-action", scalar(safeEvent.action)),
      );
      item.append(header);
      item.append(
        definitionList([
          ["Time", formatIsoTimestamp(safeEvent.timestamp)],
          ["Method", scalar(safeEvent.method)],
          ["Endpoint", scalar(safeEvent.endpointFamily)],
          ["Required", formatPermissions(safeEvent.requiredCapabilities)],
          ["Status", scalar(safeEvent.statusCode)],
          ["Reason", scalar(safeEvent.reasonCode)],
        ]),
      );
      list.append(item);
    });
    details.append(list);
    return details;
  }

  function appLogDetailsNode(logs, logsError) {
    const details = document.createElement("details");
    details.className = "json-details";
    const summary = document.createElement("summary");
    summary.textContent = "Runtime log tail";
    details.append(summary);
    if (logsError) {
      details.append(text("p", "error-state", logsError));
      return details;
    }
    if (!logs || !logs.available) {
      details.append(text("p", "empty-state", "No process log is available."));
      return details;
    }
    if (logs.truncated) {
      details.append(text("p", "empty-state", `Showing the last ${scalar(logs.maxBytes)} bytes.`));
    }
    const pre = document.createElement("pre");
    pre.className = "json-code app-log-tail";
    pre.textContent = typeof logs.text === "string" ? logs.text : "";
    details.append(pre);
    return details;
  }

  function renderApps(data) {
    shellState.appsSnapshot = data;
    shellState.appCatalogsSnapshot = Array.isArray(data.catalogs) ? data.catalogs : null;
    updateAppsToolbar();
    clear(sections.apps);

    const apps = Array.isArray(data.apps) ? data.apps : [];
    const catalogs = Array.isArray(data.catalogs) ? data.catalogs : [];
    const catalogError = typeof data.catalogError === "string" ? data.catalogError : "";
    const runningApps = apps.filter((app) => app && typeof app === "object" && app.running).length;
    const summaryEntries = [
      ["Installed apps", `${apps.length}`],
      ["Running apps", `${runningApps}`],
      ["Catalogs", `${catalogs.length}`],
      ["Scope", formPassword ? "Shell-native" : "Read-only"],
      ...topLevelFieldEntries(data, ["apps", "catalogs"]),
    ];
    sections.apps.append(summaryCard("Apps summary", summaryEntries, apps.length ? "" : "is-warning"));

    if (apps.length) {
      const list = document.createElement("div");
      list.className = "app-card-list";
      apps.forEach((app) => {
        list.append(renderAppCard(app && typeof app === "object" ? app : {}));
      });
      sections.apps.append(list);
    } else {
      sections.apps.append(text("p", "empty-state", "No installed apps were returned."));
    }

    renderCatalogs(catalogs, catalogError);
  }

  function renderCatalogs(catalogs, catalogError) {
    sections.apps.append(text("h3", "app-card-title", "Catalog apps"));
    if (catalogError) {
      sections.apps.append(text("p", "error-state", `Catalogs unavailable: ${catalogError}`));
      return;
    }
    if (!Array.isArray(catalogs) || catalogs.length === 0) {
      sections.apps.append(text("p", "empty-state", "No app catalogs were returned."));
      return;
    }
    const list = document.createElement("div");
    list.className = "app-card-list";
    catalogs.forEach((catalog) => {
      list.append(renderCatalogCard(catalog && typeof catalog === "object" ? catalog : {}));
    });
    sections.apps.append(list);
  }

  function catalogSourceKind(catalog) {
    const rawKind =
      typeof catalog.sourceKind === "string" && catalog.sourceKind
        ? catalog.sourceKind
        : typeof catalog.sourceType === "string" && catalog.sourceType
          ? catalog.sourceType
          : "";
    const normalizedKind = rawKind.trim().toLowerCase();
    if (normalizedKind) {
      return normalizedKind;
    }
    const source = typeof catalog.source === "string" ? catalog.source : "";
    try {
      const url = new URL(source, window.location.href);
      const protocol = url.protocol.replace(":", "").toLowerCase();
      return protocol || "unknown";
    } catch (error) {
      return "unknown";
    }
  }

  function catalogLastSuccessfulRefreshAt(catalog) {
    return typeof catalog.lastSuccessfulRefreshAt === "string" && catalog.lastSuccessfulRefreshAt
      ? catalog.lastSuccessfulRefreshAt
      : catalog.refreshedAt;
  }

  function catalogFetchStatus(catalog) {
    return typeof catalog.lastFetchStatus === "string" && catalog.lastFetchStatus
      ? catalog.lastFetchStatus.toLowerCase()
      : "";
  }

  function catalogFetchFailed(catalog) {
    const status = catalogFetchStatus(catalog);
    if (status && status !== "success" && status !== "ok" && status !== "refreshed") {
      return true;
    }
    return Boolean(catalog.lastFetchErrorCode || catalog.lastFetchErrorMessage);
  }

  function catalogLastFailedAttempt(catalog) {
    if (!catalogFetchFailed(catalog)) {
      return "Unavailable";
    }
    return formatIsoTimestamp(catalog.lastAttemptAt);
  }

  function catalogFetchWarningNode(catalog) {
    if (catalogSourceKind(catalog) !== "crypta" || !catalogFetchFailed(catalog)) {
      return null;
    }
    const details = [];
    if (catalog.lastFetchErrorCode) {
      details.push(scalar(catalog.lastFetchErrorCode));
    }
    if (catalog.lastFetchErrorMessage) {
      details.push(scalar(catalog.lastFetchErrorMessage));
    }
    const suffix = details.length ? ` ${details.join(": ")}` : "";
    return text(
      "p",
      "status-message is-warning",
      `Crypta catalog refresh failed; showing last successful app listing.${suffix}`,
    );
  }

  function renderCatalogCard(catalog) {
    const card = document.createElement("article");
    card.className = "app-card";
    const title = typeof catalog.name === "string" && catalog.name ? catalog.name : scalar(catalog.catalogId);
    const sourceKind = catalogSourceKind(catalog);
    const header = document.createElement("div");
    header.className = "app-card-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(text("h3", "app-card-title", title), text("p", "app-card-subtitle", scalar(catalog.catalogId)));
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill("Signed catalog"));
    pills.append(createPill(sourceKind));
    if (catalogFetchFailed(catalog)) {
      pills.append(createPill("refresh failed", "is-warning"));
    }
    pills.append(createPill(`${Array.isArray(catalog.apps) ? catalog.apps.length : 0} apps`));
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Source type", sourceKind],
        ["Source", scalar(catalog.source)],
        ["Resolved source", scalar(catalog.lastResolvedUri)],
        ["Generated", formatIsoTimestamp(catalog.generatedAt)],
        ["Last successful refresh", formatIsoTimestamp(catalogLastSuccessfulRefreshAt(catalog))],
        ["Last failed attempt", catalogLastFailedAttempt(catalog)],
      ]),
    );
    const fetchWarning = catalogFetchWarningNode(catalog);
    if (fetchWarning) {
      card.append(fetchWarning);
    }
    if (catalog.appsError) {
      card.append(text("p", "error-state", `Catalog apps unavailable: ${catalog.appsError}`));
    }
    if (formPassword) {
      const actions = document.createElement("div");
      actions.className = "app-card-actions";
      const refreshForm = buildCatalogActionForm(catalog, null, "refresh", "Refresh");
      const removeForm = buildCatalogActionForm(catalog, null, "remove", "Remove");
      if (refreshForm) {
        actions.append(refreshForm);
      }
      if (removeForm) {
        actions.append(removeForm);
      }
      if (actions.childNodes.length) {
        card.append(actions);
      }
    }

    const apps = Array.isArray(catalog.apps) ? catalog.apps : [];
    if (!apps.length) {
      card.append(text("p", "empty-state", "No apps were returned for this catalog."));
      return card;
    }
    const appList = document.createElement("div");
    appList.className = "catalog-app-list";
    apps.forEach((app) => {
      appList.append(renderCatalogAppCard(catalog, app && typeof app === "object" ? app : {}));
    });
    card.append(appList);
    return card;
  }

  function catalogReviewDetailsNode(app) {
    const review = recordValue(app.review);
    const details = document.createElement("details");
    details.className = "json-details catalog-review-details";
    const summary = document.createElement("summary");
    summary.textContent = "Review and trust";
    details.append(summary);
    details.append(
      definitionList([
        ["Catalog trust", "Signed catalog metadata"],
        ["Review status", normalizedStatus(review.status, "Unreviewed")],
        ["Review note", scalar(review.note)],
        ["Review semantics", "Advisory metadata; catalog and bundle verification still control installation."],
      ]),
    );
    return details;
  }

  function catalogCompatibilityDetailsNode(app) {
    const compatibility = recordValue(app.compatibility);
    const details = document.createElement("details");
    details.className = "json-details catalog-compatibility-details";
    const summary = document.createElement("summary");
    summary.textContent = "Compatibility";
    details.append(summary);
    details.append(
      definitionList([
        ["Minimum Crypta version", scalar(compatibility.minimumCryptaVersion)],
        ["Current Crypta version", scalar(compatibility.currentCryptaVersion)],
        ["Satisfied", compatibility.satisfied == null ? "Advisory" : compatibility.satisfied ? "Yes" : "No"],
        ["Status", normalizedStatus(compatibility.status, "Advisory")],
        ["Advisory", compatibility.advisory === false ? "No" : "Yes"],
      ]),
    );
    return details;
  }

  function catalogPermissionReviewDetailsNode(app) {
    const details = document.createElement("details");
    details.className = "json-details catalog-permission-details";
    const summary = document.createElement("summary");
    summary.textContent = "Permission review";
    details.append(summary);

    const permissions = stringList(app.permissions);
    const rationales = recordValue(app.permissionRationales);
    const delta = recordValue(app.permissionDelta);
    details.append(
      definitionList([
        ["Added", formatPermissions(delta.added)],
        ["Removed", formatPermissions(delta.removed)],
        ["Unchanged", formatPermissions(delta.unchanged)],
      ]),
    );

    if (!permissions.length) {
      details.append(text("p", "empty-state", "No permissions declared by this catalog version."));
      return details;
    }

    const list = document.createElement("div");
    list.className = "permission-review-list";
    permissions.forEach((permission) => {
      const item = document.createElement("div");
      item.className = "permission-review-item";

      const header = document.createElement("div");
      header.className = "permission-review-header";
      header.append(text("span", "permission-name", permission));
      const deltaStatus = permissionDeltaStatus(permission, delta);
      if (deltaStatus) {
        header.append(createPill(deltaStatus[0], deltaStatus[1]));
      }

      item.append(header, text("p", "permission-rationale", permissionRationale(permission, rationales)));
      list.append(item);
    });
    details.append(list);
    return details;
  }

  function catalogReleaseDetailsNode(app) {
    const changelog = recordValue(app.changelog);
    const bundle = recordValue(app.bundle);
    const details = document.createElement("details");
    details.className = "json-details catalog-release-details";
    const summary = document.createElement("summary");
    summary.textContent = "Release metadata";
    details.append(summary);
    details.append(
      definitionList([
        ["Changelog summary", scalar(changelog.summary)],
        ["Changelog link", metadataLinkNode(changelog.uri)],
        ["Screenshot links", metadataLinkListNode(app.screenshots)],
        ["Bundle URI", metadataLinkNode(bundle.uri)],
        ["Bundle type", scalar(bundle.type)],
        ["Bundle size", formatBytes(bundle.sizeBytes)],
        ["Bundle SHA-256", scalar(bundle.sha256)],
      ]),
    );
    return details;
  }

  function renderCatalogAppCard(catalog, app) {
    const card = document.createElement("section");
    card.className = "catalog-app-card";
    if (app.updateAvailable) {
      card.className += " is-update-available";
    }

    const review = recordValue(app.review);
    const compatibility = recordValue(app.compatibility);
    const header = document.createElement("div");
    header.className = "catalog-app-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h4", "catalog-app-title", appDisplayName(app)),
      text("p", "app-card-subtitle", typeof app.appId === "string" && app.appId ? app.appId : "Unavailable"),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill("Signed catalog"));
    pills.append(createPill(normalizedStatus(review.status, "Unreviewed"), reviewTone(review.status)));
    pills.append(createPill(versionLabel(app), versionTone(app)));
    pills.append(createPill(compatibilityLabel(compatibility), compatibilityTone(compatibility)));
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["App ID", scalar(app.appId)],
        ["Catalog version", scalar(app.version)],
        ["Installed version", scalar(app.installedVersion)],
        ["Version change", versionSummary(app)],
        ["Summary", scalar(app.summary)],
        ["Homepage", metadataLinkNode(app.homepage)],
        ["Source", metadataLinkNode(app.source)],
        ["License", scalar(app.license)],
        ["Categories", chipListNode(app.categories)],
        ["Review status", normalizedStatus(review.status, "Unreviewed")],
        ["Review note", scalar(review.note)],
        ["Permissions", formatPermissions(app.permissions)],
        ["Permission changes", `+${stringList(recordValue(app.permissionDelta).added).length} / -${stringList(recordValue(app.permissionDelta).removed).length}`],
        ["Compatibility", compatibilityLabel(compatibility)],
        ["Minimum Crypta version", scalar(compatibility.minimumCryptaVersion)],
        ["Changelog", scalar(recordValue(app.changelog).summary)],
        ["Installed", app.installed ? "Yes" : "No"],
        ["Running", app.running ? "Yes" : "No"],
      ]),
    );
    card.append(catalogReviewDetailsNode(app));
    card.append(catalogCompatibilityDetailsNode(app));
    card.append(catalogPermissionReviewDetailsNode(app));
    card.append(catalogReleaseDetailsNode(app));
    if (formPassword) {
      const actions = document.createElement("div");
      actions.className = "app-card-actions";
      const action = app.installed ? "update" : "install";
      const label = app.installed
        ? app.updateAvailable
          ? "Update from catalog"
          : app.versionDifferent
            ? "Apply catalog version"
            : "Update installed app"
        : "Install from catalog";
      const form = buildCatalogActionForm(catalog, app, action, label);
      if (form) {
        actions.append(form);
        card.append(actions);
      }
    }
    return card;
  }

  function getNestedValue(root, path) {
    let current = root;
    for (let index = 0; index < path.length; index += 1) {
      if (!current || typeof current !== "object" || Array.isArray(current)) {
        return null;
      }
      const segment = path[index];
      if (Object.prototype.hasOwnProperty.call(current, segment)) {
        current = current[segment];
        continue;
      }
      const remainingPath = path.slice(index).join(".");
      if (Object.prototype.hasOwnProperty.call(current, remainingPath)) {
        return current[remainingPath];
      }
      return null;
    }
    return current;
  }

  function configBoolean(value) {
    return value === true || value === "true";
  }

  function renderConfig(data) {
    shellState.configSnapshot = data;
    updateConfigToolbar();
    clear(sections.config);

    const currentSection =
      data && typeof data.CURRENT === "object" && !Array.isArray(data.CURRENT) ? data.CURRENT : {};
    const updaterEnabled = getNestedValue(currentSection, ["node", "updater", "enabled"]);
    const updaterAutoupdate = getNestedValue(currentSection, ["node", "updater", "autoupdate"]);
    const inputBandwidthLimit = getNestedValue(currentSection, ["node", "inputBandwidthLimit"]);
    const outputBandwidthLimit = getNestedValue(currentSection, ["node", "outputBandwidthLimit"]);

    configControls.updaterEnabled.checked = configBoolean(updaterEnabled);
    configControls.updaterAutoupdate.checked = configBoolean(updaterAutoupdate);
    configControls.inputBandwidthLimit.value =
      typeof inputBandwidthLimit === "string" ? inputBandwidthLimit : "";
    configControls.outputBandwidthLimit.value =
      typeof outputBandwidthLimit === "string" ? outputBandwidthLimit : "";

    sections.config.append(
      summaryCard("Current values", [
        ["node.updater.enabled", scalar(updaterEnabled)],
        ["node.updater.autoupdate", scalar(updaterAutoupdate)],
        ["node.inputBandwidthLimit", scalar(inputBandwidthLimit)],
        ["node.outputBandwidthLimit", scalar(outputBandwidthLimit)],
      ]),
    );

    const rawDetails = document.createElement("details");
    rawDetails.className = "json-details";
    const summary = document.createElement("summary");
    summary.textContent = "Raw current config JSON";
    const rawPre = document.createElement("pre");
    rawPre.className = "json-code";
    rawPre.textContent = formatJson(data);
    rawDetails.append(summary, rawPre);
    sections.config.append(rawDetails);
  }

  function updateWizardFieldVisibility() {
    const usingMonthlyLimit = wizardControls.haveMonthlyLimit.checked;
    const knowsTrustedOperators = wizardControls.knowSomeone.checked;
    const passwordAlreadySet =
      !!(shellState.wizardSnapshot && shellState.wizardSnapshot.passwordAlreadySet);
    const editingBandwidth = wizardControls.editBandwidth.checked;
    const networkThreatEditable =
      wizardCanEditCurrentNetworkThreatLevel(shellState.wizardSnapshot);
    const physicalThreatEditable =
      wizardCanEditCurrentPhysicalThreatLevel(shellState.wizardSnapshot);
    wizardControls.knowSomeone.parentElement.hidden = !networkThreatEditable;
    wizardControls.editBandwidth.parentElement.hidden = false;
    wizardControls.haveMonthlyLimit.parentElement.hidden = !editingBandwidth;
    wizardControls.rateFields.hidden = !editingBandwidth || usingMonthlyLimit;
    wizardControls.monthlyLimitField.hidden = !editingBandwidth || !usingMonthlyLimit;
    wizardControls.connectToStrangers.parentElement.hidden =
      !networkThreatEditable || !knowsTrustedOperators;
    if (!networkThreatEditable || !knowsTrustedOperators) {
      wizardControls.connectToStrangers.checked = false;
    }
    wizardControls.setPassword.parentElement.hidden = passwordAlreadySet || !physicalThreatEditable;
    wizardControls.passwordFields.hidden =
      passwordAlreadySet || !physicalThreatEditable || !wizardControls.setPassword.checked;
  }

  function wizardBandwidthModeUnknown(data) {
    return !!(
      data &&
      typeof data === "object" &&
      data.currentBandwidthLimits &&
      typeof data.currentBandwidthLimits === "object"
    );
  }

  function wizardCanEditCurrentNetworkThreatLevel(data) {
    return !!(
      data &&
      typeof data === "object" &&
      (data.currentNetworkThreatLevel === "NORMAL" || data.currentNetworkThreatLevel === "HIGH")
    );
  }

  function wizardCanEditCurrentPhysicalThreatLevel(data) {
    return !!(
      data &&
      typeof data === "object" &&
      (data.currentPhysicalThreatLevel === "NORMAL" || data.currentPhysicalThreatLevel === "HIGH")
    );
  }

  function wizardSubmissionSupported(data) {
    return !!(data && typeof data === "object");
  }

  function wizardUnsupportedMessage(data) {
    if (!data || typeof data !== "object") {
      return "Wizard controls stay unavailable until the current snapshot loads.";
    }
    return "";
  }

  function wizardBandwidthChoiceRequired(data) {
    return false;
  }

  function wizardBandwidthChoiceMessage() {
    return "Current bandwidth settings are already configured. Choose direct rates or monthly budget explicitly and enter the values you want before applying wizard changes.";
  }

  function renderWizard(data) {
    shellState.wizardSnapshot = data;
    updateWizardToolbar();
    clear(sections.wizard);

    const currentBandwidthLimits =
      data.currentBandwidthLimits && typeof data.currentBandwidthLimits === "object"
        ? data.currentBandwidthLimits
        : null;
    const detectedDownloadLimit = data.detectedDownloadLimitKiB || "";
    const detectedUploadLimit = data.detectedUploadLimitKiB || "";
    const configuredBandwidth = wizardBandwidthModeUnknown(data);
    const networkThreatEditable = wizardCanEditCurrentNetworkThreatLevel(data);
    const physicalThreatEditable = wizardCanEditCurrentPhysicalThreatLevel(data);
    wizardControls.knowSomeone.checked =
      networkThreatEditable && data.currentNetworkThreatLevel === "HIGH";
    wizardControls.connectToStrangers.checked = false;
    wizardControls.editBandwidth.checked = false;
    wizardControls.haveMonthlyLimit.checked = false;
    wizardControls.haveMonthlyLimit.indeterminate = false;
    wizardControls.downloadLimit.value =
      currentBandwidthLimits && Number.isFinite(currentBandwidthLimits.downloadBytes)
        ? String(Math.round(currentBandwidthLimits.downloadBytes / 1024))
        : detectedDownloadLimit || String(data.minBandwidthKiB || "");
    wizardControls.uploadLimit.value =
      currentBandwidthLimits && Number.isFinite(currentBandwidthLimits.uploadBytes)
        ? String(Math.round(currentBandwidthLimits.uploadBytes / 1024))
        : detectedUploadLimit || String(data.minBandwidthKiB || "");
    wizardControls.monthlyLimit.value = data.minBandwidthMonthlyLimitGiB || "";
    wizardControls.storageLimit.value = data.initialStorageLimitGiB || "";
    wizardControls.setPassword.checked = false;
    wizardControls.password.value = "";
    wizardControls.confirmPassword.value = "";
    updateWizardFieldVisibility();

    const currentBandwidthSummary =
      currentBandwidthLimits
        ? `${scalar(currentBandwidthLimits.downloadBytes)} / ${scalar(currentBandwidthLimits.uploadBytes)}`
        : "Unavailable";

    sections.wizard.append(
      summaryCard("Current defaults", [
        ["Opennet enabled", scalar(data.opennetEnabled)],
        ["Password already set", scalar(data.passwordAlreadySet)],
        ["Current network threat", scalar(data.currentNetworkThreatLevel)],
        ["Current physical threat", scalar(data.currentPhysicalThreatLevel)],
        [
          "Storage range",
          `${scalar(data.minStorageLimitGiB)} GiB to ${scalar(data.maxStorageLimitGiB)} GiB`,
        ],
        ["Minimum bandwidth", `${scalar(data.minBandwidthKiB)} KiB/s`],
        ["Detected bandwidth", `${scalar(detectedDownloadLimit)} / ${scalar(detectedUploadLimit)}`],
        ["Current bandwidth row", currentBandwidthSummary],
      ]),
    );
    const unsupportedMessage = wizardUnsupportedMessage(data);
    if (unsupportedMessage) {
      setWizardStatus(unsupportedMessage, "is-error");
    } else if (wizardBandwidthChoiceRequired(data)) {
      setWizardStatus(wizardBandwidthChoiceMessage(), "is-error");
    } else {
      const notes = [];
      if (!networkThreatEditable) {
        notes.push(
          "Current LOW/MAXIMUM network threat level will be preserved; use the security controls to change it.",
        );
      }
      if (!physicalThreatEditable) {
        notes.push(
          "Current LOW/MAXIMUM physical threat level will be preserved; use the security controls to change it.",
        );
      }
      notes.push(
        configuredBandwidth
          ? "Current bandwidth settings will be preserved unless you enable bandwidth editing."
          : "Default bandwidth settings will be preserved unless you enable bandwidth editing.",
      );
      setWizardStatus(notes.join(" "));
    }
  }

  function updatePeerToolbar() {
    peerControls.createForm.hidden = !formPassword;
    if (sections.peersReadonlyHint) {
      sections.peersReadonlyHint.hidden = !!formPassword;
    }
  }

  function updateAlertsToolbar() {
    if (sections.alertsReadonlyHint) {
      sections.alertsReadonlyHint.hidden = !!formPassword;
    }
  }

  function updateAppsToolbar() {
    if (appsControls.catalogSourceForm) {
      appsControls.catalogSourceForm.hidden = !formPassword;
    }
    if (sections.appsReadonlyHint) {
      sections.appsReadonlyHint.hidden = !!formPassword;
    }
  }

  function updatePublisherToolbar() {
    publisherControls.fileForm.hidden = !formPassword;
    publisherControls.directoryForm.hidden = !formPassword;
    if (sections.publisherReadonlyHint) {
      sections.publisherReadonlyHint.hidden = !!formPassword;
    }
  }

  function updateDiagnosticsToolbar() {}

  function updateSecurityToolbar() {
    securityControls.form.hidden = !formPassword || !shellState.securitySnapshot;
    if (sections.securityReadonlyHint) {
      sections.securityReadonlyHint.hidden = !!formPassword;
    }
  }

  function updateUpdatesToolbar() {
    const available =
      !!(shellState.updatesSnapshot && shellState.updatesSnapshot.downloadAllowed);
    updatesControls.downloadButton.hidden = !formPassword;
    updatesControls.downloadButton.disabled = !available;
    if (sections.updatesReadonlyHint) {
      sections.updatesReadonlyHint.hidden = !!formPassword;
    }
  }

  function updateConfigToolbar() {
    configControls.form.hidden = !formPassword || !shellState.configSnapshot;
    if (sections.configReadonlyHint) {
      sections.configReadonlyHint.hidden = !!formPassword;
    }
  }

  function updateWizardToolbar() {
    wizardControls.form.hidden =
      !formPassword || !shellState.wizardSnapshot || !wizardSubmissionSupported(shellState.wizardSnapshot);
    if (sections.wizardReadonlyHint) {
      sections.wizardReadonlyHint.hidden = !!formPassword;
    }
    updateWizardFieldVisibility();
  }

  function familyLabel(peer) {
    return peer.family === "opennet" ? "Opennet" : "Darknet";
  }

  function peerDetailEntries(peer) {
    const entries = [
      ["Identity", peer.identity || "Unavailable"],
      ["Family", familyLabel(peer)],
      ["Status", peer.status || "Unavailable"],
      ["Trust", peer.trust || "Unavailable"],
      ["Visibility", peer.visibility || "Unavailable"],
    ];
    if (peer.family === "darknet") {
      entries.push(["Their visibility", peer.theirVisibility || "Unavailable"]);
      entries.push(["Disabled", scalar(peer.disabled)]);
      entries.push(["Listen only", scalar(peer.listenOnly)]);
      entries.push(["Burst only", scalar(peer.burstOnly)]);
      entries.push(["Routing enabled", scalar(peer.routingEnabled)]);
      entries.push(["Private note", peer.hasPrivateNote ? "Present" : "Empty"]);
    }
    return entries;
  }

  function buildPeerSelectField(id, name, label, currentValue, options) {
    const wrapper = document.createElement("label");
    wrapper.className = "queue-field peer-form-field";
    wrapper.setAttribute("for", id);

    wrapper.append(text("span", "", label));
    const select = document.createElement("select");
    select.id = id;
    select.name = name;
    for (const optionValue of options) {
      const option = document.createElement("option");
      option.value = optionValue;
      option.textContent = optionValue.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
      if (optionValue === currentValue) {
        option.selected = true;
      }
      select.append(option);
    }
    wrapper.append(select);
    return wrapper;
  }

  function buildPeerSettingsForm(peer) {
    if (peer.family !== "darknet" || !formPassword) {
      return null;
    }
    const identityToken = encodeURIComponent(peer.identity || "peer");
    const form = document.createElement("form");
    form.className = "peer-inline-form";
    form.dataset.peerAction = "settings";
    form.dataset.peerIdentity = peer.identity || "";
    form.dataset.peerDisplayName = peer.displayName || peer.identity || "peer";

    form.append(text("p", "peer-form-title", "Trust and visibility"));
    const fields = document.createElement("div");
    fields.className = "peer-form-grid";
    fields.append(
      buildPeerSelectField(
        `peer-trust-${identityToken}`,
        "trust",
        "Trust",
        peer.trust || "NORMAL",
        ["HIGH", "NORMAL", "LOW"],
      ),
      buildPeerSelectField(
        `peer-visibility-${identityToken}`,
        "visibility",
        "Visibility",
        peer.visibility || "YES",
        ["YES", "NAME_ONLY", "NO"],
      ),
    );
    form.append(fields);

    const actions = document.createElement("div");
    actions.className = "peer-form-actions";
    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = "Save settings";
    actions.append(submit);
    form.append(actions);
    return form;
  }

  function buildPeerNoteForm(peer) {
    if (peer.family !== "darknet" || !formPassword) {
      return null;
    }
    const identityToken = encodeURIComponent(peer.identity || "peer");
    const form = document.createElement("form");
    form.className = "peer-inline-form";
    form.dataset.peerAction = "note";
    form.dataset.peerIdentity = peer.identity || "";
    form.dataset.peerDisplayName = peer.displayName || peer.identity || "peer";

    form.append(text("p", "peer-form-title", "Private note"));
    const label = document.createElement("label");
    label.className = "queue-field peer-form-field";
    label.setAttribute("for", `peer-note-${identityToken}`);
    label.append(text("span", "", "Note text"));
    const textarea = document.createElement("textarea");
    textarea.id = `peer-note-${identityToken}`;
    textarea.name = "noteText";
    textarea.rows = 3;
    textarea.maxLength = 250;
    textarea.value = typeof peer.privateNoteText === "string" ? peer.privateNoteText : "";
    label.append(textarea);
    form.append(label);

    const actions = document.createElement("div");
    actions.className = "peer-form-actions";
    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = "Save note";
    actions.append(submit);
    form.append(actions);
    return form;
  }

  function buildPeerRemoveForm(peer) {
    if (!formPassword) {
      return null;
    }
    const form = document.createElement("form");
    form.className = "peer-inline-form peer-remove-form";
    form.dataset.peerAction = "remove";
    form.dataset.peerIdentity = peer.identity || "";
    form.dataset.peerDisplayName = peer.displayName || peer.identity || "peer";
    form.dataset.peerRequiresForceRemoval = peer.removableWithoutForce === false ? "true" : "false";

    const actions = document.createElement("div");
    actions.className = "peer-form-actions";
    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = "Remove peer";
    actions.append(submit);
    form.append(actions);
    return form;
  }

  function renderPeerCard(peer) {
    const card = document.createElement("article");
    card.className = "peer-card";

    const header = document.createElement("div");
    header.className = "peer-card-header";
    const heading = document.createElement("div");
    heading.className = "peer-card-heading";
    heading.append(
      text("h3", "peer-card-title", peer.displayName || peer.identity || "Peer"),
      text("p", "peer-card-subtitle", peer.identity || "Unavailable"),
    );
    const pills = document.createElement("div");
    pills.className = "peer-card-pills";
    pills.append(createPill(familyLabel(peer), peer.disabled ? "is-warning" : ""));
    if (peer.status) {
      pills.append(createPill(peer.status, peer.disabled ? "is-warning" : ""));
    }
    header.append(heading, pills);
    card.append(header);

    card.append(definitionList(peerDetailEntries(peer)));

    const links = document.createElement("div");
    links.className = "peer-card-links";
    const rawLink = document.createElement("a");
    rawLink.className = "button button-secondary";
    rawLink.href = apiUrl(
      `peers/${encodeURIComponent(peer.identity)}?includeMetadata=true&includeVolatile=true`,
    );
    rawLink.textContent = "Raw JSON";
    links.append(rawLink);
    card.append(links);

    const settingsForm = buildPeerSettingsForm(peer);
    if (settingsForm) {
      card.append(settingsForm);
    }
    const noteForm = buildPeerNoteForm(peer);
    if (noteForm) {
      card.append(noteForm);
    }
    const removeForm = buildPeerRemoveForm(peer);
    if (removeForm) {
      card.append(removeForm);
    }

    return card;
  }

  function renderPeers(data) {
    const peers = data && Array.isArray(data.peers) ? data.peers : [];
    const peerCount = data && typeof data.peerCount === "number" ? data.peerCount : peers.length;
    clear(sections.peers);
    updatePeerToolbar();

    sections.peers.append(
      summaryCard("Roster", [
        ["Peers exported", `${peerCount}`],
        ["Scope", formPassword ? "Shell-native" : "Read-only"],
      ]),
    );

    if (!peers.length) {
      sections.peers.append(text("p", "empty-state", "No peer records were exported."));
      return;
    }

    const list = document.createElement("div");
    list.className = "peer-card-list";
    peers.forEach((peer) => {
      list.append(renderPeerCard(peer));
    });
    sections.peers.append(list);
  }

  function updateQueueToolbar() {
    queueControls.downloadsButton.classList.toggle("is-active", queueState.page === "downloads");
    queueControls.uploadsButton.classList.toggle("is-active", queueState.page === "uploads");
    queueControls.advancedToggle.checked = queueState.advancedMode;
    queueControls.keysButton.textContent = queueState.keysVisible ? "Hide keys" : "Show keys";
    queueControls.createForm.hidden = queueState.page !== "downloads" || !formPassword;
  }

  function queueQueryString() {
    const params = new URLSearchParams();
    params.set("page", queueState.page);
    params.set("advancedMode", String(queueState.advancedMode));
    if (queueState.sortBy) {
      params.set("sortBy", queueState.sortBy);
    }
    if (queueState.reversed) {
      params.set("reversed", "true");
    }
    return params.toString();
  }

  function queuePageUrl() {
    return apiUrl(`queue?${queueQueryString()}`);
  }

  function queueCountUrl() {
    return apiUrl(`queue/count?page=${encodeURIComponent(queueState.page)}`);
  }

  function queueKeysUrl() {
    return apiUrl(`queue/keys?page=${encodeURIComponent(queueState.page)}`);
  }

  function formsWithin(root) {
    if (root instanceof HTMLFormElement) {
      return [root];
    }
    return Array.from(root.querySelectorAll("form"));
  }

  function injectFormPassword(root) {
    formsWithin(root).forEach((form) => {
      let field = form.querySelector('input[name="formPassword"]');
      if (!formPassword) {
        if (field) {
          field.remove();
        }
        return;
      }
      if (!field) {
        field = document.createElement("input");
        field.type = "hidden";
        field.name = "formPassword";
        form.append(field);
      }
      field.value = formPassword;
    });
  }

  function normalizeQueueBasePath(rawPath) {
    if (typeof rawPath !== "string" || !rawPath.startsWith("/")) {
      return `/${queueState.page}/`;
    }
    return rawPath.endsWith("/") ? rawPath : `${rawPath}/`;
  }

  function rewriteQueueRelativeLinks(root) {
    const actionForm = formsWithin(root).find((form) => typeof form.getAttribute("action") === "string");
    const queueBasePath = normalizeQueueBasePath(actionForm && actionForm.getAttribute("action"));

    root.querySelectorAll("a[href]").forEach((anchor) => {
      const href = anchor.getAttribute("href");
      if (typeof href !== "string" || href.length === 0) {
        return;
      }
      if (href.startsWith("?")) {
        anchor.dataset.shellHref = href;
        anchor.setAttribute("href", `${queueBasePath}${href}`);
        return;
      }
      if (href === "listKeys.txt") {
        anchor.dataset.shellHref = href;
        anchor.setAttribute("href", `${queueBasePath}listKeys.txt`);
      }
    });
  }

  function stripReadOnlyQueueForms(root) {
    const forms = formsWithin(root);
    if (forms.length === 0) {
      return;
    }
    root.prepend(text("p", "status-message is-warning", "Queue mutations unavailable in read-only mode."));
    forms.forEach((form) => {
      form
        .querySelectorAll('input:not([type="hidden"]), button, select, textarea')
        .forEach((control) => {
          control.disabled = true;
          control.hidden = true;
        });
    });
  }

  async function refreshFormPassword() {
    const response = await fetch(shellRootUrl.toString(), {
      headers: { Accept: "text/html" },
      cache: "no-store",
    });
    if (!response.ok) {
      throw new Error(`${response.status} ${response.statusText}`);
    }
    const html = await response.text();
    const parsedDocument = new DOMParser().parseFromString(html, "text/html");
    const nextBootstrapElement = parsedDocument.getElementById("web-shell-bootstrap");
    if (!(nextBootstrapElement instanceof HTMLScriptElement)) {
      throw new Error("Web Shell bootstrap unavailable.");
    }
    const nextBootstrap = JSON.parse(nextBootstrapElement.textContent || "{}");
    formPassword = typeof nextBootstrap.formPassword === "string" ? nextBootstrap.formPassword : "";
    updateSecurityToolbar();
    updateAppsToolbar();
    updatePublisherToolbar();
    updateUpdatesToolbar();
    updateConfigToolbar();
    updateWizardToolbar();
    return formPassword;
  }

  function renderQueueHtmlFragment(html, className) {
    const container = document.createElement("div");
    container.className = className;
    if (typeof html !== "string" || html.length === 0) {
      return container;
    }

    const parsedDocument = new DOMParser().parseFromString(html, "text/html");
    sanitizeQueueNode(parsedDocument.body);
    container.replaceChildren(...Array.from(parsedDocument.body.childNodes));
    return container;
  }

  function sanitizeQueueNode(root) {
    root
      .querySelectorAll("script, style, template, iframe, frame, frameset, object, embed, link, meta, base")
      .forEach((node) => {
        node.remove();
      });

    root.querySelectorAll("*").forEach((element) => {
      Array.from(element.attributes).forEach((attribute) => {
        const attributeName = attribute.name.toLowerCase();
        if (attributeName.startsWith("on") || attributeName === "style" || attributeName === "srcdoc") {
          element.removeAttribute(attribute.name);
          return;
        }
        if (
          (attributeName === "href" ||
            attributeName === "src" ||
            attributeName === "action" ||
            attributeName === "formaction") &&
          !isSafeQueueUrl(attribute.value)
        ) {
          element.removeAttribute(attribute.name);
        }
      });
    });
  }

  function isSafeQueueUrl(rawValue) {
    const value = typeof rawValue === "string" ? rawValue.trim() : "";
    if (value.length === 0 || value.startsWith("//")) {
      return value.length === 0;
    }
    try {
      const url = new URL(value, window.location.href);
      return (
        (url.protocol === "http:" || url.protocol === "https:") && url.origin === window.location.origin
      );
    } catch (error) {
      return false;
    }
  }

  function renderQueue(snapshot, countSnapshot, keysPayload) {
    clear(sections.queue);
    clear(sections.queueCount);
    clear(sections.queueKeys);

    updateQueueToolbar();

    if (countSnapshot && typeof countSnapshot.contentHtml === "string" && countSnapshot.contentHtml) {
      const countNode = renderQueueHtmlFragment(
        countSnapshot.contentHtml,
        "queue-html queue-count-html",
      );
      rewriteQueueRelativeLinks(countNode);
      injectFormPassword(countNode);
      if (!formPassword) {
        stripReadOnlyQueueForms(countNode);
      }
      sections.queueCount.append(countNode);
    }

    if (snapshot && typeof snapshot.contentHtml === "string") {
      const contentNode = renderQueueHtmlFragment(snapshot.contentHtml, "queue-html");
      rewriteQueueRelativeLinks(contentNode);
      injectFormPassword(contentNode);
      if (!formPassword) {
        stripReadOnlyQueueForms(contentNode);
      }
      sections.queue.append(contentNode);
    } else {
      sections.queue.append(text("p", "empty-state", "No queue snapshot was returned."));
    }

    if (queueState.keysVisible && keysPayload && Array.isArray(keysPayload.keys)) {
      sections.queueKeys.hidden = false;
      const label = text("p", "panel-kicker", `${keysPayload.keyCount} exported keys`);
      const exportField = document.createElement("textarea");
      exportField.className = "queue-key-text";
      exportField.readOnly = true;
      exportField.value = keysPayload.keys.join("\n");
      sections.queueKeys.append(label, exportField);
    } else {
      sections.queueKeys.hidden = true;
    }
  }

  function extractApiError(data, response) {
    if (data && data.error && typeof data.error.message === "string") {
      return data.error.message;
    }
    return `${response.status} ${response.statusText}`;
  }

  function renderError(node, label, error) {
    clear(node);
    const message =
      error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    node.append(text("p", "error-state", `${label} unavailable: ${message}`));
  }

  async function loadJson(url) {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(extractApiError(data, response));
    }
    return data;
  }

  async function loadOptionalJson(url, optionalStatuses = [404]) {
    const response = await fetch(url, { headers: { Accept: "application/json" } });
    const data = await response.json().catch(() => ({}));
    if (response.ok) {
      return data;
    }
    if (optionalStatuses.includes(response.status)) {
      return null;
    }
    throw new Error(extractApiError(data, response));
  }

  async function loadBestEffortOptionalJson(url) {
    try {
      return await loadOptionalJson(url);
    } catch (error) {
      return null;
    }
  }

  async function postForm(path, formData, unavailableMessage) {
    return submitFormMutation("POST", path, formData, unavailableMessage);
  }

  // DELETE reuses the same formPassword body flow so uninstall stays behind the existing bridge auth.
  async function deleteForm(path, formData, unavailableMessage) {
    return submitFormMutation("DELETE", path, formData, unavailableMessage);
  }

  async function submitFormMutation(method, path, formData, unavailableMessage) {
    const currentFormPassword = await refreshFormPassword();
    if (!currentFormPassword) {
      throw new Error(unavailableMessage || "Queue mutations unavailable in read-only mode.");
    }
    const body = new URLSearchParams();
    for (const [key, value] of formData.entries()) {
      if (typeof value === "string") {
        body.append(key, value);
      }
    }
    if (currentFormPassword) {
      body.set("formPassword", currentFormPassword);
    }

    const response = await fetch(apiUrl(path), {
      method,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      },
      body: body.toString(),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(extractApiError(data, response));
    }
    return data;
  }

  async function loadSecuritySection() {
    const loadGeneration = ++securityLoadGeneration;
    shellState.securitySnapshot = null;
    clear(sections.security);
    sections.security.append(text("p", "loading", "Loading security snapshot..."));
    updateSecurityToolbar();

    try {
      const snapshot = await loadJson(apiUrl("security-levels"));
      if (loadGeneration !== securityLoadGeneration) {
        return;
      }
      renderSecurity(snapshot);
    } catch (error) {
      if (loadGeneration !== securityLoadGeneration) {
        return;
      }
      renderError(sections.security, "security", error);
    }
  }

  async function loadUpdatesSection() {
    const loadGeneration = ++updatesLoadGeneration;
    shellState.updatesSnapshot = null;
    clear(sections.updates);
    sections.updates.append(text("p", "loading", "Loading updater status..."));
    updateUpdatesToolbar();

    try {
      const snapshot = await loadJson(apiUrl("updates/core"));
      if (loadGeneration !== updatesLoadGeneration) {
        return;
      }
      renderUpdates(snapshot);
    } catch (error) {
      if (loadGeneration !== updatesLoadGeneration) {
        return;
      }
      renderError(sections.updates, "updates", error);
    }
  }

  async function loadConfigSection() {
    const loadGeneration = ++configLoadGeneration;
    shellState.configSnapshot = null;
    clear(sections.config);
    sections.config.append(text("p", "loading", "Loading config snapshot..."));
    updateConfigToolbar();

    try {
      const snapshot = await loadJson(apiUrl("config?sections=CURRENT"));
      if (loadGeneration !== configLoadGeneration) {
        return;
      }
      renderConfig(snapshot);
    } catch (error) {
      if (loadGeneration !== configLoadGeneration) {
        return;
      }
      renderError(sections.config, "config", error);
    }
  }

  async function loadWizardSection() {
    const loadGeneration = ++wizardLoadGeneration;
    shellState.wizardSnapshot = null;
    clear(sections.wizard);
    sections.wizard.append(text("p", "loading", "Loading wizard snapshot..."));
    updateWizardToolbar();

    try {
      const snapshot = await loadJson(apiUrl("wizard/first-time"));
      if (loadGeneration !== wizardLoadGeneration) {
        return;
      }
      renderWizard(snapshot);
    } catch (error) {
      if (loadGeneration !== wizardLoadGeneration) {
        return;
      }
      renderError(sections.wizard, "wizard", error);
    }
  }

  function peerPath(peerIdentity, action) {
    return `peers/${encodeURIComponent(peerIdentity)}/${action}`;
  }

  async function loadPeersSection() {
    const loadGeneration = ++peerLoadGeneration;
    updatePeerToolbar();
    clear(sections.peers);
    sections.peers.append(text("p", "loading", "Loading peer roster..."));

    try {
      const roster = await loadJson(apiUrl("peers?view=summary"));
      if (loadGeneration !== peerLoadGeneration) {
        return;
      }
      renderPeers(roster);
    } catch (error) {
      if (loadGeneration !== peerLoadGeneration) {
        return;
      }
      renderError(sections.peers, "peers", error);
    }
  }

  async function loadAlertsSection() {
    const loadGeneration = ++alertsLoadGeneration;
    shellState.alertsSnapshot = null;
    clear(sections.alerts);
    sections.alerts.append(text("p", "loading", "Loading alerts snapshot..."));
    updateAlertsToolbar();

    try {
      const snapshot = await loadJson(apiUrl("alerts"));
      if (loadGeneration !== alertsLoadGeneration) {
        return;
      }
      renderAlerts(snapshot);
    } catch (error) {
      if (loadGeneration !== alertsLoadGeneration) {
        return;
      }
      renderError(sections.alerts, "alerts", error);
    }
  }

  async function loadDiagnosticsSection() {
    const loadGeneration = ++diagnosticsLoadGeneration;
    shellState.diagnosticsSnapshot = null;
    clear(sections.diagnostics);
    sections.diagnostics.append(text("p", "loading", "Loading diagnostics snapshot..."));
    updateDiagnosticsToolbar();

    try {
      const snapshot = await loadJson(apiUrl("diagnostics"));
      if (loadGeneration !== diagnosticsLoadGeneration) {
        return;
      }
      renderDiagnostics(snapshot);
    } catch (error) {
      if (loadGeneration !== diagnosticsLoadGeneration) {
        return;
      }
      renderError(sections.diagnostics, "diagnostics", error);
    }
  }

  async function loadAppsSection() {
    const loadGeneration = ++appsLoadGeneration;
    shellState.appsSnapshot = null;
    shellState.appCatalogsSnapshot = null;
    clear(sections.apps);
    sections.apps.append(text("p", "loading", "Loading installed apps and catalogs..."));
    updateAppsToolbar();

    let installedSnapshot;
    try {
      installedSnapshot = await loadJson(apiUrl("apps"));
      const apps =
        installedSnapshot && Array.isArray(installedSnapshot.apps)
          ? await Promise.all(installedSnapshot.apps.map(loadAppRuntimeDetails))
          : [];
      installedSnapshot = { ...installedSnapshot, apps };
    } catch (error) {
      if (loadGeneration !== appsLoadGeneration) {
        return;
      }
      renderError(sections.apps, "apps", error);
      return;
    }

    let catalogs = [];
    let catalogError = "";
    try {
      const catalogsSnapshot = await loadOptionalJson(apiUrl("app-catalogs"));
      catalogs =
        catalogsSnapshot && Array.isArray(catalogsSnapshot.catalogs)
          ? await Promise.all(
              catalogsSnapshot.catalogs.map(loadCatalogApps),
            )
          : [];
    } catch (error) {
      catalogError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    }

    if (loadGeneration !== appsLoadGeneration) {
      return;
    }
    renderApps({ ...installedSnapshot, catalogs, catalogError });
  }

  async function loadAppRuntimeDetails(app) {
    if (!app || typeof app !== "object" || typeof app.appId !== "string" || app.appId.length === 0) {
      return app;
    }
    const runtimePath = appRuntimePath(app.appId);
    const logsPath = appLogsPath(app.appId, 65536);
    const auditPath = appAuditPath(app.appId);
    let runtime = null;
    let runtimeError = "";
    let logs = null;
    let logsError = "";
    let audit = app.audit && typeof app.audit === "object" ? app.audit : null;
    let auditError = "";
    try {
      const runtimeSnapshot = runtimePath ? await loadOptionalJson(apiUrl(runtimePath)) : null;
      runtime =
        runtimeSnapshot && runtimeSnapshot.runtime && typeof runtimeSnapshot.runtime === "object"
          ? runtimeSnapshot.runtime
          : runtimeSnapshot;
    } catch (error) {
      runtimeError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    }
    try {
      const logsSnapshot = logsPath ? await loadOptionalJson(apiUrl(logsPath)) : null;
      logs =
        logsSnapshot && logsSnapshot.logs && typeof logsSnapshot.logs === "object"
          ? logsSnapshot.logs
          : logsSnapshot;
    } catch (error) {
      logsError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    }
    try {
      const auditSnapshot = auditPath ? await loadOptionalJson(apiUrl(auditPath)) : null;
      audit =
        auditSnapshot && auditSnapshot.audit && typeof auditSnapshot.audit === "object"
          ? auditSnapshot.audit
          : auditSnapshot || audit;
    } catch (error) {
      auditError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    }
    return { ...app, runtime, runtimeError, logs, logsError, audit, auditError };
  }

  async function loadCatalogApps(catalog) {
    if (!catalog || typeof catalog !== "object" || typeof catalog.catalogId !== "string") {
      return catalog;
    }
    try {
      const apps = await loadJson(apiUrl(`app-catalogs/${encodeURIComponent(catalog.catalogId)}/apps`));
      return { ...catalog, apps: apps && Array.isArray(apps.apps) ? apps.apps : [] };
    } catch (error) {
      const appsError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
      return { ...catalog, apps: [], appsError };
    }
  }

  async function dismissAlert(form) {
    const alertId = form.dataset.alertId ?? "";
    if (alertId === "") {
      setAlertsStatus("Alert dismissal unavailable without an alert ID.", "is-error");
      return;
    }

    try {
      await postForm(
        alertDismissPath(alertId),
        new FormData(),
        "Alert dismissal unavailable in read-only mode.",
      );
      setAlertsStatus("Alert dismissed.", "is-success");
      await loadAlertsSection();
    } catch (error) {
      setAlertsStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitAppMutation(form, action) {
    const appId = form.dataset.appId || "";
    const path = appMutationPath(appId, action);
    const appName = form.dataset.appName || appDisplayName({ appId });
    if (!path) {
      setAppsStatus("App lifecycle action unavailable for this app.", "is-error");
      return;
    }

    const formData = new FormData(form);

    try {
      const data =
        action === "uninstall"
          ? await deleteForm(path, formData, "App lifecycle actions unavailable in read-only mode.")
          : await postForm(path, formData, "App lifecycle actions unavailable in read-only mode.");
      const operation = data.operation || action;
      if (action === "uninstall") {
        setAppsStatus(`${appName} uninstalled.`, "is-success");
      } else if (action === "stop") {
        setAppsStatus(`${appName} stopped.`, "is-success");
      } else {
        setAppsStatus(`${appName} started.`, "is-success");
      }
      if (operation && operation !== action) {
        setAppsStatus(`App action completed: ${operation.replaceAll("_", " ")}.`, "is-success");
      }
      await loadAppsSection();
    } catch (error) {
      setAppsStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitCatalogSource(event) {
    event.preventDefault();
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) {
      return;
    }
    if (typeof form.reportValidity === "function" && !form.reportValidity()) {
      return;
    }
    try {
      await postForm(
        "app-catalogs/add",
        new FormData(form),
        "Catalog actions unavailable in read-only mode.",
      );
      form.reset();
      setAppsStatus("Catalog source added.", "is-success");
      await loadAppsSection();
    } catch (error) {
      setAppsStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitCatalogMutation(form, action) {
    const catalogId = form.dataset.catalogId || "";
    const appId = form.dataset.catalogAppId || "";
    const path = catalogMutationPath(catalogId, appId, action);
    if (!path) {
      setAppsStatus("Catalog action unavailable for this entry.", "is-error");
      return;
    }
    try {
      if (action === "remove") {
        await deleteForm(path, new FormData(form), "Catalog actions unavailable in read-only mode.");
      } else {
        await postForm(path, new FormData(form), "Catalog actions unavailable in read-only mode.");
      }
      setAppsStatus(`Catalog action completed: ${action}.`, "is-success");
      await loadAppsSection();
    } catch (error) {
      setAppsStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  function queueMutationPath(submitterName) {
    switch (submitterName) {
      case "remove_request":
        return "queue/requests/remove";
      case "restart_request":
        return "queue/requests/restart";
      case "remove_finished_uploads_request":
        return "queue/cleanup/uploads";
      case "remove_finished_downloads_request":
        return "queue/cleanup/downloads";
      default:
        if (submitterName && submitterName.indexOf("change_priority") === 0) {
          return "queue/requests/priority";
        }
        return null;
    }
  }

  function updateQueueSort(rawHref) {
    const href = typeof rawHref === "string" ? rawHref : "";
    if (!href.startsWith("?")) {
      return false;
    }
    const params = new URLSearchParams(href.slice(1));
    queueState.sortBy = params.get("sortBy");
    queueState.reversed = params.get("reversed") === "true" || params.has("reversed");
    setStatus(`Sorted ${queueState.page} queue${queueState.sortBy ? ` by ${queueState.sortBy}` : ""}.`);
    loadQueueSection();
    return true;
  }

  async function loadQueueSection() {
    const loadGeneration = ++queueLoadGeneration;
    updateQueueToolbar();
    clear(sections.queue);
    sections.queue.append(text("p", "loading", "Loading queue snapshot..."));
    clear(sections.queueCount);
    if (queueState.keysVisible) {
      clear(sections.queueKeys);
    }

    const snapshotRequest = loadJson(queuePageUrl());
    const countRequest =
      queueState.page === "downloads" ? loadBestEffortOptionalJson(queueCountUrl()) : Promise.resolve(null);
    const keysRequest = queueState.keysVisible ? loadBestEffortOptionalJson(queueKeysUrl()) : Promise.resolve(null);

    try {
      const snapshot = await snapshotRequest;
      const [countSnapshot, keysPayload] = await Promise.all([countRequest, keysRequest]);
      if (loadGeneration !== queueLoadGeneration) {
        return;
      }
      renderQueue(snapshot, countSnapshot, keysPayload);
    } catch (error) {
      if (loadGeneration !== queueLoadGeneration) {
        return;
      }
      renderError(sections.queue, "queue", error);
      clear(sections.queueCount);
      clear(sections.queueKeys);
    }
  }

  function queuePriorityFieldName(submitterName) {
    switch (submitterName) {
      case "change_priority_top":
        return "priority_top";
      case "change_priority_bottom":
        return "priority_bottom";
      default:
        return null;
    }
  }

  function buildQueueMutationFormData(form, submitter, path) {
    const source = new FormData(form, submitter);
    const filtered = new FormData();

    for (const [key, value] of source.entries()) {
      if (typeof value !== "string") {
        continue;
      }
      if (key === "identifier" || key.indexOf("identifier-") === 0) {
        filtered.append(key, value);
      }
    }

    if (path === "queue/requests/restart" && source.has("disableFilterData")) {
      filtered.append("disableFilterData", "disableFilterData");
    }

    if (path === "queue/requests/priority") {
      const priorityField = queuePriorityFieldName(submitter && submitter.name);
      if (priorityField) {
        const priorityValue = source.get(priorityField);
        if (typeof priorityValue === "string") {
          filtered.set("priority", priorityValue);
        }
      }
    }

    return filtered;
  }

  async function submitQueueMutation(form, submitter, path) {
    const formData = buildQueueMutationFormData(form, submitter, path);

    try {
      const data = await postForm(path, formData);
      const operation = data.operation || submitter.name;
      setStatus(`Queue action completed: ${operation.replaceAll("_", " ")}.`, "is-success");
      await loadQueueSection();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitDirectDownload(event) {
    event.preventDefault();
    const formData = new FormData(queueControls.createForm);
    try {
      const data = await postForm("queue/downloads", formData);
      if (data.operation === directDownloadOperation) {
        queueControls.createForm.reset();
      }
      setStatus("Direct download queued.", "is-success");
      await loadQueueSection();
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitPeerCreate(event) {
    event.preventDefault();
    const formData = new FormData(peerControls.createForm);
    try {
      const data = await postForm(
        "peers/add",
        formData,
        "Peer mutations unavailable in read-only mode.",
      );
      if (data.operation === "add") {
        peerControls.createForm.reset();
      }
      setPeerStatus("Peer added.", "is-success");
      await loadPeersSection();
    } catch (error) {
      setPeerStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitPeerMutation(form, action) {
    const peerIdentity = form.dataset.peerIdentity || "";
    const formData = new FormData(form);

    try {
      const data = await postForm(
        peerPath(peerIdentity, action),
        formData,
        "Peer mutations unavailable in read-only mode.",
      );
      const operation = data.operation || action;
      if (action === "remove") {
        setPeerStatus("Peer removed.", "is-success");
      } else {
        setPeerStatus(`Peer action completed: ${operation.replaceAll("_", " ")}.`, "is-success");
      }
      await loadPeersSection();
    } catch (error) {
      setPeerStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitSecurityForm(event) {
    event.preventDefault();
    const currentSnapshot = shellState.securitySnapshot;
    if (!currentSnapshot) {
      setSecurityStatus("Security controls stay unavailable until the current snapshot loads.", "is-error");
      return;
    }
    const requestedNetwork = securityControls.networkLevel.value;
    const requestedPhysical = securityControls.physicalLevel.value;
    const networkChanged = requestedNetwork !== currentSnapshot.networkThreatLevel;
    const physicalChanged = requestedPhysical !== currentSnapshot.physicalThreatLevel;

    if (!networkChanged && !physicalChanged) {
      setSecurityStatus("No threat-level changes to apply.");
      return;
    }

    if (networkChanged && physicalChanged) {
      setSecurityStatus(
        "Save one threat-level change at a time so warnings and failures cannot partially apply a combined update.",
        "is-error",
      );
      return;
    }

    if (
      physicalChanged &&
      (requestedPhysical === "HIGH" ||
        (currentSnapshot.physicalThreatLevel === "HIGH" &&
          (requestedPhysical === "LOW" || requestedPhysical === "NORMAL")))
    ) {
      setSecurityStatus(
        "Changing to or from physical HIGH still requires the legacy security page because it updates master-password state.",
        "is-error",
      );
      return;
    }
    if (
      physicalChanged &&
      requestedPhysical === "MAXIMUM" &&
      currentSnapshot.hasDatabase &&
      !window.confirm(
        "Changing the physical threat level to MAXIMUM can delete queued work. Continue?",
      )
    ) {
      return;
    }

    try {
      if (networkChanged) {
        const warning = await loadJson(
          apiUrlWithQuery("security-levels/network-warning", { newLevel: requestedNetwork }),
        );
        const networkFormData = new FormData();
        networkFormData.set("newLevel", requestedNetwork);
        if (warning.confirmationRequired) {
          const warningText =
            htmlToText(warning.warningHtml) ||
            `Change the network threat level to ${requestedNetwork}?`;
          if (!window.confirm(warningText)) {
            return;
          }
          networkFormData.set("confirmed", "true");
        } else if (!window.confirm(`Change the network threat level to ${requestedNetwork}?`)) {
          return;
        }
        await postForm(
          "security-levels/network",
          networkFormData,
          "Security mutations unavailable in read-only mode.",
        );
      }
      if (physicalChanged) {
        const physicalFormData = new FormData();
        physicalFormData.set("newLevel", requestedPhysical);
        if (requestedPhysical === "MAXIMUM" && currentSnapshot.hasDatabase) {
          physicalFormData.set("confirmed", "true");
        }
        await postForm(
          "security-levels/physical",
          physicalFormData,
          "Security mutations unavailable in read-only mode.",
        );
      }
      setSecurityStatus("Security levels updated.", "is-success");
      shellState.wizardSnapshot = null;
      updateWizardToolbar();
      await Promise.all([loadSecuritySection(), loadWizardSection()]);
    } catch (error) {
      setSecurityStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  function buildConfigFormData() {
    const formData = new FormData();
    formData.set("node.updater.enabled", String(configControls.updaterEnabled.checked));
    formData.set("node.updater.autoupdate", String(configControls.updaterAutoupdate.checked));
    if (configControls.inputBandwidthLimit.value.trim()) {
      formData.set("node.inputBandwidthLimit", configControls.inputBandwidthLimit.value.trim());
    }
    if (configControls.outputBandwidthLimit.value.trim()) {
      formData.set("node.outputBandwidthLimit", configControls.outputBandwidthLimit.value.trim());
    }
    return formData;
  }

  async function submitConfigForm(event) {
    event.preventDefault();
    if (!shellState.configSnapshot) {
      setConfigStatus("Config controls stay unavailable until the current snapshot loads.", "is-error");
      return;
    }
    const formData = buildConfigFormData();

    try {
      await postForm("config/overrides", formData, "Config mutations unavailable in read-only mode.");
      await postForm("config/persist", new FormData(), "Config mutations unavailable in read-only mode.");
      setConfigStatus("Config overrides applied and persisted.", "is-success");
      shellState.updatesSnapshot = null;
      shellState.wizardSnapshot = null;
      updateUpdatesToolbar();
      updateWizardToolbar();
      await Promise.all([loadConfigSection(), loadUpdatesSection(), loadWizardSection()]);
    } catch (error) {
      setConfigStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function persistCurrentConfig() {
    if (!shellState.configSnapshot) {
      setConfigStatus("Config controls stay unavailable until the current snapshot loads.", "is-error");
      return;
    }
    try {
      await postForm("config/persist", new FormData(), "Config mutations unavailable in read-only mode.");
      setConfigStatus("Current config persisted.", "is-success");
      await loadConfigSection();
    } catch (error) {
      setConfigStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function triggerCoreDownload() {
    if (!shellState.updatesSnapshot) {
      setUpdatesStatus("Updater actions stay unavailable until the current status loads.", "is-error");
      return;
    }
    if (!shellState.updatesSnapshot.downloadAllowed) {
      setUpdatesStatus("No downloadable core update is currently available.", "is-error");
      return;
    }
    try {
      await postForm("updates/core/download", new FormData(), "Updater actions unavailable in read-only mode.");
      setUpdatesStatus("Core download triggered.", "is-success");
      await loadUpdatesSection();
    } catch (error) {
      setUpdatesStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  function buildWizardFormData() {
    const formData = new FormData();
    const preserveBandwidthSettings = !wizardControls.editBandwidth.checked;
    const preserveCurrentNetworkThreatLevel =
      !wizardCanEditCurrentNetworkThreatLevel(shellState.wizardSnapshot);
    const preserveCurrentPhysicalThreatLevel =
      !wizardCanEditCurrentPhysicalThreatLevel(shellState.wizardSnapshot);
    if (wizardControls.knowSomeone.checked) {
      formData.set("knowSomeone", "on");
    }
    if (wizardControls.connectToStrangers.checked) {
      formData.set("connectToStrangers", "on");
    }
    if (preserveBandwidthSettings) {
      formData.set("preserveBandwidthSettings", "on");
    } else if (wizardControls.haveMonthlyLimit.checked) {
      formData.set("haveMonthlyLimit", "on");
    }
    if (preserveCurrentNetworkThreatLevel) {
      formData.set("preserveCurrentNetworkThreatLevel", "on");
    }
    if (preserveCurrentPhysicalThreatLevel) {
      formData.set("preserveCurrentPhysicalThreatLevel", "on");
    }
    if (wizardControls.setPassword.checked) {
      formData.set("setPassword", "on");
    }
    if (!preserveBandwidthSettings) {
      formData.set(
        "downloadLimitKiB",
        wizardControls.haveMonthlyLimit.checked ? "" : wizardControls.downloadLimit.value.trim(),
      );
      formData.set(
        "uploadLimitKiB",
        wizardControls.haveMonthlyLimit.checked ? "" : wizardControls.uploadLimit.value.trim(),
      );
      formData.set(
        "bandwidthMonthlyLimitGiB",
        wizardControls.haveMonthlyLimit.checked ? wizardControls.monthlyLimit.value.trim() : "",
      );
    }
    formData.set("storageLimitGiB", wizardControls.storageLimit.value.trim());
    formData.set("password", wizardControls.setPassword.checked ? wizardControls.password.value : "");
    return formData;
  }

  function clearWizardBandwidthChoiceRequirement() {
    if (wizardControls.haveMonthlyLimit.indeterminate) {
      wizardControls.haveMonthlyLimit.indeterminate = false;
    }
  }

  async function submitWizardForm(event) {
    event.preventDefault();
    if (!shellState.wizardSnapshot) {
      setWizardStatus("Wizard controls stay unavailable until the current snapshot loads.", "is-error");
      return;
    }
    if (!wizardSubmissionSupported(shellState.wizardSnapshot)) {
      setWizardStatus(wizardUnsupportedMessage(shellState.wizardSnapshot), "is-error");
      return;
    }
    if (wizardBandwidthChoiceRequired(shellState.wizardSnapshot) && wizardControls.haveMonthlyLimit.indeterminate) {
      setWizardStatus(wizardBandwidthChoiceMessage(), "is-error");
      return;
    }
    const passwordAlreadySet = !!shellState.wizardSnapshot.passwordAlreadySet;
    if (
      !passwordAlreadySet &&
      wizardControls.setPassword.checked &&
      wizardControls.password.value !== wizardControls.confirmPassword.value
    ) {
      setWizardStatus("Password confirmation does not match.", "is-error");
      return;
    }

    try {
      await postForm(
        "wizard/first-time/apply",
        buildWizardFormData(),
        "Wizard submission unavailable in read-only mode.",
      );
      setWizardStatus("Wizard settings applied.", "is-success");
      await Promise.all([
        loadShellData(),
        loadSecuritySection(),
        loadUpdatesSection(),
        loadConfigSection(),
        loadWizardSection(),
      ]);
    } catch (error) {
      setWizardStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  function submitLegacyQueueForm(form, submitter) {
    if (
      typeof form.requestSubmit === "function" &&
      (submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement)
    ) {
      nativeQueueSubmitBypass.add(form);
      form.requestSubmit(submitter);
      return;
    }

    let transientSubmitter = null;
    if (
      (submitter instanceof HTMLButtonElement || submitter instanceof HTMLInputElement) &&
      submitter.name
    ) {
      transientSubmitter = document.createElement("input");
      transientSubmitter.type = "hidden";
      transientSubmitter.name = submitter.name;
      transientSubmitter.value = submitter.value;
      form.append(transientSubmitter);
    }
    form.submit();
    if (transientSubmitter) {
      transientSubmitter.remove();
    }
  }

  function bindQueueInteractions() {
    queueControls.downloadsButton.addEventListener("click", () => {
      queueState.page = "downloads";
      queueState.sortBy = null;
      queueState.reversed = false;
      setStatus("Showing download queue.");
      loadQueueSection();
    });
    queueControls.uploadsButton.addEventListener("click", () => {
      queueState.page = "uploads";
      queueState.sortBy = null;
      queueState.reversed = false;
      setStatus("Showing upload queue.");
      loadQueueSection();
    });
    queueControls.advancedToggle.addEventListener("change", () => {
      queueState.advancedMode = queueControls.advancedToggle.checked;
      loadQueueSection();
    });
    queueControls.refreshButton.addEventListener("click", () => {
      setStatus(`Refreshing ${queueState.page} queue.`);
      loadQueueSection();
    });
    queueControls.keysButton.addEventListener("click", () => {
      queueState.keysVisible = !queueState.keysVisible;
      loadQueueSection();
    });
    queueControls.createForm.addEventListener("submit", submitDirectDownload);

    sections.queue.addEventListener("submit", async (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) {
        return;
      }
      if (nativeQueueSubmitBypass.has(form)) {
        nativeQueueSubmitBypass.delete(form);
        return;
      }
      const submitter = event.submitter;
      if (!(submitter instanceof HTMLElement)) {
        return;
      }
      const path = queueMutationPath(submitter.name);
      event.preventDefault();
      if (path) {
        await submitQueueMutation(form, submitter, path);
        return;
      }
      try {
        await refreshFormPassword();
        if (!formPassword) {
          setStatus("Queue mutations unavailable in read-only mode.", "is-error");
          return;
        }
        injectFormPassword(form);
        submitLegacyQueueForm(form, submitter);
      } catch (error) {
        setStatus(error instanceof Error ? error.message : String(error), "is-error");
      }
    });

    sections.queue.addEventListener("click", (event) => {
      const anchor = event.target instanceof Element ? event.target.closest("a") : null;
      if (!(anchor instanceof HTMLAnchorElement)) {
        return;
      }
      const shellHref = anchor.dataset.shellHref || anchor.getAttribute("href") || "";
      if (shellHref === "listKeys.txt") {
        event.preventDefault();
        if (!queueState.keysVisible) {
          queueState.keysVisible = true;
        }
        loadQueueSection();
        return;
      }
      if (updateQueueSort(shellHref)) {
        event.preventDefault();
      }
    });
  }

  function bindPeerInteractions() {
    peerControls.refreshButton.addEventListener("click", () => {
      setPeerStatus("Refreshing peer roster.");
      loadPeersSection();
    });
    peerControls.createForm.addEventListener("submit", submitPeerCreate);
    sections.peers.addEventListener("submit", async (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) {
        return;
      }
      const action = form.dataset.peerAction;
      if (!action) {
        return;
      }
      event.preventDefault();
      if (action === "remove") {
        const displayName = form.dataset.peerDisplayName || "peer";
        const requiresForceRemoval = form.dataset.peerRequiresForceRemoval === "true";
        const confirmMessage = requiresForceRemoval
          ? `Remove ${displayName}? This peer requires force removal.`
          : `Remove ${displayName}?`;
        if (!window.confirm(confirmMessage)) {
          return;
        }
        if (requiresForceRemoval) {
          let forceRemovalField = form.querySelector('input[name="forceRemoval"]');
          if (!(forceRemovalField instanceof HTMLInputElement)) {
            forceRemovalField = document.createElement("input");
            forceRemovalField.type = "hidden";
            forceRemovalField.name = "forceRemoval";
            form.append(forceRemovalField);
          }
          forceRemovalField.value = "true";
        }
      }
      await submitPeerMutation(form, action);
    });
  }

  function bindAlertsInteractions() {
    alertsControls.refreshButton.addEventListener("click", () => {
      setAlertsStatus("Refreshing alerts.");
      loadAlertsSection();
    });
    sections.alerts.addEventListener("submit", async (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) {
        return;
      }
      if (form.dataset.alertId == null) {
        return;
      }
      event.preventDefault();
      await dismissAlert(form);
    });
  }

  function bindDiagnosticsInteractions() {
    diagnosticsControls.refreshButton.addEventListener("click", () => {
      setDiagnosticsStatus("Refreshing diagnostics.");
      loadDiagnosticsSection();
    });
  }

  function bindAppsInteractions() {
    appsControls.refreshButton.addEventListener("click", () => {
      setAppsStatus("Refreshing installed apps and catalogs.");
      loadAppsSection();
    });
    sections.apps.addEventListener("click", async (event) => {
      const link = appUiLaunchClickTarget(event);
      if (!link) {
        return;
      }
      event.preventDefault();
      await launchAppUiFromLink(link);
    });
    sections.apps.addEventListener("submit", async (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) {
        return;
      }
      const catalogAction = form.dataset.catalogAction;
      if (catalogAction) {
        event.preventDefault();
        await submitCatalogMutation(form, catalogAction);
        return;
      }
      const action = form.dataset.appAction;
      if (!action) {
        return;
      }
      event.preventDefault();
      await submitAppMutation(form, action);
    });
    if (appsControls.catalogSourceForm) {
      appsControls.catalogSourceForm.addEventListener("submit", submitCatalogSource);
    }
  }

  function bindPublisherInteractions() {
    publisherControls.fileForm.addEventListener("submit", submitPublisherForm);
    publisherControls.directoryForm.addEventListener("submit", submitPublisherForm);
    if (publisherControls.queueLink instanceof HTMLAnchorElement) {
      publisherControls.queueLink.addEventListener("click", () => {
        showUploadQueueFromPublisher().catch((error) => {
          setStatus(error instanceof Error ? error.message : String(error), "is-error");
        });
      });
    }
  }

  function bindSecurityInteractions() {
    securityControls.form.addEventListener("submit", submitSecurityForm);
  }

  function bindUpdatesInteractions() {
    updatesControls.refreshButton.addEventListener("click", () => {
      setUpdatesStatus("Refreshing updater state.");
      loadUpdatesSection();
    });
    updatesControls.downloadButton.addEventListener("click", () => {
      triggerCoreDownload();
    });
  }

  function bindConfigInteractions() {
    configControls.refreshButton.addEventListener("click", () => {
      setConfigStatus("Refreshing config snapshot.");
      loadConfigSection();
    });
    configControls.form.addEventListener("submit", submitConfigForm);
    configControls.persistButton.addEventListener("click", () => {
      persistCurrentConfig();
    });
  }

  function bindWizardInteractions() {
    wizardControls.refreshButton.addEventListener("click", () => {
      setWizardStatus("Refreshing wizard snapshot.");
      loadWizardSection();
    });
    wizardControls.knowSomeone.addEventListener("change", updateWizardFieldVisibility);
    wizardControls.editBandwidth.addEventListener("change", updateWizardFieldVisibility);
    wizardControls.haveMonthlyLimit.addEventListener("change", () => {
      clearWizardBandwidthChoiceRequirement();
      updateWizardFieldVisibility();
    });
    wizardControls.downloadLimit.addEventListener("input", clearWizardBandwidthChoiceRequirement);
    wizardControls.uploadLimit.addEventListener("input", clearWizardBandwidthChoiceRequirement);
    wizardControls.monthlyLimit.addEventListener("input", clearWizardBandwidthChoiceRequirement);
    wizardControls.setPassword.addEventListener("change", updateWizardFieldVisibility);
    wizardControls.form.addEventListener("submit", submitWizardForm);
  }

  async function loadShellData() {
    const requests = [
      loadJson(apiUrl("node/greeting"))
        .then((data) => ({ section: "overview", data }))
        .catch((error) => ({ section: "overview", error })),
      loadJson(apiUrl("connectivity"))
        .then((data) => ({ section: "connectivity", data }))
        .catch((error) => ({ section: "connectivity", error })),
    ];

    const results = await Promise.all(requests);
    for (const result of results) {
      if (result.error) {
        renderError(sections[result.section], result.section, result.error);
        continue;
      }
      if (result.section === "overview") {
        renderOverview(result.data);
      } else if (result.section === "connectivity") {
        renderConnectivity(result.data);
      }
    }
  }

  initializePublisherForm(publisherControls.fileForm);
  initializePublisherForm(publisherControls.directoryForm);
  renderLegacyLinks();
  bindAlertsInteractions();
  bindAppsInteractions();
  bindPublisherInteractions();
  bindSecurityInteractions();
  bindUpdatesInteractions();
  bindConfigInteractions();
  bindWizardInteractions();
  bindPeerInteractions();
  bindDiagnosticsInteractions();
  bindQueueInteractions();
  updateAlertsToolbar();
  updateAppsToolbar();
  updatePublisherToolbar();
  updateDiagnosticsToolbar();
  updateSecurityToolbar();
  updateUpdatesToolbar();
  updateConfigToolbar();
  updateWizardToolbar();
  updatePeerToolbar();
  updateQueueToolbar();
  loadShellData().catch((error) => {
    renderError(sections.overview, "Shell", error);
  });
  loadSecuritySection().catch((error) => {
    renderError(sections.security, "security", error);
  });
  loadAlertsSection().catch((error) => {
    renderError(sections.alerts, "alerts", error);
  });
  loadAppsSection().catch((error) => {
    renderError(sections.apps, "apps", error);
  });
  loadUpdatesSection().catch((error) => {
    renderError(sections.updates, "updates", error);
  });
  loadConfigSection().catch((error) => {
    renderError(sections.config, "config", error);
  });
  loadWizardSection().catch((error) => {
    renderError(sections.wizard, "wizard", error);
  });
  loadPeersSection().catch((error) => {
    renderError(sections.peers, "peers", error);
  });
  loadQueueSection().catch((error) => {
    renderError(sections.queue, "queue", error);
  });
})();
