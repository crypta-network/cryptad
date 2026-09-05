(function () {
  "use strict";

  const bootstrapElement = document.getElementById("web-shell-bootstrap");
  const bootstrap = bootstrapElement
    ? JSON.parse(bootstrapElement.textContent || "{}")
    : {};

  const apiRoot = normalizeLocalRootPath(bootstrap.platformApiRoot, "/api/v1/");
  const shellRoot = normalizeLocalRootPath(bootstrap.shellRoot, "/app/node/");
  const legacySecurityLevelsPath = normalizeLocalPath(
    bootstrap.legacySecurityLevelsPath,
    "/seclevels/",
  );
  const legacyDiagnosticPath = normalizeLocalPath(bootstrap.legacyDiagnosticPath, null);
  const apiRootUrl = new URL(apiRoot, window.location.origin);
  const shellRootUrl = new URL(shellRoot, window.location.origin);
  const legacySecurityLevelsFallbackPath =
    legacySecurityLevelsPath + "?legacyFallback=security-levels";
  const legacyDiagnosticExportFallbackPath = legacyDiagnosticPath
    ? legacyDiagnosticPath + "?legacyFallback=diagnostic-export"
    : null;
  let formPassword = typeof bootstrap.formPassword === "string" ? bootstrap.formPassword : "";
  const legacyLinks = Array.isArray(bootstrap.legacyLinks) ? bootstrap.legacyLinks : [];
  const catalogChannels = ["stable", "beta", "nightly", "deprecated"];
  const catalogChannelStorageKey = "crypta.webShell.catalogChannel";
  const shellState = {
    alertsSnapshot: null,
    appCatalogsSnapshot: null,
    catalogFederationSnapshot: null,
    catalogFederationError: "",
    appsSnapshot: null,
    appSubmissionIntakeSnapshot: null,
    betaDashboardSnapshot: null,
    identityVaultSnapshot: null,
    recommendedCatalogsSnapshot: null,
    configSnapshot: null,
    diagnosticsSnapshot: null,
    supportBundlePreviewSnapshot: null,
    securitySnapshot: null,
    supportBundleSnapshot: null,
    updatesSnapshot: null,
    wizardSnapshot: null,
    catalogChannel: readStoredCatalogChannel(),
  };
  const directDownloadOperation = "create_direct_download";
  const isolatedLaunchParameter = "cryptadIsolatedLaunch";
  const isolatedOriginProbePath = "/.well-known/cryptad-origin.json";
  const publisherDefaultCompatibilityMode = "COMPAT_CURRENT";
  const vaultCapabilityPrefix = "vault.";
  const vaultGrantScopes = [
    "metadata.read",
    "sign.domain-separated",
    "publish.content",
    "publish.profile",
    "use.external-reference",
  ];
  const queueState = {
    page: "downloads",
    advancedMode: false,
    sortBy: null,
    reversed: false,
    keysVisible: false,
  };
  let peerLoadGeneration = 0;
  let queueLoadGeneration = 0;
  let betaDashboardLoadGeneration = 0;
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
    betaDashboard: document.getElementById("beta-dashboard-body"),
    betaDashboardStatus: document.getElementById("beta-dashboard-status"),
    betaDashboardReadonlyHint: document.getElementById("beta-dashboard-readonly-hint"),
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
  const betaDashboardControls = {
    refreshButton: document.getElementById("beta-dashboard-refresh-button"),
    supportRefreshButton: document.getElementById("support-bundle-refresh-button"),
    supportDownloadButton: document.getElementById("support-bundle-download-button"),
    supportCopyButton: document.getElementById("support-bundle-copy-button"),
    allAppDataBackupButton: document.getElementById("all-app-data-backup-button"),
    appDataRestoreForm: document.getElementById("operator-app-data-restore-form"),
    appDataRestorePayload: document.getElementById("operator-app-data-restore-payload"),
    appDataRestoreMode: document.getElementById("operator-app-data-restore-mode"),
    appDataRestoreResult: document.getElementById("operator-app-data-restore-result"),
  };
  const appsControls = {
    refreshButton: document.getElementById("apps-refresh-button"),
    catalogChannelSelect: document.getElementById("catalog-channel-select"),
    catalogSourceForm: document.getElementById("catalog-source-form"),
    catalogSourceInput: document.getElementById("catalog-source-input"),
    catalogSourceSubmit: document.getElementById("catalog-source-submit"),
    catalogSourceTrustBindingField: document.getElementById("catalog-source-trust-binding-field"),
    catalogSourceTrustBinding: document.getElementById("catalog-source-trust-binding"),
    catalogSourceTrustBindingStatus: document.getElementById("catalog-source-trust-binding-status"),
  };
  const publisherControls = {
    fileForm: document.getElementById("publisher-file-form"),
    directoryForm: document.getElementById("publisher-directory-form"),
    queueLink: document.querySelector('#publisher .queue-toolbar a[href="#queue"]'),
  };
  const diagnosticsControls = {
    refreshButton: document.getElementById("diagnostics-refresh-button"),
    legacyExportLink: document.getElementById("diagnostics-legacy-export-link"),
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

  function normalizeLocalPath(value, fallback) {
    if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//")) {
      return fallback;
    }
    try {
      const url = new URL(value, window.location.origin);
      if (url.origin !== window.location.origin || url.search !== "" || url.hash !== "") {
        return fallback;
      }
      return url.pathname;
    } catch (error) {
      return fallback;
    }
  }

  function clear(node) {
    node.replaceChildren();
  }

  function normalizeCatalogChannel(value) {
    if (typeof value !== "string") {
      return "stable";
    }
    const normalized = value.trim().toLowerCase();
    return catalogChannels.includes(normalized) ? normalized : "stable";
  }

  function readStoredCatalogChannel() {
    try {
      return normalizeCatalogChannel(window.localStorage.getItem(catalogChannelStorageKey));
    } catch (error) {
      return "stable";
    }
  }

  function storeCatalogChannel(value) {
    try {
      window.localStorage.setItem(catalogChannelStorageKey, normalizeCatalogChannel(value));
    } catch (error) {
      // Storage can be disabled; the in-memory state remains authoritative for this page load.
    }
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

  function setBetaDashboardStatus(message, tone) {
    setSectionStatus(sections.betaDashboardStatus, message, tone);
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

  function securityLegacyFallbackLink(label) {
    const fallbackLink = document.createElement("a");
    fallbackLink.href = legacySecurityLevelsFallbackPath;
    fallbackLink.textContent = label;
    return fallbackLink;
  }

  function setSecurityLegacyFallbackStatus(message) {
    clear(sections.securityStatus);
    const paragraph = text("p", "status-message is-error", `${message} `);
    paragraph.append(securityLegacyFallbackLink("Open the legacy security page."));
    sections.securityStatus.append(paragraph);
  }

  function renderSecurityLegacyFallbackAction() {
    const actions = document.createElement("div");
    actions.className = "security-fallback-actions";
    const fallbackLink = securityLegacyFallbackLink("Open legacy password and recovery forms");
    fallbackLink.className = "button button-secondary";
    actions.append(fallbackLink);
    return actions;
  }

  function configureDiagnosticLegacyExportAction() {
    if (!diagnosticsControls.legacyExportLink) {
      return;
    }
    if (!legacyDiagnosticExportFallbackPath) {
      diagnosticsControls.legacyExportLink.hidden = true;
      diagnosticsControls.legacyExportLink.removeAttribute("href");
      return;
    }
    diagnosticsControls.legacyExportLink.href = legacyDiagnosticExportFallbackPath;
    diagnosticsControls.legacyExportLink.hidden = false;
    diagnosticsControls.legacyExportLink.addEventListener("click", () => {
      setDiagnosticsStatus("Opening legacy plaintext diagnostic export fallback.", "is-warning");
    });
  }

  function securityErrorRequiresLegacyFallback(error) {
    if (
      error instanceof Error &&
      (error.apiErrorCode === "physical_threat_level_password_required" ||
        error.apiErrorCode === "physical_threat_level_master_password_cleanup_failed")
    ) {
      return true;
    }
    const message = error instanceof Error ? error.message : String(error);
    return message.includes("Use the legacy security page");
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

  function downloadBlob(blob, fileName) {
    const href = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = href;
    link.download = fileName;
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(href);
  }

  function downloadJsonBlob(value, fileName) {
    downloadBlob(new Blob([`${formatJson(value)}\n`], { type: "application/json" }), fileName);
  }

  function safeFilePart(value, fallback) {
    const raw = typeof value === "string" && value ? value : fallback;
    return raw.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || fallback;
  }

  function isoFileTimestamp(value) {
    const timestamp = typeof value === "string" ? new Date(value) : new Date();
    return Number.isNaN(timestamp.getTime())
      ? "unknown"
      : timestamp.toISOString().replace(/[:.]/g, "-");
  }

  function bytesToUrlSafeBase64(bytes) {
    let binary = "";
    const chunkSize = 0x8000;
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
      binary += String.fromCharCode(...bytes.slice(offset, offset + chunkSize));
    }
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }

  function urlSafeBase64ToBytes(value) {
    const normalized = String(value || "")
      .trim()
      .replace(/-/g, "+")
      .replace(/_/g, "/");
    const paddingLength = (4 - (normalized.length % 4)) % 4;
    const padded = normalized.padEnd(normalized.length + paddingLength, "=");
    const binary = window.atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) {
      bytes[index] = binary.charCodeAt(index);
    }
    return bytes;
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
      if (url.username || url.password) {
        return null;
      }
      if (url.origin === window.location.origin) {
        return app && app.uiMode === "shell-panel"
          ? safeShellPanelAppUiHref(url)
          : safeSameOriginAppUiHref(url, false);
      }
      if (!allowedAppUiOrigin(url, app) || url.search !== "" || url.hash !== "") {
        return null;
      }
      return url.href;
    } catch (error) {
      return null;
    }
  }

  function safeSameOriginAppUiHref(url, allowIsolatedLaunchParameter) {
    if (
      url.origin !== window.location.origin ||
      url.username ||
      url.password ||
      !url.pathname.startsWith("/apps/")
    ) {
      return null;
    }
    if (allowIsolatedLaunchParameter) {
      if (
        url.hash !== "" ||
        url.searchParams.size !== 1 ||
        url.searchParams.get(isolatedLaunchParameter) !== "1"
      ) {
        return null;
      }
      return `${url.pathname}?${isolatedLaunchParameter}=1`;
    }
    if (url.search !== "" || url.hash !== "") {
      return null;
    }
    return url.pathname;
  }

  function safeShellPanelAppUiHref(url) {
    if (
      url.origin !== window.location.origin ||
      url.username ||
      url.password ||
      url.pathname !== shellRootUrl.pathname ||
      url.search !== ""
    ) {
      return null;
    }
    return `${url.pathname}${url.hash}`;
  }

  function registeredAppUiOrigin(app) {
    if (!app || app.uiOriginMode !== "isolated-loopback" || app.uiOriginStatus !== "active") {
      return null;
    }
    if (typeof app.uiOrigin !== "string" || app.uiOrigin.length === 0) {
      return null;
    }
    try {
      const origin = new URL(app.uiOrigin);
      if (
        origin.protocol !== "http:" ||
        origin.hostname.toLowerCase() !== "127.0.0.1" ||
        origin.port === "" ||
        origin.username ||
        origin.password ||
        origin.search !== "" ||
        origin.hash !== "" ||
        origin.pathname !== "/"
      ) {
        return null;
      }
      return origin.origin;
    } catch (error) {
      return null;
    }
  }

  function allowedAppUiOrigin(url, app) {
    const registeredOrigin = registeredAppUiOrigin(app);
    if (!registeredOrigin) {
      return false;
    }
    if (url.username || url.password) {
      return false;
    }
    const hostname = url.hostname.toLowerCase();
    return (
      url.origin === registeredOrigin &&
      url.protocol === "http:" &&
      hostname === "127.0.0.1" &&
      url.port !== ""
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

  function renderBetaDashboard(data) {
    shellState.betaDashboardSnapshot = data;
    updateBetaDashboardToolbar();
    clear(sections.betaDashboard);

    const summary = recordValue(data.summary);
    const warnings = stringList(data.warnings);
    const catalogs = arrayValue(data.catalogs);
    const apps = arrayValue(data.apps);
    const subscriptions = arrayValue(data.subscriptions);
    const appServices = recordValue(data.appServices);
    const trustGraph = recordValue(data.trustGraph);
    const operatorRcRecovery = recordValue(data.operatorRcRecovery);
    const networkBudgets = recordValue(data.networkBudgets);
    const securityResponse = recordValue(data.securityResponse);
    const thirdPartyIntake = recordValue(data.thirdPartyIntake);
    const platformApiCompatibility = recordValue(data.platformApiCompatibility);

    const summaryCards = document.createElement("div");
    summaryCards.className = "app-card-list";
    summaryCards.append(
      summaryCard(
        normalizedStatus(data.overallStatus, "Unavailable"),
        [
          ["Catalogs", scalar(summary.catalogCount)],
          ["Apps", `${scalar(summary.installedAppCount)} installed / ${scalar(summary.runningAppCount)} running`],
          ["Updates", `${scalar(summary.pendingUpdateCount)} pending / ${scalar(summary.stagedUpdateCount)} staged`],
          ["Rollback", scalar(summary.rollbackAvailableCount)],
          ["Stale subscriptions", scalar(summary.staleSubscriptionCount)],
          ["Pending grants", scalar(summary.pendingGrantCount)],
          ["Quota warnings", scalar(summary.quotaWarningCount)],
        ],
        operatorStatusTone(data.overallStatus),
      ),
      summaryCard(
        "Support bundle",
        [
          ["Warnings", scalar(summary.supportWarningCount)],
          ["Last dashboard refresh", formatTimestampMillis(data.generatedAtEpochMillis)],
          [
            "Support report",
            shellState.supportBundleSnapshot
              ? formatTimestampMillis(shellState.supportBundleSnapshot.generatedAtEpochMillis)
              : "Not generated",
          ],
          [
            "Redaction status",
            supportBundleRedactionStatus(
              shellState.supportBundleSnapshot || shellState.supportBundlePreviewSnapshot,
            ),
          ],
          ["Support bundle digest", supportBundleDigestShort(shellState.supportBundleSnapshot)],
          [
            "Omitted fields",
            scalar(supportBundleOmittedFieldCount(shellState.supportBundleSnapshot)),
          ],
          ["Export model", "Local only until copied or downloaded"],
        ],
        supportBundleRedactionFailed(shellState.supportBundleSnapshot)
          ? "is-error"
          : warnings.length
            ? "is-warning"
            : "",
      ),
      summaryCard(
        "App-data backups",
        [
          ["Scope", "Single app or all known app data"],
          ["Restore modes", "merge / replaceNamespace / replaceApp"],
          ["Sensitivity", "Contains raw app-owned user data"],
        ],
        "is-warning",
      ),
      summaryCard(
        "Platform API 1.x compatibility",
        [
          ["URL API version", scalar(platformApiCompatibility.urlApiVersion)],
          ["Contract version", scalar(platformApiCompatibility.contractVersion)],
          [
            "Active stable baselines",
            stringList(platformApiCompatibility.activeStableBaselines).join(", ") || "None",
          ],
          [
            "Supported baseline lifecycle",
            arrayValue(platformApiCompatibility.baselineRegistrySummary?.supportedBaselines)
              .map((baseline) => `${scalar(baseline?.id)} (${normalizedStatus(baseline?.status, "Unknown")})`)
              .join(", ") || "None",
          ],
          ["Support phase", normalizedStatus(platformApiCompatibility.supportPhase, "Unknown")],
          ["History chain", normalizedStatus(platformApiCompatibility.historyChainHealth, "Unknown")],
          ["Candidate proposals", scalar(platformApiCompatibility.candidateBaselineProposalCount)],
          ["Graduation blockers", scalar(platformApiCompatibility.graduationBlockerCount)],
          ["Stable deprecations", scalar(platformApiCompatibility.stableDeprecationCount)],
          ["App matrix", normalizedStatus(platformApiCompatibility.appCompatibilityMatrixStatus, "Not generated")],
          ["Runtime observation", normalizedStatus(platformApiCompatibility.runtimeObservationStatus, "Not observed")],
          ["Protected evidence", normalizedStatus(platformApiCompatibility.protectedOperationState, "Not observed")],
          [
            "Evidence boundary",
            platformApiCompatibility.evidenceBoundary
              || "Static compatibility metadata is not a runtime verification.",
          ],
        ],
        platformApiCompatibility.historyChainHealth === "healthy" ? "" : "is-warning",
      ),
    );
    sections.betaDashboard.append(summaryCards);

    if (warnings.length) {
      sections.betaDashboard.append(renderBetaWarningList(warnings));
    }
    if (data.rcCompatibilityFallback === true) {
      sections.betaDashboard.append(
        text(
          "p",
          "error-state",
          "Operator RC Recovery is using the beta dashboard compatibility fallback.",
        ),
      );
    }

    sections.betaDashboard.append(
      renderSecurityResponseSummary(securityResponse),
      renderThirdPartyIntake(thirdPartyIntake),
      renderBetaCatalogs(catalogs),
      renderBetaApps(apps),
      renderBetaSubscriptions(subscriptions),
      renderBetaTrustAndServices(trustGraph, appServices),
      renderOperatorRcRecovery(operatorRcRecovery, networkBudgets),
      renderBetaRecoveryActions(arrayValue(data.recoveryActions)),
    );
  }

  function renderBetaWarningList(warnings) {
    const card = document.createElement("section");
    card.className = "alert-card";
    card.append(text("h3", "alert-card-title", "Operator warnings"));
    const list = document.createElement("ul");
    list.className = "permission-list";
    warnings.forEach((warning) => {
      const item = document.createElement("li");
      item.textContent = warning;
      list.append(item);
    });
    card.append(list);
    return card;
  }

  function renderThirdPartyIntake(intake) {
    const group = document.createElement("section");
    group.className = "diagnostics-section";
    group.append(text("h3", "diagnostics-section-title", "Third-party app intake"));
    if (!intake || Object.keys(intake).length === 0) {
      group.append(text("p", "empty-state", "Submission intake status is unavailable."));
      return group;
    }
    const submissions = arrayValue(intake.submissions).map(recordValue);
    const warnings = stringList(intake.warnings);
    const list = document.createElement("div");
    list.className = "app-card-list";
    list.append(
      summaryCard(
        intake.configured === true ? "Queue configured" : "Queue not configured",
        [
          ["Submissions", scalar(intake.queueCount ?? submissions.length)],
          ["Operator route", scalar(intake.route)],
          ["Operator-only", yesNoText(intake.operatorOnly, true)],
          ["App contract", intake.operatorRoutesInAppContract === false ? "Internal" : "Unknown"],
        ],
        intake.configured === true ? "" : "is-warning",
      ),
    );
    submissions.slice(0, 8).forEach((submission) => {
      const submissionWarnings = stringList(submission.warnings);
      const tone = intakeSubmissionTone(submission);
      const card = document.createElement("article");
      card.className = tone ? `app-card ${tone}` : "app-card";
      card.append(
        betaCardHeader(
          submission.appId || submission.submissionId || "Submission",
          normalizedStatus(submission.status, "Unknown"),
          tone,
        ),
        definitionList([
          ["Submission ID", submission.submissionId],
          ["Version", submission.appVersion],
          ["Reviewer", submission.reviewerDisplayName || submission.reviewerKeyId],
          ["Pre-review", normalizedStatus(submission.preReviewStatus, "Not run")],
          ["Decision", normalizedStatus(submission.decision, "Pending")],
          ["Catalog candidate", submission.catalogCandidateCreated ? "Created" : "None"],
          ["Beta channel", submission.betaCatalogChannel],
          ["Install smoke", normalizedStatus(submission.installSmokeStatus, "Pending")],
          ["Transparency digest", submission.transparencyLogDigest],
          ["Redaction", normalizedStatus(submission.redactionStatus, "Unknown")],
          ["Non-production", yesNoText(submission.nonProduction, false)],
        ]),
      );
      if (submissionWarnings.length) {
        card.append(renderCompactWarningText(submissionWarnings));
      }
      list.append(card);
    });
    group.append(list);
    if (warnings.length) {
      group.append(renderCompactWarningText(warnings));
    }
    return group;
  }

  function intakeSubmissionTone(submission) {
    const status = typeof submission.status === "string" ? submission.status : "";
    const redaction = typeof submission.redactionStatus === "string" ? submission.redactionStatus : "";
    const decision = typeof submission.decision === "string" ? submission.decision : "";
    if (redaction === "fail" || status === "rejected" || decision === "rejected") {
      return "is-error";
    }
    if (
      status === "caution" ||
      decision === "caution" ||
      status === "resubmission_requested" ||
      status === "pre_review_failed"
    ) {
      return "is-warning";
    }
    if (status === "beta_install_smoke_passed" || submission.installSmokeStatus === "pass") {
      return "is-success";
    }
    return "";
  }

  function renderSecurityResponseSummary(response) {
    const safeResponse = recordValue(response);
    const group = document.createElement("section");
    group.className = "diagnostics-section";
    group.append(text("h3", "diagnostics-section-title", "Production security response"));
    const summary = recordValue(safeResponse.summary);
    const advisories = arrayValue(safeResponse.activeAdvisories).map(recordValue);
    const denylistedVersions = arrayValue(safeResponse.denylistedVersions).map(recordValue);
    const reviewerGovernance = recordValue(safeResponse.reviewerGovernance);
    const catalogSigningKeys = arrayValue(safeResponse.catalogSigningKeys).map(recordValue);
    const securityDrills = recordValue(safeResponse.securityDrills);
    const registryCounts = recordValue(reviewerGovernance.counts);
    const status = typeof safeResponse.status === "string" ? safeResponse.status : "unavailable";
    const list = document.createElement("div");
    list.className = "app-card-list";

    const overview = document.createElement("article");
    overview.className = securityResponseTone(status) ? `app-card ${securityResponseTone(status)}` : "app-card";
    overview.append(
      betaCardHeader("Security response", normalizedStatus(status, "Unavailable"), securityResponseTone(status)),
      definitionList([
        ["Active advisories", scalar(summary.activeAdvisoryCount)],
        ["Denylisted versions", scalar(summary.denylistedVersionCount)],
        ["Installed vulnerable apps", scalar(summary.installedVulnerableAppCount)],
        ["Revoked reviewer keys", scalar(summary.revokedReviewerKeyCount ?? registryCounts.revoked)],
        ["Revoked receipts", scalar(summary.revokedReceiptCount)],
        ["Catalog signing keys", scalar(summary.catalogSigningKeyCount)],
        ["Catalog key rotation", normalizedStatus(summary.catalogKeyRotationStatus, "Unavailable")],
        ["Emergency replacement guidance", yesNoText(summary.emergencyReplacementGuidanceAvailable, null)],
        ["Support redaction", normalizedStatus(summary.supportRedactionStatus, "Unavailable")],
        ["Security drills", normalizedStatus(summary.securityDrillsStatus, "Unavailable")],
        ["Last drill status", normalizedStatus(summary.securityDrillsLastStatus, "Unavailable")],
      ]),
      renderSecurityResponseActionLabels(arrayValue(safeResponse.operatorActions)),
    );
    list.append(overview);

    if (advisories.length) {
      list.append(renderSecurityResponseRecordCard("Active advisories", advisories, securityResponseAdvisoryLine));
    }
    if (denylistedVersions.length) {
      list.append(
        renderSecurityResponseRecordCard("Denylisted app versions", denylistedVersions, securityResponseDenylistLine),
      );
    }
    if (catalogSigningKeys.length) {
      list.append(
        renderSecurityResponseRecordCard("Catalog signing keys", catalogSigningKeys, securityResponseCatalogKeyLine),
      );
    }
    if (Object.keys(securityDrills).length) {
      list.append(renderSecurityDrillsSummaryCard(securityDrills));
    }
    if (typeof safeResponse.supportGuidance === "string" && safeResponse.supportGuidance.length) {
      const support = document.createElement("article");
      support.className = "app-card";
      support.append(
        betaCardHeader("Support handling", "redacted", ""),
        text("p", "empty-state", safeResponse.supportGuidance),
      );
      list.append(support);
    }
    group.append(list);
    return group;
  }

  function renderSecurityDrillsSummaryCard(securityDrills) {
    const status = typeof securityDrills.status === "string" ? securityDrills.status : "unavailable";
    const card = document.createElement("article");
    card.className = securityResponseTone(status) ? `app-card ${securityResponseTone(status)}` : "app-card";
    card.append(
      betaCardHeader("Security drills", normalizedStatus(status, "Unavailable"), securityResponseTone(status)),
      definitionList([
        ["Last status", normalizedStatus(securityDrills.lastStatus, "Unavailable")],
        ["Promotion ready", yesNoText(securityDrills.promotionReady, false)],
        ["Required scenarios", scalar(securityDrills.requiredScenarioCount)],
        ["Redaction", normalizedStatus(securityDrills.redactionStatus, "Unavailable")],
        ["Artifact", scalar(securityDrills.artifactKind)],
      ]),
    );
    if (typeof securityDrills.summary === "string" && securityDrills.summary.length) {
      card.append(text("p", "empty-state", securityDrills.summary));
    }
    return card;
  }

  function securityResponseTone(status) {
    if (status === "denylist_active") {
      return "is-error";
    }
    if (
      status === "advisory_active" ||
      status === "reviewer_revocation_active" ||
      status === "unavailable"
    ) {
      return "is-warning";
    }
    return "";
  }

  function renderSecurityResponseActionLabels(actions) {
    const list = document.createElement("ul");
    list.className = "permission-list";
    actions.slice(0, 6).forEach((actionValue) => {
      const action = recordValue(actionValue);
      const label = typeof action.label === "string" && action.label ? action.label : action.id;
      if (typeof label === "string" && label.length) {
        const item = document.createElement("li");
        item.textContent = label;
        list.append(item);
      }
    });
    return list;
  }

  function renderSecurityResponseRecordCard(title, records, lineFormatter) {
    const card = document.createElement("article");
    card.className = "app-card is-warning";
    const list = document.createElement("ul");
    list.className = "permission-list";
    records.slice(0, 6).forEach((record) => {
      const item = document.createElement("li");
      item.textContent = lineFormatter(record);
      list.append(item);
    });
    card.append(betaCardHeader(title, `${records.length}`, "is-warning"), list);
    return card;
  }

  function securityResponseAdvisoryLine(advisory) {
    return [
      scalar(advisory.id),
      normalizedStatus(advisory.severity, "Unknown"),
      normalizedStatus(advisory.action, "Unknown"),
      scalar(advisory.replacementAppId),
    ].join(" / ");
  }

  function securityResponseDenylistLine(denylistEntry) {
    return [
      scalar(denylistEntry.appId),
      scalar(denylistEntry.version),
      scalar(denylistEntry.advisoryId),
      scalar(denylistEntry.replacementAppId),
    ].join(" / ");
  }

  function securityResponseCatalogKeyLine(catalogKey) {
    return [
      scalar(catalogKey.catalogId),
      scalar(catalogKey.keyId),
      normalizedStatus(catalogKey.rotationStatus, "Unavailable"),
    ].join(" / ");
  }

  function renderBetaCatalogs(catalogs) {
    const group = document.createElement("section");
    group.className = "diagnostics-section";
    group.append(text("h3", "diagnostics-section-title", "Catalog health"));
    if (!catalogs.length) {
      group.append(text("p", "empty-state", "No catalog health entries were returned."));
      return group;
    }
    const list = document.createElement("div");
    list.className = "app-card-list";
    catalogs.forEach((catalog) => {
      const card = document.createElement("article");
      card.className = "app-card";
      const warnings = stringList(catalog.warnings);
      card.append(
        betaCardHeader(
          catalog.name || catalog.catalogId || "Catalog",
          catalog.sourceKind || "unknown",
          warnings.length ? "is-warning" : operatorStatusTone(catalog.lastFetchStatus),
        ),
        definitionList([
          ["Catalog ID", catalog.catalogId],
          ["Source", catalog.sourceDisplay],
          ["Trusted key", normalizedStatus(catalog.trustedCatalogKeyStatus, "Unknown")],
          ["Last status", normalizedStatus(catalog.lastFetchStatus, "Unknown")],
          ["Last success", formatIsoTimestamp(catalog.lastSuccessfulRefreshAt)],
          ["Entries", scalar(catalog.entryCount)],
        ]),
        renderBetaActionList(arrayValue(catalog.recoveryActions), 2),
      );
      list.append(card);
    });
    group.append(list);
    return group;
  }

  function renderBetaApps(apps) {
    const group = document.createElement("section");
    group.className = "diagnostics-section";
    group.append(text("h3", "diagnostics-section-title", "App health and recovery"));
    if (!apps.length) {
      group.append(text("p", "empty-state", "No installed app health entries were returned."));
      return group;
    }
    const list = document.createElement("div");
    list.className = "app-card-list";
    apps.forEach((app) => {
      const update = recordValue(app.update);
      const warnings = stringList(app.warnings);
      const quota = recordValue(app.quota);
      const sandbox = recordValue(app.sandbox);
      const card = document.createElement("article");
      card.className = warnings.length ? "app-card is-warning" : "app-card";
      card.append(
        betaCardHeader(
          app.name || app.appId || "App",
          app.running ? "running" : "stopped",
          warnings.length ? "is-warning" : app.running ? "is-success" : "",
        ),
        definitionList([
          ["App ID", app.appId],
          ["Version", app.version],
          ["Signed bundle", normalizedStatus(app.signedBundleStatus, "Unknown")],
          ["Sandbox", `${normalizedStatus(sandbox.provider, "Unknown")} / ${normalizedStatus(sandbox.supportLevel, "Unknown")}`],
          ["Update", normalizedStatus(appUpdateStatus(update), "Unavailable")],
          ["Staged", stagedUpdateAvailable(update) ? "Available" : "None"],
          ["Rollback", recordValue(update.rollback).available ? "Available" : "None"],
          ["Data quota", quota.dataOverLimit || quota.cacheOverLimit ? "Over limit" : "Within current limits"],
        ]),
        renderBetaActionList(arrayValue(app.recoveryActions), 5),
      );
      if (warnings.length) {
        card.append(renderCompactWarningText(warnings));
      }
      list.append(card);
    });
    group.append(list);
    return group;
  }

  function renderBetaSubscriptions(subscriptions) {
    const group = document.createElement("section");
    group.className = "diagnostics-section";
    group.append(text("h3", "diagnostics-section-title", "Content subscriptions"));
    if (!subscriptions.length) {
      group.append(text("p", "empty-state", "No content subscription summaries were returned."));
      return group;
    }
    const list = document.createElement("div");
    list.className = "app-card-list";
    subscriptions.forEach((subscription) => {
      const warnings = stringList(subscription.warnings);
      const card = document.createElement("article");
      card.className = warnings.length ? "app-card is-warning" : "app-card";
      card.append(
        betaCardHeader(
          subscription.label || subscription.subscriptionId || "Subscription",
          subscription.status || "unknown",
          warnings.length ? "is-warning" : operatorStatusTone(subscription.status),
        ),
        definitionList([
          ["App", subscription.appId],
          ["Subscription ID", subscription.subscriptionId],
          ["Source", subscription.sourceDisplay],
          ["Last success", formatIsoTimestamp(subscription.lastSuccessAt)],
          ["Last failure", formatIsoTimestamp(subscription.lastFailureAt)],
          ["Next due", formatIsoTimestamp(subscription.nextCheckAt)],
          ["Failures", scalar(subscription.failureCount)],
          ["Last edition", scalar(subscription.lastSeenEdition)],
        ]),
        renderBetaActionList(arrayValue(subscription.recoveryActions), 3),
      );
      if (warnings.length) {
        card.append(renderCompactWarningText(warnings));
      }
      list.append(card);
    });
    group.append(list);
    return group;
  }

  function renderBetaTrustAndServices(trustGraph, appServices) {
    const group = document.createElement("section");
    group.className = "diagnostics-section";
    group.append(text("h3", "diagnostics-section-title", "Trust Graph Local RC and app-service grants"));
    const list = document.createElement("div");
    list.className = "app-card-list";
    const scope = recordValue(trustGraph.scope);
    const lifecycle = recordValue(trustGraph.statementLifecycle);
    const trustCard = document.createElement("article");
    trustCard.className = "app-card";
    trustCard.append(
      betaCardHeader("Trust Graph Local RC", "local operator-curated", "is-warning"),
      definitionList([
        ["Mode", scalar(trustGraph.mode || "local-rc")],
        ["Local anchors only", yesNoText(scope.localAnchorsOnly, true)],
        ["Imported statements only", yesNoText(scope.importedStatementsOnly, true)],
        ["No crawling", yesNoText(scope.noCrawling, true)],
        ["No global moderation", yesNoText(scope.noGlobalModeration, true)],
        ["No blocking policy", yesNoText(scope.noBlocking, true)],
        ["No routing decisions", yesNoText(scope.noRoutingDecisions, true)],
        ["No legacy WoT/Freetalk/Sone/Freemail", yesNoText(scope.noLegacyWoTCompatibility, true)],
        ["Revoked contributes", yesNoText(lifecycle.revokedContributes, false)],
        ["Deprecated contributes", yesNoText(lifecycle.deprecatedContributes, false)],
        ["Global Web of Trust", trustGraph.completeWot ? "Yes" : "No"],
        ["Durable", scalar(trustGraph.durable)],
        ["Anchors", scalar(trustGraph.anchorCount)],
        ["Statements", scalar(trustGraph.statementCount)],
        ["Audit entries", scalar(trustGraph.auditCount)],
      ]),
      renderTrustGraphScopeNotes(),
      renderCompactWarningText(stringList(trustGraph.warnings)),
    );
    const servicesCard = document.createElement("article");
    servicesCard.className = "app-card";
    servicesCard.append(
      betaCardHeader(
        "App-service grants",
        `${scalar(appServices.pendingGrantCount)} pending`,
        appServices.pendingGrantCount ? "is-warning" : "",
      ),
      definitionList([
        ["Services", scalar(appServices.serviceCount)],
        ["Requests", scalar(appServices.requestCount)],
        ["Pending grants", scalar(appServices.pendingGrantCount)],
        ["Active grants", scalar(appServices.activeGrantCount)],
        ["Revoked/inactive", scalar(appServices.revokedOrInactiveGrantCount)],
      ]),
    );
    const grantsLink = document.createElement("a");
    grantsLink.className = "button button-secondary";
    grantsLink.href = "#apps";
    grantsLink.textContent = "Review grants";
    servicesCard.append(grantsLink);
    list.append(trustCard, servicesCard);
    group.append(list);
    return group;
  }

  function renderTrustGraphScopeNotes() {
    const list = document.createElement("ul");
    list.className = "permission-list trust-scope-notes";
    [
      "Local trust only; it is not global truth.",
      "Not moderation, not blocking, not routing policy, not peer selection, and not network crawling.",
      "No legacy WoT, Freetalk, Sone, Freemail, or old WebOfTrust plugin compatibility promise.",
    ].forEach((note) => {
      const item = document.createElement("li");
      item.textContent = note;
      list.append(item);
    });
    return list;
  }

  function yesNoText(value, fallback) {
    const effective = typeof value === "boolean" ? value : fallback;
    if (effective === true) {
      return "Yes";
    }
    if (effective === false) {
      return "No";
    }
    return "Unavailable";
  }

  function renderBetaRecoveryActions(actions) {
    const group = document.createElement("section");
    group.className = "diagnostics-section";
    group.append(text("h3", "diagnostics-section-title", "Safe recovery actions"));
    const rendered = renderBetaActionList(actions, 18);
    if (!rendered.childElementCount) {
      group.append(text("p", "empty-state", "No recovery actions are currently available."));
      return group;
    }
    group.append(rendered);
    return group;
  }

  function renderOperatorRcRecovery(recovery, networkBudgets) {
    const group = document.createElement("section");
    group.className = "diagnostics-section";
    group.append(text("h3", "diagnostics-section-title", "Operator RC Recovery"));
    const actionGroups = recordValue(recovery.actions);
    const networkSnapshots = arrayValue(networkBudgets.snapshots);
    const summaryCards = document.createElement("div");
    summaryCards.className = "app-card-list";
    summaryCards.append(
      summaryCard(
        normalizedStatus(recovery.status || "unavailable", "Unavailable"),
        [
          ["Plan before execute", yesNoText(recovery.planBeforeExecute, false)],
          ["Closed action dispatch", yesNoText(recovery.closedActionDispatch, false)],
          ["Recent recovery events", scalar(arrayValue(recovery.recentAudit).length)],
        ],
        recovery.status === "available" ? "is-success" : "is-warning",
      ),
      summaryCard(
        "Network budgets",
        [
          ["Available", yesNoText(networkBudgets.available, false)],
          ["Snapshots", scalar(networkSnapshots.length)],
          ["Safe fields", "app id, operation, window, counts, limits"],
        ],
        networkBudgets.available === true ? "" : "is-warning",
      ),
    );
    group.append(summaryCards);

    const categories = Object.keys(actionGroups);
    if (!categories.length) {
      group.append(text("p", "empty-state", "No typed RC recovery actions were returned."));
      return group;
    }

    const list = document.createElement("div");
    list.className = "app-card-list operator-rc-action-list";
    categories.forEach((category) => {
      const actions = arrayValue(actionGroups[category]);
      if (!actions.length) {
        return;
      }
      const card = document.createElement("article");
      card.className = "app-card";
      card.append(betaCardHeader(operatorRecoveryCategoryLabel(category), `${actions.length} actions`, ""));
      const forms = document.createElement("div");
      forms.className = "app-card-actions operator-rc-action-forms";
      actions.forEach((action) => {
        const form = buildOperatorRcRecoveryAction(action);
        if (form) {
          forms.append(form);
        }
      });
      card.append(forms);
      list.append(card);
    });
    group.append(list);
    return group;
  }

  function operatorRecoveryCategoryLabel(category) {
    switch (category) {
      case "catalog":
        return "Catalog health and repair";
      case "app":
        return "App lifecycle and update";
      case "subscription":
        return "Content subscriptions";
      case "app-service":
        return "App-service grants and bundles";
      case "trust-graph":
        return "Trust Graph Local RC";
      case "network-budget":
        return "Network budgets";
      case "support":
        return "Support bundle";
      default:
        return normalizedStatus(category, "Recovery");
    }
  }

  function betaCardHeader(title, subtitle, tone) {
    const header = document.createElement("div");
    header.className = "app-card-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(text("h3", "app-card-title", title), text("p", "app-card-subtitle", subtitle));
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill(subtitle, tone));
    header.append(heading, pills);
    return header;
  }

  function renderCompactWarningText(warnings) {
    const textNode = text("p", "error-state", warnings.join(" • "));
    if (!warnings.length) {
      textNode.hidden = true;
    }
    return textNode;
  }

  function renderBetaActionList(actions, limit) {
    const container = document.createElement("div");
    container.className = "app-card-actions";
    actions
      .filter((action) => operatorRecoveryActionVisible(action))
      .slice(0, limit)
      .forEach((action) => {
        const node = buildOperatorRecoveryAction(action);
        if (node) {
          container.append(node);
        }
      });
    return container;
  }

  function operatorRecoveryActionVisible(action) {
    const actionId = typeof action?.id === "string" ? action.id : "";
    return actionId !== "preserve-data-uninstall";
  }

  function buildOperatorRecoveryAction(action) {
    if (!action || typeof action.path !== "string" || typeof action.method !== "string") {
      return null;
    }
    const method = action.method.toUpperCase();
    const label = typeof action.label === "string" && action.label ? action.label : action.id || method;
    if (method === "GET") {
      const link = document.createElement("a");
      link.className = "button button-secondary";
      link.href = apiUrl(action.path);
      link.textContent = label;
      return link;
    }
    const form = document.createElement("form");
    form.className = "app-action-form";
    form.dataset.operatorRecoveryMethod = method;
    form.dataset.operatorRecoveryPath = action.path;
    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = label;
    submit.disabled = !formPassword || action.available === false;
    form.append(submit);
    return form;
  }

  function buildOperatorRcRecoveryAction(action) {
    const actionId = typeof action?.actionId === "string" ? action.actionId : "";
    if (!actionId) {
      return null;
    }
    const form = document.createElement("form");
    form.className = "app-action-form operator-rc-action-form";
    form.dataset.operatorRcRecoveryActionId = actionId;
    form.dataset.operatorRcRecoveryPlanned = "false";
    const actionInput = document.createElement("input");
    actionInput.type = "hidden";
    actionInput.name = "actionId";
    actionInput.value = actionId;
    form.append(actionInput);
    const planTokenInput = document.createElement("input");
    planTokenInput.type = "hidden";
    planTokenInput.name = "planToken";
    form.append(planTokenInput);
    form.append(
      text(
        "p",
        "app-card-subtitle",
        typeof action.description === "string" ? action.description : actionId,
      ),
    );

    arrayValue(action.targetFields).forEach((fieldName) => {
      if (typeof fieldName !== "string" || !fieldName) {
        return;
      }
      const label = document.createElement("label");
      label.className = "queue-field operator-rc-target-field";
      label.append(text("span", "", fieldName));
      const input = document.createElement("input");
      input.name = fieldName;
      input.autocomplete = "off";
      input.spellcheck = false;
      input.placeholder = fieldName;
      input.addEventListener("input", () => {
        form.dataset.operatorRcRecoveryPlanned = "false";
        planTokenInput.value = "";
      });
      label.append(input);
      form.append(label);
    });

    if (action.destructive === true) {
      const confirmLabel = document.createElement("label");
      confirmLabel.className = "queue-checkbox";
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.name = "confirm";
      checkbox.value = "true";
      confirmLabel.append(checkbox, document.createTextNode(" Confirm destructive action"));
      form.append(confirmLabel);

      const phraseLabel = document.createElement("label");
      phraseLabel.className = "queue-field operator-rc-confirmation-field";
      phraseLabel.append(text("span", "", "confirmationPhrase"));
      const phrase = document.createElement("input");
      phrase.name = "confirmationPhrase";
      phrase.autocomplete = "off";
      phrase.spellcheck = false;
      phrase.placeholder = "Use phrase from plan";
      phraseLabel.append(phrase);
      form.append(phraseLabel);
    }

    const buttons = document.createElement("div");
    buttons.className = "app-card-actions";
    buttons.append(
      operatorRcSubmitButton("Plan", "plan", false),
      operatorRcSubmitButton("Execute", "execute", action.destructive === true),
    );
    form.append(buttons);
    const result = document.createElement("div");
    result.className = "app-data-restore-result operator-rc-plan-result";
    result.hidden = true;
    form.append(result);
    return form;
  }

  function operatorRcSubmitButton(label, action, destructive) {
    const button = document.createElement("button");
    button.className = destructive ? "button button-danger" : "button button-secondary";
    button.type = "submit";
    button.textContent = label;
    button.dataset.operatorRcRecoverySubmit = action;
    button.disabled = !formPassword;
    return button;
  }

  function operatorStatusTone(status) {
    const normalized = typeof status === "string" ? status.toLowerCase() : "";
    if (normalized.includes("healthy") || normalized.includes("success") || normalized.includes("active")) {
      return "is-success";
    }
    if (
      normalized.includes("warning") ||
      normalized.includes("stale") ||
      normalized.includes("backoff") ||
      normalized.includes("pending")
    ) {
      return "is-warning";
    }
    if (normalized.includes("required") || normalized.includes("unavailable") || normalized.includes("failed")) {
      return "is-error";
    }
    return "";
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
      card.append(text("p", "empty-state", "No diagnostic lines were returned."));
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

  function redactedDiagnosticsSnapshot(data) {
    if (!data || typeof data !== "object") {
      return data;
    }
    const redacted = { ...data };
    delete redacted.plainTextExport;
    delete redacted.export;
    delete redacted.textExport;
    return redacted;
  }

  function renderDiagnostics(data) {
    shellState.diagnosticsSnapshot = redactedDiagnosticsSnapshot(data);
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
    sections.security.append(renderSecurityLegacyFallbackAction());
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
    sections.updates.append(renderSupportLifecycle(data.supportLifecycle));
  }

  function lifecycleBuildLabel(value) {
    return Number.isInteger(value) && value > 0 ? `v${value}` : "Unknown";
  }

  function supportLifecyclePresentation(lifecycle) {
    if (!lifecycle || lifecycle.known !== true) {
      return {
        label: "Unknown",
        guidance: "No authenticated local lifecycle state is available. Support must not be assumed.",
        tone: "is-warning",
      };
    }
    const presentations = {
      "current-stable": {
        label: "Current stable",
        guidance: "This build is the authenticated current Stable 1.0 release.",
        tone: "",
      },
      "supported-maintenance": {
        label: "Supported maintenance",
        guidance: "This build remains fully supported; upgrading to the current build is recommended.",
        tone: "",
      },
      "security-fixes-only": {
        label: "Security fixes only",
        guidance: "Full maintenance has ended. Prioritize an authenticated security update.",
        tone: "is-warning",
      },
      deprecated: {
        label: "Deprecated",
        guidance: "Persistent upgrade guidance is active for this build.",
        tone: "is-warning",
      },
      "end-of-support": {
        label: "End of support",
        guidance: "This build is unsupported. Normal browsing and local data remain available while you upgrade.",
        tone: "is-warning",
      },
      revoked: {
        label: "Revoked build",
        guidance: "An authenticated security decision marks this build unsafe. Follow only the verified replacement or recovery guidance shown here.",
        tone: "is-warning",
      },
    };
    const presentation = presentations[lifecycle.runningStatus] || {
      label: "Unknown",
      guidance: "The lifecycle status is not recognized. Support must not be assumed.",
      tone: "is-warning",
    };
    if (lifecycle.stale !== true) {
      return presentation;
    }
    const terminalStatus =
      lifecycle.runningStatus === "end-of-support" || lifecycle.runningStatus === "revoked";
    if (terminalStatus) {
      return {
        label: `${presentation.label} — descriptor stale`,
        guidance: `${presentation.guidance} The last-known-good descriptor is also stale; refresh it without treating this build as supported or safe.`,
        tone: "is-warning",
      };
    }
    return {
      label: "Stale — verification required",
      guidance: "The last-known-good descriptor is stale. Refresh it before relying on support claims.",
      tone: "is-warning",
    };
  }

  function renderSupportLifecycle(lifecycle) {
    const safeLifecycle = lifecycle && typeof lifecycle === "object" ? lifecycle : {};
    const presentation = supportLifecyclePresentation(safeLifecycle);
    const advisoryIds = Array.isArray(safeLifecycle.advisoryIds)
      ? safeLifecycle.advisoryIds.join(", ")
      : "";
    const warnings = Array.isArray(safeLifecycle.warnings)
      ? safeLifecycle.warnings.join(", ")
      : "";
    return summaryCard("Stable 1.0 support lifecycle", [
      ["Status", presentation.label],
      ["Running build", lifecycleBuildLabel(safeLifecycle.runningBuild)],
      ["Current stable", lifecycleBuildLabel(safeLifecycle.currentStableBuild)],
      ["Recommended", lifecycleBuildLabel(safeLifecycle.recommendedBuild)],
      ["Full support until", safeLifecycle.fullSupportUntil || "Not available"],
      ["Security fixes until", safeLifecycle.securityFixesUntil || "Not available"],
      ["End of support", safeLifecycle.endOfSupportAt || "Not available"],
      ["Required replacement", lifecycleBuildLabel(safeLifecycle.requiredReplacementBuild)],
      ["Recovery guidance", safeLifecycle.recoveryGuidance || "Not available"],
      ["Advisories", advisoryIds || "None published"],
      ["Descriptor edition", safeLifecycle.descriptorEdition ?? "Unknown"],
      ["Last verified", safeLifecycle.lastVerifiedAt || "Never"],
      ["Guidance", presentation.guidance],
      ["Warnings", warnings || "None"],
    ], presentation.tone);
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

  function appDataBackupFormDataForApp(appId) {
    if (typeof appId !== "string" || appId.length === 0) {
      return null;
    }
    const formData = new FormData();
    formData.set("appId", appId);
    return formData;
  }

  function allAppDataBackupFormData() {
    const formData = new FormData();
    formData.set("scope", "all");
    return formData;
  }

  function appendHiddenField(form, name, value) {
    const input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    input.value = value;
    form.append(input);
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

  function appUpdatesPath(appId, action) {
    if (typeof appId !== "string" || appId.length === 0) {
      return null;
    }
    const basePath = `apps/${encodeURIComponent(appId)}/updates`;
    switch (action) {
      case "check":
      case "stage":
      case "apply":
      case "rollback":
        return `${basePath}/${action}`;
      case "summary":
        return basePath;
      default:
        return null;
    }
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
    if (action === "refreshPrimary") {
      return `app-catalogs/${encodedCatalogId}/operations/refresh-primary`;
    }
    if (action === "emergencyRefresh") {
      return `app-catalogs/${encodedCatalogId}/operations/emergency-refresh`;
    }
    if (action === "rollback") {
      return `app-catalogs/${encodedCatalogId}/operations/rollback`;
    }
    if (action === "addRecommended") {
      return `app-catalogs/recommended/${encodedCatalogId}/add`;
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

  function identityVaultGrantPath(grantId) {
    return typeof grantId === "string" && grantId.length > 0
      ? `identity-vault/grants/${encodeURIComponent(grantId)}`
      : null;
  }

  function appServiceGrantPath(grantId, action) {
    return typeof grantId === "string" &&
      grantId.length > 0 &&
      typeof action === "string" &&
      action.length > 0
      ? `app-services/grants/${encodeURIComponent(grantId)}/${encodeURIComponent(action)}`
      : null;
  }

  function appServiceBundlePath(bundleId, action) {
    return typeof bundleId === "string" &&
      bundleId.length > 0 &&
      typeof action === "string" &&
      action.length > 0
      ? `app-services/grant-bundles/${encodeURIComponent(bundleId)}/${encodeURIComponent(action)}`
      : null;
  }

  function consentInstallPreviewPath(catalogId, appId) {
    return typeof catalogId === "string" &&
      catalogId.length > 0 &&
      typeof appId === "string" &&
      appId.length > 0
      ? `consent/install-preview?catalogId=${encodeURIComponent(catalogId)}&appId=${encodeURIComponent(appId)}`
      : null;
  }

  function consentCatalogUpdatePreviewPath(catalogId, appId) {
    return typeof catalogId === "string" &&
      catalogId.length > 0 &&
      typeof appId === "string" &&
      appId.length > 0
      ? `consent/catalog-update-preview?catalogId=${encodeURIComponent(catalogId)}&appId=${encodeURIComponent(appId)}`
      : null;
  }

  function consentUpdatePreviewPath(appId) {
    return typeof appId === "string" && appId.length > 0
      ? "consent/update-preview"
      : null;
  }

  function consentServiceGrantPreviewPath(bundleId) {
    return typeof bundleId === "string" && bundleId.length > 0
      ? `consent/service-grant-preview?bundleId=${encodeURIComponent(bundleId)}`
      : null;
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
    const registeredOrigin = registeredAppUiOrigin(app);
    if (!registeredOrigin) {
      return null;
    }
    try {
      const url = new URL(isolatedOriginProbePath, registeredOrigin);
      if (!allowedAppUiOrigin(url, app)) {
        return null;
      }
      if (url.pathname !== isolatedOriginProbePath || url.search !== "" || url.hash !== "") {
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
      registeredAppUiOrigin(app) &&
      typeof app.appId === "string" &&
      app.appId.length > 0
    ) {
      link.dataset.isolatedLaunchHref = isolatedLaunchHref;
      link.dataset.isolatedProbeHref = isolatedProbeHref;
      link.dataset.isolatedAppId = app.appId;
      link.dataset.isolatedUiOrigin = registeredAppUiOrigin(app);
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
    const expectedOrigin = link.dataset.isolatedUiOrigin || "";
    const safeFallbackHref = normalizeLaunchFallbackHref(fallbackHref);
    const safeIsolatedLaunchHref = normalizeIsolatedLaunchHref(isolatedLaunchHref);
    const safeProbeHref = normalizeIsolatedProbeHref(probeHref, expectedOrigin);
    if (
      safeIsolatedLaunchHref &&
      safeProbeHref &&
      await isolatedAppOriginReachable(safeProbeHref, expectedAppId, expectedOrigin)
    ) {
      window.location.assign(safeIsolatedLaunchHref);
      return;
    }
    if (safeFallbackHref) {
      window.location.assign(safeFallbackHref);
    }
  }

  function normalizeLaunchFallbackHref(value) {
    if (!value) {
      return null;
    }
    try {
      return safeSameOriginAppUiHref(new URL(value, window.location.origin), false);
    } catch (error) {
      return null;
    }
  }

  function normalizeIsolatedLaunchHref(value) {
    if (!value) {
      return null;
    }
    try {
      return safeSameOriginAppUiHref(new URL(value, window.location.origin), true);
    } catch (error) {
      return null;
    }
  }

  function normalizeIsolatedProbeHref(value, expectedOrigin) {
    if (!value || !expectedOrigin) {
      return null;
    }
    try {
      const expected = new URL(expectedOrigin);
      const url = new URL(value);
      if (
        expected.protocol !== "http:" ||
        expected.hostname.toLowerCase() !== "127.0.0.1" ||
        expected.port === "" ||
        expected.username ||
        expected.password ||
        expected.search !== "" ||
        expected.hash !== "" ||
        expected.pathname !== "/" ||
        url.origin !== expected.origin ||
        url.protocol !== "http:" ||
        url.hostname.toLowerCase() !== "127.0.0.1" ||
        url.port === "" ||
        url.username ||
        url.password ||
        url.pathname !== isolatedOriginProbePath ||
        url.search !== "" ||
        url.hash !== ""
      ) {
        return null;
      }
      return url.href;
    } catch (error) {
      return null;
    }
  }

  async function isolatedAppOriginReachable(probeHref, expectedAppId, expectedOrigin) {
    if (!probeHref || !expectedAppId || !expectedOrigin) {
      return false;
    }
    const controller = typeof AbortController === "function" ? new AbortController() : null;
    const timeoutId = controller
      ? window.setTimeout(() => controller.abort(), 1000)
      : null;
    try {
      const probeOrigin = new URL(probeHref).origin;
      if (probeOrigin !== expectedOrigin) {
        return false;
      }
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

  function buildAppActionForm(app, action, label, options = {}) {
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
    if (options && options.uninstallMode) {
      form.dataset.appUninstallMode = options.uninstallMode;
    }
    for (const [name, value] of Object.entries(recordValue(options && options.hiddenFields))) {
      appendHiddenField(form, name, value);
    }

    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = label;
    form.append(submit);
    return form;
  }

  function buildAppDataBackupActionForm(app, action, label) {
    const appId = typeof app.appId === "string" ? app.appId : "";
    if (!appDataBackupFormDataForApp(appId)) {
      return null;
    }
    const form = document.createElement("form");
    form.className = "app-action-form";
    form.dataset.appId = appId;
    form.dataset.appName = appDisplayName(app);
    form.dataset.appDataBackupAction = action;

    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = label;
    form.append(submit);
    return form;
  }

  function buildAppDataRestoreDetails(app) {
    const appId = typeof app.appId === "string" ? app.appId : "";
    if (!appId) {
      return null;
    }
    const details = document.createElement("details");
    details.className = "json-details app-data-restore-details";
    const summary = document.createElement("summary");
    summary.textContent = "Restore app data";
    details.append(summary);

    const form = document.createElement("form");
    form.className = "control-form app-data-restore-form";
    form.dataset.appDataRestoreAction = "app";
    form.dataset.appId = appId;
    form.dataset.appName = appDisplayName(app);

    const description = text(
      "p",
      "panel-description",
      "App-data backups contain sensitive user data. Restore previews show metadata only.",
    );
    const grid = document.createElement("div");
    grid.className = "control-form-grid";

    const payloadField = document.createElement("label");
    payloadField.className = "queue-field app-data-restore-payload";
    payloadField.append(text("span", "", "Sensitive backup payload"));
    const payloadInput = document.createElement("textarea");
    payloadInput.name = "backupPayload";
    payloadInput.autocomplete = "off";
    payloadInput.spellcheck = false;
    payloadInput.required = true;
    payloadField.append(payloadInput);

    const modeField = selectField("Restore mode", "mode", [
      ["merge", "Merge"],
      ["replaceNamespace", "Replace namespace"],
      ["replaceApp", "Replace app"],
    ]);
    appendHiddenField(form, "appId", appId);
    grid.append(payloadField, modeField);

    const actions = document.createElement("div");
    actions.className = "control-form-actions";
    const preview = document.createElement("button");
    preview.className = "button button-secondary";
    preview.name = "restoreAction";
    preview.type = "submit";
    preview.value = "preview";
    preview.textContent = "Preview restore";
    const restore = document.createElement("button");
    restore.className = "button button-primary";
    restore.name = "restoreAction";
    restore.type = "submit";
    restore.value = "restore";
    restore.textContent = "Restore app data";
    actions.append(preview, restore);

    const result = document.createElement("div");
    result.className = "app-data-restore-result";
    result.setAttribute("aria-live", "polite");
    form.append(description, grid, actions, result);
    details.append(form);
    return details;
  }

  function buildAppUpdateActionForm(app, action, label, disabledReason) {
    const appId = typeof app.appId === "string" ? app.appId : "";
    const path = appUpdatesPath(appId, action);
    if (!path) {
      return null;
    }

    const form = document.createElement("form");
    form.className = "app-action-form";
    form.dataset.appId = appId;
    form.dataset.appUpdateAction = action;
    form.dataset.appName = appDisplayName(app);
    if (disabledReason) {
      form.dataset.disabledReason = disabledReason;
    }

    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = label;
    if (disabledReason) {
      submit.disabled = true;
      submit.title = disabledReason;
    }
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
    const reviewTrust = app ? recordValue(app.reviewTrust) : {};
    const securityDecision = app ? securityDecisionForCatalogAction(app) : {};
    const disabledReason = app
      ? reviewTrustActionReason(reviewTrust, action) || securityDecisionActionReason(securityDecision, action)
      : "";

    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = label;
    if (disabledReason) {
      submit.disabled = true;
      submit.title = disabledReason;
      form.dataset.disabledReason = disabledReason;
    }
    form.append(submit);
    return form;
  }

  function buildCatalogRollbackForm(catalog, candidate) {
    const revision = recordValue(candidate && candidate.revision);
    const revisionDigest = typeof revision.revisionDigest === "string" ? revision.revisionDigest : "";
    if (!candidate || candidate.eligible !== true || !revisionDigest) {
      return null;
    }
    const path = catalogMutationPath(catalog.catalogId || "", "", "rollback");
    if (!path) {
      return null;
    }
    const form = document.createElement("form");
    form.className = "app-action-form";
    form.dataset.catalogId = catalog.catalogId || "";
    form.dataset.catalogAction = "rollback";
    form.dataset.catalogAppName = catalog.catalogId || "";
    const digestInput = document.createElement("input");
    digestInput.type = "hidden";
    digestInput.name = "revisionDigest";
    digestInput.value = revisionDigest;
    const reasonInput = document.createElement("input");
    reasonInput.type = "hidden";
    reasonInput.name = "reason";
    reasonInput.value = "operator rollback from Web Shell";
    const submit = document.createElement("button");
    submit.className = "button button-danger";
    submit.type = "submit";
    submit.textContent = "Rollback catalog";
    submit.title = `Roll back to ${revisionDigest}`;
    form.append(digestInput, reasonInput, submit);
    return form;
  }

  function buildIdentityVaultGrantForm(identities, apps) {
    if (!formPassword || !identities.length || !apps.length) {
      return null;
    }
    const form = document.createElement("form");
    form.className = "vault-grant-form";
    form.dataset.identityVaultAction = "grant";

    form.append(
      selectField(
        "Identity",
        "identityId",
        identities.map((identity) => [
          scalar(identity.identityId),
          `${scalar(identity.label || identity.identityId)} (${scalar(identity.fingerprint)})`,
        ]),
      ),
      selectField(
        "App",
        "appId",
        apps
          .filter((app) => app && typeof app.appId === "string" && app.appId)
          .map((app) => [app.appId, appDisplayName(app)]),
      ),
      selectField(
        "Scope",
        "scopes",
        vaultGrantScopes.map((scope) => [scope, scope]),
      ),
    );

    const reasonField = document.createElement("label");
    reasonField.className = "queue-field";
    reasonField.append(text("span", "", "Reason"));
    const reasonInput = document.createElement("input");
    reasonInput.name = "reason";
    reasonInput.type = "text";
    reasonInput.autocomplete = "off";
    reasonInput.placeholder = "operator grant";
    reasonField.append(reasonInput);
    form.append(reasonField);

    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = "Grant";
    form.append(submit);
    return form;
  }

  function consentPreviewPathForForm(form, action) {
    if (form.dataset.catalogAction === "install") {
      return consentInstallPreviewPath(form.dataset.catalogId || "", form.dataset.catalogAppId || "");
    }
    if (form.dataset.catalogAction === "update") {
      return consentCatalogUpdatePreviewPath(form.dataset.catalogId || "", form.dataset.catalogAppId || "");
    }
    if (form.dataset.appUpdateAction === "stage") {
      return consentUpdatePreviewPath(form.dataset.appId || "");
    }
    if (
      form.dataset.appServiceBundleAction === "approve" ||
      form.dataset.appServiceBundleAction === "renew"
    ) {
      return consentServiceGrantPreviewPath(form.dataset.bundleId || "");
    }
    return null;
  }

  async function loadConsentPreviewForForm(form, action) {
    const path = consentPreviewPathForForm(form, action);
    if (!path) {
      return null;
    }
    if (form.dataset.appUpdateAction === "stage") {
      const formData = new FormData();
      formData.set("appId", form.dataset.appId || "");
      const response = await postForm(
        path,
        formData,
        "Consent previews unavailable in read-only mode.",
      );
      return recordValue(response.consent || response);
    }
    const response = await loadJson(apiUrl(path));
    return recordValue(response.consent || response);
  }

  async function ensureConsentApprovedForForm(form, action) {
    if (form.dataset.consentApproved === "true") {
      return true;
    }
    const preview = await loadConsentPreviewForForm(form, action);
    if (!preview || preview.requiresApproval !== true) {
      return true;
    }
    renderConsentPreview(preview, form);
    setAppsStatus("Review the consent preview before continuing.", "is-warning");
    return false;
  }

  function renderConsentPreview(preview, form) {
    clearConsentPreview(form);
    const card = document.createElement("div");
    card.className = "consent-preview";
    card.setAttribute("role", "group");
    card.setAttribute("aria-label", "Consent preview");
    card.append(
      text("h4", "", "Consent preview"),
      definitionList([
        ["Action", normalizedStatus(preview.action)],
        ["Risk level", normalizedStatus(preview.riskLevel)],
        ["Blocks auto-update", preview.blocksAutoUpdate === true ? "Yes" : "No"],
        ["Snapshot digest", scalar(preview.snapshotDigest)],
      ]),
    );
    const reasons = stringList(preview.blockingReasons);
    if (reasons.length) {
      card.append(text("p", "consent-risk-summary", reasons.map(normalizedStatus).join(", ")));
    }
    const sectionList = document.createElement("div");
    sectionList.className = "consent-section-list";
    arrayValue(preview.sections).forEach((section) => {
      sectionList.append(renderConsentSection(section));
    });
    card.append(sectionList, consentPreviewActions(preview, form));
    form.after(card);
  }

  function renderConsentSection(section) {
    const item = recordValue(section);
    const node = document.createElement("section");
    node.className = "consent-section";
    const heading = document.createElement("div");
    heading.className = "consent-section-heading";
    heading.append(
      text("h5", "", item.title || normalizedStatus(item.id)),
      createPill(normalizedStatus(item.riskLevel), consentRiskTone(item.riskLevel)),
    );
    const list = document.createElement("ul");
    list.className = "consent-finding-list";
    arrayValue(item.items).forEach((finding) => {
      list.append(renderConsentFinding(finding));
    });
    node.append(heading, list);
    return node;
  }

  function renderConsentFinding(finding) {
    const item = recordValue(finding);
    const row = document.createElement("li");
    row.className = "consent-finding";
    row.append(
      text("span", "consent-finding-label", scalar(item.label)),
      text("span", "consent-finding-summary", scalar(item.summary)),
      createPill(normalizedStatus(item.change || item.riskLevel), consentRiskTone(item.riskLevel)),
    );
    return row;
  }

  function consentPreviewActions(preview, form) {
    const actions = document.createElement("div");
    actions.className = "consent-actions";
    const approve = document.createElement("button");
    approve.className = "button button-primary";
    approve.type = "button";
    approve.textContent = "Approve";
    approve.addEventListener("click", async () => {
      try {
        await submitConsentDecision(preview, "approve");
        appendConsentSnapshotFields(form, preview);
        form.dataset.consentApproved = "true";
        clearConsentPreview(form);
        setAppsStatus("Consent approved. Continuing action.", "is-success");
        form.requestSubmit();
      } catch (error) {
        setAppsStatus(consentStaleErrorMessage(error), "is-error");
      }
    });
    const reject = document.createElement("button");
    reject.className = "button button-secondary";
    reject.type = "button";
    reject.textContent = "Reject";
    reject.addEventListener("click", async () => {
      try {
        await submitConsentDecision(preview, "reject");
        clearConsentPreview(form);
        setAppsStatus("Consent rejected. No app-platform mutation was applied.", "is-warning");
        await loadAppsSection();
      } catch (error) {
        setAppsStatus(consentStaleErrorMessage(error), "is-error");
      }
    });
    actions.append(approve, reject);
    return actions;
  }

  async function submitConsentDecision(preview, decision) {
    const formData = new FormData();
    formData.set("consentRequestId", scalar(preview.consentRequestId));
    formData.set("snapshotDigest", scalar(preview.snapshotDigest));
    await postForm(`consent/${decision}`, formData, "Consent decisions unavailable in read-only mode.");
  }

  function appendConsentSnapshotFields(form, preview) {
    removeNamedFields(form, "consentRequestId");
    removeNamedFields(form, "snapshotDigest");
    appendHiddenField(form, "consentRequestId", scalar(preview.consentRequestId));
    appendHiddenField(form, "snapshotDigest", scalar(preview.snapshotDigest));
  }

  function clearConsentPreview(form) {
    const existing = form.nextElementSibling;
    if (existing && existing.classList.contains("consent-preview")) {
      existing.remove();
    }
  }

  function removeNamedFields(form, name) {
    form.querySelectorAll(`input[name="${name}"]`).forEach((node) => node.remove());
  }

  function consentRiskTone(riskLevel) {
    const risk = typeof riskLevel === "string" ? riskLevel : "";
    if (risk === "blocking") {
      return "is-error";
    }
    if (risk === "material") {
      return "is-warning";
    }
    return "is-success";
  }

  function consentStaleErrorMessage(error) {
    return error && error.apiErrorCode === "stale_consent_snapshot"
      ? "This approval is stale. Refresh the consent preview."
      : error instanceof Error
        ? error.message
        : String(error);
  }

  function buildIdentityVaultRevokeForm(grant) {
    if (!formPassword || typeof grant.grantId !== "string" || !grant.grantId) {
      return null;
    }
    const form = document.createElement("form");
    form.className = "app-action-form";
    form.dataset.identityVaultAction = "revoke";
    form.dataset.grantId = grant.grantId;
    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = "Revoke";
    form.append(submit);
    return form;
  }

  function buildAppServiceGrantActionForm(grant, action, label) {
    if (!formPassword || typeof grant.grantId !== "string" || !grant.grantId) {
      return null;
    }
    const form = document.createElement("form");
    form.className = "app-action-form";
    form.dataset.appServiceGrantAction = action;
    form.dataset.grantId = grant.grantId;
    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = label;
    form.append(submit);
    return form;
  }

  function buildAppServiceBundleActionForm(bundle, action, label) {
    if (!formPassword || typeof bundle.bundleId !== "string" || !bundle.bundleId) {
      return null;
    }
    const form = document.createElement("form");
    form.className = "app-action-form";
    form.dataset.appServiceBundleAction = action;
    form.dataset.bundleId = bundle.bundleId;
    const submit = document.createElement("button");
    submit.className = "button button-secondary";
    submit.type = "submit";
    submit.textContent = label;
    form.append(submit);
    return form;
  }

  function selectField(label, name, options) {
    const field = document.createElement("label");
    field.className = "queue-field";
    field.append(text("span", "", label));
    const select = document.createElement("select");
    select.name = name;
    select.required = true;
    options.forEach(([value, display]) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = display;
      select.append(option);
    });
    field.append(select);
    return field;
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

  function arrayValue(value) {
    return Array.isArray(value) ? value : [];
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

  function reviewTrustTone(reviewTrust) {
    const trust = recordValue(reviewTrust);
    const status = typeof trust.status === "string" ? trust.status.toLowerCase() : "";
    if (trust.positive === true && trust.trusted === true) {
      return "is-success";
    }
    if (
      status.includes("reject")
      || status.includes("mismatch")
      || status.includes("expired")
      || status.includes("invalid")
      || status.includes("revoked")
      || status.includes("policy")
    ) {
      return "is-error";
    }
    return "is-warning";
  }

  function reviewTrustLabel(reviewTrust) {
    const trust = recordValue(reviewTrust);
    const status = typeof trust.status === "string" ? trust.status : "";
    if (!status) {
      return "Trusted receipt unavailable";
    }
    if (trust.positive === true && trust.trusted === true) {
      return "Trusted receipt reviewed";
    }
    if (status === "publisher_claim_only") {
      return "Publisher advisory only";
    }
    return normalizedStatus(status);
  }

  function reviewTrustWarnings(reviewTrust) {
    return stringList(recordValue(reviewTrust).warnings).join("; ") || "None";
  }

  function reviewTrustActionReason(reviewTrust, action) {
    const trust = recordValue(reviewTrust);
    const blockField = reviewTrustBlockFieldForAction(action);
    if (trust[blockField] === true) {
      return `${normalizedStatus(action)} blocked by app review policy: ${reviewTrustLabel(trust)}.`;
    }
    return "";
  }

  function reviewTrustBlockFieldForAction(action) {
    if (action === "install") {
      return "blocksInstall";
    }
    if (action === "update" || action === "stage") {
      return "blocksUpdate";
    }
    return "";
  }

  function appendReviewAcknowledgement(form, reviewTrust, action) {
    const trust = recordValue(reviewTrust);
    if (trust.requiresAcknowledgement !== true) {
      return;
    }
    if (reviewTrustActionReason(trust, action)) {
      return;
    }
    const label = document.createElement("label");
    label.className = "checkbox-field review-acknowledgement";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = "reviewAcknowledged";
    input.value = "true";
    input.required = true;
    label.append(input, document.createTextNode(` Acknowledge ${reviewTrustLabel(trust)}`));
    form.append(label);
  }

  function updateDataMigrationForAction(updateState, action) {
    const state = recordValue(updateState);
    const candidate = recordValue(state.candidate);
    const staged = recordValue(state.staged);
    if (action === "apply") {
      return recordValue(staged.dataMigration || candidate.dataMigration);
    }
    if (action === "stage") {
      return recordValue(candidate.dataMigration);
    }
    return {};
  }

  function migrationActionReason(dataMigration, action) {
    const plan = recordValue(dataMigration);
    if (Object.keys(plan).length === 0) {
      return "";
    }
    if (migrationAcknowledgementRequired(plan, action)) {
      return "";
    }
    if (typeof plan.blockReason === "string" && plan.blockReason) {
      return `${normalizedStatus(action)} blocked by app-data migration: ${normalizedStatus(plan.blockReason)}.`;
    }
    const status = typeof plan.status === "string" ? plan.status : "";
    if (
      action === "apply" &&
      plan.required === true &&
      status &&
      status !== "ready" &&
      status !== "applied" &&
      status !== "not_required"
    ) {
      return `Apply blocked by app-data migration status: ${normalizedStatus(status)}.`;
    }
    return "";
  }

  function migrationAcknowledgementRequired(dataMigration, action) {
    const plan = recordValue(dataMigration);
    return (
      action === "stage" &&
      plan.operatorReviewRequired === true &&
      plan.blockReason === "app_data_migration_review_required"
    );
  }

  function appendMigrationAcknowledgement(form, dataMigration, action) {
    if (!migrationAcknowledgementRequired(dataMigration, action)) {
      return;
    }
    const label = document.createElement("label");
    label.className = "checkbox-field review-acknowledgement migration-acknowledgement";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = "migrationAcknowledged";
    input.value = "true";
    input.required = true;
    label.append(input, document.createTextNode(" Acknowledge rollback-incompatible app-data migration"));
    form.append(label);
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

  function apiCompatibilityTone(apiCompatibility) {
    const status =
      apiCompatibility && typeof apiCompatibility.status === "string" ? apiCompatibility.status.toLowerCase() : "";
    if (status === "compatible") {
      return "is-success";
    }
    if (status === "below_minimum" || status === "incompatible" || status === "unsupported-baseline") {
      return "is-error";
    }
    return "is-warning";
  }

  function apiCompatibilityLabel(apiCompatibility) {
    if (!apiCompatibility || Object.keys(apiCompatibility).length === 0) {
      return "API contract unknown";
    }
    const status = typeof apiCompatibility.status === "string" ? apiCompatibility.status.toLowerCase() : "";
    if (status === "compatible") {
      return "API contract compatible";
    }
    if (status === "below_minimum") {
      return "API contract too old";
    }
    if (status === "newer_than_tested") {
      return "Newer API contract";
    }
    if (status === "incompatible") {
      return "API contract warning";
    }
    if (status === "unsupported-baseline") {
      return "Unsupported API baseline";
    }
    return "API contract unknown";
  }

  function apiTargetBaselinePresentation(apiCompatibility) {
    const compatibility = recordValue(apiCompatibility);
    const targetBaseline =
      typeof compatibility.targetBaseline === "string" ? compatibility.targetBaseline.trim() : "";
    if (!targetBaseline) {
      return { targetBaseline: "Not targeted", declaration: "Not targeted" };
    }
    return {
      targetBaseline,
      declaration: compatibility.targetBaselineDeclared ? "Explicit" : "Compatibility default",
    };
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

  function appUpdateState(app) {
    if (
      app &&
      app.updateState &&
      typeof app.updateState === "object" &&
      !Array.isArray(app.updateState)
    ) {
      return app.updateState;
    }
    if (app && app.updates && typeof app.updates === "object" && !Array.isArray(app.updates)) {
      return app.updates;
    }
    return {};
  }

  function appHasUpdateState(updateState) {
    return [
      "status",
      "candidate",
      "staged",
      "policy",
      "rollback",
      "scheduler",
      "lastCheck",
      "lastCheckAt",
      "nextCheckAt",
      "lastCheckResult",
    ].some((key) => Object.prototype.hasOwnProperty.call(updateState, key));
  }

  function updateVersionSummary(updateInfo) {
    const info = recordValue(updateInfo);
    const version =
      typeof info.targetVersion === "string" && info.targetVersion
        ? info.targetVersion
        : typeof info.version === "string" && info.version
          ? info.version
          : "";
    const summary = typeof info.summary === "string" && info.summary ? info.summary : "";
    const status = typeof info.status === "string" && info.status ? normalizedStatus(info.status) : "";
    return [version, summary, status].filter((entry) => entry).join(" - ") || "Unavailable";
  }

  function updatePolicySummary(policy) {
    if (typeof policy === "string" && policy.length > 0) {
      return normalizedStatus(policy);
    }
    const value = recordValue(policy);
    const mode = typeof value.mode === "string" && value.mode ? normalizedStatus(value.mode) : "";
    const allowedChannels = stringList(value.allowedChannels)
      .map((channel) => catalogChannelLabel(channel))
      .join(", ");
    const requireManualApply = value.requireManualApply === true ? "manual apply" : "";
    const allowPrerelease = value.allowPrerelease === true ? "prerelease allowed" : "";
    const deprecatedBlocked =
      value.deprecatedAutoUpdatesBlocked === true ? "deprecated blocked" : "";
    const entries = [
      mode,
      allowedChannels ? `channels: ${allowedChannels}` : "",
      requireManualApply,
      allowPrerelease,
      deprecatedBlocked,
    ].filter((entry) => entry);
    return entries.length ? entries.join("; ") : "Unavailable";
  }

  function updatePermissionDeltaSummary(source) {
    const sourceRecord = recordValue(source);
    const delta = recordValue(sourceRecord.permissionDelta || sourceRecord.permissionsDelta);
    const added = stringList(delta.added).length;
    const removed = stringList(delta.removed).length;
    const unchanged = stringList(delta.unchanged).length;
    if (added === 0 && removed === 0 && unchanged === 0) {
      return "Unavailable";
    }
    return `+${added} / -${removed} / ${unchanged} unchanged`;
  }

  function updateApiRiskSummary(source) {
    const compatibility = recordValue(recordValue(source).apiCompatibility);
    return Object.keys(compatibility).length
      ? apiCompatibilityLabel(compatibility)
      : "Unavailable";
  }

  function appUpdateSchedulerValue(updateState, field, nestedField) {
    const scheduler = recordValue(updateState.scheduler);
    const lastCheck = recordValue(updateState.lastCheck);
    const schedulerValue = Object.prototype.hasOwnProperty.call(scheduler, nestedField)
      ? scheduler[nestedField]
      : undefined;
    if (field === "lastCheckAt") {
      return schedulerValue || lastCheck.checkedAt || updateState[field];
    }
    if (field === "lastCheckResult") {
      return (
        schedulerValue ||
        lastCheck.status ||
        lastCheck.errorCode ||
        updateState[field]
      );
    }
    return schedulerValue !== undefined ? schedulerValue : updateState[field];
  }

  function rollbackAvailable(updateState) {
    const rollback = recordValue(updateState.rollback);
    if (typeof rollback.available === "boolean") {
      return rollback.available;
    }
    if (typeof updateState.rollbackAvailable === "boolean") {
      return updateState.rollbackAvailable;
    }
    return false;
  }

  function appUpdateStatus(updateState) {
    if (typeof updateState.status === "string" && updateState.status) {
      return updateState.status;
    }
    if (typeof updateState.candidateStatus === "string" && updateState.candidateStatus) {
      return updateState.candidateStatus;
    }
    const candidate = recordValue(updateState.candidate);
    if (typeof candidate.status === "string" && candidate.status) {
      return candidate.status;
    }
    return "";
  }

  function updateActionAllowed(updateState, action) {
    const key = `can${action.charAt(0).toUpperCase()}${action.slice(1)}`;
    return updateState[key] !== false;
  }

  function updateRunningAllowed(updateState, action) {
    const title = action.charAt(0).toUpperCase() + action.slice(1);
    const explicitKeys = [`can${title}WhileRunning`, `${action}AllowedWhileRunning`];
    if (action === "apply") {
      explicitKeys.push("canUpdateWhileRunning", "updateAllowedWhileRunning");
    }
    return explicitKeys.some((key) => updateState[key] === true);
  }

  function stageableUpdateCandidate(updateState) {
    const candidate = recordValue(updateState.candidate);
    const status =
      typeof candidate.status === "string" && candidate.status
        ? candidate.status
        : appUpdateStatus(updateState);
    return status === "available";
  }

  function updateReviewTrustForAction(updateState, action) {
    const state = recordValue(updateState);
    const candidate = recordValue(state.candidate);
    const staged = recordValue(state.staged);
    if (action === "apply") {
      return recordValue(staged.reviewTrust || candidate.reviewTrust);
    }
    if (action === "stage") {
      return recordValue(candidate.reviewTrust);
    }
    return {};
  }

  function updateActionDisabledReason(app, updateState, action, runtimeRunning) {
    if (!updateActionAllowed(updateState, action)) {
      return `${normalizedStatus(action)} is unavailable for this app update state.`;
    }
    if (
      (action === "apply" || action === "rollback") &&
      runtimeRunning &&
      !updateRunningAllowed(updateState, action)
    ) {
      return `${normalizedStatus(action)} requires stopping or restarting the running app first.`;
    }
    if (action === "apply" && !stagedUpdateAvailable(updateState)) {
      return "Apply is unavailable until an update is staged.";
    }
    if (action === "stage" && !stageableUpdateCandidate(updateState)) {
      return "Stage is unavailable until a newer update candidate is available.";
    }
    if (action === "stage" || action === "apply") {
      const reviewReason = reviewTrustActionReason(updateReviewTrustForAction(updateState, action), action);
      if (reviewReason) {
        return reviewReason;
      }
      const securityReason = securityDecisionActionReason(
        securityDecisionForUpdateAction(updateState, action),
        action,
      );
      if (securityReason) {
        return securityReason;
      }
      const migrationReason = migrationActionReason(
        updateDataMigrationForAction(updateState, action),
        action,
      );
      if (migrationReason) {
        return migrationReason;
      }
    }
    if (action === "rollback" && !rollbackAvailable(updateState)) {
      return "Rollback is unavailable for this app.";
    }
    return "";
  }

  function stagedUpdateAvailable(updateState) {
    const staged = recordValue(updateState.staged);
    return staged.available === true || staged.status === "staged";
  }

  function appUpdateDetailsNode(app, updateState) {
    if (!appHasUpdateState(updateState)) {
      return null;
    }
    const details = document.createElement("details");
    details.className = "json-details app-update-details";
    const summary = document.createElement("summary");
    summary.textContent = "App update lifecycle";
    details.append(summary);

    const candidate = recordValue(updateState.candidate);
    const staged = recordValue(updateState.staged);
    const rollback = recordValue(updateState.rollback);
    const applyMigration = updateDataMigrationForAction(updateState, "apply");
    const candidateMigration = updateDataMigrationForAction(updateState, "stage");
    const installedSecurity = recordValue(updateState.installedSecurityDecision);
    const candidateSecurity = securityDecisionForUpdateAction(updateState, "stage");
    const applySecurity = securityDecisionForUpdateAction(updateState, "apply");
    const visibleMigration = Object.keys(recordValue(applyMigration)).length
      ? applyMigration
      : candidateMigration;
    details.append(
      definitionList([
        ["Update candidate", normalizedStatus(appUpdateStatus(updateState), "Unavailable")],
        ["Candidate summary", updateVersionSummary(candidate)],
        ["Staged update", updateVersionSummary(staged)],
        ["Policy", updatePolicySummary(updateState.policy)],
        ["Permission changes before apply", updatePermissionDeltaSummary(staged)],
        ["API compatibility before apply", updateApiRiskSummary(staged)],
        ["Installed security decision", securityDecisionLabel(installedSecurity)],
        ["Candidate security decision", securityDecisionLabel(candidateSecurity)],
        ["Security policy before apply", securityDecisionLabel(applySecurity)],
        ["Security policy handling", securityDecisionWarnings(applySecurity)],
        ["Trusted review before apply", reviewTrustLabel(updateReviewTrustForAction(updateState, "apply"))],
        ["Review policy handling", reviewTrustWarnings(updateReviewTrustForAction(updateState, "apply"))],
        ["Candidate app-data migration", updateDataMigrationSummary(candidateMigration)],
        ["App-data migration before apply", updateDataMigrationSummary(applyMigration)],
        ["App-data migration blocker", migrationBlockerSummary(visibleMigration)],
        ["Rollback available", rollbackAvailable(updateState) ? "Yes" : "No"],
        [
          "Rollback version",
          scalar(rollback.previousVersion || rollback.version || updateState.rollbackVersion),
        ],
        [
          "Last rollback result",
          normalizedStatus(rollback.lastResult || updateState.lastRollbackResult, "Unavailable"),
        ],
        ["Last rollback at", formatIsoTimestamp(rollback.lastCompletedAt || updateState.lastRollbackAt)],
        [
          "Last scheduler check",
          formatIsoTimestamp(appUpdateSchedulerValue(updateState, "lastCheckAt", "lastCheckAt")),
        ],
        [
          "Scheduler",
          appUpdateSchedulerValue(updateState, "schedulerEnabled", "enabled") === false
            ? "Disabled"
            : appUpdateSchedulerValue(updateState, "schedulerEnabled", "enabled") === true
              ? "Enabled"
              : "Unavailable",
        ],
        [
          "Scheduler status",
          normalizedStatus(appUpdateSchedulerValue(updateState, "schedulerStatus", "status"), "Unavailable"),
        ],
        ["Last scheduler result", scalar(appUpdateSchedulerValue(updateState, "lastCheckResult", "lastResult"))],
        [
          "Next scheduler check",
          formatIsoTimestamp(appUpdateSchedulerValue(updateState, "nextCheckAt", "nextCheckAt")),
        ],
        [
          "Scheduler failures",
          scalar(appUpdateSchedulerValue(updateState, "schedulerFailureCount", "failureCount")),
        ],
        [
          "Last scheduler error",
          scalar(appUpdateSchedulerValue(updateState, "schedulerLastError", "lastErrorCode")),
        ],
      ]),
    );
    const migrationDetails = appDataMigrationDetailsNode(applyMigration, candidateMigration);
    if (migrationDetails) {
      details.append(migrationDetails);
    }
    return details;
  }

  function updateDataMigrationSummary(dataMigration) {
    const plan = recordValue(dataMigration);
    if (Object.keys(plan).length === 0) {
      return "Unavailable";
    }
    const status = normalizedStatus(plan.status, "Unavailable");
    if (plan.required !== true) {
      return `Not required (${status})`;
    }
    const current = scalar(plan.currentSchemaVersion);
    const target = scalar(plan.targetSchemaVersion);
    const review = plan.operatorReviewRequired === true ? "; operator review required" : "";
    return `Required: schema ${current} to ${target}; ${status}${review}`;
  }

  function migrationBlockerSummary(dataMigration) {
    const plan = recordValue(dataMigration);
    if (typeof plan.blockReason === "string" && plan.blockReason) {
      return normalizedStatus(plan.blockReason);
    }
    if (plan.operatorReviewRequired === true) {
      return "Operator acknowledgement required before automatic apply";
    }
    return "None";
  }

  function appDataMigrationDetailsNode(applyMigration, candidateMigration) {
    const plan = Object.keys(recordValue(applyMigration)).length
      ? recordValue(applyMigration)
      : recordValue(candidateMigration);
    if (Object.keys(plan).length === 0) {
      return null;
    }
    const details = document.createElement("details");
    details.className = "json-details app-data-migration-details";
    const summary = document.createElement("summary");
    summary.textContent = "App-data migration plan";
    details.append(summary);
    details.append(
      definitionList([
        ["Required", plan.required === true ? "Yes" : "No"],
        ["Status", normalizedStatus(plan.status, "Unavailable")],
        ["Installed/current schema", scalar(plan.currentSchemaVersion)],
        ["Candidate/target schema", scalar(plan.targetSchemaVersion)],
        ["Dry-run", scalar(plan.dryRunStatus)],
        ["Snapshot", scalar(plan.snapshotStatus)],
        ["Apply", scalar(plan.applyStatus)],
        ["Operator review", plan.operatorReviewRequired === true ? "Required" : "Not required"],
        ["Block reason", migrationBlockerSummary(plan)],
      ]),
    );
    const namespaceNode = appDataMigrationNamespaceList(plan.namespaces);
    if (namespaceNode) {
      details.append(namespaceNode);
    }
    return details;
  }

  function appDataMigrationNamespaceList(namespaces) {
    if (!Array.isArray(namespaces) || namespaces.length === 0) {
      return null;
    }
    const list = document.createElement("ul");
    list.className = "migration-step-list";
    namespaces.forEach((namespace) => {
      const step = recordValue(namespace);
      const item = document.createElement("li");
      item.className = "migration-step-item";
      item.append(
        text(
          "span",
          "migration-step-title",
          `${scalar(step.namespace)}: ${scalar(step.from)} to ${scalar(step.to)}`,
        ),
      );
      item.append(
        text(
          "span",
          "migration-step-meta",
          [
            `step ${scalar(step.stepId)}`,
            step.rollbackCompatible === true ? "rollback compatible" : "rollback incompatible",
            step.requiresStopped === true ? "requires stopped app" : null,
            scalar(step.description),
          ]
            .filter(Boolean)
            .join("; "),
        ),
      );
      list.append(item);
    });
    return list;
  }

  function appendAppUpdateActionForms(actions, app, updateState, runtimeRunning) {
    const checkDisabledReason =
      updateActionDisabledReason(app, updateState, "check", runtimeRunning);
    const stageDisabledReason =
      updateActionDisabledReason(app, updateState, "stage", runtimeRunning);
    const applyDisabledReason =
      updateActionDisabledReason(app, updateState, "apply", runtimeRunning);
    const rollbackDisabledReason =
      updateActionDisabledReason(app, updateState, "rollback", runtimeRunning);
    const applyRequiresRestart = applyDisabledReason.includes("requires stopping or restarting");
    const rollbackRequiresRestart = rollbackDisabledReason.includes("requires stopping or restarting");
    const forms = [
      buildAppUpdateActionForm(app, "check", "Check for app update", checkDisabledReason),
      buildAppUpdateActionForm(app, "stage", "Stage app update", stageDisabledReason),
      buildAppUpdateActionForm(
        app,
        "apply",
        applyRequiresRestart ? "Apply requires restart" : "Apply staged update",
        applyDisabledReason,
      ),
      buildAppUpdateActionForm(
        app,
        "rollback",
        rollbackRequiresRestart ? "Rollback requires restart" : "Rollback app update",
        rollbackDisabledReason,
      ),
    ];
    forms.forEach((form) => {
      if (form) {
        actions.append(form);
      }
    });
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
    const updateState = appUpdateState(app);
    const hasUpdateState = appHasUpdateState(updateState);
    const vault = appVaultStatus(app);
    const vaultPermissions = appVaultPermissions(app);

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
    pills.append(
      createPill(apiCompatibilityLabel(recordValue(app.apiCompatibility)), apiCompatibilityTone(recordValue(app.apiCompatibility))),
    );
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
    if (hasUpdateState) {
      const updateStatus = appUpdateStatus(updateState);
      const installedSecurity = recordValue(updateState.installedSecurityDecision);
      pills.append(createPill(updateStatus ? normalizedStatus(updateStatus) : "Update status", "is-warning"));
      if (securityDecisionStatus(installedSecurity) !== "ok") {
        pills.append(createPill(securityDecisionLabel(installedSecurity), securityDecisionTone(installedSecurity)));
      }
      if (stagedUpdateAvailable(updateState)) {
        pills.append(createPill("Update staged", "is-warning"));
      }
      if (rollbackAvailable(updateState)) {
        pills.append(createPill("Rollback available", "is-warning"));
      }
    }
    if (vaultPermissions.length) {
      pills.append(createPill("Vault permissions", "is-warning"));
    }
    if (vault.appOwnedSecrets > 0) {
      pills.append(createPill(`${vault.appOwnedSecrets} vault secrets`));
    }
    if (vault.activeIdentityGrants > 0) {
      pills.append(createPill(`${vault.activeIdentityGrants} active grants`, "is-success"));
    } else if (vault.identityGrants > 0) {
      pills.append(createPill(`${vault.identityGrants} inactive grants`, "is-warning"));
    }
    if (vault.retainedAfterUninstall) {
      pills.append(createPill("Vault retained", "is-warning"));
    }
    header.append(heading, pills);
    card.append(header);

    const uiEntryNode = appUiEntryNode(app);
    const entries = [
      ["App ID", typeof app.appId === "string" && app.appId ? app.appId : "Unavailable"],
      ["Version", typeof app.version === "string" && app.version ? app.version : "Unavailable"],
      ["Permissions", formatPermissions(app.permissions)],
      ["API contract", apiCompatibilityLabel(recordValue(app.apiCompatibility))],
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
      ["Vault permissions", formatPermissions(vaultPermissions)],
      ["App-owned secrets", scalar(vault.appOwnedSecrets || 0)],
      ["Identity grants", appVaultGrantSummary(vault)],
      ["Vault retained", vault.retainedAfterUninstall ? "Yes" : "No"],
      ["Process log size", logs && logs.available ? formatBytes(logs.sizeBytes) : formatBytes(runtime && runtime.logSizeBytes)],
      ["Process log limit", quota ? formatBytes(quota.processLogMaxBytes) : "Unavailable"],
      ["Process log tail limit", logs ? formatBytes(logs.maxBytes) : "Unavailable"],
      ["Process log truncated", logs && logs.truncated ? "Yes" : "No"],
      ["Runtime detail", runtimeError || (runtime ? "Available" : "Unavailable")],
      [
        "Update candidate",
        hasUpdateState ? normalizedStatus(appUpdateStatus(updateState), "Unavailable") : "Unavailable",
      ],
      ["Staged update", hasUpdateState ? updateVersionSummary(updateState.staged) : "Unavailable"],
      ["Update policy", hasUpdateState ? updatePolicySummary(updateState.policy) : "Unavailable"],
      ["Rollback availability", hasUpdateState && rollbackAvailable(updateState) ? "Available" : "Unavailable"],
      ["Update detail", app.updatesError || (hasUpdateState ? "Available" : "Unavailable")],
      [
        "Last app update check",
        hasUpdateState
          ? formatIsoTimestamp(appUpdateSchedulerValue(updateState, "lastCheckAt", "lastCheckAt"))
          : "Unavailable",
      ],
      [
        "Next app update check",
        hasUpdateState
          ? formatIsoTimestamp(appUpdateSchedulerValue(updateState, "nextCheckAt", "nextCheckAt"))
          : "Unavailable",
      ],
    ];
    card.append(definitionList(entries));
    if (hasUpdateState) {
      const installedSecurityNotice = securityDecisionNoticeNode(updateState.installedSecurityDecision, true);
      if (installedSecurityNotice) {
        card.append(installedSecurityNotice);
      }
    }
    card.append(apiCompatibilityDetailsNode(app));
    card.append(appPermissionsDetailsNode(app));
    card.append(appVaultDetailsNode(app));
    const updateDetails = appUpdateDetailsNode(app, updateState);
    if (updateDetails) {
      card.append(updateDetails);
    }
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
      const backupForm = buildAppDataBackupActionForm(app, "export", "Export app data");
      const preserveDataForm = runtimeStoppable
        ? null
        : buildAppActionForm(app, "uninstall", "Uninstall preserving data", {
            hiddenFields: { preserveData: "true" },
            uninstallMode: "preserveData",
          });
      const deleteDataForm = runtimeStoppable
        ? null
        : buildAppActionForm(app, "uninstall", "Delete app and data", {
            uninstallMode: "deleteData",
          });
      const exportBeforeDeleteForm = runtimeStoppable
        ? null
        : buildAppDataBackupActionForm(app, "exportBeforeDelete", "Export backup before delete");
      if (startForm) {
        actions.append(startForm);
      }
      if (backupForm) {
        actions.append(backupForm);
      }
      if (preserveDataForm) {
        actions.append(preserveDataForm);
      }
      if (deleteDataForm) {
        actions.append(deleteDataForm);
      }
      if (exportBeforeDeleteForm) {
        actions.append(exportBeforeDeleteForm);
      }
      if (hasUpdateState) {
        appendAppUpdateActionForms(actions, app, updateState, runtimeRunning);
      }
    }
    if (actions.childNodes.length) {
      card.append(actions);
    }
    if (formPassword) {
      const restoreDetails = buildAppDataRestoreDetails(app);
      if (restoreDetails) {
        card.append(restoreDetails);
      }
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

  function appVaultStatus(app) {
    return recordValue(app.vault);
  }

  function appVaultPermissions(app) {
    return stringList(app.permissions).filter((permission) =>
      permission.startsWith(vaultCapabilityPrefix),
    );
  }

  function appVaultGrantSummary(vault) {
    const total = typeof vault.identityGrants === "number" ? vault.identityGrants : 0;
    const active =
      typeof vault.activeIdentityGrants === "number" ? vault.activeIdentityGrants : 0;
    return total ? `${active} active / ${total} total` : "None";
  }

  function appVaultDetailsNode(app) {
    const vault = appVaultStatus(app);
    const vaultPermissions = appVaultPermissions(app);
    const hasVaultStatus =
      vaultPermissions.length ||
      vault.appOwnedSecrets ||
      vault.identityGrants ||
      vault.retainedAfterUninstall;
    const details = document.createElement("details");
    details.className = "json-details app-vault-details";
    const summary = document.createElement("summary");
    summary.textContent = "Vault status";
    details.append(summary);
    if (!hasVaultStatus) {
      details.append(text("p", "empty-state", "No vault permissions or retained vault material."));
      return details;
    }
    details.append(
      definitionList([
        ["Declared vault permissions", formatPermissions(vaultPermissions)],
        ["App-owned secrets", scalar(vault.appOwnedSecrets || 0)],
        ["Identity grants", appVaultGrantSummary(vault)],
        ["Retained after uninstall", vault.retainedAfterUninstall ? "Yes" : "No"],
      ]),
    );
    appendVaultAuditEvents(details, vault.recentAudit);
    return details;
  }

  function appendVaultAuditEvents(details, eventsValue) {
    const events = Array.isArray(eventsValue) ? eventsValue : [];
    if (!events.length) {
      details.append(text("p", "empty-state", "No recent vault audit events."));
      return;
    }
    const list = document.createElement("div");
    list.className = "app-audit-list";
    events.slice(0, 8).forEach((event) => {
      const safeEvent = recordValue(event);
      const item = document.createElement("div");
      item.className = "app-audit-event";
      const header = document.createElement("div");
      header.className = "app-audit-event-header";
      header.append(
        createPill(normalizedStatus(safeEvent.operation, "Vault event")),
        text("span", "app-audit-action", scalar(safeEvent.targetId)),
      );
      item.append(header);
      item.append(
        definitionList([
          ["Time", formatIsoTimestamp(safeEvent.timestamp)],
          ["App ID", scalar(safeEvent.appId)],
          ["Target", scalar(safeEvent.targetType)],
          ["Outcome", scalar(safeEvent.outcome)],
          ["Reason", scalar(safeEvent.reasonCode)],
        ]),
      );
      list.append(item);
    });
    details.append(list);
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
    shellState.catalogFederationSnapshot = recordValue(data.catalogFederation);
    shellState.catalogFederationError =
      typeof data.catalogFederationError === "string" ? data.catalogFederationError : "";
    shellState.identityVaultSnapshot = recordValue(data.identityVault);
    shellState.recommendedCatalogsSnapshot = Array.isArray(data.recommendedCatalogs)
      ? data.recommendedCatalogs
      : null;
    updateAppsToolbar();
    clear(sections.apps);

    const apps = Array.isArray(data.apps) ? data.apps : [];
    const catalogs = Array.isArray(data.catalogs) ? data.catalogs : [];
    const recommendedCatalogs = Array.isArray(data.recommendedCatalogs)
      ? data.recommendedCatalogs
      : [];
    const catalogError = typeof data.catalogError === "string" ? data.catalogError : "";
    const recommendedCatalogError =
      typeof data.recommendedCatalogError === "string" ? data.recommendedCatalogError : "";
    const identityVault = recordValue(data.identityVault);
    const identityVaultError =
      typeof data.identityVaultError === "string" ? data.identityVaultError : "";
    const vaultIdentities = Array.isArray(identityVault.identities) ? identityVault.identities : [];
    const vaultGrants = Array.isArray(identityVault.grants) ? identityVault.grants : [];
    const appServices = recordValue(data.appServices);
    const appServicesError =
      typeof data.appServicesError === "string" ? data.appServicesError : "";
    const serviceDescriptors = Array.isArray(appServices.services) ? appServices.services : [];
    const serviceGrants = Array.isArray(appServices.grants) ? appServices.grants : [];
    const reviewGovernance = recordValue(data.reviewGovernance);
    const reviewerKeys = recordValue(data.reviewerKeys);
    const transparencyVerification = recordValue(data.reviewTransparencyVerification);
    const runningApps = apps.filter((app) => app && typeof app === "object" && app.running).length;
    const summaryEntries = [
      ["Installed apps", `${apps.length}`],
      ["Running apps", `${runningApps}`],
      ["Catalogs", `${catalogs.length}`],
      ["Recommended catalogs", `${recommendedCatalogs.length}`],
      ["Vault identities", `${vaultIdentities.length}`],
      ["Identity grants", `${vaultGrants.length}`],
      ["App services", `${serviceDescriptors.length}`],
      ["Service grants", `${serviceGrants.length}`],
      ["Review log verified", transparencyVerification.verified === false ? "No" : "Yes"],
      ["Reviewer keys", `${Array.isArray(reviewerKeys.keys) ? reviewerKeys.keys.length : 0}`],
      ["Scope", formPassword ? "Shell-native" : "Read-only"],
      ...topLevelFieldEntries(data, [
        "apps",
        "catalogs",
        "recommendedCatalogs",
        "identityVault",
        "appServices",
        "reviewGovernance",
        "reviewerKeys",
        "reviewTransparencyLog",
        "reviewTransparencyVerification",
        "catalogError",
        "recommendedCatalogError",
        "identityVaultError",
        "appServicesError",
        "reviewGovernanceError",
      ]),
    ];
    sections.apps.append(summaryCard("Apps summary", summaryEntries, apps.length ? "" : "is-warning"));

    renderReviewGovernance(
      reviewGovernance,
      reviewerKeys,
      recordValue(data.reviewTransparencyLog),
      transparencyVerification,
      typeof data.reviewGovernanceError === "string" ? data.reviewGovernanceError : "",
    );

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

    renderAppServices(appServices, appServicesError);
    renderIdentityVault(identityVault, identityVaultError, apps);
    renderCatalogDiscovery(recordValue(data.catalogFederation));
    renderRecommendedCatalogs(recommendedCatalogs, recommendedCatalogError, catalogs);
    renderCatalogs(catalogs, catalogError);
  }

  function renderReviewGovernance(governance, reviewerKeys, transparencyLog, verification, error) {
    sections.apps.append(text("h3", "app-card-title", "Review governance"));
    if (error) {
      sections.apps.append(text("p", "error-state", `Review governance unavailable: ${error}`));
      return;
    }
    const registry = recordValue(governance.trustedReviewerRegistry);
    const counts = recordValue(registry.counts);
    const log = recordValue(governance.transparencyLog);
    const keys = Array.isArray(reviewerKeys.keys) ? reviewerKeys.keys : [];
    sections.apps.append(
      summaryCard(
        "Governance summary",
        [
          ["Review policy mode", normalizedStatus(governance.reviewPolicyMode, "Advisory")],
          ["Registry version", scalar(registry.version)],
          ["Active reviewers", scalar(counts.active || 0)],
          ["Retired reviewers", scalar(counts.retired || 0)],
          ["Revoked reviewers", scalar(counts.revoked || 0)],
          ["Transparency records", scalar(log.recordCount || transparencyLog.records?.length || 0)],
          ["Transparency verified", verification.verified === false ? "No" : "Yes"],
          ["Latest hash", scalar(log.latestRecordHash || verification.latestRecordHash)],
        ],
        verification.verified === false ? "is-error" : "",
      ),
    );
    if (keys.length) {
      const list = document.createElement("div");
      list.className = "app-card-list";
      keys.forEach((key) => {
        const card = document.createElement("article");
        card.className = "app-card";
        const header = document.createElement("div");
        header.className = "app-card-header";
        const heading = document.createElement("div");
        heading.className = "app-card-heading";
        heading.append(
          text("h4", "catalog-app-title", scalar(key.displayName || key.keyId)),
          text("p", "app-card-subtitle", scalar(key.keyId)),
        );
        const pills = document.createElement("div");
        pills.className = "app-card-pills";
        pills.append(createPill(normalizedStatus(key.status, "Active"), reviewerKeyTone(key.status)));
        pills.append(createPill(scalar(key.algorithm)));
        header.append(heading, pills);
        card.append(header);
        card.append(
          definitionList([
            ["Policy", [key.policyId, key.policyVersion].filter((value) => value).join(" ") || "Any"],
            ["Valid from", formatIsoTimestamp(key.validFrom)],
            ["Valid until", formatIsoTimestamp(key.validUntil)],
            ["Rotates from", scalar(key.rotatesFrom)],
            ["Rotates to", scalar(key.rotatesTo)],
            ["Revoked at", formatIsoTimestamp(key.revokedAt)],
          ]),
        );
        list.append(card);
      });
      sections.apps.append(list);
    } else {
      sections.apps.append(text("p", "empty-state", "No trusted reviewer keys are configured."));
    }
  }

  function reviewerKeyTone(status) {
    const normalized = typeof status === "string" ? status.toLowerCase() : "";
    if (normalized === "active") {
      return "is-success";
    }
    if (normalized === "revoked") {
      return "is-error";
    }
    return "is-warning";
  }

  function renderAppServices(appServices, appServicesError) {
    sections.apps.append(text("h3", "app-card-title", "App-service grants"));
    if (appServicesError) {
      sections.apps.append(
        text("p", "error-state", `App-service grants unavailable: ${appServicesError}`),
      );
      return;
    }
    const services = Array.isArray(appServices.services) ? appServices.services : [];
    const requests = Array.isArray(appServices.requests) ? appServices.requests : [];
    const grants = Array.isArray(appServices.grants) ? appServices.grants : [];
    const dependencyGraph = appServices.dependencyGraph || { apps: [], edges: [] };
    const dependencyApps = Array.isArray(dependencyGraph.apps) ? dependencyGraph.apps : [];
    const dependencyEdges = Array.isArray(dependencyGraph.edges) ? dependencyGraph.edges : [];
    const bundles = Array.isArray(appServices.bundles) ? appServices.bundles : [];
    const audit = Array.isArray(appServices.audit) ? appServices.audit : [];
    sections.apps.append(
      summaryCard(
        "Service grant summary",
        [
          ["Advertised services", `${services.length}`],
          ["Declared requests", `${requests.length}`],
          ["Dependency edges", `${dependencyEdges.length}`],
          ["Grant bundles", `${bundles.length}`],
          ["Pending grants", `${grants.filter((grant) => grant.status === "pending").length}`],
          ["Active grants", `${grants.filter((grant) => grant.status === "active").length}`],
          ["Revoked grants", `${grants.filter((grant) => grant.status === "revoked").length}`],
          ["Audit events", `${audit.length}`],
        ],
        services.length || requests.length || dependencyEdges.length || bundles.length || grants.length
          ? ""
          : "is-warning",
      ),
    );
    if (!services.length && !requests.length && !dependencyEdges.length && !bundles.length && !grants.length) {
      sections.apps.append(text("p", "empty-state", "No app-service descriptors or grants were returned."));
      return;
    }
    const list = document.createElement("div");
    list.className = "app-card-list";
    if (dependencyEdges.length || dependencyApps.length) {
      list.append(renderAppServiceDependencyGraph(dependencyGraph));
    }
    dependencyApps.forEach((app) => {
      const dependencies = Array.isArray(app.dependencies) ? app.dependencies : [];
      dependencies.forEach((dependency) => {
        list.append(renderAppServiceDependencyCard(dependency));
      });
    });
    bundles.forEach((bundle) => {
      list.append(renderAppServiceBundleCard(bundle));
    });
    services.forEach((service) => {
      list.append(renderAppServiceDescriptorCard(service));
    });
    requests.forEach((request) => {
      list.append(renderAppServiceRequestCard(request));
    });
    grants.forEach((grant) => {
      list.append(renderAppServiceGrantCard(grant));
    });
    sections.apps.append(list);
    if (audit.length) {
      sections.apps.append(renderAppServiceAuditDetails(audit));
    }
  }

  function renderAppServiceDescriptorCard(service) {
    const card = document.createElement("article");
    card.className = "catalog-app-card";
    const header = document.createElement("div");
    header.className = "catalog-app-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h4", "catalog-app-title", scalar(service.name || service.serviceId)),
      text("p", "app-card-subtitle", `${scalar(service.providerAppId)} / ${scalar(service.serviceId)}`),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill("Service"));
    pills.append(createPill(service.available === false ? "Unavailable" : "Available", service.available === false ? "is-warning" : "is-success"));
    pills.append(createPill(scalar(service.stability || "preview")));
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Provider", scalar(service.providerName || service.providerAppId)],
        ["Provider version", scalar(service.providerVersion)],
        ["Service version", scalar(service.version)],
        ["Kind", scalar(service.kind)],
        ["Adapter", scalar(service.adapter)],
        ["Scopes", formatPermissions(service.scopes)],
        ["Contexts", formatPermissions(service.contexts)],
        ["Description", scalar(service.description)],
      ]),
    );
    return card;
  }

  function renderAppServiceDependencyGraph(graph) {
    const card = document.createElement("article");
    card.className = "catalog-app-card";
    const apps = Array.isArray(graph.apps) ? graph.apps : [];
    const edges = Array.isArray(graph.edges) ? graph.edges : [];
    const header = document.createElement("div");
    header.className = "catalog-app-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h4", "catalog-app-title", "Dependency graph"),
      text("p", "app-card-subtitle", `${apps.length} apps / ${edges.length} service edges`),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill("Graph"));
    const warningCount = edges.filter((edge) => edge.status && edge.status !== "grant-active").length;
    pills.append(createPill(`${warningCount} review`, warningCount ? "is-warning" : "is-success"));
    header.append(heading, pills);
    card.append(header);
    apps.forEach((app) => {
      const dependencies = Array.isArray(app.dependencies) ? app.dependencies : [];
      const appSection = document.createElement("section");
      appSection.className = "catalog-app-list";
      appSection.append(
        text("h5", "catalog-app-title", scalar(app.name || app.appId)),
        definitionList([
          ["App", scalar(app.appId)],
          ["Version", scalar(app.version)],
          ["Dependencies", `${dependencies.length}`],
          ["Dependency status", appServiceDependencySummaries(dependencies)],
        ]),
      );
      card.append(appSection);
    });
    return card;
  }

  function renderAppServiceDependencyCard(dependency) {
    const card = document.createElement("article");
    card.className = "catalog-app-card";
    const status = typeof dependency.status === "string" ? dependency.status : "unavailable";
    const header = document.createElement("div");
    header.className = "catalog-app-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h5", "catalog-app-title", scalar(dependency.featureName || dependency.alias)),
      text("p", "app-card-subtitle", `${scalar(dependency.providerAppId)} / ${scalar(dependency.serviceId)}`),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill(dependency.required ? "Required" : "Optional", dependency.required ? "is-error" : ""));
    pills.append(createPill(normalizedStatus(status, "dependency"), appServiceGrantTone(status)));
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Alias", scalar(dependency.alias)],
        ["Feature", scalar(dependency.featureId)],
        ["Scopes", formatPermissions(dependency.scopes)],
        ["Contexts", formatPermissions(dependency.contexts)],
        ["Version range", appServiceVersionRange(dependency.versionRange)],
        ["Degrade behavior", scalar(dependency.degradeBehavior)],
        ["Grant bundle", scalar(dependency.grantBundle)],
        ["Grant expiry", scalar(dependency.grantExpiresAfter)],
        ["Grant", scalar(dependency.grantId)],
        ["Blocking", scalar(dependency.blocking)],
        ["Reason", scalar(dependency.reason)],
      ]),
    );
    return card;
  }

  function renderAppServiceBundleCard(bundle) {
    const card = document.createElement("section");
    card.className = "catalog-app-card";
    const status = typeof bundle.status === "string" ? bundle.status : "";
    if (status && status !== "approved") {
      card.className += " is-update-available";
    }
    const header = document.createElement("div");
    header.className = "catalog-app-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h4", "catalog-app-title", `${scalar(bundle.consumerAppId)} grant bundle`),
      text("p", "app-card-subtitle", scalar(bundle.bundleId)),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill(normalizedStatus(status, "bundle"), appServiceGrantTone(status)));
    pills.append(createPill(scalar(bundle.bundleAlias || "default")));
    header.append(heading, pills);
    card.append(header);
    const dependencies = Array.isArray(bundle.dependencies) ? bundle.dependencies : [];
    card.append(
      definitionList([
        ["Consumer", scalar(bundle.consumerAppId)],
        ["Purpose", scalar(bundle.purpose)],
        ["Dependencies", `${dependencies.length}`],
        ["Grant ids", formatPermissions(bundle.grantIds)],
        ["Created", formatIsoTimestamp(bundle.createdAt)],
        ["Updated", formatIsoTimestamp(bundle.updatedAt)],
        ["Approved", formatIsoTimestamp(bundle.approvedAt)],
        ["Rejected", formatIsoTimestamp(bundle.rejectedAt)],
        ["Expires", formatIsoTimestamp(bundle.expiresAt)],
        ["Renewed", formatIsoTimestamp(bundle.renewedAt)],
      ]),
    );
    if (dependencies.length) {
      card.append(
        definitionList([["Dependency status", appServiceDependencySummaries(dependencies)]]),
      );
    }
    const actions = document.createElement("div");
    actions.className = "app-card-actions";
    if (status === "pending") {
      const approveForm = buildAppServiceBundleActionForm(bundle, "approve", "Approve bundle");
      const rejectForm = buildAppServiceBundleActionForm(bundle, "reject", "Reject bundle");
      if (approveForm) {
        actions.append(approveForm);
      }
      if (rejectForm) {
        actions.append(rejectForm);
      }
    }
    if (status === "approved" || status === "expired" || status === "revalidation-required") {
      const renewForm = buildAppServiceBundleActionForm(bundle, "renew", "Renew bundle");
      if (renewForm) {
        actions.append(renewForm);
      }
    }
    if (actions.childNodes.length) {
      card.append(actions);
    }
    return card;
  }

  function appServiceDependencySummaries(dependencies) {
    if (!Array.isArray(dependencies) || !dependencies.length) {
      return "none";
    }
    return dependencies
      .map(
        (dependency) =>
          `${scalar(dependency.alias)}: ${scalar(dependency.providerAppId)} / ${scalar(dependency.serviceId)} (${scalar(dependency.status)})`,
      )
      .join("; ");
  }

  function renderAppServiceRequestCard(request) {
    const card = document.createElement("article");
    card.className = "catalog-app-card";
    const header = document.createElement("div");
    header.className = "catalog-app-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h4", "catalog-app-title", scalar(request.consumerName || request.consumerAppId)),
      text("p", "app-card-subtitle", `${scalar(request.providerAppId)} / ${scalar(request.serviceId)}`),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill("Request", "is-warning"));
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Consumer", scalar(request.consumerAppId)],
        ["Consumer version", scalar(request.consumerVersion)],
        ["Provider", scalar(request.providerAppId)],
        ["Service", scalar(request.serviceId)],
        ["Scopes", formatPermissions(request.scopes)],
        ["Contexts", formatPermissions(request.contexts)],
        ["Purpose", scalar(request.purpose)],
      ]),
    );
    return card;
  }

  function renderAppServiceGrantCard(grant) {
    const card = document.createElement("section");
    card.className = "catalog-app-card";
    const status = typeof grant.status === "string" ? grant.status : "";
    if (status && status !== "active") {
      card.className += " is-update-available";
    }
    const header = document.createElement("div");
    header.className = "catalog-app-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h4", "catalog-app-title", `${scalar(grant.consumerAppId)} -> ${scalar(grant.providerAppId)}`),
      text("p", "app-card-subtitle", scalar(grant.grantId)),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill(normalizedStatus(status, "grant"), appServiceGrantTone(status)));
    pills.append(createPill(scalar(grant.serviceId)));
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Consumer", scalar(grant.consumerAppId)],
        ["Provider", scalar(grant.providerAppId)],
        ["Service", scalar(grant.serviceId)],
        ["Scopes", formatPermissions(grant.scopes)],
        ["Contexts", formatPermissions(grant.contexts)],
        ["Purpose", scalar(grant.purpose)],
        ["Created", formatIsoTimestamp(grant.createdAt)],
        ["Approved", formatIsoTimestamp(grant.approvedAt)],
        ["Revoked", formatIsoTimestamp(grant.revokedAt)],
        ["Last used", formatIsoTimestamp(grant.lastUsedAt)],
        ["Expires", formatIsoTimestamp(grant.expiresAt)],
        ["Renewed", formatIsoTimestamp(grant.renewedAt)],
        ["Bundle", scalar(grant.bundleId)],
        ["Provider version at approval", scalar(grant.providerServiceVersionAtApproval)],
        ["Compatibility fingerprint", scalar(grant.compatibilityFingerprint)],
        ["Use count", scalar(grant.useCount || 0)],
      ]),
    );
    const actions = document.createElement("div");
    actions.className = "app-card-actions";
    if (status === "pending") {
      const approveForm = buildAppServiceGrantActionForm(grant, "approve", "Approve");
      if (approveForm) {
        actions.append(approveForm);
      }
    }
    if (status === "pending" || status === "active") {
      const revokeForm = buildAppServiceGrantActionForm(grant, "revoke", "Revoke");
      if (revokeForm) {
        actions.append(revokeForm);
      }
    }
    if (actions.childNodes.length) {
      card.append(actions);
    }
    return card;
  }

  function renderAppServiceAuditDetails(auditEvents) {
    const details = document.createElement("details");
    details.className = "json-details";
    const summary = document.createElement("summary");
    summary.textContent = "App-service audit";
    details.append(summary);
    const list = document.createElement("div");
    list.className = "catalog-app-list";
    auditEvents.forEach((event) => {
      const item = document.createElement("section");
      item.className = "catalog-app-card";
      item.append(
        text("h4", "catalog-app-title", scalar(event.eventType)),
        definitionList([
          ["Time", formatIsoTimestamp(event.timestamp)],
          ["Consumer", scalar(event.consumerAppId)],
          ["Provider", scalar(event.providerAppId)],
          ["Service", scalar(event.serviceId)],
          ["Grant", scalar(event.grantId)],
          ["Scope", scalar(event.scope)],
          ["Context", scalar(event.context)],
          ["Status", scalar(event.status)],
          ["Reason", scalar(event.reasonCode)],
          ["Subject hash", scalar(event.subjectUriHash)],
        ]),
      );
      list.append(item);
    });
    details.append(list);
    return details;
  }

  function appServiceGrantTone(status) {
    if (status === "active" || status === "grant-active" || status === "approved") {
      return "is-success";
    }
    if (
      status === "revoked" ||
      status === "inactive" ||
      status === "expired" ||
      status === "grant-expired" ||
      status === "missing-provider" ||
      status === "missing-service" ||
      status === "version-mismatch" ||
      status === "scope-mismatch" ||
      status === "context-mismatch"
    ) {
      return "is-error";
    }
    return "is-warning";
  }

  function appServiceVersionRange(versionRange) {
    if (!versionRange || typeof versionRange !== "object") {
      return "any";
    }
    const min = scalar(versionRange.min || "any");
    const max = scalar(versionRange.max || "any");
    return `${min} - ${max}`;
  }

  function renderIdentityVault(identityVault, identityVaultError, apps) {
    sections.apps.append(text("h3", "app-card-title", "Identity vault"));
    if (identityVaultError) {
      sections.apps.append(
        text("p", "error-state", `Identity vault unavailable: ${identityVaultError}`),
      );
      return;
    }
    const identities = Array.isArray(identityVault.identities) ? identityVault.identities : [];
    const grants = Array.isArray(identityVault.grants) ? identityVault.grants : [];
    sections.apps.append(
      summaryCard(
        "Vault summary",
        [
          ["Identities", `${identities.length}`],
          ["Grants", `${grants.length}`],
          ["Active grants", `${grants.filter((grant) => grant.status === "active").length}`],
        ],
        identities.length || grants.length ? "" : "is-warning",
      ),
    );
    const grantForm = buildIdentityVaultGrantForm(identities, apps);
    if (grantForm) {
      sections.apps.append(grantForm);
    }
    if (!identities.length && !grants.length) {
      sections.apps.append(text("p", "empty-state", "No vault identities or grants were returned."));
      return;
    }
    const list = document.createElement("div");
    list.className = "app-card-list";
    identities.forEach((identity) => {
      list.append(renderIdentityVaultCard(identity, grants));
    });
    grants
      .filter((grant) => !identities.some((identity) => identity.identityId === grant.identityId))
      .forEach((grant) => {
        list.append(renderIdentityGrantCard(grant));
      });
    sections.apps.append(list);
  }

  function renderIdentityVaultCard(identity, grants) {
    const card = document.createElement("article");
    card.className = "app-card";
    const identityGrants = grants.filter((grant) => grant.identityId === identity.identityId);
    const header = document.createElement("div");
    header.className = "app-card-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h3", "app-card-title", scalar(identity.label || identity.identityId)),
      text("p", "app-card-subtitle", scalar(identity.identityId)),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill(scalar(identity.kind)));
    pills.append(createPill(`${identityGrants.length} grants`));
    if (identity.ownerAppId) {
      pills.append(createPill("App-owned"));
    } else {
      pills.append(createPill("Operator-managed"));
    }
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Kind", scalar(identity.kind)],
        ["Owner app", scalar(identity.ownerAppId)],
        ["Fingerprint", scalar(identity.fingerprint)],
        ["Public summary", scalar(identity.publicSummary)],
        ["Usage scopes", formatPermissions(identity.usageScopes)],
        ["Created", formatIsoTimestamp(identity.createdAt)],
        ["Updated", formatIsoTimestamp(identity.updatedAt)],
      ]),
    );
    if (identityGrants.length) {
      const grantsList = document.createElement("div");
      grantsList.className = "catalog-app-list";
      identityGrants.forEach((grant) => {
        grantsList.append(renderIdentityGrantCard(grant));
      });
      card.append(grantsList);
    }
    return card;
  }

  function renderIdentityGrantCard(grant) {
    const card = document.createElement("section");
    card.className = "catalog-app-card";
    const status = typeof grant.status === "string" ? grant.status : "";
    if (status && status !== "active") {
      card.className += " is-update-available";
    }
    const header = document.createElement("div");
    header.className = "catalog-app-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h4", "catalog-app-title", scalar(grant.appId)),
      text("p", "app-card-subtitle", scalar(grant.grantId)),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill(normalizedStatus(status, "grant"), status === "active" ? "is-success" : "is-warning"));
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Identity", scalar(grant.identityId)],
        ["App ID", scalar(grant.appId)],
        ["Scopes", formatPermissions(grant.scopes)],
        ["Granted by", scalar(grant.grantedBy)],
        ["Reason", scalar(grant.reason)],
        ["Expires", formatIsoTimestamp(grant.expiresAt)],
        ["Review receipt", scalar(grant.sourceReviewReceiptId)],
      ]),
    );
    const revokeForm = buildIdentityVaultRevokeForm(grant);
    if (revokeForm) {
      const actions = document.createElement("div");
      actions.className = "app-card-actions";
      actions.append(revokeForm);
      card.append(actions);
    }
    return card;
  }

  function renderCatalogs(catalogs, catalogError) {
    const selectedChannel = normalizeCatalogChannel(shellState.catalogChannel);
    const routineCatalogs = Array.isArray(catalogs) ? catalogs : [];
    const federation = recordValue(shellState.catalogFederationSnapshot);
    const configuredIds = Array.isArray(federation.configuredCatalogIds)
      ? federation.configuredCatalogIds.filter(
          (catalogId) => typeof catalogId === "string" && catalogId,
        )
      : [];
    const routineIds = new Set(
      routineCatalogs
        .map((catalog) => (catalog && typeof catalog.catalogId === "string" ? catalog.catalogId : ""))
        .filter(Boolean),
    );
    const unavailableConfiguredIds = configuredIds.filter((catalogId) => !routineIds.has(catalogId));
    sections.apps.append(text("h3", "app-card-title", "Catalog apps"));
    sections.apps.append(
      text("p", "panel-description", `Showing ${catalogChannelLabel(selectedChannel)} channel apps.`),
    );
    if (catalogError) {
      sections.apps.append(text("p", "error-state", `Catalogs unavailable: ${catalogError}`));
    }
    if (!routineCatalogs.length && !unavailableConfiguredIds.length) {
      sections.apps.append(text("p", "empty-state", "No app catalogs were returned."));
      return;
    }
    const list = document.createElement("div");
    list.className = "app-card-list";
    routineCatalogs.forEach((catalog) => {
      list.append(
        renderCatalogCard(catalog && typeof catalog === "object" ? catalog : {}, selectedChannel),
      );
    });
    const bindings = Array.isArray(federation.bindings) ? federation.bindings : [];
    unavailableConfiguredIds.forEach((catalogId) => {
      const binding = bindings.find((candidate) => candidate && candidate.catalogId === catalogId);
      list.append(renderUnavailableConfiguredCatalogCard(catalogId, recordValue(binding)));
    });
    sections.apps.append(list);
  }

  function renderUnavailableConfiguredCatalogCard(catalogId, binding) {
    const card = document.createElement("article");
    card.className = "app-card";
    const status = typeof binding.status === "string" ? binding.status : "unavailable";
    const header = document.createElement("div");
    header.className = "app-card-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h3", "app-card-title", catalogId),
      text("p", "app-card-subtitle", "Configured source unavailable for routine work"),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(
      createPill(status, operatorStatusTone(status)),
      createPill("local recovery required", "is-warning"),
    );
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Catalog ID", catalogId],
        ["Local binding", scalar(binding.bindingId)],
        ["Binding status", status],
      ]),
      text(
        "p",
        "panel-description",
        "This source remains configured but is not authorized for refresh, install, or update. Remove it before re-adding it under an active, exact local trust binding.",
      ),
    );
    if (formPassword) {
      const removeForm = buildCatalogActionForm({ catalogId }, null, "remove", "Remove");
      if (removeForm) {
        const actions = document.createElement("div");
        actions.className = "app-card-actions";
        actions.append(removeForm);
        card.append(actions);
      }
    }
    return card;
  }

  function renderRecommendedCatalogs(recommendedCatalogs, recommendedCatalogError, catalogs) {
    sections.apps.append(text("h3", "app-card-title", "Recommended catalogs"));
    sections.apps.append(
      text(
        "p",
        "app-card-subtitle",
        "Known, recommended, and endorsed catalogs are evidence only. Local trust is explicit; suspended, revoked, or conflicted catalogs cannot authorize routine app operations, and source switching is never automatic.",
      ),
    );
    if (recommendedCatalogError) {
      sections.apps.append(
        text("p", "error-state", `Recommended catalogs unavailable: ${recommendedCatalogError}`),
      );
      return;
    }
    if (!Array.isArray(recommendedCatalogs) || recommendedCatalogs.length === 0) {
      sections.apps.append(text("p", "empty-state", "No recommended app catalogs were returned."));
      return;
    }
    const list = document.createElement("div");
    list.className = "app-card-list";
    recommendedCatalogs.forEach((catalog) => {
      list.append(
        renderRecommendedCatalogCard(
          catalog && typeof catalog === "object" ? catalog : {},
          Array.isArray(catalogs) ? catalogs : [],
        ),
      );
    });
    sections.apps.append(list);
  }

  function renderCatalogDiscovery(federation) {
    sections.apps.append(text("h3", "app-card-title", "Federated catalog discovery"));
    sections.apps.append(
      text(
        "p",
        "app-card-subtitle",
        "Signed descriptors and direct endorsements are local evidence only. Import never trusts a catalog, configures a source, follows an endorsement chain, or publishes this node's subscriptions.",
      ),
    );
    const pending = Array.isArray(federation.pendingDiscoveries)
      ? federation.pendingDiscoveries
      : [];
    if (federation.mode !== "federated-local-trust") {
      sections.apps.append(
        text("p", "empty-state", "Pending discovery import is available only in federated local-trust mode."),
      );
      return;
    }
    if (federation.discoveryAvailable && formPassword) {
      sections.apps.append(buildCatalogDiscoveryImportForm());
    } else if (!federation.discoveryAvailable) {
      sections.apps.append(
        text("p", "status-message is-warning", "Pending catalog discovery storage is unavailable."),
      );
    }
    if (!pending.length) {
      sections.apps.append(text("p", "empty-state", "No pending discovery recommendations."));
      return;
    }
    const list = document.createElement("div");
    list.className = "app-card-list";
    pending.forEach((recommendation) => {
      list.append(renderPendingCatalogDiscoveryCard(recordValue(recommendation)));
    });
    sections.apps.append(list);
  }

  function buildCatalogDiscoveryImportForm() {
    const form = document.createElement("form");
    form.className = "control-form";
    form.dataset.catalogDiscoveryAction = "import";
    const descriptorLabel = document.createElement("label");
    descriptorLabel.className = "queue-field";
    descriptorLabel.append(text("span", "", "Signed discovery descriptor JSON"));
    const descriptor = document.createElement("textarea");
    descriptor.name = "descriptorDocument";
    descriptor.rows = 6;
    descriptor.required = true;
    descriptor.autocomplete = "off";
    descriptorLabel.append(descriptor);
    const endorsementsLabel = document.createElement("label");
    endorsementsLabel.className = "queue-field";
    endorsementsLabel.append(text("span", "", "Optional direct endorsements JSON array"));
    const endorsements = document.createElement("textarea");
    endorsements.name = "endorsementDocuments";
    endorsements.rows = 4;
    endorsements.autocomplete = "off";
    endorsementsLabel.append(endorsements);
    const actions = document.createElement("div");
    actions.className = "control-form-actions";
    const submit = document.createElement("button");
    submit.className = "button button-primary";
    submit.type = "submit";
    submit.textContent = "Import pending evidence";
    actions.append(submit);
    form.append(
      descriptorLabel,
      endorsementsLabel,
      text(
        "p",
        "panel-description",
        "Only the supplied public documents are verified and retained locally; no source hint is fetched automatically.",
      ),
      actions,
    );
    return form;
  }

  function renderPendingCatalogDiscoveryCard(recommendation) {
    const card = document.createElement("article");
    card.className = "app-card";
    const header = document.createElement("div");
    header.className = "app-card-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h3", "app-card-title", scalar(recommendation.name || recommendation.catalogId)),
      text("p", "app-card-subtitle", scalar(recommendation.catalogId)),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill("known", "is-info"), createPill("recommended", "is-warning"));
    pills.append(
      createPill(
        scalar(recommendation.descriptorStatus),
        recommendation.descriptorStatus === "active" ? "is-success" : "is-error",
      ),
    );
    if (Number(recommendation.endorsementCount || 0) > 0) {
      pills.append(createPill("endorsed evidence", "is-warning"));
    }
    pills.append(createPill("not locally trusted", "is-error"));
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Descriptor ID", scalar(recommendation.descriptorId)],
        ["Current descriptor evidence", scalar(recommendation.descriptorStatus)],
        ["Summary", scalar(recommendation.summary)],
        ["Provider", scalar(recommendation.providerId)],
        ["Catalog signer", scalar(recommendation.catalogSignerKeyId)],
        ["Signer fingerprint", scalar(recommendation.catalogSignerFingerprintSha256)],
        ["Public source hints", stringList(recommendation.sourceHints).join(", ") || "Unavailable"],
        ["Channels", stringList(recommendation.channels).join(", ") || "Unavailable"],
        ["Descriptor digest", scalar(recommendation.descriptorDigestSha256)],
        ["Issuer", scalar(recommendation.issuerId)],
        ["Expires", formatIsoTimestamp(recommendation.expiresAt)],
        ["Direct endorsements", scalar(recommendation.endorsementCount || 0)],
        ["Local trust", "Not granted"],
        ["Catalog source", "Not configured"],
      ]),
    );
    if (formPassword && typeof recommendation.descriptorId === "string") {
      const actions = document.createElement("div");
      actions.className = "app-card-actions";
      const discard = document.createElement("form");
      discard.dataset.catalogDiscoveryAction = "discard";
      discard.dataset.descriptorId = recommendation.descriptorId;
      const button = document.createElement("button");
      button.className = "button button-secondary";
      button.type = "submit";
      button.textContent = "Discard pending evidence";
      discard.append(button);
      actions.append(discard);
      card.append(actions);
    }
    return card;
  }

  function matchingConfiguredCatalog(recommended, catalogs) {
    const catalogId = typeof recommended.catalogId === "string" ? recommended.catalogId : "";
    if (!catalogId) {
      return null;
    }
    return (
      catalogs.find(
        (catalog) => catalog && typeof catalog === "object" && catalog.catalogId === catalogId,
      ) || null
    );
  }

  function renderRecommendedCatalogCard(recommended, catalogs) {
    const configuredCatalog = matchingConfiguredCatalog(recommended, catalogs);
    const sourceKind =
      typeof recommended.sourceKind === "string" && recommended.sourceKind
        ? recommended.sourceKind
        : "unknown";
    const configured = Boolean(recommended.configured || configuredCatalog);
    const missingConfiguration = stringList(recommended.missingConfiguration);
    const warnings = stringList(recommended.warnings);
    const card = document.createElement("article");
    card.className = "app-card";
    const title =
      typeof recommended.name === "string" && recommended.name
        ? recommended.name
        : scalar(recommended.catalogId);
    const header = document.createElement("div");
    header.className = "app-card-header";
    const heading = document.createElement("div");
    heading.className = "app-card-heading";
    heading.append(
      text("h3", "app-card-title", title),
      text("p", "app-card-subtitle", scalar(recommended.catalogId)),
    );
    const pills = document.createElement("div");
    pills.className = "app-card-pills";
    pills.append(createPill(normalizedStatus(recommended.channel, "Beta")));
    pills.append(createPill(sourceKind));
    pills.append(createPill(configured ? "configured" : "not configured", configured ? "is-success" : "is-warning"));
    pills.append(
      createPill(
        recommended.trustedCatalogKeyConfigured ? "trusted key configured" : "trusted key missing",
        recommended.trustedCatalogKeyConfigured ? "is-success" : "is-warning",
      ),
    );
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Description", scalar(recommended.description)],
        ["Channel", normalizedStatus(recommended.channel, "Beta")],
        ["Source type", sourceKind],
        ["Source", scalar(recommended.source)],
        ["Catalog status", configured ? "Configured" : "Not configured"],
        ["Last successful refresh", configuredCatalog ? formatIsoTimestamp(catalogLastSuccessfulRefreshAt(configuredCatalog)) : "Unavailable"],
        ["Last failed attempt", configuredCatalog ? catalogLastFailedAttempt(configuredCatalog) : "Unavailable"],
        ["Trusted catalog key", scalar(recommended.trustedCatalogKeyId)],
        ["Reviewer policy", scalar(recommended.reviewerPolicyHint)],
        ["Missing configuration", missingConfiguration.join(", ") || "None"],
        ["Warnings", warnings.join(", ") || "None"],
      ]),
    );
    if (configuredCatalog) {
      const fetchWarning = catalogFetchWarningNode(configuredCatalog);
      if (fetchWarning) {
        card.append(fetchWarning);
      }
    }
    if (missingConfiguration.length && !configured) {
      card.append(
        text(
          "p",
          "status-message is-warning",
          `Catalog onboarding is waiting for ${missingConfiguration.join(", ")} configuration.`,
        ),
      );
    }
    if (formPassword && recommended.canAdd) {
      const actions = document.createElement("div");
      actions.className = "app-card-actions";
      const addForm = buildCatalogActionForm(recommended, null, "addRecommended", "Add catalog");
      if (addForm) {
        actions.append(addForm);
        card.append(actions);
      }
    }
    return card;
  }

  function catalogAppChannel(app) {
    return normalizeCatalogChannel(app && typeof app.channel === "string" ? app.channel : "stable");
  }

  function catalogChannelLabel(channel) {
    return normalizedStatus(normalizeCatalogChannel(channel), "Stable");
  }

  function catalogChannelTone(channel) {
    const normalized = normalizeCatalogChannel(channel);
    if (normalized === "stable") {
      return "is-success";
    }
    if (normalized === "deprecated") {
      return "is-error";
    }
    if (normalized === "nightly") {
      return "is-warning";
    }
    return "is-info";
  }

  function catalogMaintenancePolicy(app) {
    return recordValue(app && app.maintenance);
  }

  function catalogMaintenanceDeclared(maintenance) {
    return (
      typeof maintenance.owner === "string" ||
      typeof maintenance.supportLevel === "string" ||
      typeof maintenance.dataSchemaPolicy === "string" ||
      typeof maintenance.migrationPolicy === "string" ||
      typeof maintenance.backupRestore === "string" ||
      typeof maintenance.securityPolicy === "string" ||
      typeof maintenance.deprecationPolicy === "string"
    );
  }

  function maintenancePolicyTone(supportLevel) {
    const normalized = typeof supportLevel === "string" ? supportLevel.toLowerCase() : "";
    if (normalized === "core" || normalized === "maintained") {
      return "is-success";
    }
    if (normalized === "local-rc" || normalized === "preview" || normalized === "reference") {
      return "is-info";
    }
    if (normalized === "deprecated" || normalized === "unsupported") {
      return "is-error";
    }
    return "is-warning";
  }

  function catalogAppDeprecation(app) {
    return recordValue(app && app.deprecation);
  }

  function catalogAppDeprecated(app) {
    const deprecation = catalogAppDeprecation(app);
    const deprecationStatus =
      typeof deprecation.status === "string" ? deprecation.status.toLowerCase() : "none";
    const supportStatus =
      app && typeof app.supportStatus === "string" ? app.supportStatus.toLowerCase() : "";
    return (
      catalogAppChannel(app) === "deprecated" ||
      (deprecationStatus && deprecationStatus !== "none") ||
      supportStatus === "deprecated" ||
      supportStatus === "unsupported"
    );
  }

  function securityAdvisoryListNode(values) {
    const advisories = Array.isArray(values) ? values : [];
    if (!advisories.length) {
      return "None";
    }
    const list = document.createElement("ul");
    list.className = "metadata-link-list";
    advisories.forEach((value) => {
      const advisory = recordValue(value);
      const id = typeof advisory.id === "string" && advisory.id ? advisory.id : "Advisory";
      const item = document.createElement("li");
      if (typeof advisory.uri === "string" && advisory.uri) {
        item.append(metadataLinkNode(advisory.uri, id));
      } else {
        item.textContent = id;
      }
      list.append(item);
    });
    return list;
  }

  function securityDecisionStatus(securityDecision) {
    const decision = recordValue(securityDecision);
    return typeof decision.status === "string" && decision.status ? decision.status : "ok";
  }

  function securityDecisionLabel(securityDecision) {
    const decision = recordValue(securityDecision);
    const status = securityDecisionStatus(decision);
    if (status === "ok") {
      return "No active security advisory";
    }
    if (status === "denylisted") {
      return "Denylisted by catalog security policy";
    }
    return normalizedStatus(status);
  }

  function securityDecisionTone(securityDecision) {
    const status = securityDecisionStatus(securityDecision);
    if (status === "ok") {
      return "is-success";
    }
    if (status === "informational") {
      return "is-info";
    }
    if (status === "warning") {
      return "is-warning";
    }
    return "is-error";
  }

  function securityDecisionAdvisoryIds(securityDecision) {
    const ids = stringList(recordValue(securityDecision).advisoryIds);
    return ids.length ? ids.join(", ") : "None";
  }

  function securityDecisionWarnings(securityDecision) {
    const warnings = stringList(recordValue(securityDecision).warnings);
    return warnings.length ? warnings.join("; ") : "None";
  }

  function securityDecisionActionReason(securityDecision, action) {
    const decision = recordValue(securityDecision);
    if (action === "install" && decision.blocksInstall === true) {
      return `Install blocked by catalog security policy: ${securityDecisionLabel(decision)}.`;
    }
    if ((action === "update" || action === "stage" || action === "apply") && decision.blocksUpdate === true) {
      return `${normalizedStatus(action)} blocked by catalog security policy: ${securityDecisionLabel(decision)}.`;
    }
    return "";
  }

  function securityDecisionForCatalogAction(app) {
    return recordValue(app && app.securityDecision);
  }

  function installedSecurityDecisionForCatalogApp(app) {
    return recordValue(app && app.installedSecurityDecision);
  }

  function securityDecisionForUpdateAction(updateState, action) {
    const state = recordValue(updateState);
    const candidate = recordValue(state.candidate);
    const staged = recordValue(state.staged);
    if (action === "apply") {
      return recordValue(staged.securityDecision || candidate.securityDecision);
    }
    if (action === "stage") {
      return recordValue(candidate.securityDecision);
    }
    return {};
  }

  function appendSecurityAcknowledgement(form, securityDecision, action) {
    const decision = recordValue(securityDecision);
    if (decision.requiresAcknowledgement !== true) {
      return;
    }
    if (securityDecisionActionReason(decision, action)) {
      return;
    }
    const label = document.createElement("label");
    label.className = "checkbox-field security-acknowledgement";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.name = "securityAcknowledged";
    input.value = "true";
    input.required = true;
    label.append(input, document.createTextNode(` Acknowledge ${securityDecisionLabel(decision)}`));
    form.append(label);
  }

  function securityDecisionNoticeNode(securityDecision, installed) {
    const decision = recordValue(securityDecision);
    const status = securityDecisionStatus(decision);
    if (status === "ok") {
      return null;
    }
    const parts = [installed ? "Installed version security warning." : "Catalog security warning."];
    parts.push(securityDecisionLabel(decision));
    if (decision.severity && decision.severity !== "none") {
      parts.push(`Severity: ${normalizedStatus(decision.severity)}.`);
    }
    if (decision.safeUninstallGuidance) {
      parts.push(`Safe uninstall guidance: ${scalar(decision.safeUninstallGuidance)}`);
    }
    if (decision.replacementAppId) {
      parts.push(`Replacement guidance: ${scalar(decision.replacementAppId)}.`);
    }
    return text(
      "p",
      `status-message ${securityDecisionTone(decision)}`,
      parts.filter(Boolean).join(" "),
    );
  }

  function catalogSecurityDetailsNode(app) {
    const decision = securityDecisionForCatalogAction(app);
    const installedDecision = installedSecurityDecisionForCatalogApp(app);
    const details = document.createElement("details");
    details.className = "json-details catalog-security-details";
    const summary = document.createElement("summary");
    summary.textContent = "Security policy";
    details.append(summary);
    details.append(
      definitionList([
        ["Catalog target decision", securityDecisionLabel(decision)],
        ["Catalog target action", normalizedStatus(decision.action, "Inform")],
        ["Catalog target severity", normalizedStatus(decision.severity, "None")],
        ["Catalog target advisory IDs", securityDecisionAdvisoryIds(decision)],
        ["Target install handling", decision.blocksInstall ? "Blocked" : decision.requiresAcknowledgement ? "Acknowledgement required" : "Allowed"],
        ["Target update handling", decision.blocksUpdate ? "Blocked" : decision.requiresAcknowledgement ? "Acknowledgement required" : "Allowed"],
        ["Safe uninstall guidance", scalar(decision.safeUninstallGuidance)],
        ["Replacement guidance", scalar(decision.replacementAppId)],
        ["Warnings", securityDecisionWarnings(decision)],
        ["Installed version decision", securityDecisionLabel(installedDecision)],
        ["Installed advisory IDs", securityDecisionAdvisoryIds(installedDecision)],
        ["Installed safe uninstall guidance", scalar(installedDecision.safeUninstallGuidance)],
      ]),
    );
    return details;
  }

  function deprecationNoticeNode(app) {
    const deprecation = catalogAppDeprecation(app);
    const replacement =
      typeof deprecation.replacementAppId === "string" && deprecation.replacementAppId
        ? deprecation.replacementAppId
        : "";
    const message =
      typeof deprecation.message === "string" && deprecation.message ? deprecation.message : "";
    const suffix = replacement ? ` Replacement: ${replacement}.` : "";
    return text(
      "p",
      "status-message is-warning",
      `${message || "This catalog entry is deprecated and is not shown as a normal install or update candidate."}${suffix}`,
    );
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

  function catalogSourceDisplay(catalog) {
    return typeof catalog.sourceDisplay === "string" && catalog.sourceDisplay
      ? catalog.sourceDisplay
      : typeof catalog.source === "string"
        ? catalog.source
        : "";
  }

  function catalogResolvedSourceDisplay(catalog) {
    return typeof catalog.lastResolvedDisplay === "string" && catalog.lastResolvedDisplay
      ? catalog.lastResolvedDisplay
      : typeof catalog.lastResolvedUri === "string"
        ? catalog.lastResolvedUri
        : "";
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

  function renderCatalogOperationsNode(catalog) {
    const health = recordValue(catalog.operationsHealth);
    const keyRotation = recordValue(catalog.keyRotation);
    const sourceHealth = arrayValue(health.sourceHealth);
    const rollbackCandidates = arrayValue(catalog.rollbackCandidates);
    const details = document.createElement("details");
    details.className = "json-details catalog-operations-details";
    const summary = document.createElement("summary");
    summary.textContent = "Catalog operations";
    details.append(summary);
    details.append(
      definitionList([
        ["Active source", scalar(health.activeSourceId)],
        ["Fallback used", yesNoText(health.fallbackUsed, false)],
        ["Revision digest", scalar(health.catalogDigest || catalog.catalogDigest)],
        ["Key rotation", normalizedStatus(keyRotation.status, "Unavailable")],
        ["Current key trusted", yesNoText(keyRotation.currentKeyTrusted, null)],
        ["Rollback candidates", scalar(rollbackCandidates.length)],
      ]),
    );
    if (catalog.catalogOperationsError) {
      details.append(text("p", "error-state", `Catalog operations unavailable: ${catalog.catalogOperationsError}`));
    }
    if (sourceHealth.length) {
      const list = document.createElement("ul");
      list.className = "permission-list catalog-source-health-list";
      sourceHealth.forEach((entry) => {
        const record = recordValue(entry);
        const item = document.createElement("li");
        item.textContent = [
          scalar(record.sourceId),
          normalizedStatus(record.role, "source"),
          normalizedStatus(record.lastFetchStatus, "unknown"),
          formatIsoTimestamp(record.lastSuccessfulRefreshAt),
        ].join(" / ");
        list.append(item);
      });
      details.append(list);
    }
    return details;
  }

  function renderCatalogCard(catalog, selectedChannel) {
    const card = document.createElement("article");
    card.className = "app-card";
    const title = typeof catalog.name === "string" && catalog.name ? catalog.name : scalar(catalog.catalogId);
    const sourceKind = catalogSourceKind(catalog);
    const operationsHealth = recordValue(catalog.operationsHealth);
    const keyRotation = recordValue(catalog.keyRotation);
    const rollbackCandidates = arrayValue(catalog.rollbackCandidates);
    const apps = Array.isArray(catalog.apps) ? catalog.apps : [];
    const visibleApps = apps.filter((app) => catalogAppChannel(app) === selectedChannel);
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
    if (operationsHealth.fallbackUsed === true) {
      pills.append(createPill("fallback active", "is-warning"));
    }
    if (typeof keyRotation.status === "string" && keyRotation.status) {
      pills.append(createPill(`key ${keyRotation.status}`, operatorStatusTone(keyRotation.status)));
    }
    pills.append(
      createPill(
        `${visibleApps.length}/${apps.length} ${catalogChannelLabel(selectedChannel)} apps`,
        catalogChannelTone(selectedChannel),
      ),
    );
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["Source type", sourceKind],
        ["Source", scalar(catalogSourceDisplay(catalog))],
        ["Resolved source", scalar(catalogResolvedSourceDisplay(catalog))],
        ["Active source", scalar(operationsHealth.activeSourceId)],
        ["Generated", formatIsoTimestamp(catalog.generatedAt)],
        ["Last successful refresh", formatIsoTimestamp(catalogLastSuccessfulRefreshAt(catalog))],
        ["Last failed attempt", catalogLastFailedAttempt(catalog)],
      ]),
    );
    const fetchWarning = catalogFetchWarningNode(catalog);
    if (fetchWarning) {
      card.append(fetchWarning);
    }
    card.append(renderCatalogOperationsNode(catalog));
    if (catalog.appsError) {
      card.append(text("p", "error-state", `Catalog apps unavailable: ${catalog.appsError}`));
    }
    if (formPassword) {
      const actions = document.createElement("div");
      actions.className = "app-card-actions";
      const refreshForm = buildCatalogActionForm(catalog, null, "refresh", "Refresh");
      const refreshPrimaryForm = buildCatalogActionForm(catalog, null, "refreshPrimary", "Refresh primary");
      const emergencyRefreshForm = buildCatalogActionForm(catalog, null, "emergencyRefresh", "Emergency refresh");
      const removeForm = buildCatalogActionForm(catalog, null, "remove", "Remove");
      const rollbackForm = buildCatalogRollbackForm(
        catalog,
        rollbackCandidates.find((candidate) => candidate && candidate.eligible === true),
      );
      if (refreshForm) {
        actions.append(refreshForm);
      }
      if (refreshPrimaryForm) {
        actions.append(refreshPrimaryForm);
      }
      if (emergencyRefreshForm) {
        actions.append(emergencyRefreshForm);
      }
      if (rollbackForm) {
        actions.append(rollbackForm);
      }
      if (removeForm) {
        actions.append(removeForm);
      }
      if (actions.childNodes.length) {
        card.append(actions);
      }
    }

    if (!apps.length) {
      card.append(text("p", "empty-state", "No apps were returned for this catalog."));
      return card;
    }
    if (!visibleApps.length) {
      card.append(
        text("p", "empty-state", `No ${catalogChannelLabel(selectedChannel)} apps were returned for this catalog.`),
      );
      return card;
    }
    const appList = document.createElement("div");
    appList.className = "catalog-app-list";
    visibleApps.forEach((app) => {
      appList.append(renderCatalogAppCard(catalog, app && typeof app === "object" ? app : {}));
    });
    card.append(appList);
    return card;
  }

  function catalogReviewDetailsNode(app) {
    const review = recordValue(app.review);
    const thirdPartyReview = recordValue(app.thirdPartyReview);
    const reviewTrust = recordValue(app.reviewTrust);
    const reviewHistory = recordValue(app.reviewHistory);
    const historyLog = recordValue(reviewHistory.transparencyLog);
    const historyRecords = Array.isArray(historyLog.records) ? historyLog.records : [];
    const reviewer =
      reviewTrust.reviewerDisplayName || reviewTrust.reviewerKeyId || "Unavailable";
    const policy = [reviewTrust.policyId, reviewTrust.policyVersion].filter((entry) => entry).join(" ");
    const hasSubmissionMetadata = thirdPartyReview.hasSubmissionMetadata === true;
    const details = document.createElement("details");
    details.className = "json-details catalog-review-details";
    const summary = document.createElement("summary");
    summary.textContent = "Review and trust";
    details.append(summary);
    const rows = [
      ["Catalog signature", "Signed catalog publisher metadata"],
      ["Bundle artifact", "Digest checked before bundle signature verification"],
      ["Publisher advisory review", normalizedStatus(review.status, "Unreviewed")],
      ["Publisher advisory note", scalar(review.note)],
    ];
    if (hasSubmissionMetadata) {
      rows.push(
        ["Third-party submission", normalizedStatus(thirdPartyReview.status, "Unavailable")],
        ["Submission id", scalar(thirdPartyReview.submissionId)],
        ["Submission SHA-256", scalar(thirdPartyReview.submissionSha256)],
        ["Pre-review status", normalizedStatus(thirdPartyReview.preReviewStatus, "Unavailable")],
        ["Pre-review SHA-256", scalar(thirdPartyReview.preReviewSha256)],
        ["Submission reviewer", scalar(thirdPartyReview.reviewerKeyId)],
        ["Submission policy", scalar(thirdPartyReview.reviewerPolicy)],
        ["Review receipt fingerprint", scalar(thirdPartyReview.receiptFingerprintSha256)],
        ["Resubmission of", scalar(thirdPartyReview.resubmissionOf)],
        ["Submission evidence", thirdPartyReview.nonProduction ? "Non-production" : "Production"],
      );
    }
    rows.push(
      ["Trusted review receipt", reviewTrustLabel(reviewTrust)],
      ["Trusted reviewer", scalar(reviewer)],
      ["Reviewer key id", scalar(reviewTrust.reviewerKeyId)],
      ["Reviewer key status", normalizedStatus(reviewTrust.reviewerKeyStatus, "Unavailable")],
      ["Review policy", scalar(policy)],
      ["Policy version status", normalizedStatus(reviewTrust.policyVersionStatus, "Unavailable")],
      ["Policy mode", normalizedStatus(reviewTrust.policyMode, "Advisory")],
      ["Reviewed at", formatIsoTimestamp(reviewTrust.reviewedAt)],
      ["Expires at", formatIsoTimestamp(reviewTrust.expiresAt)],
      ["Evidence SHA-256", scalar(reviewTrust.evidenceSha256)],
      ["Evidence URI", metadataLinkNode(reviewTrust.evidenceUri)],
      ["Install handling", reviewTrust.blocksInstall ? "Blocked" : reviewTrust.requiresAcknowledgement ? "Acknowledgement required" : "Allowed"],
      ["Update handling", reviewTrust.blocksUpdate ? "Blocked" : reviewTrust.requiresAcknowledgement ? "Acknowledgement required" : "Allowed"],
      ["Installed version", scalar(reviewHistory.installedVersion || app.installedVersion)],
      ["Catalog version", scalar(reviewHistory.catalogVersion || app.version)],
      ["Transparency entries", scalar(historyRecords.length)],
      ["Latest transparency hash", scalar(historyRecords.length ? historyRecords[historyRecords.length - 1].recordHash : null)],
      ["Warnings", reviewTrustWarnings(reviewTrust)],
    );
    details.append(
      definitionList(rows),
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
        ["Maximum Crypta version", scalar(compatibility.maximumCryptaVersion)],
        ["Current Crypta version", scalar(compatibility.currentCryptaVersion)],
        ["Satisfied", compatibility.satisfied == null ? "Advisory" : compatibility.satisfied ? "Yes" : "No"],
        ["Status", normalizedStatus(compatibility.status, "Advisory")],
        ["Advisory", compatibility.advisory === false ? "No" : "Yes"],
      ]),
    );
    return details;
  }

  function apiCompatibilityDetailsNode(app) {
    const compatibility = recordValue(app.apiCompatibility);
    const targetBaseline = apiTargetBaselinePresentation(compatibility);
    const details = document.createElement("details");
    details.className = "json-details api-compatibility-details";
    const summary = document.createElement("summary");
    summary.textContent = "Platform API contract";
    details.append(summary);
    details.append(
      definitionList([
        ["Current API contract version", scalar(compatibility.currentVersion)],
        ["Minimum API contract version", scalar(compatibility.minimumVersion)],
        ["Maximum tested API contract version", scalar(compatibility.maximumTestedVersion)],
        ["Target API stability", normalizedStatus(compatibility.targetStability, "Legacy experimental")],
        ["Target stable baseline", targetBaseline.targetBaseline],
        ["Target baseline declaration", targetBaseline.declaration],
        ["Status", apiCompatibilityLabel(compatibility)],
        ["Evidence boundary", "Static contract analysis; not a runtime compatibility observation"],
        ["Optional capabilities", formatPermissions(compatibility.optionalCapabilities)],
        ["Experimental capabilities accepted", compatibility.experimentalCapabilitiesAccepted ? "Yes" : "No"],
        ["Warnings", stringList(compatibility.warnings).join("; ") || "None"],
      ]),
    );
    return details;
  }

  function catalogMaintenancePolicyNode(app) {
    const maintenance = catalogMaintenancePolicy(app);
    const details = document.createElement("details");
    details.className = "json-details catalog-maintenance-details";
    const summary = document.createElement("summary");
    summary.textContent = "Maintenance policy";
    details.append(summary);
    details.append(
      definitionList([
        ["Maintenance owner", scalar(maintenance.owner)],
        ["Owner link", metadataLinkNode(maintenance.ownerUri)],
        ["Maintenance support level", normalizedStatus(maintenance.supportLevel, "Unavailable")],
        ["Data schema policy", normalizedStatus(maintenance.dataSchemaPolicy, "Unavailable")],
        ["Migration policy", normalizedStatus(maintenance.migrationPolicy, "Unavailable")],
        ["Backup/restore support", normalizedStatus(maintenance.backupRestore, "Unavailable")],
        ["Security policy", normalizedStatus(maintenance.securityPolicy, "Unavailable")],
        ["Deprecation policy", normalizedStatus(maintenance.deprecationPolicy, "Unavailable")],
        ["Support link", metadataLinkNode(maintenance.supportUri)],
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
    const channel = catalogAppChannel(app);
    const deprecation = catalogAppDeprecation(app);
    const maintenance = catalogMaintenancePolicy(app);
    const maintenanceDeclared = catalogMaintenanceDeclared(maintenance);
    const deprecated = catalogAppDeprecated(app);
    if (channel !== "stable") {
      card.className += " is-preview-channel";
    }
    if (deprecated) {
      card.className += " is-deprecated-channel";
    }

    const review = recordValue(app.review);
    const reviewTrust = recordValue(app.reviewTrust);
    const securityDecision = securityDecisionForCatalogAction(app);
    const installedSecurityDecision = installedSecurityDecisionForCatalogApp(app);
    const compatibility = recordValue(app.compatibility);
    const apiCompatibility = recordValue(app.apiCompatibility);
    if (securityDecisionStatus(securityDecision) !== "ok") {
      card.className += " has-security-warning";
    }
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
    pills.append(createPill(catalogChannelLabel(channel), catalogChannelTone(channel)));
    pills.append(
      createPill(
        normalizedStatus(app.supportStatus, "Supported"),
        deprecated ? "is-warning" : "is-info",
      ),
    );
    if (deprecated) {
      pills.append(createPill(normalizedStatus(deprecation.status, "Deprecated"), "is-error"));
    }
    if (maintenanceDeclared) {
      pills.append(
        createPill(
          `Maint: ${normalizedStatus(maintenance.supportLevel, "Policy")}`,
          maintenancePolicyTone(maintenance.supportLevel),
        ),
      );
    }
    pills.append(createPill(`Advisory: ${normalizedStatus(review.status, "Unreviewed")}`, reviewTone(review.status)));
    pills.append(createPill(reviewTrustLabel(reviewTrust), reviewTrustTone(reviewTrust)));
    if (securityDecisionStatus(securityDecision) !== "ok") {
      pills.append(createPill(securityDecisionLabel(securityDecision), securityDecisionTone(securityDecision)));
    }
    if (securityDecisionStatus(installedSecurityDecision) !== "ok") {
      pills.append(createPill("Installed version vulnerable", securityDecisionTone(installedSecurityDecision)));
    }
    pills.append(createPill(versionLabel(app), versionTone(app)));
    pills.append(createPill(compatibilityLabel(compatibility), compatibilityTone(compatibility)));
    pills.append(createPill(apiCompatibilityLabel(apiCompatibility), apiCompatibilityTone(apiCompatibility)));
    header.append(heading, pills);
    card.append(header);
    card.append(
      definitionList([
        ["App ID", scalar(app.appId)],
        ["Catalog version", scalar(app.version)],
        ["Installed version", scalar(app.installedVersion)],
        ["Version change", versionSummary(app)],
        ["Channel", catalogChannelLabel(channel)],
        ["Support status", normalizedStatus(app.supportStatus, "Supported")],
        ["Maintenance owner", maintenanceDeclared ? scalar(maintenance.owner) : "Unavailable"],
        ["Maintenance support", maintenanceDeclared ? normalizedStatus(maintenance.supportLevel, "Unavailable") : "Unavailable"],
        ["Deprecation status", normalizedStatus(deprecation.status, "None")],
        ["Replacement app", scalar(deprecation.replacementAppId)],
        ["Deprecation message", scalar(deprecation.message)],
        ["Security advisories", securityAdvisoryListNode(app.securityAdvisories)],
        ["Security decision", securityDecisionLabel(securityDecision)],
        ["Security action", normalizedStatus(securityDecision.action, "Inform")],
        ["Security severity", normalizedStatus(securityDecision.severity, "None")],
        ["Security advisory IDs", securityDecisionAdvisoryIds(securityDecision)],
        ["Installed security decision", securityDecisionLabel(installedSecurityDecision)],
        ["Safe uninstall guidance", scalar(installedSecurityDecision.safeUninstallGuidance || securityDecision.safeUninstallGuidance)],
        ["Summary", scalar(app.summary)],
        ["Homepage", metadataLinkNode(app.homepage)],
        ["Source", metadataLinkNode(app.source)],
        ["License", scalar(app.license)],
        ["Categories", chipListNode(app.categories)],
        ["Publisher advisory review", normalizedStatus(review.status, "Unreviewed")],
        ["Publisher advisory note", scalar(review.note)],
        ["Trusted review receipt", reviewTrustLabel(reviewTrust)],
        ["Trusted reviewer", scalar(reviewTrust.reviewerDisplayName || reviewTrust.reviewerKeyId)],
        ["Permissions", formatPermissions(app.permissions)],
        ["Permission changes", `+${stringList(recordValue(app.permissionDelta).added).length} / -${stringList(recordValue(app.permissionDelta).removed).length}`],
        ["Compatibility", compatibilityLabel(compatibility)],
        ["Minimum Crypta version", scalar(compatibility.minimumCryptaVersion)],
        ["Maximum Crypta version", scalar(compatibility.maximumCryptaVersion)],
        ["API contract", apiCompatibilityLabel(apiCompatibility)],
        ["Minimum API contract version", scalar(apiCompatibility.minimumVersion)],
        ["Maximum tested API contract version", scalar(apiCompatibility.maximumTestedVersion)],
        ["Changelog", scalar(recordValue(app.changelog).summary)],
        ["Installed", app.installed ? "Yes" : "No"],
        ["Running", app.running ? "Yes" : "No"],
      ]),
    );
    card.append(catalogReviewDetailsNode(app));
    const securityNotice = securityDecisionNoticeNode(securityDecision, false);
    if (securityNotice) {
      card.append(securityNotice);
    }
    const installedSecurityNotice = securityDecisionNoticeNode(installedSecurityDecision, true);
    if (installedSecurityNotice) {
      card.append(installedSecurityNotice);
    }
    if (deprecated) {
      card.append(deprecationNoticeNode(app));
    }
    card.append(catalogSecurityDetailsNode(app));
    card.append(catalogCompatibilityDetailsNode(app));
    card.append(apiCompatibilityDetailsNode(app));
    if (maintenanceDeclared) {
      card.append(catalogMaintenancePolicyNode(app));
    }
    card.append(catalogPermissionReviewDetailsNode(app));
    card.append(catalogReleaseDetailsNode(app));
    if (formPassword && !deprecated) {
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
      const securityBlockReason = securityDecisionActionReason(securityDecision, action);
      if (securityBlockReason) {
        card.append(text("p", "status-message is-error", securityBlockReason));
      } else {
        const form = buildCatalogActionForm(catalog, app, action, label);
        if (form) {
          actions.append(form);
          card.append(actions);
        }
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

  function updateBetaDashboardToolbar() {
    if (sections.betaDashboardReadonlyHint) {
      sections.betaDashboardReadonlyHint.hidden = !!formPassword;
    }
    if (betaDashboardControls.appDataRestoreForm) {
      betaDashboardControls.appDataRestoreForm.hidden = !formPassword;
    }
    const hasSupportBundle = !!shellState.supportBundleSnapshot;
    const supportExportBlocked = supportBundleExportBlocked(shellState.supportBundleSnapshot);
    betaDashboardControls.supportDownloadButton.disabled =
      !hasSupportBundle || supportExportBlocked;
    betaDashboardControls.supportCopyButton.disabled = !hasSupportBundle || supportExportBlocked;
    if (betaDashboardControls.allAppDataBackupButton) {
      betaDashboardControls.allAppDataBackupButton.disabled = !formPassword;
    }
  }

  function updateAppsToolbar() {
    if (appsControls.catalogSourceForm) {
      appsControls.catalogSourceForm.hidden = !formPassword;
    }
    if (appsControls.catalogChannelSelect) {
      appsControls.catalogChannelSelect.value = normalizeCatalogChannel(shellState.catalogChannel);
    }
    updateCatalogSourceTrustBinding();
    if (sections.appsReadonlyHint) {
      sections.appsReadonlyHint.hidden = !!formPassword;
    }
  }

  function updateCatalogSourceTrustBinding() {
    const field = appsControls.catalogSourceTrustBindingField;
    const select = appsControls.catalogSourceTrustBinding;
    const submit = appsControls.catalogSourceSubmit;
    const status = appsControls.catalogSourceTrustBindingStatus;
    if (!field || !select || !submit || !status) {
      return;
    }
    const federation = recordValue(shellState.catalogFederationSnapshot);
    const mode = typeof federation.mode === "string" ? federation.mode : "";
    const federated = mode === "federated-local-trust";
    const legacy = mode === "legacy-global-compatibility";
    field.hidden = !federated;
    select.required = federated;
    select.disabled = !formPassword || !federated;

    const previous = select.value;
    select.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "Select an active local binding";
    select.append(placeholder);
    const configuredCatalogIds = new Set(
      (Array.isArray(federation.configuredCatalogIds) ? federation.configuredCatalogIds : [])
        .filter((catalogId) => typeof catalogId === "string" && catalogId),
    );
    const bindings = Array.isArray(federation.bindings) ? federation.bindings : [];
    bindings
      .filter(
        (binding) =>
          binding &&
          binding.status === "active" &&
          typeof binding.catalogId === "string" &&
          !configuredCatalogIds.has(binding.catalogId),
      )
      .sort((left, right) => left.catalogId.localeCompare(right.catalogId))
      .forEach((binding) => {
        const option = document.createElement("option");
        option.value = binding.catalogId;
        option.textContent = binding.catalogId;
        select.append(option);
      });
    if (Array.from(select.options).some((option) => option.value === previous)) {
      select.value = previous;
    }
    const activeBindingAvailable = select.options.length > 1;
    if (federated && !activeBindingAvailable) {
      select.disabled = true;
    }
    status.hidden = legacy || (!shellState.catalogFederationError && activeBindingAvailable);
    status.textContent = shellState.catalogFederationError
      ? "Local catalog trust state is unavailable; adding a source is disabled."
      : federated && !activeBindingAvailable
        ? "No unused active local catalog trust binding is available."
        : !legacy && !federated
          ? "Local catalog trust mode is unavailable; adding a source is disabled."
          : "";
    submit.disabled =
      !formPassword ||
      (!legacy && (!federated || !activeBindingAvailable || !!shellState.catalogFederationError));
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
    updateBetaDashboardToolbar();
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

  function createApiError(data, response) {
    const error = new Error(extractApiError(data, response));
    if (data && data.error && typeof data.error.code === "string") {
      error.apiErrorCode = data.error.code;
    }
    return error;
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
      throw createApiError(data, response);
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
    throw createApiError(data, response);
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
      throw createApiError(data, response);
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
      const [snapshot, supportLifecycle] = await Promise.all([
        loadJson(apiUrl("updates/core")),
        loadBestEffortOptionalJson(apiUrl("updates/support-lifecycle")),
      ]);
      if (loadGeneration !== updatesLoadGeneration) {
        return;
      }
      renderUpdates({ ...snapshot, supportLifecycle });
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

  async function loadBetaDashboardSection() {
    const loadGeneration = ++betaDashboardLoadGeneration;
    shellState.betaDashboardSnapshot = null;
    clear(sections.betaDashboard);
    sections.betaDashboard.append(text("p", "loading", "Loading operator beta dashboard..."));
    updateBetaDashboardToolbar();

    try {
      const snapshot = await loadJson(apiUrl("operator/rc-dashboard"));
      const thirdPartyIntake = await loadOptionalJson(apiUrl("operator/app-submissions"), [404, 503]);
      if (loadGeneration !== betaDashboardLoadGeneration) {
        return;
      }
      snapshot.thirdPartyIntake = thirdPartyIntake;
      shellState.appSubmissionIntakeSnapshot = thirdPartyIntake;
      renderBetaDashboard(snapshot);
      setBetaDashboardStatus("Operator RC Recovery refreshed.", "is-success");
    } catch (error) {
      if (loadGeneration !== betaDashboardLoadGeneration) {
        return;
      }
      try {
        const fallback = await loadJson(apiUrl("operator/beta-dashboard"));
        const thirdPartyIntake = await loadOptionalJson(apiUrl("operator/app-submissions"), [404, 503]);
        if (loadGeneration !== betaDashboardLoadGeneration) {
          return;
        }
        fallback.rcCompatibilityFallback = true;
        fallback.thirdPartyIntake = thirdPartyIntake;
        shellState.appSubmissionIntakeSnapshot = thirdPartyIntake;
        renderBetaDashboard(fallback);
        setBetaDashboardStatus("Operator RC Recovery fallback loaded from beta dashboard.", "is-warning");
      } catch (fallbackError) {
        renderError(sections.betaDashboard, "operator RC recovery", fallbackError);
        setBetaDashboardStatus(
          fallbackError instanceof Error ? fallbackError.message : String(fallbackError),
          "is-error",
        );
      }
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
    shellState.catalogFederationSnapshot = null;
    shellState.catalogFederationError = "";
    shellState.identityVaultSnapshot = null;
    shellState.recommendedCatalogsSnapshot = null;
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

    let recommendedCatalogs = [];
    let recommendedCatalogError = "";
    try {
      const recommendedSnapshot = await loadOptionalJson(apiUrl("app-catalogs/recommended"));
      recommendedCatalogs =
        recommendedSnapshot && Array.isArray(recommendedSnapshot.catalogs)
          ? recommendedSnapshot.catalogs
          : [];
    } catch (error) {
      recommendedCatalogError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    }

    let catalogFederation = {};
    let catalogFederationError = "";
    try {
      const federationSnapshot = await loadOptionalJson(apiUrl("operator/catalog-federation"));
      catalogFederation = recordValue(federationSnapshot);
      if (typeof catalogFederation.mode !== "string") {
        catalogFederationError = "Local catalog federation mode was not reported.";
      }
    } catch (error) {
      catalogFederationError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    }

    let identityVault = {};
    let identityVaultError = "";
    try {
      const [identitySnapshot, grantSnapshot] = await Promise.all([
        loadOptionalJson(apiUrl("identity-vault/identities")),
        loadOptionalJson(apiUrl("identity-vault/grants")),
      ]);
      identityVault = {
        identities:
          identitySnapshot && Array.isArray(identitySnapshot.identities)
            ? identitySnapshot.identities
            : [],
        grants: grantSnapshot && Array.isArray(grantSnapshot.grants) ? grantSnapshot.grants : [],
      };
    } catch (error) {
      identityVaultError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    }

    let appServices = {};
    let appServicesError = "";
    try {
      const [serviceSnapshot, grantSnapshot, dependencySnapshot, bundleSnapshot, auditSnapshot] =
        await Promise.all([
        loadOptionalJson(apiUrl("app-services")),
        loadOptionalJson(apiUrl("app-services/grants")),
        loadOptionalJson(apiUrl("app-services/dependencies")),
        loadOptionalJson(apiUrl("app-services/grant-bundles")),
        loadOptionalJson(apiUrl("app-services/audit?limit=12")),
        ]);
      appServices = {
        services:
          serviceSnapshot && Array.isArray(serviceSnapshot.services)
            ? serviceSnapshot.services
            : [],
        requests:
          serviceSnapshot && Array.isArray(serviceSnapshot.requests)
            ? serviceSnapshot.requests
            : [],
        grants: grantSnapshot && Array.isArray(grantSnapshot.grants) ? grantSnapshot.grants : [],
        dependencyGraph:
          dependencySnapshot && dependencySnapshot.dependencyGraph
            ? dependencySnapshot.dependencyGraph
            : { apps: [], edges: [] },
        bundles:
          bundleSnapshot && Array.isArray(bundleSnapshot.bundles) ? bundleSnapshot.bundles : [],
        audit: auditSnapshot && Array.isArray(auditSnapshot.audit) ? auditSnapshot.audit : [],
      };
    } catch (error) {
      appServicesError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    }

    let reviewGovernance = {};
    let reviewerKeys = {};
    let reviewTransparencyLog = {};
    let reviewTransparencyVerification = {};
    let reviewGovernanceError = "";
    try {
      const [governanceSnapshot, keysSnapshot, logSnapshot, verifySnapshot] = await Promise.all([
        loadOptionalJson(apiUrl("app-review/governance")),
        loadOptionalJson(apiUrl("app-review/reviewer-keys")),
        loadOptionalJson(apiUrl("app-review/transparency-log?limit=8")),
        loadOptionalJson(apiUrl("app-review/transparency-log/verify")),
      ]);
      reviewGovernance = recordValue(governanceSnapshot && governanceSnapshot.governance);
      reviewerKeys = recordValue(keysSnapshot && keysSnapshot.reviewerKeys);
      reviewTransparencyLog = recordValue(logSnapshot && logSnapshot.transparencyLog);
      reviewTransparencyVerification = recordValue(verifySnapshot && verifySnapshot.verification);
    } catch (error) {
      reviewGovernanceError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    }

    if (loadGeneration !== appsLoadGeneration) {
      return;
    }
    renderApps({
      ...installedSnapshot,
      catalogs,
      catalogError,
      recommendedCatalogs,
      recommendedCatalogError,
      catalogFederation,
      catalogFederationError,
      identityVault,
      identityVaultError,
      appServices,
      appServicesError,
      reviewGovernance,
      reviewerKeys,
      reviewTransparencyLog,
      reviewTransparencyVerification,
      reviewGovernanceError,
    });
  }

  async function loadAppRuntimeDetails(app) {
    if (!app || typeof app !== "object" || typeof app.appId !== "string" || app.appId.length === 0) {
      return app;
    }
    const runtimePath = appRuntimePath(app.appId);
    const logsPath = appLogsPath(app.appId, 65536);
    const auditPath = appAuditPath(app.appId);
    const updatesPath = appUpdatesPath(app.appId, "summary");
    let runtime = null;
    let runtimeError = "";
    let logs = null;
    let logsError = "";
    let audit = app.audit && typeof app.audit === "object" ? app.audit : null;
    let auditError = "";
    let updateState = appUpdateState(app);
    let updatesError = "";
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
    try {
      const updatesSnapshot = updatesPath ? await loadOptionalJson(apiUrl(updatesPath)) : null;
      updateState =
        updatesSnapshot && updatesSnapshot.updateState && typeof updatesSnapshot.updateState === "object"
          ? updatesSnapshot.updateState
          : updatesSnapshot && updatesSnapshot.updates && typeof updatesSnapshot.updates === "object"
            ? updatesSnapshot.updates
            : updatesSnapshot || updateState;
    } catch (error) {
      updatesError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
    }
    return { ...app, runtime, runtimeError, logs, logsError, audit, auditError, updateState, updatesError };
  }

  async function loadCatalogApps(catalog) {
    if (!catalog || typeof catalog !== "object" || typeof catalog.catalogId !== "string") {
      return catalog;
    }
    const encodedCatalogId = encodeURIComponent(catalog.catalogId);
    try {
      const [apps, healthSnapshot, revisionsSnapshot, keyRotationSnapshot] = await Promise.all([
        loadJson(apiUrl(`app-catalogs/${encodedCatalogId}/apps`)),
        loadOptionalJson(apiUrl(`app-catalogs/${encodedCatalogId}/operations/health`)).catch((error) => ({
          operationError:
            error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error",
        })),
        loadOptionalJson(apiUrl(`app-catalogs/${encodedCatalogId}/operations/revisions`)).catch((error) => ({
          operationError:
            error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error",
        })),
        loadOptionalJson(apiUrl(`app-catalogs/${encodedCatalogId}/operations/key-rotation`)).catch((error) => ({
          operationError:
            error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error",
        })),
      ]);
      const catalogApps = apps && Array.isArray(apps.apps) ? apps.apps : [];
      const appsWithHistory = await Promise.all(
        catalogApps.map((app) => loadCatalogAppReviewHistory(catalog.catalogId, app)),
      );
      const operationsHealth = recordValue(healthSnapshot && healthSnapshot.health);
      const revisions = recordValue(revisionsSnapshot && revisionsSnapshot.revisions);
      const keyRotation = recordValue(keyRotationSnapshot && keyRotationSnapshot.keyRotation);
      const operationErrors = [healthSnapshot, revisionsSnapshot, keyRotationSnapshot]
        .map((snapshot) => snapshot && snapshot.operationError)
        .filter((error) => typeof error === "string" && error.length > 0);
      return {
        ...catalog,
        apps: appsWithHistory,
        operationsHealth,
        rollbackCandidates: arrayValue(revisions.revisions),
        keyRotation,
        catalogOperationsError: operationErrors.join("; "),
      };
    } catch (error) {
      const appsError =
        error instanceof Error ? error.message : typeof error === "string" ? error : "Unknown error";
      return { ...catalog, apps: [], appsError };
    }
  }

  async function loadCatalogAppReviewHistory(catalogId, app) {
    if (!app || typeof app !== "object" || typeof app.appId !== "string") {
      return app;
    }
    try {
      const snapshot = await loadOptionalJson(
        apiUrl(
          `app-catalogs/${encodeURIComponent(catalogId)}/apps/${encodeURIComponent(app.appId)}/review-history`,
        ),
      );
      return { ...app, reviewHistory: snapshot && snapshot.reviewHistory };
    } catch (_) {
      return app;
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

  async function submitAppUpdateMutation(form, action) {
    const disabledReason = form.dataset.disabledReason || "";
    if (disabledReason) {
      setAppsStatus(disabledReason, "is-error");
      return;
    }
    const appId = form.dataset.appId || "";
    const path = appUpdatesPath(appId, action);
    const appName = form.dataset.appName || appDisplayName({ appId });
    if (!path) {
      setAppsStatus("App update action unavailable for this app.", "is-error");
      return;
    }

    try {
      if (action === "stage" && !(await ensureConsentApprovedForForm(form, action))) {
        return;
      }
      const data = await postForm(path, new FormData(form), "App update actions unavailable in read-only mode.");
      const operation = data.operation || `update_${action}`;
      setAppsStatus(`${appName} update action completed: ${operation.replaceAll("_", " ")}.`, "is-success");
      await loadAppsSection();
    } catch (error) {
      form.dataset.consentApproved = "false";
      setAppsStatus(consentStaleErrorMessage(error), "is-error");
      await loadAppsSection();
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
    const federation = recordValue(shellState.catalogFederationSnapshot);
    if (federation.mode === "federated-local-trust") {
      const expectedCatalogId = appsControls.catalogSourceTrustBinding?.value || "";
      if (!expectedCatalogId) {
        setAppsStatus("Select an active local catalog trust binding before adding the source.", "is-error");
        return;
      }
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

  function catalogDiscoveryImportData(form) {
    const source = new FormData(form);
    const descriptorText = String(source.get("descriptorDocument") || "").trim();
    if (!descriptorText) {
      throw new Error("Paste a signed discovery descriptor before importing.");
    }
    const descriptor = JSON.parse(descriptorText);
    if (!descriptor || typeof descriptor !== "object" || Array.isArray(descriptor)) {
      throw new Error("The discovery descriptor must be one JSON object.");
    }
    const target = new FormData();
    target.set(
      "descriptorBase64",
      bytesToUrlSafeBase64(new TextEncoder().encode(JSON.stringify(descriptor))),
    );
    const endorsementsText = String(source.get("endorsementDocuments") || "").trim();
    if (endorsementsText) {
      const endorsements = JSON.parse(endorsementsText);
      if (!Array.isArray(endorsements) || endorsements.length > 8) {
        throw new Error("Direct endorsements must be a JSON array containing at most eight objects.");
      }
      endorsements.forEach((endorsement) => {
        if (!endorsement || typeof endorsement !== "object" || Array.isArray(endorsement)) {
          throw new Error("Every direct endorsement must be one JSON object.");
        }
        target.append(
          "endorsementBase64",
          bytesToUrlSafeBase64(new TextEncoder().encode(JSON.stringify(endorsement))),
        );
      });
    }
    return target;
  }

  async function submitCatalogDiscoveryMutation(form, action) {
    try {
      if (action === "import") {
        await postForm(
          "operator/catalog-federation/discovery",
          catalogDiscoveryImportData(form),
          "Catalog discovery import is unavailable in read-only mode.",
        );
        form.reset();
        setAppsStatus("Signed catalog discovery evidence imported as pending only.", "is-success");
      } else if (action === "discard") {
        const descriptorId = form.dataset.descriptorId || "";
        if (!descriptorId) {
          throw new Error("Pending discovery descriptor ID is unavailable.");
        }
        await postForm(
          `operator/catalog-federation/discovery/${encodeURIComponent(descriptorId)}/discard`,
          new FormData(),
          "Catalog discovery retention actions are unavailable in read-only mode.",
        );
        setAppsStatus("Pending catalog discovery evidence discarded.", "is-success");
      }
      await loadAppsSection();
    } catch (error) {
      setAppsStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitCatalogMutation(form, action) {
    const disabledReason = form.dataset.disabledReason || "";
    if (disabledReason) {
      setAppsStatus(disabledReason, "is-error");
      return;
    }
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
        if ((action === "install" || action === "update") && !(await ensureConsentApprovedForForm(form, action))) {
          return;
        }
        await postForm(path, new FormData(form), "Catalog actions unavailable in read-only mode.");
      }
      setAppsStatus(`Catalog action completed: ${action}.`, "is-success");
      await loadAppsSection();
    } catch (error) {
      form.dataset.consentApproved = "false";
      setAppsStatus(consentStaleErrorMessage(error), "is-error");
    }
  }

  async function submitIdentityVaultMutation(form, action) {
    try {
      if (action === "grant") {
        await postForm(
          "identity-vault/grants",
          new FormData(form),
          "Identity vault actions unavailable in read-only mode.",
        );
        setAppsStatus("Identity grant created.", "is-success");
      } else if (action === "revoke") {
        const path = identityVaultGrantPath(form.dataset.grantId || "");
        if (!path) {
          setAppsStatus("Identity grant revoke action unavailable.", "is-error");
          return;
        }
        await deleteForm(
          path,
          new FormData(form),
          "Identity vault actions unavailable in read-only mode.",
        );
        setAppsStatus("Identity grant revoked.", "is-success");
      }
      await loadAppsSection();
    } catch (error) {
      setAppsStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitAppServiceGrantMutation(form, action) {
    const path = appServiceGrantPath(form.dataset.grantId || "", action);
    if (!path) {
      setAppsStatus("App-service grant action unavailable.", "is-error");
      return;
    }
    try {
      await postForm(path, new FormData(form), "App-service grant actions unavailable in read-only mode.");
      setAppsStatus(`App-service grant ${action} completed.`, "is-success");
      await loadAppsSection();
    } catch (error) {
      setAppsStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitAppServiceBundleMutation(form, action) {
    const path = appServiceBundlePath(form.dataset.bundleId || "", action);
    if (!path) {
      setAppsStatus("App-service grant-bundle action unavailable.", "is-error");
      return;
    }
    try {
      if (
        (action === "approve" || action === "renew") &&
        !(await ensureConsentApprovedForForm(form, action))
      ) {
        return;
      }
      await postForm(path, new FormData(form), "App-service grant-bundle actions unavailable in read-only mode.");
      setAppsStatus(`App-service grant bundle ${action} completed.`, "is-success");
      await loadAppsSection();
    } catch (error) {
      form.dataset.consentApproved = "false";
      setAppsStatus(consentStaleErrorMessage(error), "is-error");
    }
  }

  async function loadSupportBundle() {
    try {
      shellState.supportBundlePreviewSnapshot = await loadJson(
        apiUrl("operator/support-bundle/preview"),
      ).catch(() => null);
      const bundle = await loadJson(apiUrl("operator/support-bundle"));
      shellState.supportBundleSnapshot = bundle;
      updateBetaDashboardToolbar();
      if (shellState.betaDashboardSnapshot) {
        renderBetaDashboard(shellState.betaDashboardSnapshot);
      }
      setBetaDashboardStatus("Support bundle generated.", "is-success");
    } catch (error) {
      setBetaDashboardStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  function supportBundleRedaction(bundle) {
    return recordValue(bundle && bundle.redaction);
  }

  function supportBundleRedactionStatus(bundle) {
    if (!bundle) {
      return "Not generated";
    }
    const redaction = recordValue(bundle && bundle.redaction);
    return typeof redaction.status === "string" && redaction.status
      ? redaction.status
      : "Missing redaction status";
  }

  function supportBundleRedactionFailed(bundle) {
    const status = supportBundleRedactionStatus(bundle).toLowerCase();
    return status !== "not generated" && status !== "pass";
  }

  function supportBundleExportBlocked(bundle) {
    return supportBundleRedactionFailed(bundle);
  }

  function supportBundleOmittedFieldCount(bundle) {
    const redaction = supportBundleRedaction(bundle);
    if (typeof redaction.omittedFieldCount === "number") {
      return redaction.omittedFieldCount;
    }
    return arrayValue(redaction.omittedFieldNames || redaction.omittedFields).length;
  }

  function supportBundleDigest(bundle) {
    const supportDigest = recordValue(bundle && bundle.supportDigest);
    return typeof supportDigest.digest === "string" ? supportDigest.digest : "";
  }

  function supportBundleDigestShort(bundle) {
    const digest = supportBundleDigest(bundle);
    if (!digest) {
      return "Unavailable";
    }
    return digest.length > 16 ? `${digest.slice(0, 16)}...` : digest;
  }

  function supportBundleExportBlockedMessage() {
    return "Support bundle redaction failed; copy and download are disabled.";
  }

  function supportJsonText(bundle) {
    return `${formatJson(bundle)}\n`;
  }

  function supportBundleFileName(bundle) {
    const timestamp =
      bundle && typeof bundle.generatedAtEpochMillis === "number"
        ? new Date(bundle.generatedAtEpochMillis)
        : new Date();
    const safeTimestamp = Number.isNaN(timestamp.getTime())
      ? "unknown"
      : timestamp.toISOString().replace(/[:.]/g, "-");
    return `cryptad-support-bundle-${safeTimestamp}.json`;
  }

  function downloadSupportBundle() {
    const bundle = shellState.supportBundleSnapshot;
    if (!bundle) {
      setBetaDashboardStatus("Generate a support bundle before downloading it.", "is-error");
      return;
    }
    if (supportBundleExportBlocked(bundle)) {
      setBetaDashboardStatus(supportBundleExportBlockedMessage(), "is-error");
      return;
    }
    downloadJsonBlob(bundle, supportBundleFileName(bundle));
    setBetaDashboardStatus("Support bundle download prepared.", "is-success");
  }

  async function copySupportSummary() {
    const bundle = shellState.supportBundleSnapshot;
    if (!bundle) {
      setBetaDashboardStatus("Generate a support bundle before copying its JSON.", "is-error");
      return;
    }
    if (supportBundleExportBlocked(bundle)) {
      setBetaDashboardStatus(supportBundleExportBlockedMessage(), "is-error");
      return;
    }
    const supportJson = supportJsonText(bundle);
    if (!navigator.clipboard || typeof navigator.clipboard.writeText !== "function") {
      setBetaDashboardStatus("Clipboard access is unavailable in this browser.", "is-error");
      return;
    }
    try {
      await navigator.clipboard.writeText(supportJson);
      setBetaDashboardStatus("Support JSON copied.", "is-success");
    } catch (error) {
      setBetaDashboardStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  function appDataBackupBundle(response) {
    return response && response.backup && typeof response.backup === "object"
      ? response.backup
      : recordValue(response);
  }

  function appDataBackupFileName(response, fallbackScope, fallbackAppId) {
    const bundle = appDataBackupBundle(response);
    const scope = safeFilePart(bundle.scope || fallbackScope, "app-data");
    const apps = Array.isArray(bundle.apps) ? bundle.apps : [];
    const appId =
      apps.length === 1 && apps[0] && typeof apps[0].appId === "string"
        ? apps[0].appId
        : fallbackAppId;
    const appPart = appId ? `-${safeFilePart(appId, "app")}` : "";
    return `cryptad-app-data-backup-${scope}${appPart}-${isoFileTimestamp(bundle.createdAt)}.json`;
  }

  function appDataBackupPayloadBlob(response) {
    const payloadBase64 =
      response && typeof response.payloadBase64 === "string" ? response.payloadBase64 : "";
    if (payloadBase64) {
      return new Blob([urlSafeBase64ToBytes(payloadBase64)], { type: "application/json" });
    }
    return new Blob([JSON.stringify(appDataBackupBundle(response))], { type: "application/json" });
  }

  function downloadAppDataBackupPayload(response, fallbackScope, fallbackAppId) {
    downloadBlob(
      appDataBackupPayloadBlob(response),
      appDataBackupFileName(response, fallbackScope, fallbackAppId),
    );
  }

  async function downloadAllAppDataBackup() {
    if (!formPassword) {
      setBetaDashboardStatus("App-data backup is unavailable in read-only mode.", "is-error");
      return;
    }
    try {
      const response = await postForm(
        "operator/app-data/backups",
        allAppDataBackupFormData(),
        "App-data backup is unavailable in read-only mode.",
      );
      downloadAppDataBackupPayload(response, "all-apps", "");
      setBetaDashboardStatus("All-app app-data backup download prepared.", "is-success");
    } catch (error) {
      setBetaDashboardStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function downloadAppDataBackup(appId, appName) {
    if (!formPassword) {
      setAppsStatus("App-data backup is unavailable in read-only mode.", "is-error");
      return null;
    }
    const formData = appDataBackupFormDataForApp(appId);
    if (!formData) {
      setAppsStatus("App-data backup route unavailable for this app.", "is-error");
      return null;
    }
    const response = await postForm(
      "operator/app-data/backups",
      formData,
      "App-data backup is unavailable in read-only mode.",
    );
    downloadAppDataBackupPayload(response, "single-app", appId);
    setAppsStatus(`${appName} app-data backup download prepared.`, "is-success");
    return response;
  }

  function backupPayloadBase64FromText(value) {
    const payload = typeof value === "string" ? value.trim() : "";
    if (!payload) {
      throw new Error("Paste a backup JSON bundle or payloadBase64 value before previewing restore.");
    }
    if (payload.startsWith("{")) {
      JSON.parse(payload);
      return bytesToUrlSafeBase64(new TextEncoder().encode(payload));
    }
    return payload.replace(/\s+/g, "");
  }

  function buildAppDataRestoreFormData(form) {
    const source = new FormData(form);
    const target = new FormData();
    const rawPayload = source.get("backupPayload");
    target.set(
      "payloadBase64",
      backupPayloadBase64FromText(typeof rawPayload === "string" ? rawPayload : ""),
    );
    target.set("mode", String(source.get("mode") || "merge"));
    const appId = String(source.get("appId") || form.dataset.appId || "");
    if (appId) {
      target.set("appId", appId);
    }
    return target;
  }

  function restoreModeFromForm(form) {
    const data = new FormData(form);
    return String(data.get("mode") || "merge");
  }

  function restorePlanReady(response) {
    const plan = recordValue(response && response.restorePlan);
    return (
      plan.status === "ready" &&
      arrayValue(plan.apps).every((app) => !arrayValue(recordValue(app).blockers).length)
    );
  }

  function renderAppDataRestoreMetadata(container, response) {
    if (!container) {
      return;
    }
    const plan = response && response.restorePlan ? recordValue(response.restorePlan) : null;
    const result = response && response.restoreResult ? recordValue(response.restoreResult) : null;
    const payload = plan || result || {};
    clear(container);
    if (!payload.status) {
      container.append(text("p", "error-state", "Restore response did not include metadata."));
      return;
    }
    const title = plan ? "Restore plan" : "Restore result";
    const blocked = payload.status === "blocked";
    container.append(
      summaryCard(
        `${title}: ${normalizedStatus(payload.status, "Unavailable")}`,
        [
          ["Mode", scalar(payload.mode)],
          ["Scope", scalar(payload.scope)],
          ["Apps", scalar(payload.appCount)],
          ["Records", scalar(payload.recordCount)],
          ["Bytes", formatBytes(payload.totalBytes)],
        ],
        blocked ? "is-error" : payload.status === "ready" || payload.status === "restored" ? "is-success" : "",
      ),
    );
    const apps = arrayValue(payload.apps);
    if (!apps.length) {
      return;
    }
    const list = document.createElement("div");
    list.className = "app-card-list";
    apps.forEach((appValue) => {
      const app = recordValue(appValue);
      const blockers = stringList(app.blockers);
      const warnings = stringList(app.warnings);
      const statuses = stringList(app.statuses);
      const namespaces = arrayValue(app.namespaces).map(recordValue);
      const card = document.createElement("article");
      card.className = blockers.length ? "app-card is-warning" : "app-card";
      card.append(
        betaCardHeader(
          app.appName || app.appId || "App",
          app.status || payload.status,
          blockers.length ? "is-error" : warnings.length ? "is-warning" : "is-success",
        ),
        definitionList([
          ["App ID", scalar(app.appId)],
          ["Installed", app.installed === true ? "Yes" : app.installed === false ? "No" : "Unavailable"],
          ["Version", scalar(app.appVersion)],
          ["Namespaces", scalar(app.namespaceCount)],
          [
            "Namespace names",
            namespaces.length
              ? namespaces.map((namespace) => scalar(namespace.namespace)).join(", ")
              : "Unavailable",
          ],
          [
            "Schema versions",
            namespaces.length
              ? namespaces.map((namespace) => scalar(namespace.schemaVersion)).join(", ")
              : "Unavailable",
          ],
          ["Records", scalar(app.recordCount)],
          ["Bytes", formatBytes(app.totalBytes)],
          ["Conflicts", scalar(app.conflictCount)],
          ["Statuses", statuses.length ? statuses.join(", ") : "None"],
          ["Warnings", warnings.length ? warnings.join(", ") : "None"],
          ["Blockers", blockers.length ? blockers.join(", ") : "None"],
        ]),
      );
      list.append(card);
    });
    container.append(list);
  }

  async function submitAppDataRestoreForm(form, restoreAction, statusSetter) {
    if (!formPassword) {
      statusSetter("App-data restore is unavailable in read-only mode.", "is-error");
      return;
    }
    if (typeof form.reportValidity === "function" && !form.reportValidity()) {
      return;
    }
    const resultContainer =
      form.querySelector(".app-data-restore-result") || betaDashboardControls.appDataRestoreResult;
    try {
      const formData = buildAppDataRestoreFormData(form);
      const planResponse = await postForm(
        "operator/app-data/restore/plan",
        formData,
        "App-data restore is unavailable in read-only mode.",
      );
      renderAppDataRestoreMetadata(resultContainer, planResponse);
      if (restoreAction !== "restore") {
        statusSetter("Restore preview generated.", "is-success");
        return;
      }
      if (!restorePlanReady(planResponse)) {
        statusSetter("Restore blocked by preview findings.", "is-error");
        return;
      }
      const mode = restoreModeFromForm(form);
      if (
        mode !== "merge" &&
        !window.confirm(`Commit ${mode} restore using the previewed metadata-only plan?`)
      ) {
        statusSetter("Restore cancelled.", "is-warning");
        return;
      }
      if (
        mode === "replaceApp" &&
        !window.confirm("Replace app restore clears existing durable app-data for each restored app.")
      ) {
        statusSetter("Restore cancelled.", "is-warning");
        return;
      }
      const restoreResponse = await postForm(
        "operator/app-data/restore",
        formData,
        "App-data restore is unavailable in read-only mode.",
      );
      renderAppDataRestoreMetadata(resultContainer, restoreResponse);
      statusSetter("App-data restore completed.", "is-success");
      await loadAppsSection();
    } catch (error) {
      statusSetter(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  function confirmAppUninstall(form) {
    const appName = form.dataset.appName || appDisplayName({ appId: form.dataset.appId || "" });
    const mode = form.dataset.appUninstallMode || "";
    if (mode === "preserveData") {
      return window.confirm(`Uninstall ${appName} while preserving durable app data?`);
    }
    if (mode === "deleteData") {
      return window.confirm(`Delete ${appName} and its durable app data?`);
    }
    return window.confirm(`Uninstall ${appName}?`);
  }

  async function submitAppDataBackupAction(form, action) {
    const appId = form.dataset.appId || "";
    const appName = form.dataset.appName || appDisplayName({ appId });
    try {
      await downloadAppDataBackup(appId, appName);
      if (action !== "exportBeforeDelete") {
        return;
      }
      if (!window.confirm(`${appName} backup download was prepared. Continue to app deletion?`)) {
        setAppsStatus("Delete cancelled after backup export.", "is-warning");
        return;
      }
      if (!window.confirm(`Delete ${appName} and its durable app data now?`)) {
        setAppsStatus("Delete cancelled after backup export.", "is-warning");
        return;
      }
      const path = appMutationPath(appId, "uninstall");
      if (!path) {
        setAppsStatus("App lifecycle action unavailable for this app.", "is-error");
        return;
      }
      await deleteForm(path, new FormData(), "App lifecycle actions unavailable in read-only mode.");
      setAppsStatus(`${appName} deleted after backup export.`, "is-success");
      await loadAppsSection();
    } catch (error) {
      setAppsStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitOperatorRecoveryAction(form) {
    const method = form.dataset.operatorRecoveryMethod || "POST";
    const path = form.dataset.operatorRecoveryPath || "";
    if (!path) {
      setBetaDashboardStatus("Recovery action path is unavailable.", "is-error");
      return;
    }
    try {
      await submitFormMutation(
        method,
        path,
        new FormData(),
        "Operator recovery actions unavailable in read-only mode.",
      );
      setBetaDashboardStatus("Recovery action completed.", "is-success");
      await Promise.all([loadBetaDashboardSection(), loadAppsSection()]);
    } catch (error) {
      setBetaDashboardStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  async function submitOperatorRcRecoveryAction(form, submitter) {
    const action = submitter?.dataset?.operatorRcRecoverySubmit || "plan";
    const planTokenInput = form.querySelector('input[name="planToken"]');
    if (
      action === "execute" &&
      (form.dataset.operatorRcRecoveryPlanned !== "true" || !planTokenInput?.value)
    ) {
      setBetaDashboardStatus("Review the recovery plan before executing.", "is-error");
      return;
    }
    const path = action === "execute" ? "operator/recovery/execute" : "operator/recovery/plan";
    const resultContainer = form.querySelector(".operator-rc-plan-result");
    try {
      const response = await submitFormMutation(
        "POST",
        path,
        new FormData(form),
        "Operator RC recovery actions unavailable in read-only mode.",
      );
      if (action === "execute") {
        const result = recordValue(response.result);
        renderOperatorRcResult(resultContainer, result);
        form.dataset.operatorRcRecoveryPlanned = "false";
        if (planTokenInput) {
          planTokenInput.value = "";
        }
        setBetaDashboardStatus(operatorRcResultStatusMessage(result), operatorRcResultTone(result));
        if (operatorRcResultHasSensitiveBackup(result)) {
          await loadAppsSection();
        } else if (operatorRcResultShouldReload(result)) {
          await Promise.all([loadBetaDashboardSection(), loadAppsSection()]);
        }
        return;
      }
      const plan = recordValue(response.plan);
      renderOperatorRcPlan(resultContainer, plan);
      const planExecutable = operatorRcPlanExecutable(plan);
      const planToken = typeof plan.planToken === "string" ? plan.planToken : "";
      if (planTokenInput) {
        planTokenInput.value = planExecutable ? planToken : "";
      }
      form.dataset.operatorRcRecoveryPlanned = planExecutable && planToken ? "true" : "false";
      setBetaDashboardStatus("Operator RC recovery plan generated.", "is-success");
    } catch (error) {
      if (action === "plan" && planTokenInput) {
        planTokenInput.value = "";
        form.dataset.operatorRcRecoveryPlanned = "false";
      }
      if (resultContainer) {
        clear(resultContainer);
        resultContainer.hidden = false;
        resultContainer.append(
          text("p", "error-state", error instanceof Error ? error.message : String(error)),
        );
      }
      setBetaDashboardStatus(error instanceof Error ? error.message : String(error), "is-error");
    }
  }

  function renderOperatorRcPlan(container, plan) {
    if (!container) {
      return;
    }
    clear(container);
    container.hidden = false;
    container.append(text("h4", "app-card-title", "Recovery plan"));
    container.append(
      definitionList([
        ["Action", scalar(plan.actionId)],
        ["Status", scalar(plan.status)],
        ["Confirmation phrase", scalar(plan.confirmationPhrase || "Not required")],
        ["Requires stopped app", yesNoText(plan.requiresStoppedApp, false)],
        ["Backup recommended", yesNoText(plan.backupRecommended, false)],
      ]),
    );
    appendRecoveryTextList(container, "Warnings", stringList(plan.warnings));
    appendRecoveryTextList(container, "Blockers", stringList(plan.blockReasons));
  }

  function renderOperatorRcResult(container, result) {
    if (!container) {
      return;
    }
    clear(container);
    container.hidden = false;
    container.append(text("h4", "app-card-title", "Recovery result"));
    container.append(
      definitionList([
        ["Action", scalar(result.actionId)],
        ["Status", scalar(result.status)],
        ["Completed", scalar(result.completedAt)],
        ["Reason", scalar(result.reasonCode)],
      ]),
    );
    appendOperatorRcResultSteps(container, result.steps);
    appendOperatorRcResultDetails(container, result.details);
    appendOperatorRcSupportBundleArtifact(container, result);
    appendRecoveryTextList(container, "Warnings", stringList(result.warnings));
    appendOperatorRcSensitiveBackup(container, result);
  }

  function appendOperatorRcResultSteps(container, steps) {
    const entries = arrayValue(steps)
      .map(recordValue)
      .filter((step) => Object.keys(step).length)
      .slice(0, 8);
    if (!entries.length) {
      return;
    }
    container.append(text("p", "app-card-subtitle", "Steps"));
    const list = document.createElement("ul");
    list.className = "permission-list operator-rc-result-steps";
    entries.forEach((step) => {
      const item = document.createElement("li");
      const parts = [
        step.id,
        step.status,
        step.summary || step.label || step.kind,
      ]
        .map(operatorRcBoundedScalar)
        .filter((value) => value && value !== "Unavailable");
      item.textContent = parts.join(" - ");
      list.append(item);
    });
    if (arrayValue(steps).length > entries.length) {
      const item = document.createElement("li");
      item.textContent = `${arrayValue(steps).length - entries.length} more steps omitted.`;
      list.append(item);
    }
    container.append(list);
  }

  function appendOperatorRcResultDetails(container, details) {
    const entries = Object.entries(recordValue(details)).slice(0, 12);
    if (!entries.length) {
      return;
    }
    container.append(text("p", "app-card-subtitle", "Details"));
    const list = document.createElement("div");
    list.className = "kv-list operator-rc-result-details";
    entries.forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "kv-row";
      row.append(text("div", "kv-label", operatorRcBoundedScalar(label)));
      const valueNode = document.createElement("div");
      valueNode.className = "kv-value";
      valueNode.append(operatorRcDetailNode(value, 0));
      row.append(valueNode);
      list.append(row);
    });
    const totalEntries = Object.keys(recordValue(details)).length;
    if (totalEntries > entries.length) {
      const row = document.createElement("div");
      row.className = "kv-row";
      row.append(text("div", "kv-label", "Omitted"));
      row.append(text("div", "kv-value", `${totalEntries - entries.length} more fields.`));
      list.append(row);
    }
    container.append(list);
  }

  function operatorRcDetailNode(value, depth) {
    if (Array.isArray(value)) {
      return operatorRcArrayDetailNode(value, depth);
    }
    const record = recordValue(value);
    if (Object.keys(record).length) {
      return operatorRcRecordDetailNode(record, depth);
    }
    return text("span", "", operatorRcBoundedScalar(value));
  }

  function operatorRcArrayDetailNode(values, depth) {
    if (depth >= 2) {
      return text("span", "", `${values.length} item${values.length === 1 ? "" : "s"}`);
    }
    const list = document.createElement("ul");
    list.className = "permission-list operator-rc-detail-list";
    values.slice(0, 6).forEach((value, index) => {
      const item = document.createElement("li");
      item.append(text("span", "", `${index + 1}. `), operatorRcDetailNode(value, depth + 1));
      list.append(item);
    });
    if (values.length > 6) {
      const item = document.createElement("li");
      item.textContent = `${values.length - 6} more items omitted.`;
      list.append(item);
    }
    return list;
  }

  function operatorRcRecordDetailNode(record, depth) {
    const entries = Object.entries(record);
    if (depth >= 2) {
      return text("span", "", `${entries.length} field${entries.length === 1 ? "" : "s"}`);
    }
    const list = document.createElement("div");
    list.className = "kv-list operator-rc-detail-list";
    entries.slice(0, 8).forEach(([label, value]) => {
      const row = document.createElement("div");
      row.className = "kv-row";
      row.append(text("div", "kv-label", operatorRcBoundedScalar(label)));
      const valueNode = document.createElement("div");
      valueNode.className = "kv-value";
      valueNode.append(operatorRcDetailNode(value, depth + 1));
      row.append(valueNode);
      list.append(row);
    });
    if (entries.length > 8) {
      const row = document.createElement("div");
      row.className = "kv-row";
      row.append(text("div", "kv-label", "Omitted"));
      row.append(text("div", "kv-value", `${entries.length - 8} more fields.`));
      list.append(row);
    }
    return list;
  }

  function operatorRcBoundedScalar(value) {
    const display = scalar(value);
    return display.length > 240 ? `${display.slice(0, 237)}...` : display;
  }

  function appendOperatorRcSupportBundleArtifact(container, result) {
    const supportBundle = recordValue(recordValue(result.details).supportBundle);
    if (supportBundle.kind !== "cryptad-operator-support-bundle") {
      return;
    }
    container.append(
      text(
        "p",
        "app-card-subtitle",
        `A local-only support bundle was returned. Redaction status: `
          + `${supportBundleRedactionStatus(supportBundle)}. Digest: `
          + `${supportBundleDigestShort(supportBundle)}. Review it before sharing.`,
      ),
    );
    const actions = document.createElement("div");
    actions.className = "app-card-actions";
    const download = document.createElement("button");
    download.type = "button";
    download.className = "button button-secondary";
    download.textContent = "Download support bundle";
    download.disabled = supportBundleExportBlocked(supportBundle);
    download.addEventListener("click", () => {
      if (supportBundleExportBlocked(supportBundle)) {
        setBetaDashboardStatus(supportBundleExportBlockedMessage(), "is-error");
        return;
      }
      downloadJsonBlob(supportBundle, supportBundleFileName(supportBundle));
      setBetaDashboardStatus("Support bundle download prepared.", "is-success");
    });
    actions.append(download);
    container.append(actions);
  }

  function appendOperatorRcSensitiveBackup(container, result) {
    const sensitiveBackup = recordValue(result.sensitiveBackup);
    if (!Object.keys(sensitiveBackup).length) {
      return;
    }
    const target = recordValue(result.target);
    container.append(
      text(
        "p",
        "app-card-subtitle",
        "A sensitive app-data backup was returned. Download it before refreshing this dashboard.",
      ),
    );
    const actions = document.createElement("div");
    actions.className = "app-card-actions";
    const download = document.createElement("button");
    download.type = "button";
    download.className = "button button-secondary";
    download.textContent = "Download app-data backup";
    download.addEventListener("click", () => {
      downloadAppDataBackupPayload(sensitiveBackup, "single-app", scalar(target.appId || ""));
    });
    actions.append(download);
    container.append(actions);
  }

  function appendRecoveryTextList(container, label, values) {
    if (!values.length) {
      return;
    }
    container.append(text("p", "app-card-subtitle", label));
    const list = document.createElement("ul");
    list.className = "permission-list";
    values.forEach((value) => {
      const item = document.createElement("li");
      item.textContent = value;
      list.append(item);
    });
    container.append(list);
  }

  function operatorRcPlanExecutable(plan) {
    return ["ready", "warning", "destructive"].includes(String(plan.status || "").toLowerCase());
  }

  function operatorRcResultStatus(result) {
    return String(recordValue(result).status || "").toLowerCase();
  }

  function operatorRcResultHasSensitiveBackup(result) {
    return Object.keys(recordValue(recordValue(result).sensitiveBackup)).length > 0;
  }

  function operatorRcResultPreservesVisibleArtifact(result) {
    switch (String(recordValue(result).actionId || "")) {
      case "catalog.reverify":
      case "network-budget.view":
      case "support-bundle.preview":
      case "support-bundle.export":
      case "trust-graph.export-summary":
      case "trust-graph.recompute-summary":
        return true;
      default:
        return false;
    }
  }

  function operatorRcResultShouldReload(result) {
    return (
      ["completed", "partial"].includes(operatorRcResultStatus(result)) &&
      !operatorRcResultPreservesVisibleArtifact(result)
    );
  }

  function operatorRcResultTone(result) {
    switch (operatorRcResultStatus(result)) {
      case "completed":
        return "is-success";
      case "partial":
        return "is-warning";
      case "blocked":
      case "failed":
        return "is-error";
      default:
        return "is-warning";
    }
  }

  function operatorRcResultStatusMessage(result) {
    switch (operatorRcResultStatus(result)) {
      case "completed":
        return operatorRcResultHasSensitiveBackup(result)
          ? "Operator RC recovery completed. Download the returned backup before refreshing."
          : "Operator RC recovery action completed.";
      case "partial":
        return "Operator RC recovery action partially completed. Review the result before continuing.";
      case "blocked":
        return "Operator RC recovery action was blocked. Review the result before retrying.";
      case "failed":
        return "Operator RC recovery action failed. Review the result before retrying.";
      default:
        return "Operator RC recovery action returned an unexpected status. Review the result.";
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
      setSecurityLegacyFallbackStatus(
        "Changing to or from physical HIGH still requires the legacy security page because it updates master-password state.",
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
      const message = error instanceof Error ? error.message : String(error);
      if (securityErrorRequiresLegacyFallback(error)) {
        setSecurityLegacyFallbackStatus(message);
        return;
      }
      setSecurityStatus(message, "is-error");
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

  function bindBetaDashboardInteractions() {
    betaDashboardControls.refreshButton.addEventListener("click", () => {
      setBetaDashboardStatus("Refreshing beta dashboard.");
      loadBetaDashboardSection();
    });
    betaDashboardControls.supportRefreshButton.addEventListener("click", () => {
      setBetaDashboardStatus("Generating support bundle.");
      loadSupportBundle();
    });
    betaDashboardControls.supportDownloadButton.addEventListener("click", downloadSupportBundle);
    betaDashboardControls.supportCopyButton.addEventListener("click", () => {
      copySupportSummary();
    });
    if (betaDashboardControls.allAppDataBackupButton) {
      betaDashboardControls.allAppDataBackupButton.addEventListener("click", () => {
        setBetaDashboardStatus("Preparing all-app app-data backup.");
        downloadAllAppDataBackup();
      });
    }
    if (betaDashboardControls.appDataRestoreForm) {
      betaDashboardControls.appDataRestoreForm.addEventListener("submit", async (event) => {
        event.preventDefault();
        const restoreAction = event.submitter instanceof HTMLButtonElement
          ? event.submitter.value
          : "preview";
        await submitAppDataRestoreForm(
          betaDashboardControls.appDataRestoreForm,
          restoreAction,
          setBetaDashboardStatus,
        );
      });
    }
    sections.betaDashboard.addEventListener("submit", async (event) => {
      const form = event.target;
      if (!(form instanceof HTMLFormElement)) {
        return;
      }
      if (form.dataset.operatorRcRecoveryActionId) {
        event.preventDefault();
        await submitOperatorRcRecoveryAction(form, event.submitter);
        return;
      }
      if (!form.dataset.operatorRecoveryPath) {
        return;
      }
      event.preventDefault();
      await submitOperatorRecoveryAction(form);
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
    if (appsControls.catalogChannelSelect) {
      appsControls.catalogChannelSelect.addEventListener("change", () => {
        shellState.catalogChannel = normalizeCatalogChannel(appsControls.catalogChannelSelect.value);
        storeCatalogChannel(shellState.catalogChannel);
        if (shellState.appsSnapshot) {
          renderApps(shellState.appsSnapshot);
        }
        setAppsStatus(`Showing ${catalogChannelLabel(shellState.catalogChannel)} catalog channel.`);
      });
    }
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
      const identityVaultAction = form.dataset.identityVaultAction;
      if (identityVaultAction) {
        event.preventDefault();
        await submitIdentityVaultMutation(form, identityVaultAction);
        return;
      }
      const appServiceGrantAction = form.dataset.appServiceGrantAction;
      if (appServiceGrantAction) {
        event.preventDefault();
        await submitAppServiceGrantMutation(form, appServiceGrantAction);
        return;
      }
      const appServiceBundleAction = form.dataset.appServiceBundleAction;
      if (appServiceBundleAction) {
        event.preventDefault();
        await submitAppServiceBundleMutation(form, appServiceBundleAction);
        return;
      }
      const catalogDiscoveryAction = form.dataset.catalogDiscoveryAction;
      if (catalogDiscoveryAction) {
        event.preventDefault();
        await submitCatalogDiscoveryMutation(form, catalogDiscoveryAction);
        return;
      }
      const catalogAction = form.dataset.catalogAction;
      if (catalogAction) {
        event.preventDefault();
        await submitCatalogMutation(form, catalogAction);
        return;
      }
      const appUpdateAction = form.dataset.appUpdateAction;
      if (appUpdateAction) {
        event.preventDefault();
        await submitAppUpdateMutation(form, appUpdateAction);
        return;
      }
      const appDataRestoreAction = form.dataset.appDataRestoreAction;
      if (appDataRestoreAction) {
        event.preventDefault();
        const restoreAction = event.submitter instanceof HTMLButtonElement
          ? event.submitter.value
          : "preview";
        await submitAppDataRestoreForm(form, restoreAction, setAppsStatus);
        return;
      }
      const appDataBackupAction = form.dataset.appDataBackupAction;
      if (appDataBackupAction) {
        event.preventDefault();
        await submitAppDataBackupAction(form, appDataBackupAction);
        return;
      }
      const action = form.dataset.appAction;
      if (!action) {
        return;
      }
      event.preventDefault();
      if (action === "uninstall" && !confirmAppUninstall(form)) {
        setAppsStatus("App uninstall cancelled.", "is-warning");
        return;
      }
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
  configureDiagnosticLegacyExportAction();
  renderLegacyLinks();
  bindAlertsInteractions();
  bindBetaDashboardInteractions();
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
  updateBetaDashboardToolbar();
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
  loadBetaDashboardSection().catch((error) => {
    renderError(sections.betaDashboard, "beta dashboard", error);
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
