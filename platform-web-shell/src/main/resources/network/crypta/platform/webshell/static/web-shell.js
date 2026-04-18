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
    configSnapshot: null,
    securitySnapshot: null,
    updatesSnapshot: null,
    wizardSnapshot: null,
  };
  const directDownloadOperation = "create_direct_download";
  const queueState = {
    page: "downloads",
    advancedMode: false,
    sortBy: null,
    reversed: false,
    keysVisible: false,
  };
  let peerLoadGeneration = 0;
  let queueLoadGeneration = 0;
  let securityLoadGeneration = 0;
  let updatesLoadGeneration = 0;
  let configLoadGeneration = 0;
  let wizardLoadGeneration = 0;
  const nativeQueueSubmitBypass = new WeakSet();

  const sections = {
    overview: document.getElementById("overview-body"),
    connectivity: document.getElementById("connectivity-body"),
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
      const valueNode = text("div", "kv-value", value);

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

  async function loadOptionalJson(url) {
    try {
      return await loadJson(url);
    } catch (error) {
      return null;
    }
  }

  async function postForm(path, formData, unavailableMessage) {
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
      method: "POST",
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
      queueState.page === "downloads" ? loadOptionalJson(queueCountUrl()) : Promise.resolve(null);
    const keysRequest = queueState.keysVisible ? loadOptionalJson(queueKeysUrl()) : Promise.resolve(null);

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

  renderLegacyLinks();
  bindSecurityInteractions();
  bindUpdatesInteractions();
  bindConfigInteractions();
  bindWizardInteractions();
  bindPeerInteractions();
  bindQueueInteractions();
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
