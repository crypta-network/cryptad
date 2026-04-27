package network.crypta.platform.webshell;

import network.crypta.platform.webshell.routes.WebShellPaths;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class WebShellResourcesTest {
  private static final String EVENT_PREVENT_DEFAULT = "event.preventDefault();";
  private static final String CLEAR_WIZARD_BANDWIDTH_CHOICE_REQUIREMENT =
      " clearWizardBandwidthChoiceRequirement);";

  @Test
  void readText_whenIndexResourceRequested_expectShellMarkup() {
    String html = WebShellResources.readText(WebShellPaths.INDEX_RESOURCE_PATH);

    assertContainsAll(
        html,
        "Web Shell v1",
        "Peer control plane",
        "Alert queue",
        "Runtime diagnostics",
        "Queue control plane",
        "Core updater",
        "Operator subset",
        "First-time setup",
        "Installed apps",
        "Publisher fallback panel",
        "Fallback and retained legacy pages",
        "Installed apps JSON",
        "Alerts JSON",
        "Diagnostics JSON",
        "__BOOTSTRAP_JSON__",
        "Use Refresh diagnostics to load the current diagnostics snapshot.");
    assertContainsAll(
        html,
        "id=\"apps\"",
        "id=\"apps-body\"",
        "id=\"apps-status\"",
        "id=\"catalog-source-form\"",
        "id=\"catalog-source-input\"",
        "id=\"catalog-source-submit\"",
        "peer-create-form\" hidden",
        "name=\"referenceText\"",
        "id=\"peers-status\"",
        "id=\"alerts-panel\"",
        "id=\"alerts-body\"",
        "id=\"diagnostics-panel\"",
        "id=\"diagnostics-body\"",
        "href=\"#publisher\"",
        "id=\"publisher\"",
        "id=\"publisher-status\"",
        "id=\"publisher-body\"",
        "id=\"publisher-file-form\"",
        "data-publisher-source-type=\"file\"",
        "id=\"publisher-directory-form\"",
        "data-publisher-source-type=\"directory\"",
        "id=\"publisher-file-submit\"",
        "id=\"publisher-directory-submit\"",
        "name=\"filterData\" type=\"checkbox\" checked",
        "queue-create-form\" hidden",
        "id=\"queue\"",
        "id=\"security-form\"",
        "id=\"updates-body\"",
        "id=\"config-form\"",
        "id=\"wizard-form\"");
  }

  @Test
  void readText_whenScriptResourceRequested_expectQueueMutationSafeguardsPresent() {
    String script =
        WebShellResources.readText(WebShellPaths.resourcePath(WebShellPaths.SCRIPT_PATH));

    assertQueueMutationMarkersPresent(script);
    assertQueueMutationSubmissionOrder(script);
    assertQueueLoadSequencing(script);
    assertQueueLinkRewriting(script);
    assertReadOnlyQueueHandling(script);
    assertPeerMutationMarkersPresent(script);
    assertPeerMutationSubmissionOrder(script);
    assertPeerLoadSequencing(script);
    assertAppsMarkersPresent(script);
    assertAppsSubmissionOrder(script);
    assertAppsLoadSequencing(script);
    assertPublisherMarkersPresent(script);
    assertPublisherSubmissionOrder(script);
    assertAlertsAndDiagnosticsMarkersPresent(script);
    assertPlatformControlPlaneMarkersPresent(script);
  }

  @Test
  void readText_whenStylesheetResourceRequested_expectAlertTextPreservesNewlines() {
    String stylesheet =
        WebShellResources.readText(WebShellPaths.resourcePath(WebShellPaths.STYLESHEET_PATH));

    assertTrue(stylesheet.contains(".alert-card-text {"));
    assertTrue(stylesheet.contains("white-space: pre-wrap;"));
    assertTrue(stylesheet.contains(".app-card-list {"));
    assertTrue(stylesheet.contains(".app-card-actions {"));
    assertTrue(stylesheet.contains(".app-log-tail {"));
    assertTrue(stylesheet.contains(".catalog-app-card {"));
    assertTrue(stylesheet.contains(".publisher-forms {"));
    assertTrue(stylesheet.contains(".publisher-result-actions {"));
    assertTrue(stylesheet.contains(".status-pill.is-success::before {"));
  }

  private static void assertContainsAll(String text, String... expectedFragments) {
    for (String expectedFragment : expectedFragments) {
      assertTrue(
          text.contains(expectedFragment), () -> "Expected fragment missing: " + expectedFragment);
    }
  }

  private static void assertQueueMutationMarkersPresent(String script) {
    assertTrue(
        script.contains(
            "const apiRoot = normalizeLocalRootPath(bootstrap.platformApiRoot, \"/api/v1/\");"));
    assertTrue(
        script.contains(
            "const shellRoot = normalizeLocalRootPath(bootstrap.shellRoot, \"/app/node/\");"));
    assertTrue(script.contains("const apiRootUrl = new URL(apiRoot, window.location.origin);"));
    assertTrue(script.contains("const shellRootUrl = new URL(shellRoot, window.location.origin);"));
    assertTrue(script.contains("function normalizeLocalRootPath(value, fallback)"));
    assertTrue(script.contains("function queuePriorityFieldName(submitterName)"));
    assertTrue(script.contains("function renderQueueHtmlFragment(html, className)"));
    assertTrue(script.contains("function sanitizeQueueNode(root)"));
    assertTrue(script.contains("function isSafeQueueUrl(rawValue)"));
    assertTrue(script.contains("case \"change_priority_top\":"));
    assertTrue(script.contains("case \"change_priority_bottom\":"));
    assertTrue(script.contains("let queueLoadGeneration = 0;"));
    assertTrue(script.contains("let securityLoadGeneration = 0;"));
    assertTrue(script.contains("let updatesLoadGeneration = 0;"));
    assertTrue(script.contains("let configLoadGeneration = 0;"));
    assertTrue(script.contains("let wizardLoadGeneration = 0;"));
    assertTrue(script.contains("let formPassword ="));
    assertTrue(
        script.contains(
            "throw new Error(unavailableMessage || \"Queue mutations unavailable in read-only"
                + " mode.\");"));
    assertTrue(
        script.contains(
            "queueControls.createForm.hidden = queueState.page !== \"downloads\" ||"
                + " !formPassword;"));
  }

  private static void assertQueueMutationSubmissionOrder(String script) {
    int submitHandlerIndex = script.indexOf("const path = queueMutationPath(submitter.name);");
    int preventDefaultIndex = script.indexOf(EVENT_PREVENT_DEFAULT, submitHandlerIndex);
    int awaitMutationIndex =
        script.indexOf("await submitQueueMutation(form, submitter, path);", submitHandlerIndex);
    int refreshFormPasswordIndex =
        script.indexOf("await refreshFormPassword();", submitHandlerIndex);
    int legacySubmitIndex =
        script.indexOf("submitLegacyQueueForm(form, submitter);", submitHandlerIndex);

    assertTrue(submitHandlerIndex >= 0);
    assertTrue(preventDefaultIndex > submitHandlerIndex);
    assertTrue(awaitMutationIndex > preventDefaultIndex);
    assertTrue(refreshFormPasswordIndex > submitHandlerIndex);
    assertTrue(legacySubmitIndex > refreshFormPasswordIndex);
  }

  private static void assertQueueLoadSequencing(String script) {
    int queueLoadIndex = script.indexOf("const loadGeneration = ++queueLoadGeneration;");
    int successGuardIndex =
        script.indexOf("if (loadGeneration !== queueLoadGeneration) {", queueLoadIndex);
    int renderQueueIndex =
        script.indexOf("renderQueue(snapshot, countSnapshot, keysPayload);", queueLoadIndex);
    int errorGuardIndex =
        script.indexOf("if (loadGeneration !== queueLoadGeneration) {", successGuardIndex + 1);
    int renderErrorIndex =
        script.indexOf("renderError(sections.queue, \"queue\", error);", queueLoadIndex);
    int queueCountLoadIndex =
        script.indexOf(
            "queueState.page === \"downloads\" ? loadBestEffortOptionalJson(queueCountUrl()) :"
                + " Promise.resolve(null);");
    int loadOptionalJsonIndex =
        script.indexOf("async function loadOptionalJson(url, optionalStatuses = [404])");
    int loadBestEffortOptionalJsonIndex =
        script.indexOf("async function loadBestEffortOptionalJson(url)");
    int snapshotAwaitIndex =
        script.indexOf("const snapshot = await snapshotRequest;", queueLoadIndex);
    int optionalAwaitIndex =
        script.indexOf(
            "const [countSnapshot, keysPayload] = await Promise.all([countRequest, keysRequest]);");

    assertTrue(queueLoadIndex >= 0);
    assertTrue(successGuardIndex > queueLoadIndex);
    assertTrue(renderQueueIndex > successGuardIndex);
    assertTrue(errorGuardIndex > renderQueueIndex);
    assertTrue(renderErrorIndex > errorGuardIndex);
    assertTrue(queueCountLoadIndex >= 0);
    assertTrue(loadOptionalJsonIndex >= 0);
    assertTrue(loadBestEffortOptionalJsonIndex > loadOptionalJsonIndex);
    assertTrue(script.contains("optionalStatuses.includes(response.status)"));
    assertTrue(script.contains("throw new Error(extractApiError(data, response));"));
    assertTrue(script.contains("return await loadOptionalJson(url);"));
    assertTrue(snapshotAwaitIndex > queueLoadIndex);
    assertTrue(optionalAwaitIndex > snapshotAwaitIndex);
  }

  private static void assertQueueLinkRewriting(String script) {
    int rewriteQueueLinksIndex = script.indexOf("function rewriteQueueRelativeLinks(root)");
    int rewriteCountLinksIndex = script.indexOf("rewriteQueueRelativeLinks(countNode);");
    int rewriteContentLinksIndex = script.indexOf("rewriteQueueRelativeLinks(contentNode);");
    int shellHrefDatasetIndex = script.indexOf("anchor.dataset.shellHref = href;");
    int shellHrefLookupIndex =
        script.indexOf(
            "const shellHref = anchor.dataset.shellHref || anchor.getAttribute(\"href\") || \"\";");

    assertTrue(rewriteQueueLinksIndex >= 0);
    assertTrue(rewriteCountLinksIndex > rewriteQueueLinksIndex);
    assertTrue(rewriteContentLinksIndex > rewriteQueueLinksIndex);
    assertTrue(shellHrefDatasetIndex > rewriteQueueLinksIndex);
    assertTrue(shellHrefLookupIndex > rewriteQueueLinksIndex);
  }

  private static void assertReadOnlyQueueHandling(String script) {
    int stripReadOnlyFormsIndex = script.indexOf("function stripReadOnlyQueueForms(root)");
    int renderQueueHtmlFragmentIndex =
        script.indexOf("function renderQueueHtmlFragment(html, className)");
    int countReadOnlyStripIndex = script.indexOf("stripReadOnlyQueueForms(countNode);");
    int contentReadOnlyStripIndex = script.indexOf("stripReadOnlyQueueForms(contentNode);");
    int countRenderIndex =
        script.indexOf("const countNode = renderQueueHtmlFragment(", renderQueueHtmlFragmentIndex);
    int contentRenderIndex =
        script.indexOf(
            "const contentNode = renderQueueHtmlFragment(snapshot.contentHtml, \"queue-html\");",
            renderQueueHtmlFragmentIndex);
    int buildMutationFormDataIndex =
        script.indexOf("function buildQueueMutationFormData(form, submitter, path)");
    int filteredMutationFormDataIndex =
        script.indexOf("const formData = buildQueueMutationFormData(form, submitter, path);");
    int refreshFormPasswordIndex = script.indexOf("async function refreshFormPassword()");
    int normalizedShellRootFetchIndex =
        script.indexOf("const response = await fetch(shellRootUrl.toString(), {");
    int postRefreshIndex =
        script.indexOf("const currentFormPassword = await refreshFormPassword();");

    assertTrue(stripReadOnlyFormsIndex >= 0);
    assertTrue(renderQueueHtmlFragmentIndex > stripReadOnlyFormsIndex);
    assertTrue(countRenderIndex > renderQueueHtmlFragmentIndex);
    assertTrue(contentRenderIndex > countRenderIndex);
    assertTrue(countReadOnlyStripIndex > stripReadOnlyFormsIndex);
    assertTrue(contentReadOnlyStripIndex > stripReadOnlyFormsIndex);
    assertTrue(buildMutationFormDataIndex >= 0);
    assertTrue(filteredMutationFormDataIndex > buildMutationFormDataIndex);
    assertTrue(refreshFormPasswordIndex >= 0);
    assertTrue(normalizedShellRootFetchIndex > refreshFormPasswordIndex);
    assertTrue(postRefreshIndex > refreshFormPasswordIndex);
  }

  private static void assertPeerMutationMarkersPresent(String script) {
    assertTrue(script.contains("let peerLoadGeneration = 0;"));
    assertTrue(script.contains("function updatePeerToolbar()"));
    assertTrue(script.contains("async function submitPeerCreate(event)"));
    assertTrue(script.contains("async function submitPeerMutation(form, action)"));
    assertTrue(script.contains("async function loadPeersSection()"));
    assertTrue(script.contains("loadJson(apiUrl(\"peers?view=summary\"))"));
    assertTrue(script.contains("peerControls.createForm.hidden = !formPassword;"));
    assertTrue(script.contains("form.dataset.peerRequiresForceRemoval"));
    assertTrue(script.contains("forceRemoval"));
    assertTrue(script.contains("Peer mutations unavailable in read-only mode."));
  }

  private static void assertPeerMutationSubmissionOrder(String script) {
    int bindPeersIndex = script.indexOf("function bindPeerInteractions()");
    int actionLookupIndex =
        script.indexOf("const action = form.dataset.peerAction;", bindPeersIndex);
    int preventDefaultIndex = script.indexOf(EVENT_PREVENT_DEFAULT, actionLookupIndex);
    int requiresForceRemovalIndex =
        script.indexOf(
            "const requiresForceRemoval = form.dataset.peerRequiresForceRemoval === \"true\";",
            bindPeersIndex);
    int confirmIndex = script.indexOf("window.confirm(confirmMessage)", bindPeersIndex);
    int mutationIndex = script.indexOf("await submitPeerMutation(form, action);", bindPeersIndex);

    assertTrue(bindPeersIndex >= 0);
    assertTrue(actionLookupIndex > bindPeersIndex);
    assertTrue(preventDefaultIndex > actionLookupIndex);
    assertTrue(requiresForceRemovalIndex > preventDefaultIndex);
    assertTrue(confirmIndex > requiresForceRemovalIndex);
    assertTrue(mutationIndex > confirmIndex);
  }

  private static void assertPeerLoadSequencing(String script) {
    int loadPeersIndex = script.indexOf("const loadGeneration = ++peerLoadGeneration;");
    int successGuardIndex =
        script.indexOf("if (loadGeneration !== peerLoadGeneration) {", loadPeersIndex);
    int renderPeersIndex = script.indexOf("renderPeers(roster);", loadPeersIndex);
    int errorGuardIndex =
        script.indexOf("if (loadGeneration !== peerLoadGeneration) {", successGuardIndex + 1);
    int renderErrorIndex =
        script.indexOf("renderError(sections.peers, \"peers\", error);", loadPeersIndex);
    int loadPeersCatchIndex = script.indexOf("loadPeersSection().catch((error) => {");

    assertTrue(loadPeersIndex >= 0);
    assertTrue(successGuardIndex > loadPeersIndex);
    assertTrue(renderPeersIndex > successGuardIndex);
    assertTrue(errorGuardIndex > renderPeersIndex);
    assertTrue(renderErrorIndex > errorGuardIndex);
    assertTrue(loadPeersCatchIndex > renderErrorIndex);
  }

  private static void assertAppsMarkersPresent(String script) {
    int appUiEntryHelperIndex = script.indexOf("function normalizeAppUiEntryHref(value)");
    int legacyLinkHelperIndex = script.indexOf("function normalizeLegacyLinkPath(value)");
    String appUiEntryHelper = script.substring(appUiEntryHelperIndex, legacyLinkHelperIndex);

    assertTrue(script.contains("appsSnapshot: null"));
    assertTrue(script.contains("appCatalogsSnapshot: null"));
    assertTrue(script.contains("let appsLoadGeneration = 0;"));
    assertTrue(script.contains("apps: document.getElementById(\"apps-body\")"));
    assertTrue(script.contains("appsStatus: document.getElementById(\"apps-status\")"));
    assertTrue(
        script.contains("appsReadonlyHint: document.getElementById(\"apps-readonly-hint\")"));
    assertTrue(script.contains("const appsControls = {"));
    assertTrue(
        script.contains("catalogSourceForm: document.getElementById(\"catalog-source-form\")"));
    assertTrue(script.contains("function normalizeAppUiEntryHref(value)"));
    assertTrue(appUiEntryHelper.contains("const url = new URL(value, shellRootUrl);"));
    assertTrue(script.contains("return `${url.pathname}${url.search}${url.hash}`;"));
    assertFalse(appUiEntryHelper.contains("const url = new URL(value, window.location.origin);"));
    assertTrue(script.contains("function appUiHref(app)"));
    assertTrue(script.contains("function appRuntimePath(appId)"));
    assertTrue(script.contains("function appLogsPath(appId, maxBytes)"));
    assertTrue(script.contains("async function loadAppRuntimeDetails(app)"));
    assertTrue(script.contains("const explicitHref = normalizeAppUiEntryHref(app.uiUrl);"));
    assertTrue(
        script.contains(
            "return normalizeAppUiEntryHref(`/apps/${encodeURIComponent(app.appId)}/`);"));
    assertTrue(script.contains("function renderAppCard(app)"));
    assertTrue(
        script.contains(
            "const runtimeStoppable = runtimeRunning || runtimeState === \"RESTARTING\";"));
    assertTrue(script.contains("runtimeStoppable ? \"stop\" : \"start\""));
    assertTrue(script.contains("runtimeStoppable ? \"Stop\" : \"Start\""));
    assertTrue(script.contains("const uninstallForm = runtimeStoppable"));
    assertTrue(script.contains("Runtime log tail"));
    assertTrue(script.contains("app-log-tail"));
    assertTrue(script.contains("function renderApps(data)"));
    assertTrue(script.contains("function renderCatalogs(catalogs, catalogError)"));
    assertTrue(script.contains("Catalogs unavailable: ${catalogError}"));
    assertTrue(script.contains("function renderCatalogCard(catalog)"));
    assertTrue(script.contains("function renderCatalogAppCard(catalog, app)"));
    assertTrue(script.contains("async function loadCatalogApps(catalog)"));
    assertTrue(script.contains("function appMutationPath(appId, action)"));
    assertTrue(script.contains("function catalogMutationPath(catalogId, appId, action)"));
    assertTrue(script.contains("async function loadAppsSection()"));
    assertTrue(script.contains("async function submitCatalogSource(event)"));
    assertTrue(script.contains("async function submitCatalogMutation(form, action)"));
    assertTrue(script.contains("async function deleteForm(path, formData, unavailableMessage)"));
    assertTrue(script.contains("setAppsStatus(\"Refreshing installed apps and catalogs.\");"));
    assertTrue(script.contains("loadJson(apiUrl(\"apps\"))"));
    assertTrue(script.contains("installedSnapshot.apps.map(loadAppRuntimeDetails)"));
    assertTrue(script.contains("loadOptionalJson(apiUrl(\"app-catalogs\"))"));
    assertTrue(script.contains("catalogsSnapshot.catalogs.map(loadCatalogApps)"));
    assertTrue(
        script.contains(
            "const apps = await"
                + " loadJson(apiUrl(`app-catalogs/${encodeURIComponent(catalog.catalogId)}/apps`));"));
    assertTrue(script.contains("return `apps/${encodedAppId}/${action}`;"));
    assertTrue(script.contains("return `apps/${encodedAppId}`;"));
    assertTrue(script.contains("`apps/${encodeURIComponent(appId)}/runtime`"));
    assertTrue(script.contains("`apps/${encodeURIComponent(appId)}/logs?maxBytes="));
    assertTrue(script.contains("return `app-catalogs/${encodedCatalogId}/refresh`;"));
    assertTrue(
        script.contains(
            "return `app-catalogs/${encodedCatalogId}/apps/${encodedAppId}/${action}`;"));
    assertTrue(script.contains("action === \"uninstall\""));
    assertTrue(script.contains("App lifecycle actions unavailable in read-only mode."));
    assertTrue(script.contains("Catalog actions unavailable in read-only mode."));
  }

  private static void assertAppsSubmissionOrder(String script) {
    int bindAppsIndex = script.indexOf("function bindAppsInteractions()");
    int actionLookupIndex = script.indexOf("const action = form.dataset.appAction;", bindAppsIndex);
    int preventDefaultIndex = script.indexOf(EVENT_PREVENT_DEFAULT, actionLookupIndex);
    int mutationIndex = script.indexOf("await submitAppMutation(form, action);", bindAppsIndex);
    int catalogActionLookupIndex =
        script.indexOf("const catalogAction = form.dataset.catalogAction;", bindAppsIndex);
    int catalogMutationIndex =
        script.indexOf("await submitCatalogMutation(form, catalogAction);", bindAppsIndex);

    assertTrue(bindAppsIndex >= 0);
    assertTrue(catalogActionLookupIndex > bindAppsIndex);
    assertTrue(catalogMutationIndex > catalogActionLookupIndex);
    assertTrue(actionLookupIndex > bindAppsIndex);
    assertTrue(preventDefaultIndex > actionLookupIndex);
    assertTrue(mutationIndex > preventDefaultIndex);
  }

  private static void assertAppsLoadSequencing(String script) {
    int loadAppsIndex = script.indexOf("const loadGeneration = ++appsLoadGeneration;");
    int installedAwaitIndex =
        script.indexOf("installedSnapshot = await loadJson(apiUrl(\"apps\"));", loadAppsIndex);
    int installedErrorGuardIndex =
        script.indexOf("if (loadGeneration !== appsLoadGeneration) {", installedAwaitIndex);
    int renderErrorIndex =
        script.indexOf("renderError(sections.apps, \"apps\", error);", installedErrorGuardIndex);
    int catalogLoadIndex =
        script.indexOf(
            "const catalogsSnapshot = await loadOptionalJson(apiUrl(\"app-catalogs\"));",
            renderErrorIndex);
    int catalogErrorIndex = script.indexOf("catalogError =", catalogLoadIndex);
    int successGuardIndex =
        script.indexOf("if (loadGeneration !== appsLoadGeneration) {", catalogErrorIndex);
    int renderAppsIndex =
        script.indexOf(
            "renderApps({ ...installedSnapshot, catalogs, catalogError });", successGuardIndex);

    assertTrue(loadAppsIndex >= 0);
    assertTrue(installedAwaitIndex > loadAppsIndex);
    assertTrue(installedErrorGuardIndex > installedAwaitIndex);
    assertTrue(renderErrorIndex > installedErrorGuardIndex);
    assertTrue(catalogLoadIndex > renderErrorIndex);
    assertTrue(catalogErrorIndex > catalogLoadIndex);
    assertTrue(successGuardIndex > catalogErrorIndex);
    assertTrue(renderAppsIndex > successGuardIndex);
  }

  private static void assertPublisherMarkersPresent(String script) {
    assertTrue(script.contains("const publisherDefaultCompatibilityMode = \"COMPAT_CURRENT\";"));
    assertTrue(script.contains("publisher: document.getElementById(\"publisher-body\")"));
    assertTrue(script.contains("publisherStatus: document.getElementById(\"publisher-status\")"));
    assertTrue(
        script.contains(
            "publisherReadonlyHint: document.getElementById(\"publisher-readonly-hint\")"));
    assertTrue(script.contains("const publisherControls = {"));
    assertTrue(
        script.contains(
            "queueLink: document.querySelector('#publisher .queue-toolbar a[href=\"#queue\"]'),"));
    assertTrue(script.contains("function updatePublisherToolbar()"));
    assertTrue(script.contains("function publisherSourceType(form)"));
    assertTrue(script.contains("function publisherMutationPath(sourceType)"));
    assertTrue(script.contains("function generatePublisherIdentifier(sourceType)"));
    assertTrue(script.contains("function initializePublisherForm(form)"));
    assertTrue(script.contains("function resetPublisherForm(form)"));
    assertTrue(script.contains("function buildPublisherFormData(form)"));
    assertTrue(script.contains("function renderPublisherResult(data, sourceType)"));
    assertTrue(script.contains("function publisherInsertAccepted(data)"));
    assertTrue(script.contains("function publisherInsertOutcome(data)"));
    assertTrue(script.contains("async function showUploadQueueFromPublisher()"));
    assertTrue(script.contains("async function submitPublisherForm(event)"));
    assertTrue(script.contains("Publisher actions unavailable in read-only mode."));
    assertTrue(script.contains("setStatus(\"Refreshing upload queue.\");"));
    assertTrue(script.contains("case \"IDENTIFIER_COLLISION\":"));
    assertTrue(script.contains("case \"METADATA_UNRESOLVED\":"));
    assertTrue(script.contains("insert handled:"));
    assertTrue(script.contains("insert did not start:"));
    assertTrue(script.contains("${publisherInsertOutcome(data)}."));
    assertTrue(script.contains("initializePublisherForm(publisherControls.fileForm);"));
    assertTrue(script.contains("initializePublisherForm(publisherControls.directoryForm);"));
    assertTrue(script.contains("bindPublisherInteractions();"));
    assertTrue(script.contains("updatePublisherToolbar();"));
  }

  private static void assertPublisherSubmissionOrder(String script) {
    int submitPublisherIndex = script.indexOf("async function submitPublisherForm(event)");
    int postFormIndex = script.indexOf("await postForm(", submitPublisherIndex);
    int renderResultIndex =
        script.indexOf("renderPublisherResult(data, sourceType);", submitPublisherIndex);
    int startedGuardIndex =
        script.indexOf("if (publisherInsertAccepted(data)) {", submitPublisherIndex);
    int resetFormIndex = script.indexOf("resetPublisherForm(form);", submitPublisherIndex);
    int successStatusIndex =
        script.indexOf(
            "setPublisherStatus(\n"
                + "          `Local ${publisherLabel(sourceType)} insert handled:"
                + " ${publisherInsertOutcome(data)}.`",
            submitPublisherIndex);
    int refreshQueueIndex =
        script.indexOf("await showUploadQueueFromPublisher();", submitPublisherIndex);
    int failureStatusIndex = script.indexOf("insert did not start:", submitPublisherIndex);
    int bindPublisherIndex = script.indexOf("function bindPublisherInteractions()");
    int fileSubmitIndex =
        script.indexOf(
            "publisherControls.fileForm.addEventListener(\"submit\", submitPublisherForm);",
            bindPublisherIndex);
    int directorySubmitIndex =
        script.indexOf(
            "publisherControls.directoryForm.addEventListener(\"submit\", submitPublisherForm);",
            bindPublisherIndex);

    assertTrue(submitPublisherIndex >= 0);
    assertTrue(postFormIndex > submitPublisherIndex);
    assertTrue(renderResultIndex > postFormIndex);
    assertTrue(startedGuardIndex > renderResultIndex);
    assertTrue(resetFormIndex > startedGuardIndex);
    assertTrue(successStatusIndex > resetFormIndex);
    assertTrue(refreshQueueIndex > successStatusIndex);
    assertTrue(failureStatusIndex > refreshQueueIndex);
    assertTrue(bindPublisherIndex >= 0);
    assertTrue(fileSubmitIndex > bindPublisherIndex);
    assertTrue(directorySubmitIndex > fileSubmitIndex);
  }

  private static void assertAlertsAndDiagnosticsMarkersPresent(String script) {
    assertTrue(script.contains("alertsSnapshot"));
    assertTrue(script.contains("diagnosticsSnapshot"));
    assertTrue(script.contains("let alertsLoadGeneration = 0;"));
    assertTrue(script.contains("let diagnosticsLoadGeneration = 0;"));
    assertTrue(script.contains("const alertsControls = {"));
    assertTrue(script.contains("const diagnosticsControls = {"));
    assertTrue(script.contains("function updateAlertsToolbar()"));
    assertTrue(script.contains("function updateDiagnosticsToolbar()"));
    assertTrue(script.contains("function renderAlerts(data)"));
    assertTrue(script.contains("function renderDiagnostics(data)"));
    assertTrue(script.contains("function renderAlertCard(alert, index)"));
    assertTrue(script.contains("function renderDiagnosticsSection(section, index)"));
    assertTrue(script.contains("function alertDismissPath(alertId)"));
    assertTrue(script.contains("loadJson(apiUrl(\"alerts\"))"));
    assertTrue(script.contains("loadJson(apiUrl(\"diagnostics\"))"));
    assertTrue(script.contains("alertDismissPath(alertId),"));
    assertTrue(script.contains("plainTextExport"));
    assertTrue(script.contains("alert-dismiss-form"));
    assertTrue(script.contains("diagnostics-section-list"));
    assertTrue(
        script.contains(
            "...topLevelFieldEntries(data, [\"sections\", \"plainTextExport\", \"export\","
                + " \"textExport\"])"));
    assertTrue(
        script.contains("form.dataset.alertId = alert.id == null ? \"\" : String(alert.id);"));
    assertTrue(script.contains("const alertId = form.dataset.alertId ?? \"\";"));
    assertTrue(script.contains("if (form.dataset.alertId == null) {"));
    assertTrue(script.contains("typeof alert.dismissLabel === \"string\" && alert.dismissLabel"));
    assertFalse(script.contains("loadDiagnosticsSection().catch((error) => {"));
  }

  private static void assertPlatformControlPlaneMarkersPresent(String script) {
    assertTrue(script.contains("const shellState = {"));
    assertTrue(script.contains("function apiUrlWithQuery(path, query)"));
    assertTrue(script.contains("function htmlToText(html)"));
    assertTrue(script.contains("async function loadSecuritySection()"));
    assertTrue(script.contains("async function loadUpdatesSection()"));
    assertTrue(script.contains("async function loadConfigSection()"));
    assertTrue(script.contains("async function loadWizardSection()"));
    assertTrue(script.contains("async function submitSecurityForm(event)"));
    assertTrue(script.contains("async function submitConfigForm(event)"));
    assertTrue(script.contains("async function triggerCoreDownload()"));
    assertTrue(script.contains("async function submitWizardForm(event)"));
    assertTrue(script.contains("function wizardSubmissionSupported(data)"));
    assertTrue(script.contains("function wizardBandwidthModeUnknown(data)"));
    assertTrue(script.contains("function wizardCanEditCurrentNetworkThreatLevel(data)"));
    assertTrue(script.contains("function wizardCanEditCurrentPhysicalThreatLevel(data)"));
    assertTrue(script.contains("function wizardBandwidthChoiceRequired(data)"));
    assertTrue(
        script.contains("function wizardBandwidthChoiceRequired(data) {\n    return false;\n  }"));
    assertTrue(script.contains("function wizardBandwidthChoiceMessage()"));
    assertTrue(script.contains("function clearWizardBandwidthChoiceRequirement()"));
    assertTrue(script.contains("function wizardUnsupportedMessage(data)"));
    assertTrue(script.contains("apiUrlWithQuery(\"security-levels/network-warning\""));
    assertTrue(script.contains("loadJson(apiUrl(\"updates/core\"))"));
    assertTrue(script.contains("loadJson(apiUrl(\"config?sections=CURRENT\"))"));
    assertTrue(script.contains("loadJson(apiUrl(\"wizard/first-time\"))"));
    assertTrue(
        script.contains(
            "securityControls.form.hidden = !formPassword || !shellState.securitySnapshot;"));
    assertTrue(
        script.contains(
            "configControls.form.hidden = !formPassword || !shellState.configSnapshot;"));
    assertTrue(
        script.contains(
            "wizardControls.form.hidden =\n"
                + "      !formPassword || !shellState.wizardSnapshot ||"
                + " !wizardSubmissionSupported(shellState.wizardSnapshot);"));
    assertTrue(
        script.contains(
            "wizardControls.knowSomeone.parentElement.hidden = !networkThreatEditable;"));
    assertTrue(
        script.contains(
            "wizardControls.connectToStrangers.parentElement.hidden =\n"
                + "      !networkThreatEditable || !knowsTrustedOperators;"));
    assertTrue(script.contains("wizardControls.editBandwidth.parentElement.hidden = false;"));
    assertTrue(script.contains("wizardControls.connectToStrangers.checked = false;"));
    assertTrue(script.contains("wizardControls.editBandwidth.checked = false;"));
    assertTrue(
        script.contains(
            "wizardControls.knowSomeone.checked =\n"
                + "      networkThreatEditable && data.currentNetworkThreatLevel === \"HIGH\";"));
    assertTrue(script.contains("wizardControls.haveMonthlyLimit.indeterminate = false;"));
    assertTrue(script.contains("currentNetworkThreatLevel"));
    assertTrue(script.contains("currentPhysicalThreatLevel"));
    assertTrue(
        script.contains(
            "Current LOW/MAXIMUM network threat level will be preserved; use the security controls"
                + " to change it."));
    assertTrue(
        script.contains(
            "Current LOW/MAXIMUM physical threat level will be preserved; use the security controls"
                + " to change it."));
    assertTrue(
        script.contains(
            "Current bandwidth settings will be preserved unless you enable bandwidth editing."));
    assertTrue(
        script.contains(
            "Default bandwidth settings will be preserved unless you enable bandwidth editing."));
    assertTrue(script.contains("can delete queued work. Continue?"));
    assertTrue(
        script.contains(
            "Save one threat-level change at a time so warnings and failures cannot partially apply"
                + " a combined update."));
    assertTrue(script.contains("shellState.securitySnapshot = null;"));
    assertTrue(script.contains("shellState.configSnapshot = null;"));
    assertTrue(script.contains("shellState.updatesSnapshot = null;"));
    assertTrue(script.contains("shellState.wizardSnapshot = null;"));
    assertTrue(script.contains("const loadGeneration = ++securityLoadGeneration;"));
    assertTrue(script.contains("const loadGeneration = ++updatesLoadGeneration;"));
    assertTrue(script.contains("const loadGeneration = ++configLoadGeneration;"));
    assertTrue(script.contains("const loadGeneration = ++wizardLoadGeneration;"));
    assertTrue(script.contains("if (loadGeneration !== securityLoadGeneration) {"));
    assertTrue(script.contains("if (loadGeneration !== updatesLoadGeneration) {"));
    assertTrue(script.contains("if (loadGeneration !== configLoadGeneration) {"));
    assertTrue(script.contains("if (loadGeneration !== wizardLoadGeneration) {"));
    assertTrue(script.contains("await Promise.all([loadSecuritySection(), loadWizardSection()]);"));
    assertTrue(
        script.contains(
            "await Promise.all([loadConfigSection(), loadUpdatesSection(),"
                + " loadWizardSection()]);"));
    assertTrue(
        script.contains(
            "wizardControls.knowSomeone.addEventListener(\"change\","
                + " updateWizardFieldVisibility);"));
    assertTrue(
        script.contains(
            "wizardControls.editBandwidth.addEventListener(\"change\","
                + " updateWizardFieldVisibility);"));
    assertTrue(
        script.contains(
            "wizardControls.downloadLimit.addEventListener(\"input\","
                + CLEAR_WIZARD_BANDWIDTH_CHOICE_REQUIREMENT));
    assertTrue(
        script.contains(
            "wizardControls.uploadLimit.addEventListener(\"input\","
                + CLEAR_WIZARD_BANDWIDTH_CHOICE_REQUIREMENT));
    assertTrue(
        script.contains(
            "wizardControls.monthlyLimit.addEventListener(\"input\","
                + CLEAR_WIZARD_BANDWIDTH_CHOICE_REQUIREMENT));
    assertTrue(script.contains("await postForm(\"config/overrides\", formData"));
    assertTrue(script.contains("await postForm(\"updates/core/download\", new FormData()"));
    assertTrue(
        script.contains(
            "const preserveBandwidthSettings = !wizardControls.editBandwidth.checked;"));
    assertTrue(script.contains("formData.set(\"preserveBandwidthSettings\", \"on\");"));
    assertTrue(script.contains("formData.set(\"preserveCurrentNetworkThreatLevel\", \"on\");"));
    assertTrue(script.contains("formData.set(\"preserveCurrentPhysicalThreatLevel\", \"on\");"));
    assertTrue(script.contains("await postForm("));
  }
}
