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
        "Operator RC Recovery",
        "The beta dashboard route remains a compatibility fallback.",
        "Generate support bundle",
        "Download support JSON",
        "Copy support JSON",
        "This support bundle is generated locally and is not uploaded automatically.",
        "It excludes",
        "Review it before sharing.",
        "Download all app-data backup",
        "Sensitive backup payload",
        "Preview restore",
        "Restore app data",
        "App-data backups contain sensitive user data.",
        "Use the legacy plaintext export",
        "only as an explicit support or emergency fallback.",
        "Open legacy plaintext diagnostic export",
        "Publisher fallback panel",
        "Retained and pending legacy tools",
        "Installed apps JSON",
        "Alerts JSON",
        "Diagnostics JSON",
        "__BOOTSTRAP_JSON__",
        "Use Refresh diagnostics to load the current diagnostics snapshot.");
    assertContainsAll(
        html,
        "id=\"apps\"",
        "href=\"#beta-dashboard\"",
        "id=\"beta-dashboard\"",
        "id=\"beta-dashboard-body\"",
        "id=\"beta-dashboard-status\"",
        "id=\"beta-dashboard-refresh-button\"",
        "id=\"support-bundle-refresh-button\"",
        "id=\"support-bundle-download-button\"",
        "id=\"support-bundle-copy-button\"",
        "id=\"all-app-data-backup-button\"",
        "id=\"operator-app-data-restore-form\"",
        "id=\"operator-app-data-restore-payload\"",
        "id=\"operator-app-data-restore-mode\"",
        "id=\"operator-app-data-restore-preview-button\"",
        "id=\"operator-app-data-restore-commit-button\"",
        "id=\"operator-app-data-restore-result\"",
        "id=\"beta-dashboard-readonly-hint\"",
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
        "id=\"diagnostics-legacy-export-link\"",
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
    assertBetaDashboardMarkersPresent(script);
    assertAppDataBackupRestoreMarkersPresent(script);
    assertBetaDashboardLoadSequencing(script);
    assertAppsMarkersPresent(script);
    assertConsentUxMarkersPresent(script);
    assertAppUpdateLifecycleMarkersPresent(script);
    assertAppStoreMetadataMarkersPresent(script);
    assertCompatibilityUndeclaredPrecedesSuccess(script);
    assertAppsSubmissionOrder(script);
    assertAppsLoadSequencing(script);
    assertPublisherMarkersPresent(script);
    assertPublisherSubmissionOrder(script);
    assertAlertsAndDiagnosticsMarkersPresent(script);
    assertPlatformControlPlaneMarkersPresent(script);
    assertAppUiOriginHardeningMarkersPresent(script);
  }

  @Test
  void readText_whenStylesheetResourceRequested_expectAlertTextPreservesNewlines() {
    String stylesheet =
        WebShellResources.readText(WebShellPaths.resourcePath(WebShellPaths.STYLESHEET_PATH));

    assertStylesheetMarkersPresent(stylesheet);
    assertFalse(stylesheet.contains(".diagnostics-export"));
  }

  private static void assertContainsAll(String text, String... expectedFragments) {
    for (String expectedFragment : expectedFragments) {
      assertTrue(
          text.contains(expectedFragment), () -> "Expected fragment missing: " + expectedFragment);
    }
  }

  private static void assertStylesheetMarkersPresent(String stylesheet) {
    assertContainsAll(
        stylesheet,
        ".alert-card-text {",
        "white-space: pre-wrap;",
        ".app-card-list {",
        ".app-card-actions {",
        ".app-log-tail {",
        ".permission-list {",
        ".consent-preview {",
        ".consent-section-list {",
        ".consent-finding-list {",
        ".consent-actions {",
        ".vault-grant-form {",
        ".app-audit-event.is-denied {",
        ".catalog-app-card {",
        ".catalog-app-card.is-update-available {",
        ".metadata-link-list {",
        ".permission-review-list {",
        ".publisher-forms {",
        ".publisher-result-actions,",
        ".security-fallback-actions {",
        ".app-data-restore-form {",
        ".app-data-restore-payload {",
        ".app-data-restore-result {",
        ".app-data-restore-details {",
        ".support-bundle-notice {",
        ".status-pill.is-success::before {");
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
    assertTrue(script.contains("function normalizeLocalPath(value, fallback)"));
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
    assertTrue(script.contains("function createApiError(data, response)"));
    assertTrue(script.contains("error.apiErrorCode = data.error.code;"));
    assertTrue(script.contains("throw createApiError(data, response);"));
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

  private static void assertAppUiOriginHardeningMarkersPresent(String script) {
    assertContainsAll(
        script,
        "function registeredAppUiOrigin(app)",
        "function safeSameOriginAppUiHref(url, allowIsolatedLaunchParameter)",
        "function safeShellPanelAppUiHref(url)",
        "function normalizeLaunchFallbackHref(value)",
        "function normalizeIsolatedLaunchHref(value)",
        "function normalizeIsolatedProbeHref(value, expectedOrigin)",
        "link.dataset.isolatedUiOrigin = registeredAppUiOrigin(app);",
        "await isolatedAppOriginReachable(safeProbeHref, expectedAppId, expectedOrigin)",
        "credentials: \"omit\"",
        "mode: \"cors\"");
    assertContainsAll(
        script,
        "origin.protocol !== \"http:\"",
        "origin.hostname.toLowerCase() !== \"127.0.0.1\"",
        "origin.username",
        "origin.password",
        "origin.search !== \"\"",
        "origin.hash !== \"\"",
        "origin.pathname !== \"/\"",
        "url.pathname !== isolatedOriginProbePath",
        "url.search !== \"\"",
        "url.hash !== \"\"");
    assertContainsAll(
        script,
        "url.username ||",
        "url.password ||",
        "!url.pathname.startsWith(\"/apps/\")",
        "app && app.uiMode === \"shell-panel\"",
        "url.pathname !== shellRootUrl.pathname",
        "url.searchParams.get(isolatedLaunchParameter) !== \"1\"");
    assertFalse(script.contains("javascript:"));
    assertFalse(script.contains("data:"));
    assertFalse(script.contains("blob:"));
    assertFalse(script.contains("file:"));
    assertFalse(script.contains("ftp:"));
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

  private static void assertBetaDashboardMarkersPresent(String script) {
    assertContainsAll(
        script,
        "betaDashboardSnapshot: null",
        "supportBundlePreviewSnapshot: null",
        "supportBundleSnapshot: null",
        "let betaDashboardLoadGeneration = 0;",
        "betaDashboard: document.getElementById(\"beta-dashboard-body\")",
        "betaDashboardStatus: document.getElementById(\"beta-dashboard-status\")",
        "betaDashboardReadonlyHint: document.getElementById(\"beta-dashboard-readonly-hint\")",
        "const betaDashboardControls = {",
        "supportRefreshButton: document.getElementById(\"support-bundle-refresh-button\")",
        "supportDownloadButton: document.getElementById(\"support-bundle-download-button\")",
        "supportCopyButton: document.getElementById(\"support-bundle-copy-button\")",
        "allAppDataBackupButton: document.getElementById(\"all-app-data-backup-button\")",
        "appDataRestoreForm: document.getElementById(\"operator-app-data-restore-form\")",
        "appDataRestorePayload: document.getElementById(\"operator-app-data-restore-payload\")",
        "appDataRestoreMode: document.getElementById(\"operator-app-data-restore-mode\")",
        "appDataRestoreResult: document.getElementById(\"operator-app-data-restore-result\")",
        "function setBetaDashboardStatus(message, tone)",
        "function updateBetaDashboardToolbar()",
        "function renderBetaDashboard(data)",
        "function renderBetaWarningList(warnings)",
        "function renderSecurityResponseSummary(response)",
        "function securityResponseTone(status)",
        "function renderSecurityResponseActionLabels(actions)",
        "function renderSecurityResponseRecordCard(title, records, lineFormatter)",
        "function securityResponseAdvisoryLine(advisory)",
        "function securityResponseDenylistLine(denylistEntry)",
        "function securityResponseCatalogKeyLine(catalogKey)",
        "reviewer_revocation_active",
        "Production security response",
        "Security response",
        "Denylisted app versions",
        "Support handling",
        "function renderBetaCatalogs(catalogs)",
        "function renderBetaApps(apps)",
        "function renderBetaSubscriptions(subscriptions)",
        "function renderBetaTrustAndServices(trustGraph, appServices)",
        "function renderOperatorRcRecovery(recovery, networkBudgets)",
        "function buildOperatorRcRecoveryAction(action)",
        "function submitOperatorRcRecoveryAction(form, submitter)",
        "function renderOperatorRcPlan(container, plan)",
        "function renderOperatorRcResult(container, result)",
        "function appendOperatorRcResultSteps(container, steps)",
        "function appendOperatorRcResultDetails(container, details)",
        "function operatorRcDetailNode(value, depth)",
        "function operatorRcBoundedScalar(value)",
        "function appendOperatorRcSupportBundleArtifact(container, result)",
        "function appendOperatorRcSensitiveBackup(container, result)",
        "function operatorRcResultStatus(result)",
        "function operatorRcResultHasSensitiveBackup(result)",
        "function operatorRcResultPreservesVisibleArtifact(result)",
        "function operatorRcResultShouldReload(result)",
        "function operatorRcResultTone(result)",
        "function operatorRcResultStatusMessage(result)",
        "function renderBetaRecoveryActions(actions)",
        "function buildOperatorRecoveryAction(action)",
        "function loadBetaDashboardSection()",
        "function loadSupportBundle()",
        "function supportBundleRedactionStatus(bundle)",
        "function supportBundleRedactionFailed(bundle)",
        "Missing redaction status",
        "function supportBundleExportBlocked(bundle)",
        "function supportBundleOmittedFieldCount(bundle)",
        "function supportBundleDigestShort(bundle)",
        "function supportJsonText(bundle)",
        "function downloadSupportBundle()",
        "function copySupportSummary()",
        "function downloadAllAppDataBackup()",
        "function submitAppDataRestoreForm(form, restoreAction, statusSetter)",
        "function submitOperatorRecoveryAction(form)",
        "function bindBetaDashboardInteractions()",
        "loadJson(apiUrl(\"operator/rc-dashboard\"))",
        "loadJson(apiUrl(\"operator/beta-dashboard\"))",
        "apiUrl(\"operator/support-bundle/preview\")",
        "loadJson(apiUrl(\"operator/support-bundle\"))",
        "\"operator/recovery/plan\"",
        "\"operator/recovery/execute\"",
        "operatorRcSubmitButton(\"Plan\", \"plan\", false)",
        "operatorRcSubmitButton(\"Execute\", \"execute\", action.destructive === true)",
        "input[name=\"planToken\"]",
        "planTokenInput.name = \"planToken\"",
        "typeof plan.planToken === \"string\" ? plan.planToken : \"\"",
        "form.dataset.operatorRcRecoveryPlanned !== \"true\"",
        "Review the recovery plan before executing.",
        "operatorRcResultStatus(result)",
        "operatorRcResultHasSensitiveBackup(result)",
        "Operator RC recovery action was blocked. Review the result before retrying.",
        "Operator RC recovery action failed. Review the result before retrying.",
        "appendOperatorRcResultSteps(container, result.steps)",
        "appendOperatorRcResultDetails(container, result.details)",
        "appendOperatorRcSupportBundleArtifact(container, result)",
        "Support bundle redaction failed; copy and download are disabled.",
        "Support JSON copied.",
        "downloadJsonBlob(supportBundle, supportBundleFileName(supportBundle))",
        "case \"support-bundle.export\":",
        "case \"trust-graph.export-summary\":",
        "case \"network-budget.view\":",
        "!operatorRcResultPreservesVisibleArtifact(result)",
        "A sensitive app-data backup was returned. Download it before refreshing this dashboard.",
        "downloadAppDataBackupPayload(sensitiveBackup, \"single-app\", scalar(target.appId ||"
            + " \"\"))",
        "Operator RC recovery actions unavailable in read-only mode.",
        "submitFormMutation(",
        "new FormData(),",
        "Operator recovery actions unavailable in read-only mode.",
        "sections.betaDashboard.addEventListener(\"submit\"",
        "bindBetaDashboardInteractions();",
        "updateBetaDashboardToolbar();",
        "loadBetaDashboardSection().catch((error) => {");
    assertFalse(script.contains("operatorRcSubmitButton(\"Plan\", \"plan\", action.destructive"));
  }

  private static void assertAppDataBackupRestoreMarkersPresent(String script) {
    assertContainsAll(
        script,
        "function appDataBackupFormDataForApp(appId)",
        "function allAppDataBackupFormData()",
        "function downloadJsonBlob(value, fileName)",
        "function urlSafeBase64ToBytes(value)",
        "function appDataBackupBundle(response)",
        "function appDataBackupFileName(response, fallbackScope, fallbackAppId)",
        "function appDataBackupPayloadBlob(response)",
        "function downloadAppDataBackupPayload(response, fallbackScope, fallbackAppId)",
        "function backupPayloadBase64FromText(value)",
        "function buildAppDataRestoreFormData(form)",
        "function restorePlanReady(response)",
        "function renderAppDataRestoreMetadata(container, response)",
        "operator/app-data/backups",
        "postForm(",
        "operator/app-data/restore/plan",
        "operator/app-data/restore",
        "formData.set(\"scope\", \"all\")",
        "payloadBase64",
        "app.installed === true ? \"Yes\" : app.installed === false ? \"No\" : \"Unavailable\"",
        "replaceNamespace",
        "replaceApp",
        "Export app data",
        "Restore app data",
        "Uninstall preserving data",
        "Delete app and data",
        "Export backup before delete",
        "new Blob([urlSafeBase64ToBytes(payloadBase64)]",
        "downloadAppDataBackupPayload(response, \"all-apps\", \"\")",
        "downloadAppDataBackupPayload(response, \"single-app\", appId)",
        "URL.createObjectURL(blob)",
        "link.download = fileName;",
        "URL.revokeObjectURL(href)",
        "App-data backups contain sensitive user data. Restore previews show metadata only.",
        "App-data backup is unavailable in read-only mode.",
        "App-data restore is unavailable in read-only mode.");
  }

  private static void assertBetaDashboardLoadSequencing(String script) {
    int loadIndex = script.indexOf("async function loadBetaDashboardSection()");
    int generationIndex =
        script.indexOf("const loadGeneration = ++betaDashboardLoadGeneration;", loadIndex);
    int resetIndex = script.indexOf("shellState.betaDashboardSnapshot = null;", generationIndex);
    int fetchIndex = script.indexOf("loadJson(apiUrl(\"operator/rc-dashboard\"))", resetIndex);
    int successGuardIndex =
        script.indexOf("if (loadGeneration !== betaDashboardLoadGeneration) {", fetchIndex);
    int renderIndex = script.indexOf("renderBetaDashboard(snapshot);", successGuardIndex);
    int errorGuardIndex =
        script.indexOf("if (loadGeneration !== betaDashboardLoadGeneration) {", renderIndex);
    int fallbackIndex =
        script.indexOf("loadJson(apiUrl(\"operator/beta-dashboard\"))", errorGuardIndex);
    int renderErrorIndex =
        script.indexOf(
            "renderError(sections.betaDashboard, \"operator RC recovery\", fallbackError);",
            fallbackIndex);
    int bindIndex = script.indexOf("function bindBetaDashboardInteractions()");
    int rcActionIndex = script.indexOf("if (form.dataset.operatorRcRecoveryActionId) {", bindIndex);
    int rcMutationIndex =
        script.indexOf(
            "await submitOperatorRcRecoveryAction(form, event.submitter);", rcActionIndex);
    int actionPathIndex =
        script.indexOf("if (!form.dataset.operatorRecoveryPath) {", rcMutationIndex);
    int preventDefaultIndex = script.indexOf(EVENT_PREVENT_DEFAULT, actionPathIndex);
    int mutationIndex =
        script.indexOf("await submitOperatorRecoveryAction(form);", preventDefaultIndex);

    assertTrue(loadIndex >= 0);
    assertTrue(generationIndex > loadIndex);
    assertTrue(resetIndex > generationIndex);
    assertTrue(fetchIndex > resetIndex);
    assertTrue(successGuardIndex > fetchIndex);
    assertTrue(renderIndex > successGuardIndex);
    assertTrue(errorGuardIndex > renderIndex);
    assertTrue(fallbackIndex > errorGuardIndex);
    assertTrue(renderErrorIndex > errorGuardIndex);
    assertTrue(bindIndex > renderErrorIndex);
    assertTrue(rcActionIndex > bindIndex);
    assertTrue(rcMutationIndex > rcActionIndex);
    assertTrue(actionPathIndex > bindIndex);
    assertTrue(preventDefaultIndex > actionPathIndex);
    assertTrue(mutationIndex > preventDefaultIndex);
  }

  private static void assertAppsMarkersPresent(String script) {
    int appUiEntryHelperIndex = script.indexOf("function normalizeAppUiEntryHref(value, app)");
    int legacyLinkHelperIndex = script.indexOf("function normalizeLegacyLinkPath(value)");
    String appUiEntryHelper = script.substring(appUiEntryHelperIndex, legacyLinkHelperIndex);

    assertTrue(script.contains("appsSnapshot: null"));
    assertTrue(script.contains("appCatalogsSnapshot: null"));
    assertTrue(script.contains("identityVaultSnapshot: null"));
    assertTrue(script.contains("recommendedCatalogsSnapshot: null"));
    assertTrue(script.contains("const vaultCapabilityPrefix = \"vault.\";"));
    assertTrue(script.contains("let appsLoadGeneration = 0;"));
    assertTrue(script.contains("apps: document.getElementById(\"apps-body\")"));
    assertTrue(script.contains("appsStatus: document.getElementById(\"apps-status\")"));
    assertTrue(
        script.contains("appsReadonlyHint: document.getElementById(\"apps-readonly-hint\")"));
    assertTrue(script.contains("const appsControls = {"));
    assertTrue(
        script.contains("catalogSourceForm: document.getElementById(\"catalog-source-form\")"));
    assertTrue(script.contains("function normalizeAppUiEntryHref(value, app)"));
    assertTrue(appUiEntryHelper.contains("const url = new URL(value, shellRootUrl);"));
    assertTrue(script.contains("allowedAppUiOrigin(url, app)"));
    assertTrue(script.contains("? safeShellPanelAppUiHref(url)"));
    assertTrue(script.contains(": safeSameOriginAppUiHref(url, false);"));
    assertTrue(script.contains("return url.href;"));
    assertFalse(appUiEntryHelper.contains("const url = new URL(value, window.location.origin);"));
    assertTrue(script.contains("function appUiHref(app)"));
    assertTrue(script.contains("const isolatedFallbackHref = isolatedAppUiFallbackHref(app);"));
    assertTrue(script.contains("function isolatedAppUiLaunchHref(app)"));
    assertTrue(script.contains("url.searchParams.set(isolatedLaunchParameter, \"1\");"));
    assertTrue(script.contains("function isolatedAppUiFallbackHref(app)"));
    assertTrue(script.contains("return normalizeAppUiEntryHref(app.sameOriginFallbackUrl, app);"));
    assertTrue(script.contains("function isolatedAppUiProbeHref(app)"));
    assertTrue(
        script.contains(
            "async function isolatedAppOriginReachable(probeHref, expectedAppId, expectedOrigin)"));
    assertTrue(script.contains("const probeOrigin = new URL(probeHref).origin;"));
    assertTrue(script.contains("credentials: \"omit\""));
    assertTrue(script.contains("mode: \"cors\""));
    assertTrue(script.contains("data.uiOrigin === probeOrigin"));
    assertTrue(script.contains("function isolatedAppUiActive(app)"));
    assertTrue(script.contains("function appSandboxStatus(app, runtime)"));
    assertTrue(script.contains("function sandboxLabel(status)"));
    assertTrue(script.contains("supportLevel === \"enforced\""));
    assertTrue(script.contains("Enforced sandbox"));
    assertTrue(script.contains("function inactiveEnforcedSandboxLabel(status)"));
    assertTrue(script.contains("Enforced sandbox available"));
    assertTrue(script.contains("Last launch enforced sandbox"));
    assertTrue(script.contains("return \"is-success\""));
    assertTrue(script.contains("status.active === false ? \"is-warning\" : \"is-success\""));
    assertTrue(script.contains("Unsupported required sandbox"));
    assertTrue(script.contains("[\"Sandbox\", sandboxLabel(sandbox)]"));
    assertTrue(
        script.contains(
            "[\"Sandbox provider\", sandbox ? scalar(sandbox.provider) : \"Unavailable\"]"));
    assertTrue(script.contains("function appQuotaStatus(app, runtime)"));
    assertTrue(script.contains("function formatBytes(value)"));
    assertTrue(script.contains("function quotaWarnings(quota, runtime)"));
    assertTrue(script.contains("[\"Data usage\", formatQuotaUsage("));
    assertTrue(script.contains("[\"Cache usage\", formatQuotaUsage("));
    assertTrue(script.contains("[\"Data limit\", formatQuotaLimit("));
    assertTrue(script.contains("[\"Cache limit\", formatQuotaLimit("));
    assertTrue(script.contains("[\"Quota warnings\", quotaWarnings(quota, runtime)]"));
    assertTrue(script.contains("[\"Process log size\","));
    assertTrue(script.contains("[\"Process log limit\","));
    assertTrue(script.contains("[\"Process log tail limit\","));
    assertTrue(script.contains("[\"Process log truncated\","));
    assertTrue(script.contains("function appRuntimePath(appId)"));
    assertTrue(script.contains("function appLogsPath(appId, maxBytes)"));
    assertTrue(script.contains("function appAuditPath(appId)"));
    assertTrue(script.contains("function appUpdatesPath(appId, action)"));
    assertTrue(script.contains("async function loadAppRuntimeDetails(app)"));
    assertTrue(script.contains("const explicitHref = normalizeAppUiEntryHref(app.uiUrl, app);"));
    assertTrue(
        script.contains(
            "return normalizeAppUiEntryHref(`/apps/${encodeURIComponent(app.appId)}/`, app);"));
    assertTrue(script.contains("[\"UI origin mode\", scalar(app.uiOriginMode)]"));
    assertTrue(script.contains("function renderAppCard(app)"));
    assertTrue(
        script.contains(
            "const runtimeStoppable = runtimeRunning || runtimeState === \"RESTARTING\";"));
    assertTrue(script.contains("runtimeStoppable ? \"stop\" : \"start\""));
    assertTrue(script.contains("runtimeStoppable ? \"Stop\" : \"Start\""));
    assertTrue(script.contains("const preserveDataForm = runtimeStoppable"));
    assertTrue(script.contains("const deleteDataForm = runtimeStoppable"));
    assertTrue(script.contains("Runtime log tail"));
    assertTrue(script.contains("Declared permissions"));
    assertTrue(script.contains("Vault status"));
    assertTrue(script.contains("function appVaultStatus(app)"));
    assertTrue(script.contains("function appVaultPermissions(app)"));
    assertTrue(script.contains("function appVaultDetailsNode(app)"));
    assertTrue(script.contains("function buildIdentityVaultGrantForm("));
    assertTrue(script.contains("function buildIdentityVaultRevokeForm(grant)"));
    assertTrue(script.contains("function identityVaultGrantPath(grantId)"));
    assertTrue(script.contains("function appServiceGrantPath(grantId, action)"));
    assertTrue(script.contains("function buildAppServiceGrantActionForm(grant, action, label)"));
    assertTrue(script.contains("function renderAppServices(appServices, appServicesError)"));
    assertTrue(script.contains("function renderAppServiceDescriptorCard(service)"));
    assertTrue(script.contains("function renderAppServiceRequestCard(request)"));
    assertTrue(script.contains("function renderAppServiceGrantCard(grant)"));
    assertTrue(script.contains("function renderAppServiceAuditDetails(auditEvents)"));
    assertTrue(script.contains("function appServiceGrantTone(status)"));
    assertTrue(script.contains("function renderIdentityVault("));
    assertTrue(script.contains("function renderIdentityVaultCard(identity, grants)"));
    assertTrue(script.contains("function renderIdentityGrantCard(grant)"));
    assertTrue(script.contains("Recent app audit"));
    assertTrue(script.contains("function appAuditDetailsNode(audit, auditError)"));
    assertTrue(script.contains("app-log-tail"));
    assertTrue(script.contains("function renderApps(data)"));
    assertTrue(script.contains("function renderRecommendedCatalogs("));
    assertTrue(script.contains("function renderRecommendedCatalogCard("));
    assertTrue(script.contains("function renderCatalogs(catalogs, catalogError)"));
    assertTrue(script.contains("function catalogSourceKind(catalog)"));
    assertTrue(script.contains("function catalogLastSuccessfulRefreshAt(catalog)"));
    assertTrue(script.contains("function catalogFetchFailed(catalog)"));
    assertTrue(script.contains("function catalogFetchWarningNode(catalog)"));
    assertTrue(script.contains("Catalogs unavailable: ${catalogError}"));
    assertTrue(script.contains("Recommended catalogs"));
    assertTrue(script.contains("Recommended catalogs unavailable: ${recommendedCatalogError}"));
    assertTrue(script.contains("Catalog onboarding is waiting for"));
    assertTrue(script.contains("Identity vault"));
    assertTrue(script.contains("Vault summary"));
    assertTrue(
        script.contains(
            "catalogChannelSelect: document.getElementById(\"catalog-channel-select\")"));
    assertTrue(script.contains("function renderCatalogCard(catalog, selectedChannel)"));
    assertTrue(script.contains("function catalogAppChannel(app)"));
    assertTrue(script.contains("function catalogChannelLabel(channel)"));
    assertTrue(script.contains("function catalogChannelTone(channel)"));
    assertTrue(script.contains("function catalogAppDeprecation(app)"));
    assertTrue(script.contains("function catalogMaintenancePolicy(app)"));
    assertTrue(script.contains("function catalogMaintenanceDeclared(maintenance)"));
    assertTrue(script.contains("function maintenancePolicyTone(supportLevel)"));
    assertTrue(script.contains("function catalogAppDeprecated(app)"));
    assertTrue(script.contains("function securityAdvisoryListNode(values)"));
    assertTrue(script.contains("function securityDecisionLabel(securityDecision)"));
    assertTrue(
        script.contains("function appendSecurityAcknowledgement(form, securityDecision, action)"));
    assertTrue(script.contains("input.name = \"securityAcknowledged\";"));
    assertTrue(script.contains("function catalogSecurityDetailsNode(app)"));
    assertTrue(script.contains("function catalogMaintenancePolicyNode(app)"));
    assertTrue(script.contains("Safe uninstall guidance"));
    assertTrue(script.contains("Maintenance policy"));
    assertTrue(script.contains("[\"Maintenance owner\","));
    assertTrue(script.contains("[\"Maintenance support level\","));
    assertTrue(script.contains("[\"Backup/restore support\","));
    assertTrue(script.contains("function deprecationNoticeNode(app)"));
    assertTrue(
        script.contains(
            "const visibleApps = apps.filter((app) => catalogAppChannel(app) ==="
                + " selectedChannel);"));
    assertTrue(
        script.contains(
            "No ${catalogChannelLabel(selectedChannel)} apps were returned for this catalog."));
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
    assertTrue(script.contains("loadOptionalJson(apiUrl(\"app-catalogs/recommended\"))"));
    assertTrue(script.contains("loadOptionalJson(apiUrl(\"identity-vault/identities\"))"));
    assertTrue(script.contains("loadOptionalJson(apiUrl(\"identity-vault/grants\"))"));
    assertTrue(script.contains("loadOptionalJson(apiUrl(\"app-services\"))"));
    assertTrue(script.contains("loadOptionalJson(apiUrl(\"app-services/grants\"))"));
    assertTrue(script.contains("loadOptionalJson(apiUrl(\"app-services/dependencies\"))"));
    assertTrue(script.contains("loadOptionalJson(apiUrl(\"app-services/grant-bundles\"))"));
    assertTrue(script.contains("loadOptionalJson(apiUrl(\"app-services/audit?limit=12\"))"));
    assertTrue(script.contains("App-service grants"));
    assertTrue(script.contains("Service grant summary"));
    assertTrue(script.contains("Advertised services"));
    assertTrue(script.contains("Declared requests"));
    assertTrue(script.contains("Dependency edges"));
    assertTrue(script.contains("Grant bundles"));
    assertTrue(script.contains("Pending grants"));
    assertTrue(script.contains("Active grants"));
    assertTrue(script.contains("Revoked grants"));
    assertTrue(script.contains("App-service audit"));
    assertTrue(script.contains("App-service grant actions unavailable in read-only mode."));
    assertTrue(script.contains("App-service grant-bundle actions unavailable in read-only mode."));
    assertTrue(script.contains("App-service grant action unavailable."));
    assertTrue(script.contains("App-service grant-bundle action unavailable."));
    assertTrue(script.contains("App-service grant ${action} completed."));
    assertTrue(script.contains("App-service grant bundle ${action} completed."));
    assertTrue(script.contains("form.dataset.appServiceGrantAction = action;"));
    assertTrue(script.contains("form.dataset.appServiceBundleAction = action;"));
    assertTrue(
        script.contains("await submitAppServiceGrantMutation(form, appServiceGrantAction);"));
    assertTrue(
        script.contains("await submitAppServiceBundleMutation(form, appServiceBundleAction);"));
    assertTrue(script.contains("function renderAppServiceDependencyGraph(graph)"));
    assertTrue(script.contains("function renderAppServiceDependencyCard(dependency)"));
    assertTrue(script.contains("function renderAppServiceBundleCard(bundle)"));
    assertTrue(script.contains("catalogsSnapshot.catalogs.map(loadCatalogApps)"));
    assertTrue(script.contains("recommendedSnapshot.catalogs"));
    assertTrue(script.contains("renderRecommendedCatalogs("));
    assertTrue(script.contains("typeof catalog.sourceKind === \"string\" && catalog.sourceKind"));
    assertTrue(script.contains("typeof catalog.sourceType === \"string\" && catalog.sourceType"));
    assertTrue(script.contains("pills.append(createPill(sourceKind));"));
    assertTrue(script.contains("pills.append(createPill(\"refresh failed\", \"is-warning\"));"));
    assertTrue(script.contains("[\"Source type\", sourceKind]"));
    assertTrue(script.contains("[\"Source\", scalar(catalogSourceDisplay(catalog))]"));
    assertTrue(
        script.contains("[\"Resolved source\", scalar(catalogResolvedSourceDisplay(catalog))]"));
    assertTrue(script.contains("function renderCatalogOperationsNode(catalog)"));
    assertTrue(
        script.contains(
            "[\"Last successful refresh\","
                + " formatIsoTimestamp(catalogLastSuccessfulRefreshAt(catalog))]"));
    assertTrue(script.contains("[\"Last failed attempt\", catalogLastFailedAttempt(catalog)]"));
    assertTrue(
        script.contains("Crypta catalog refresh failed; showing last successful app listing."));
    assertTrue(script.contains("catalog.appsError"));
    assertTrue(script.contains("loadJson(apiUrl(`app-catalogs/${encodedCatalogId}/apps`))"));
    assertTrue(script.contains("operations/health"));
    assertTrue(script.contains("operations/revisions"));
    assertTrue(script.contains("operations/key-rotation"));
    assertTrue(script.contains("return `apps/${encodedAppId}/${action}`;"));
    assertTrue(script.contains("return `apps/${encodedAppId}`;"));
    assertTrue(script.contains("`apps/${encodeURIComponent(appId)}/runtime`"));
    assertTrue(script.contains("`apps/${encodeURIComponent(appId)}/logs?maxBytes="));
    assertTrue(script.contains("`apps/${encodeURIComponent(appId)}/audit`"));
    assertTrue(script.contains("`apps/${encodeURIComponent(appId)}/updates`"));
    assertTrue(script.contains("return `app-catalogs/${encodedCatalogId}/refresh`;"));
    assertTrue(
        script.contains("return `app-catalogs/${encodedCatalogId}/operations/refresh-primary`;"));
    assertTrue(
        script.contains("return `app-catalogs/${encodedCatalogId}/operations/emergency-refresh`;"));
    assertTrue(script.contains("return `app-catalogs/${encodedCatalogId}/operations/rollback`;"));
    assertTrue(script.contains("return `app-catalogs/recommended/${encodedCatalogId}/add`;"));
    assertTrue(
        script.contains(
            "return `app-catalogs/${encodedCatalogId}/apps/${encodedAppId}/${action}`;"));
    assertTrue(script.contains("`identity-vault/grants/${encodeURIComponent(grantId)}`"));
    assertTrue(
        script.contains(
            "`app-services/grants/${encodeURIComponent(grantId)}/${encodeURIComponent(action)}`"));
    assertTrue(
        script.contains(
            "`app-services/grant-bundles/${encodeURIComponent(bundleId)}/${encodeURIComponent(action)}`"));
    assertTrue(script.contains("action === \"uninstall\""));
    assertTrue(script.contains("App lifecycle actions unavailable in read-only mode."));
    assertTrue(script.contains("Catalog actions unavailable in read-only mode."));
    assertTrue(script.contains("Identity vault actions unavailable in read-only mode."));
    assertTrue(script.contains("Identity grant created."));
    assertTrue(script.contains("Identity grant revoked."));
  }

  private static void assertConsentUxMarkersPresent(String script) {
    assertTrue(script.contains("function consentInstallPreviewPath(catalogId, appId)"));
    assertTrue(script.contains("function consentCatalogUpdatePreviewPath(catalogId, appId)"));
    assertTrue(script.contains("function consentUpdatePreviewPath(appId)"));
    assertTrue(script.contains("function consentServiceGrantPreviewPath(bundleId)"));
    assertTrue(script.contains("function consentPreviewPathForForm(form, action)"));
    assertTrue(script.contains("function loadConsentPreviewForForm(form, action)"));
    assertTrue(script.contains("function ensureConsentApprovedForForm(form, action)"));
    assertTrue(script.contains("function renderConsentPreview(preview, form)"));
    assertTrue(script.contains("function renderConsentSection(section)"));
    assertTrue(script.contains("function renderConsentFinding(finding)"));
    assertTrue(script.contains("function submitConsentDecision(preview, decision)"));
    assertTrue(script.contains("function appendConsentSnapshotFields(form, preview)"));
    assertTrue(script.contains("function consentStaleErrorMessage(error)"));
    assertTrue(script.contains("consent/install-preview?catalogId="));
    assertTrue(script.contains("consent/catalog-update-preview?catalogId="));
    assertTrue(script.contains("\"consent/update-preview\""));
    assertTrue(script.contains("consent/service-grant-preview?bundleId="));
    assertTrue(script.contains("Consent previews unavailable in read-only mode."));
    assertTrue(script.contains("await postForm(`consent/${decision}`"));
    assertTrue(script.contains("formData.set(\"consentRequestId\""));
    assertTrue(script.contains("formData.set(\"snapshotDigest\""));
    assertTrue(script.contains("appendHiddenField(form, \"consentRequestId\""));
    assertTrue(script.contains("appendHiddenField(form, \"snapshotDigest\""));
    assertTrue(script.contains("preview.requiresApproval !== true"));
    assertTrue(script.contains("preview.blocksAutoUpdate === true ? \"Yes\" : \"No\""));
    assertTrue(script.contains("arrayValue(preview.sections).forEach((section)"));
    assertTrue(script.contains("arrayValue(item.items).forEach((finding)"));
    assertTrue(script.contains("Consent preview"));
    assertTrue(script.contains("Risk level"));
    assertTrue(script.contains("Blocks auto-update"));
    assertTrue(script.contains("Snapshot digest"));
    assertTrue(script.contains("Consent approved. Continuing action."));
    assertTrue(script.contains("Consent rejected. No app-platform mutation was applied."));
    assertTrue(script.contains("This approval is stale. Refresh the consent preview."));
    assertTrue(script.contains("await ensureConsentApprovedForForm(form, action)"));
  }

  private static void assertAppUpdateLifecycleMarkersPresent(String script) {
    assertTrue(script.contains("function appUpdateState(app)"));
    assertTrue(script.contains("function appHasUpdateState(updateState)"));
    assertTrue(script.contains("function updateVersionSummary(updateInfo)"));
    assertTrue(script.contains("info.targetVersion"));
    assertTrue(script.contains("\"lastCheck\""));
    assertTrue(script.contains("lastCheck.checkedAt"));
    assertTrue(script.contains("lastCheck.status"));
    assertTrue(script.contains("function updatePolicySummary(policy)"));
    assertTrue(script.contains("function updatePermissionDeltaSummary(source)"));
    assertTrue(script.contains("sourceRecord.permissionDelta || sourceRecord.permissionsDelta"));
    assertTrue(script.contains("function updateApiRiskSummary(source)"));
    assertTrue(script.contains("function rollbackAvailable(updateState)"));
    assertTrue(script.contains("function stageableUpdateCandidate(updateState)"));
    assertFalse(script.contains("candidate.autoStageAllowed"));
    assertTrue(script.contains("status === \"available\""));
    assertTrue(
        script.contains("Stage is unavailable until a newer update candidate is available."));
    assertTrue(script.contains("function updateActionDisabledReason("));
    assertTrue(script.contains("function reviewTrustBlockFieldForAction(action)"));
    assertTrue(script.contains("if (action === \"update\" || action === \"stage\")"));
    assertFalse(
        script.contains(
            "action === \"install\" ? \"blocksInstall\" : action === \"update\" || action ==="
                + " \"stage\" ? \"blocksUpdate\" : \"blocksPolicyApply\""));
    assertTrue(script.contains("function stagedUpdateAvailable(updateState)"));
    assertTrue(script.contains("staged.available === true || staged.status === \"staged\""));
    assertTrue(script.contains("if (stagedUpdateAvailable(updateState))"));
    assertTrue(script.contains("rollback.previousVersion"));
    assertTrue(script.contains("function appUpdateDetailsNode(app, updateState)"));
    assertTrue(script.contains("function appendAppUpdateActionForms("));
    assertTrue(script.contains("function buildAppUpdateActionForm("));
    assertTrue(script.contains("async function submitAppUpdateMutation(form, action)"));
    assertTrue(script.contains("form.dataset.appUpdateAction = action;"));
    assertTrue(script.contains("submit.disabled = true;"));
    assertTrue(script.contains("submit.title = disabledReason;"));
    assertTrue(script.contains("const updatesPath = appUpdatesPath(app.appId, \"summary\");"));
    assertTrue(script.contains("await loadOptionalJson(apiUrl(updatesPath))"));
    assertTrue(script.contains("updatesSnapshot.updateState"));
    assertTrue(script.contains("updatesSnapshot.updates"));
    assertTrue(script.contains("[\"Update candidate\","));
    assertTrue(script.contains("[\"Staged update\","));
    assertTrue(script.contains("[\"Update policy\","));
    assertTrue(script.contains("[\"Permission changes before apply\","));
    assertTrue(script.contains("[\"API compatibility before apply\","));
    assertTrue(script.contains("[\"Rollback available\","));
    assertTrue(script.contains("\"Last scheduler check\","));
    assertTrue(script.contains("\"Next scheduler check\","));
    assertTrue(script.contains("App update lifecycle"));
    assertTrue(script.contains("Check for app update"));
    assertTrue(script.contains("Stage app update"));
    assertTrue(script.contains("Apply staged update"));
    assertTrue(script.contains("Rollback app update"));
    assertTrue(script.contains("Apply requires restart"));
    assertTrue(script.contains("Rollback requires restart"));
    assertTrue(script.contains("requires stopping or restarting the running app first"));
    assertTrue(script.contains("App update actions unavailable in read-only mode."));
    assertTrue(script.contains("const appUpdateAction = form.dataset.appUpdateAction;"));
    assertTrue(script.contains("await submitAppUpdateMutation(form, appUpdateAction);"));
  }

  private static void assertAppStoreMetadataMarkersPresent(String script) {
    assertTrue(script.contains("function safeMetadataUri(value)"));
    assertTrue(script.contains("function metadataLinkNode(value, label)"));
    assertTrue(script.contains("function metadataLinkListNode(values)"));
    assertTrue(script.contains("function catalogReviewDetailsNode(app)"));
    assertTrue(script.contains("function catalogCompatibilityDetailsNode(app)"));
    assertTrue(script.contains("function apiCompatibilityDetailsNode(app)"));
    assertTrue(script.contains("function apiCompatibilityLabel(apiCompatibility)"));
    assertTrue(script.contains("function apiCompatibilityTone(apiCompatibility)"));
    assertTrue(script.contains("function catalogPermissionReviewDetailsNode(app)"));
    assertTrue(script.contains("function catalogReleaseDetailsNode(app)"));
    assertTrue(script.contains("function catalogMaintenancePolicyNode(app)"));
    assertTrue(script.contains("Review and trust"));
    assertTrue(script.contains("Publisher advisory review"));
    assertTrue(script.contains("Third-party submission"));
    assertTrue(script.contains("Submission id"));
    assertTrue(script.contains("Pre-review status"));
    assertTrue(script.contains("Trusted review receipt"));
    assertTrue(script.contains("function reviewTrustLabel(reviewTrust)"));
    assertTrue(script.contains("function appendReviewAcknowledgement(form, reviewTrust, action)"));
    assertTrue(script.contains("reviewAcknowledged"));
    assertTrue(script.contains("Permission review"));
    assertTrue(script.contains("Release metadata"));
    assertTrue(script.contains("[\"Homepage\", metadataLinkNode(app.homepage)]"));
    assertTrue(script.contains("[\"Source\", metadataLinkNode(app.source)]"));
    assertTrue(script.contains("[\"Categories\", chipListNode(app.categories)]"));
    assertTrue(script.contains("[\"Maintenance owner\","));
    assertTrue(script.contains("[\"Maintenance support\","));
    assertTrue(script.contains("[\"Permission changes\","));
    assertTrue(script.contains("[\"API contract\", apiCompatibilityLabel(apiCompatibility)]"));
    assertTrue(
        script.contains(
            "[\"Minimum API contract version\", scalar(apiCompatibility.minimumVersion)]"));
    assertTrue(script.contains("Platform API contract"));
    assertTrue(script.contains("[\"Screenshot links\", metadataLinkListNode(app.screenshots)]"));
    assertTrue(script.contains("link.rel = \"noopener noreferrer\";"));
    assertTrue(
        script.contains(
            "link.textContent = typeof label === \"string\" && label ? label : value;"));
    assertTrue(script.contains("pills.append(createPill(\"Signed catalog\"));"));
    assertTrue(script.contains("pills.append(createPill(versionLabel(app), versionTone(app)));"));
    assertTrue(script.contains("No permission rationale supplied."));
    assertTrue(script.contains("Update from catalog"));
    assertTrue(script.contains("Apply catalog version"));
    assertTrue(script.contains("Install from catalog"));
  }

  private static void assertCompatibilityUndeclaredPrecedesSuccess(String script) {
    int toneStart = script.indexOf("function compatibilityTone(compatibility)");
    int toneUndeclaredIndex = script.indexOf("status === \"not_declared\"", toneStart);
    int toneSuccessIndex = script.indexOf("compatibility.satisfied === true", toneStart);
    assertTrue(toneUndeclaredIndex > toneStart);
    assertTrue(toneSuccessIndex > toneUndeclaredIndex);

    int labelStart = script.indexOf("function compatibilityLabel(compatibility)");
    int labelUndeclaredIndex = script.indexOf("status === \"not_declared\"", labelStart);
    int labelSuccessIndex = script.indexOf("compatibility.satisfied === true", labelStart);
    assertTrue(labelUndeclaredIndex > labelStart);
    assertTrue(labelSuccessIndex > labelUndeclaredIndex);
    assertTrue(script.contains("Compatibility not declared"));
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
    int appServiceActionLookupIndex =
        script.indexOf(
            "const appServiceGrantAction = form.dataset.appServiceGrantAction;", bindAppsIndex);
    int appServiceMutationIndex =
        script.indexOf(
            "await submitAppServiceGrantMutation(form, appServiceGrantAction);", bindAppsIndex);
    int appDataRestoreLookupIndex =
        script.indexOf(
            "const appDataRestoreAction = form.dataset.appDataRestoreAction;", bindAppsIndex);
    int appDataRestoreMutationIndex =
        script.indexOf(
            "await submitAppDataRestoreForm(form, restoreAction, setAppsStatus);", bindAppsIndex);
    int appDataBackupLookupIndex =
        script.indexOf(
            "const appDataBackupAction = form.dataset.appDataBackupAction;", bindAppsIndex);
    int appDataBackupMutationIndex =
        script.indexOf(
            "await submitAppDataBackupAction(form, appDataBackupAction);", bindAppsIndex);
    int uninstallConfirmIndex =
        script.indexOf(
            "if (action === \"uninstall\" && !confirmAppUninstall(form))", bindAppsIndex);

    assertTrue(bindAppsIndex >= 0);
    assertTrue(appServiceActionLookupIndex > bindAppsIndex);
    assertTrue(appServiceMutationIndex > appServiceActionLookupIndex);
    assertTrue(catalogActionLookupIndex > bindAppsIndex);
    assertTrue(catalogMutationIndex > catalogActionLookupIndex);
    assertTrue(appDataRestoreLookupIndex > bindAppsIndex);
    assertTrue(appDataRestoreMutationIndex > appDataRestoreLookupIndex);
    assertTrue(appDataBackupLookupIndex > appDataRestoreMutationIndex);
    assertTrue(appDataBackupMutationIndex > appDataBackupLookupIndex);
    assertTrue(actionLookupIndex > bindAppsIndex);
    assertTrue(actionLookupIndex > appDataBackupMutationIndex);
    assertTrue(preventDefaultIndex > actionLookupIndex);
    assertTrue(uninstallConfirmIndex > preventDefaultIndex);
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
    int recommendedLoadIndex =
        script.indexOf(
            "const recommendedSnapshot = await"
                + " loadOptionalJson(apiUrl(\"app-catalogs/recommended\"));",
            catalogErrorIndex);
    int recommendedErrorIndex = script.indexOf("recommendedCatalogError =", recommendedLoadIndex);
    int successGuardIndex =
        script.indexOf("if (loadGeneration !== appsLoadGeneration) {", recommendedErrorIndex);
    int renderAppsIndex = script.indexOf("renderApps({", successGuardIndex);

    assertTrue(loadAppsIndex >= 0);
    assertTrue(installedAwaitIndex > loadAppsIndex);
    assertTrue(installedErrorGuardIndex > installedAwaitIndex);
    assertTrue(renderErrorIndex > installedErrorGuardIndex);
    assertTrue(catalogLoadIndex > renderErrorIndex);
    assertTrue(catalogErrorIndex > catalogLoadIndex);
    assertTrue(recommendedLoadIndex > catalogErrorIndex);
    assertTrue(recommendedErrorIndex > recommendedLoadIndex);
    assertTrue(successGuardIndex > recommendedErrorIndex);
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
    assertTrue(
        script.contains(
            "const legacyDiagnosticPath = normalizeLocalPath(bootstrap.legacyDiagnosticPath,"
                + " null);"));
    assertTrue(script.contains("const legacyDiagnosticExportFallbackPath = legacyDiagnosticPath"));
    assertTrue(script.contains("legacyDiagnosticPath + \"?legacyFallback=diagnostic-export\""));
    assertTrue(
        script.contains(
            "legacyExportLink: document.getElementById(\"diagnostics-legacy-export-link\"),"));
    assertTrue(script.contains("function configureDiagnosticLegacyExportAction()"));
    assertTrue(
        script.contains(
            "diagnosticsControls.legacyExportLink.href ="
                + " legacyDiagnosticExportFallbackPath;"));
    assertTrue(script.contains("Opening legacy plaintext diagnostic export fallback."));
    assertTrue(script.contains("function redactedDiagnosticsSnapshot(data)"));
    assertTrue(
        script.contains("shellState.diagnosticsSnapshot = redactedDiagnosticsSnapshot(data);"));
    assertTrue(script.contains("delete redacted.plainTextExport;"));
    assertTrue(script.contains("configureDiagnosticLegacyExportAction();"));
    assertFalse(script.contains("\"/diagnostic/?legacyFallback=diagnostic-export\""));
    assertFalse(script.contains("summary.textContent = \"Plain-text export\";"));
    assertFalse(script.contains("diagnostics-export"));
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
    assertTrue(script.contains("const legacySecurityLevelsPath = normalizeLocalPath("));
    assertTrue(script.contains("bootstrap.legacySecurityLevelsPath,"));
    assertTrue(script.contains("const legacySecurityLevelsFallbackPath ="));
    assertTrue(script.contains("legacySecurityLevelsPath + \"?legacyFallback=security-levels\""));
    assertFalse(script.contains("\"/seclevels/?legacyFallback=security-levels\""));
    assertTrue(script.contains("function securityLegacyFallbackLink(label)"));
    assertTrue(script.contains("function setSecurityLegacyFallbackStatus(message)"));
    assertTrue(script.contains("function renderSecurityLegacyFallbackAction()"));
    assertTrue(script.contains("sections.security.append(renderSecurityLegacyFallbackAction())"));
    assertTrue(script.contains("Open legacy password and recovery forms"));
    assertTrue(script.contains("function securityErrorRequiresLegacyFallback(error)"));
    assertTrue(script.contains("physical_threat_level_password_required"));
    assertTrue(script.contains("physical_threat_level_master_password_cleanup_failed"));
    assertTrue(script.contains("if (securityErrorRequiresLegacyFallback(error))"));
    assertTrue(script.contains("Open the legacy security page."));
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
