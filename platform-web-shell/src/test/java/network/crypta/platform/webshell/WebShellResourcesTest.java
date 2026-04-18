package network.crypta.platform.webshell;

import network.crypta.platform.webshell.routes.WebShellPaths;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class WebShellResourcesTest {
  @Test
  void readText_whenIndexResourceRequested_expectShellMarkup() {
    String html = WebShellResources.readText(WebShellPaths.INDEX_RESOURCE_PATH);

    assertTrue(html.contains("Web Shell v1"));
    assertTrue(html.contains("Peer control plane"));
    assertTrue(html.contains("Queue control plane"));
    assertTrue(html.contains("Core updater"));
    assertTrue(html.contains("Operator subset"));
    assertTrue(html.contains("First-time setup"));
    assertTrue(html.contains("__BOOTSTRAP_JSON__"));
    assertTrue(html.contains("peer-create-form\" hidden"));
    assertTrue(html.contains("name=\"referenceText\""));
    assertTrue(html.contains("id=\"peers-status\""));
    assertTrue(html.contains("name=\"filterData\" type=\"checkbox\" checked"));
    assertTrue(html.contains("queue-create-form\" hidden"));
    assertTrue(html.contains("id=\"security-form\""));
    assertTrue(html.contains("id=\"updates-body\""));
    assertTrue(html.contains("id=\"config-form\""));
    assertTrue(html.contains("id=\"wizard-form\""));
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
    assertPlatformControlPlaneMarkersPresent(script);
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
    int preventDefaultIndex = script.indexOf("event.preventDefault();", submitHandlerIndex);
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
            "queueState.page === \"downloads\" ? loadOptionalJson(queueCountUrl()) :"
                + " Promise.resolve(null);");
    int loadOptionalJsonIndex = script.indexOf("async function loadOptionalJson(url)");
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
    int preventDefaultIndex = script.indexOf("event.preventDefault();", actionLookupIndex);
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
                + " clearWizardBandwidthChoiceRequirement);"));
    assertTrue(
        script.contains(
            "wizardControls.uploadLimit.addEventListener(\"input\","
                + " clearWizardBandwidthChoiceRequirement);"));
    assertTrue(
        script.contains(
            "wizardControls.monthlyLimit.addEventListener(\"input\","
                + " clearWizardBandwidthChoiceRequirement);"));
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
