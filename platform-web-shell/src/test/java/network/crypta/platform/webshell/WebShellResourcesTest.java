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
    assertTrue(html.contains("__BOOTSTRAP_JSON__"));
    assertTrue(html.contains("peer-create-form\" hidden"));
    assertTrue(html.contains("name=\"referenceText\""));
    assertTrue(html.contains("id=\"peers-status\""));
    assertTrue(html.contains("name=\"filterData\" type=\"checkbox\" checked"));
    assertTrue(html.contains("queue-create-form\" hidden"));
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
  }

  private static void assertQueueMutationMarkersPresent(String script) {
    assertTrue(script.contains("function queuePriorityFieldName(submitterName)"));
    assertTrue(script.contains("case \"change_priority_top\":"));
    assertTrue(script.contains("case \"change_priority_bottom\":"));
    assertTrue(script.contains("let queueLoadGeneration = 0;"));
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
    int countReadOnlyStripIndex = script.indexOf("stripReadOnlyQueueForms(countNode);");
    int contentReadOnlyStripIndex = script.indexOf("stripReadOnlyQueueForms(contentNode);");
    int buildMutationFormDataIndex =
        script.indexOf("function buildQueueMutationFormData(form, submitter, path)");
    int filteredMutationFormDataIndex =
        script.indexOf("const formData = buildQueueMutationFormData(form, submitter, path);");
    int refreshFormPasswordIndex = script.indexOf("async function refreshFormPassword()");
    int postRefreshIndex =
        script.indexOf("const currentFormPassword = await refreshFormPassword();");

    assertTrue(stripReadOnlyFormsIndex >= 0);
    assertTrue(countReadOnlyStripIndex > stripReadOnlyFormsIndex);
    assertTrue(contentReadOnlyStripIndex > stripReadOnlyFormsIndex);
    assertTrue(buildMutationFormDataIndex >= 0);
    assertTrue(filteredMutationFormDataIndex > buildMutationFormDataIndex);
    assertTrue(refreshFormPasswordIndex >= 0);
    assertTrue(postRefreshIndex > refreshFormPasswordIndex);
  }

  private static void assertPeerMutationMarkersPresent(String script) {
    assertTrue(script.contains("let peerLoadGeneration = 0;"));
    assertTrue(script.contains("function updatePeerToolbar()"));
    assertTrue(script.contains("async function submitPeerCreate(event)"));
    assertTrue(script.contains("async function submitPeerMutation(form, action)"));
    assertTrue(script.contains("async function loadPeersSection()"));
    assertTrue(script.contains("loadJson(apiUrl(\"peers/roster\"))"));
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
}
