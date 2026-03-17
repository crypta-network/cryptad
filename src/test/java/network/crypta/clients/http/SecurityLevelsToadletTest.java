package network.crypta.clients.http;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.runtime.spi.ConfigPort;
import network.crypta.runtime.spi.SecurityLevelsPort;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SecurityLevelsToadletTest {

  @Test
  void path_whenCalled_returnsSecurityLevelsPath() {
    SecurityLevelsPort securityLevelsPort = mock(SecurityLevelsPort.class);
    ConfigPort configPort = mock(ConfigPort.class);
    SecurityLevelsToadlet toadlet =
        new SecurityLevelsToadlet(
            mock(HighLevelSimpleClient.class),
            new SecurityLevelsToadletRuntimePorts(securityLevelsPort, configPort));

    String result = toadlet.path();

    assertEquals(SecurityLevelsToadlet.PATH, result);
  }

  @Test
  void handleMethodPost_whenNetworkLevelChanges_persistsThroughConfigPort() throws Exception {
    SecurityLevelsPort securityLevelsPort = mock(SecurityLevelsPort.class);
    ConfigPort configPort = mock(ConfigPort.class);
    SecurityLevelsToadlet toadlet =
        new SecurityLevelsToadlet(
            mock(HighLevelSimpleClient.class),
            new SecurityLevelsToadletRuntimePorts(securityLevelsPort, configPort));
    HTTPRequest request = mock(HTTPRequest.class);
    ToadletContext ctx = mock(ToadletContext.class);

    when(ctx.checkFullAccess(toadlet)).thenReturn(true);
    when(request.isPartSet("seclevels")).thenReturn(true);
    when(request.isPartSet("security-levels.networkThreatLevel.confirm")).thenReturn(false);
    when(request.getPartAsStringFailsafe("security-levels.networkThreatLevel", 128))
        .thenReturn("HIGH");
    when(request.getPartAsStringFailsafe("security-levels.physicalThreatLevel", 128))
        .thenReturn("");
    when(securityLevelsPort.snapshot())
        .thenReturn(
            new SecurityLevelsSnapshot(
                SecurityNetworkThreatLevel.NORMAL,
                SecurityPhysicalThreatLevel.NORMAL,
                false,
                false,
                "/tmp/master.keys"));
    when(securityLevelsPort.networkThreatLevelConfirmWarningHtml(
            SecurityNetworkThreatLevel.HIGH, "security-levels.networkThreatLevel.confirm"))
        .thenReturn(null);

    toadlet.handleMethodPOST(URI.create(SecurityLevelsToadlet.PATH), request, ctx);

    verify(securityLevelsPort).setNetworkThreatLevel(SecurityNetworkThreatLevel.HIGH);
    verify(configPort).persist();
    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), any(), eq(null), eq(0L));
  }

  @Test
  void generatePasswordFormPage_whenUpgrade_addsConfirmationAndHiddenFields() {
    HTMLNode content = new HTMLNode("div");
    HTMLNode formNode = content.addChild("form");

    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(false, false, false, true, "HIGH", "/next"), formNode, content);

    assertFalse(findInputsByName(formNode, "masterPassword").isEmpty());
    assertFalse(findInputsByName(formNode, "confirmMasterPassword").isEmpty());
    assertEquals(
        "HIGH",
        findInputsByName(formNode, "security-levels.physicalThreatLevel")
            .getFirst()
            .getAttribute("value"));
    assertEquals("true", findInputsByName(formNode, "seclevels").getFirst().getAttribute("value"));
    assertEquals("/next", findInputsByName(formNode, "redirect").getFirst().getAttribute("value"));
    assertFalse(findSubmitInputs(formNode).isEmpty());
  }

  @Test
  void generatePasswordFormPage_whenDowngradeWithoutUpgrade_usesSinglePasswordField() {
    HTMLNode content = new HTMLNode("div");
    HTMLNode formNode = content.addChild("form");

    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(false, false, true, false, null, null), formNode, content);

    assertEquals(1, findInputsByName(formNode, "masterPassword").size());
    assertTrue(findInputsByName(formNode, "confirmMasterPassword").isEmpty());
    assertTrue(findInputsByName(formNode, "security-levels.physicalThreatLevel").isEmpty());
  }

  @Test
  void generatePasswordFormPage_whenFirstTimeWizard_postsToWizardUrl() {
    ToadletContainer container = mock(ToadletContainer.class);
    HTMLNode content = new HTMLNode("div");
    when(container.addFormChild(any(HTMLNode.class), anyString(), anyString()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              String target = invocation.getArgument(1);
              String id = invocation.getArgument(2);
              HTMLNode form = parent.addChild("form");
              form.addAttribute("target", target);
              form.addAttribute("id", id);
              return form;
            });

    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(false, true, false, false, "LOW", null), container, content);

    verify(container)
        .addFormChild(content, FirstTimeWizardToadlet.TOADLET_URL, "masterPasswordForm");
    HTMLNode form = findByTag(content, "form").getFirst();
    assertEquals(
        "LOW",
        findInputsByName(form, "security-levels.physicalThreatLevel")
            .getFirst()
            .getAttribute("value"));
    assertEquals("true", findInputsByName(form, "seclevels").getFirst().getAttribute("value"));
    assertEquals(FirstTimeWizardToadlet.TOADLET_URL, form.getAttribute("target"));
  }

  @Test
  void sendCantDeleteMasterKeysFileInner_whenCannotDelete_addsHiddenFieldsAndFilename() {
    PageNode pageNode = simplePageNode();
    ToadletContext ctx = contextStub(pageNode);

    HTMLNode outer =
        SecurityLevelsToadlet.sendCantDeleteMasterKeysFileInner(
            ctx, "/tmp/master.keys", false, "HIGH");

    HTMLNode form = findByTag(pageNode.getContentNode(), "form").getFirst();
    assertEquals(
        "HIGH",
        findInputsByName(form, "security-levels.physicalThreatLevel")
            .getFirst()
            .getAttribute("value"));
    assertEquals("true", findInputsByName(form, "seclevels").getFirst().getAttribute("value"));
    assertFalse(findInputsByName(form, "tryAgain").isEmpty());
    assertTrue(outer.generate().contains("/tmp/master.keys"));
  }

  @Test
  void sendPasswordFileCorruptedPageInner_whenCalled_addsFilePathAndBackLink() {
    PageNode pageNode = simplePageNode();
    ToadletContext ctx = contextStub(pageNode);

    SecurityLevelsToadlet.sendPasswordFileCorruptedPageInner(ctx, "/tmp/master.keys");

    HTMLNode content = pageNode.getContentNode();
    assertTrue(
        findByTag(content, "p").stream()
            .anyMatch(node -> node.generateChildren().contains("/tmp/master.keys")));
    assertTrue(
        findByTag(content, "a").stream()
            .anyMatch(node -> SecurityLevelsToadlet.PATH.equals(node.getAttribute("href"))));
  }

  private PageNode simplePageNode() {
    HTMLNode outer = new HTMLNode("html");
    HTMLNode head = outer.addChild("head");
    HTMLNode body = outer.addChild("body");
    return new PageNode(outer, head, body);
  }

  private ToadletContext contextStub(PageNode pageNode) {
    PageMaker pageMaker = mock(PageMaker.class);
    when(pageMaker.getPageNode(anyString(), any(ToadletContext.class))).thenReturn(pageNode);
    when(pageMaker.getInfobox(
            anyString(), anyString(), any(HTMLNode.class), anyString(), anyBoolean()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              return parent.addChild("div");
            });

    ToadletContext ctx = mock(ToadletContext.class);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    lenient()
        .when(ctx.addFormChild(any(HTMLNode.class), anyString(), anyString()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              String target = invocation.getArgument(1);
              String id = invocation.getArgument(2);
              HTMLNode form = parent.addChild("form");
              form.addAttribute("target", target);
              form.addAttribute("id", id);
              return form;
            });
    return ctx;
  }

  private List<HTMLNode> findInputsByName(HTMLNode node, String name) {
    return findByTag(node, "input").stream()
        .filter(n -> name.equals(n.getAttribute("name")))
        .toList();
  }

  private List<HTMLNode> findSubmitInputs(HTMLNode node) {
    return findByTag(node, "input").stream()
        .filter(n -> "submit".equals(n.getAttribute("type")))
        .toList();
  }

  private List<HTMLNode> findByTag(HTMLNode node, String tag) {
    List<HTMLNode> matches = new ArrayList<>();
    collectByTag(node, tag, matches);
    return matches;
  }

  private void collectByTag(HTMLNode node, String tag, List<HTMLNode> matches) {
    if (tag.equals(node.getName())) {
      matches.add(node);
    }
    for (HTMLNode child : node.getChildren()) {
      collectByTag(child, tag, matches);
    }
  }
}
