package network.crypta.node.useralerts;

import java.util.List;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.StringCallback;
import network.crypta.config.StringOption;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.PeerManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class MeaningfulNodeNameUserAlertTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore clientCore;
  @Mock private PeerManager peerManager;

  @BeforeEach
  void ensureL10nInitialized() {
    // Ensure localization is initialized deterministically
    NodeL10n.getBase();
  }

  @Test
  @DisplayName("getTitle/Text/ShortText_whenCalled_returnsLocalizedStrings")
  void getTitleTextShort_whenCalled_returnsLocalizedStrings() {
    // Arrange (no peer stubs needed for text getters)

    MeaningfulNodeNameUserAlert alert = new MeaningfulNodeNameUserAlert(node);

    // Act + Assert
    assertEquals(
        NodeL10n.getBase().getString("MeaningfulNodeNameUserAlert.noNodeNickTitle"),
        alert.getTitle());
    assertEquals(
        NodeL10n.getBase().getString("MeaningfulNodeNameUserAlert.noNodeNick"), alert.getText());
    assertEquals(
        NodeL10n.getBase().getString("MeaningfulNodeNameUserAlert.noNodeNickShort"),
        alert.getShortText());
  }

  @Test
  @DisplayName("getHTMLText_whenConfigHasNameOption_buildsFormWithExpectedFields")
  void getHTMLText_whenConfigHasNameOption_buildsFormWithExpectedFields() throws Exception {
    // Arrange: real config + option to avoid mocking final Option methods
    PersistentConfig cfg = new PersistentConfig(new SimpleFieldSet(true));
    SubConfig nodeSc = cfg.createSubConfig("node");
    // String option: default value + metadata
    StringOption nameOpt =
        new StringOption(
            nodeSc,
            "name",
            "DefaultName",
            new Option.Meta(0, false, false, "node.name.short", "node.name.long"),
            new StringCallback() {
              private String v = "DefaultName";

              @Override
              public String get() {
                return v;
              }

              @Override
              public void set(String val) {
                v = val;
              }
            });
    nodeSc.register(nameOpt);
    // Set a non-default current value deterministically without invoking callbacks
    nameOpt.setInitialValue("AliceNode");

    // Node wiring: config + client core for form password
    when(node.getConfig()).thenReturn(cfg);
    when(node.services().clientCore()).thenReturn(clientCore);
    when(clientCore.getFormPassword()).thenReturn("formpw");
    // No peer interactions are required by getHTMLText()

    MeaningfulNodeNameUserAlert alert = new MeaningfulNodeNameUserAlert(node);

    // Act
    HTMLNode html = alert.getHTMLText();

    // Assert: root structure and leading explanatory text
    assertNotNull(html);
    assertEquals("div", html.getName());
    List<HTMLNode> rootChildren = html.getChildren();
    assertTrue(rootChildren.size() >= 2, "expect text <div> and <form>");
    HTMLNode textDiv = rootChildren.getFirst();
    assertEquals("div", textDiv.getName());
    assertEquals(
        NodeL10n.getBase().getString("MeaningfulNodeNameUserAlert.noNodeNick"),
        textDiv.getChildren().getFirst().getContent());

    // Find the <form>
    HTMLNode form =
        rootChildren.stream().filter(n -> "form".equals(n.getName())).findFirst().orElseThrow();
    assertEquals("/config/" + nodeSc.getPrefix(), form.getAttribute("action"));
    assertEquals("post", form.getAttribute("method"));

    // Hidden inputs: formPassword and subconfig
    List<HTMLNode> formChildren = form.getChildren();
    HTMLNode hiddenPw =
        formChildren.stream()
            .filter(n -> "input".equals(n.getName()))
            .filter(n -> "hidden".equals(n.getAttribute("type")))
            .filter(n -> "formPassword".equals(n.getAttribute("name")))
            .findFirst()
            .orElseThrow();
    assertEquals("formpw", hiddenPw.getAttribute("value"));

    HTMLNode hiddenSubcfg =
        formChildren.stream()
            .filter(n -> "input".equals(n.getName()))
            .filter(n -> "hidden".equals(n.getAttribute("type")))
            .filter(n -> "subconfig".equals(n.getAttribute("name")))
            .findFirst()
            .orElseThrow();
    assertEquals(nodeSc.getPrefix(), hiddenSubcfg.getAttribute("value"));

    // The editable list item with the option
    HTMLNode ul =
        formChildren.stream().filter(n -> "ul".equals(n.getName())).findFirst().orElseThrow();
    assertEquals("config", ul.getAttribute("class"));
    HTMLNode li =
        ul.getChildren().stream().filter(n -> "li".equals(n.getName())).findFirst().orElseThrow();

    // The title span includes the default tooltip and a small short description node appended
    HTMLNode titleSpan =
        li.getChildren().stream().filter(n -> "span".equals(n.getName())).findFirst().orElseThrow();
    assertEquals("configshortdesc", titleSpan.getAttribute("class"));
    String expectedTooltip =
        NodeL10n.getBase()
            .getString(
                "ConfigToadlet.defaultIs",
                new String[] {"default"},
                new String[] {nameOpt.getDefault()});
    assertEquals(expectedTooltip, titleSpan.getAttribute("title"));
    assertEquals("cursor: help;", titleSpan.getAttribute("style"));

    // The input uses the option metadata and current display value
    HTMLNode input =
        li.getChildren().stream()
            .filter(n -> "input".equals(n.getName()))
            .findFirst()
            .orElseThrow();
    assertEquals("text", input.getAttribute("type"));
    assertEquals("config", input.getAttribute("class"));
    assertEquals("node.name", input.getAttribute("name"));
    assertEquals("node.name.short", input.getAttribute("alt"));
    assertEquals("AliceNode", input.getAttribute("value"));

    // Submit/reset buttons use localized labels
    HTMLNode submit =
        formChildren.stream()
            .filter(n -> "input".equals(n.getName()))
            .filter(n -> "submit".equals(n.getAttribute("type")))
            .findFirst()
            .orElseThrow();
    assertEquals(NodeL10n.getBase().getString("UserAlert.apply"), submit.getAttribute("value"));

    HTMLNode reset =
        formChildren.stream()
            .filter(n -> "input".equals(n.getName()))
            .filter(n -> "reset".equals(n.getAttribute("type")))
            .findFirst()
            .orElseThrow();
    assertEquals(NodeL10n.getBase().getString("UserAlert.reset"), reset.getAttribute("value"));
  }

  @Test
  @DisplayName("isValid_whenPeersPresent_reflectsAnyDarknetPeers")
  void isValid_whenPeersPresent_reflectsAnyDarknetPeers() {
    // Arrange
    when(node.network().peers()).thenReturn(peerManager);

    when(peerManager.anyDarknetPeers()).thenReturn(false);
    assertFalse(new MeaningfulNodeNameUserAlert(node).isValid());

    when(peerManager.anyDarknetPeers()).thenReturn(true);
    assertTrue(new MeaningfulNodeNameUserAlert(node).isValid());
  }

  @Test
  @DisplayName("constructor_whenCreated_configuresDismissalAndPriority")
  void constructor_whenCreated_configuresDismissalAndPriority() {
    // Arrange (no peer interactions here)

    MeaningfulNodeNameUserAlert alert = new MeaningfulNodeNameUserAlert(node);

    // Assert dismissal wiring and severity
    assertTrue(alert.userCanDismiss());
    assertTrue(alert.shouldUnregisterOnDismiss());
    assertEquals(NodeL10n.getBase().getString("UserAlert.hide"), alert.dismissButtonText());
    assertEquals(UserAlert.WARNING, alert.getPriorityClass());
  }
}
