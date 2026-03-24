package network.crypta.runtime.alerts;

import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;

@SuppressWarnings({"java:S100", "rawtypes", "unchecked"})
@ExtendWith(MockitoExtension.class)
class InvalidAddressOverrideUserAlertTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore clientCore;
  @Mock private PersistentConfig config;
  @Mock private SubConfig nodeSubConfig;
  @Mock private Option<?> ipAddressOverrideOption;

  private InvalidAddressOverrideUserAlert alert;

  @BeforeEach
  void setUp() {
    // Common stubbing for config + client core used by getHTMLText()
    lenient().when(node.services().clientCore()).thenReturn(clientCore);
    lenient().when(clientCore.getFormPassword()).thenReturn("secret-form-pass");

    lenient().when(node.getConfig()).thenReturn(config);
    lenient().when(config.get("node")).thenReturn(nodeSubConfig);
    lenient().when(nodeSubConfig.getPrefix()).thenReturn("node");
    lenient()
        .when(nodeSubConfig.getOption("ipAddressOverride"))
        .thenReturn((Option) ipAddressOverrideOption);

    // Provide deterministic display strings for the option used in the HTML form
    lenient().when(ipAddressOverrideOption.getLocalisedShortDesc()).thenReturn("ShortDesc");
    lenient().when(ipAddressOverrideOption.getLocalisedLongDesc()).thenReturn("LongDesc");
    lenient().when(ipAddressOverrideOption.getValueDisplayString()).thenReturn("DisplayVal");

    alert = new InvalidAddressOverrideUserAlert(node);
  }

  @Test
  void getTitle_whenCalled_returnsLocalizedTitle() {
    String expected =
        NodeL10n.getBase().getString("InvalidAddressOverrideUserAlert.unknownAddressTitle");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  void getText_whenCalled_returnsLocalizedBody() {
    String expected =
        NodeL10n.getBase().getString("InvalidAddressOverrideUserAlert.unknownAddress");
    assertEquals(expected, alert.getText());
  }

  @Test
  void getShortText_whenCalled_returnsLocalizedShortText() {
    String expected =
        NodeL10n.getBase().getString("InvalidAddressOverrideUserAlert.unknownAddressShort");
    assertEquals(expected, alert.getShortText());
  }

  @Test
  void getPriorityClass_whenCalled_isError() {
    assertEquals(UserAlert.ERROR, alert.getPriorityClass());
  }

  @Test
  void getHTMLText_whenCalled_containsConfigLinkFormAndInputs() {
    HTMLNode html = alert.getHTMLText();
    assertNotNull(html, "HTML node should not be null");
    String out = html.generate();

    // Contains a localized intro with a link to /config/node
    assertTrue(out.contains("href=\"/config/node\""), "HTML should contain a config link");

    // Form action + method
    assertTrue(out.contains("<form"), "HTML should contain a form element");
    assertTrue(out.contains("action=\"/config/node\""), "Form should post to /config/node");
    assertTrue(out.contains("method=\"post\""), "Form method should be POST");

    // Hidden inputs: formPassword and subconfig
    assertTrue(
        out.contains("type=\"hidden\"")
            && out.contains("name=\"formPassword\"")
            && out.contains("value=\"secret-form-pass\""),
        "Form should include hidden formPassword with provided value");
    assertTrue(
        out.contains("name=\"subconfig\"") && out.contains("value=\"node\""),
        "Form should include hidden subconfig with the node prefix");

    // Config list structure including option desc, input and long description
    assertTrue(out.contains("<ul class=\"config\">"), "HTML should include a UL with class config");
    assertTrue(out.contains("class=\"configshortdesc\">ShortDesc"));
    assertTrue(
        out.contains("type=\"text\"")
            && out.contains("name=\"node.ipAddressOverride\"")
            && out.contains("value=\"DisplayVal\""),
        "Text input should target node.ipAddressOverride and show display value");
    assertTrue(out.contains("class=\"configlongdesc\">LongDesc"));

    // Submit/reset inputs use localized labels
    String apply = NodeL10n.getBase().getString("UserAlert.apply");
    String reset = NodeL10n.getBase().getString("UserAlert.reset");
    assertTrue(out.contains("type=\"submit\"") && out.contains("value=\"" + apply + "\""));
    assertTrue(out.contains("type=\"reset\"") && out.contains("value=\"" + reset + "\""));
  }
}
