package network.crypta.node.useralerts;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import java.util.concurrent.TimeUnit;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeIPDetector;
import network.crypta.node.PeerManager;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings({"java:S100", "rawtypes", "unchecked"})
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IPUndetectedUserAlertTest {

  @Mock private Node node;
  @Mock private NodeIPDetector ipDetector;
  @Mock private PeerManager peers;
  @Mock private NodeClientCore clientCore;
  @Mock private PersistentConfig config;
  @Mock private SubConfig nodeSubConfig;
  @Mock private Option<?> tempIPAddressHintOption;

  @InjectMocks private IPUndetectedUserAlert alert;

  @BeforeEach
  void setUp() {
    // Initialize localization to ensure NodeL10n has a valid base
    new NodeL10n();

    // Common stubs used by multiple tests
    lenient().when(node.getIpDetector()).thenReturn(ipDetector);
    lenient().when(node.getPeers()).thenReturn(peers);
    lenient().when(node.getDarknetPortNumber()).thenReturn(12345);
    lenient().when(node.getOpennetFNPPort()).thenReturn(-1);
    lenient().when(node.isOpennetEnabled()).thenReturn(false);
    lenient().when(peers.countConnectiblePeers()).thenReturn(0);
    lenient().when(node.getUptime()).thenReturn(0L);

    // Config + form for getHTMLText()
    lenient().when(node.getClientCore()).thenReturn(clientCore);
    lenient().when(clientCore.getFormPassword()).thenReturn("secret-form-pass");

    lenient().when(node.getConfig()).thenReturn(config);
    lenient().when(config.get("node")).thenReturn(nodeSubConfig);
    lenient().when(nodeSubConfig.getPrefix()).thenReturn("node");
    lenient()
        .when(nodeSubConfig.getOption("tempIPAddressHint"))
        .thenReturn((Option) tempIPAddressHintOption);

    // Provide deterministic strings for option display in HTML
    lenient().when(tempIPAddressHintOption.getLocalisedShortDesc()).thenReturn("ShortDesc");
    lenient().when(tempIPAddressHintOption.getLocalisedLongDesc()).thenReturn("LongDesc");
    lenient().when(tempIPAddressHintOption.getValueDisplayString()).thenReturn("DisplayVal");
  }

  @Test
  @DisplayName("title_returnsLocalizedTitle")
  void title_returnsLocalizedTitle() {
    String expected = NodeL10n.getBase().getString("IPUndetectedUserAlert.unknownAddressTitle");
    assertEquals(expected, alert.getTitle());
  }

  @Test
  @DisplayName("shortText_whenNoPlugins_returnsNoDetectorPlugins")
  void shortText_whenNoPlugins_returnsNoDetectorPlugins() {
    when(ipDetector.noDetectPlugins()).thenReturn(true);
    String expected = NodeL10n.getBase().getString("IPUndetectedUserAlert.noDetectorPlugins");
    assertEquals(expected, alert.getShortText());
  }

  @Test
  @DisplayName("shortText_whenDetecting_returnsDetectingShort")
  void shortText_whenDetecting_returnsDetectingShort() {
    when(ipDetector.noDetectPlugins()).thenReturn(false);
    when(ipDetector.isDetecting()).thenReturn(true);
    String expected = NodeL10n.getBase().getString("IPUndetectedUserAlert.detectingShort");
    assertEquals(expected, alert.getShortText());
  }

  @Test
  @DisplayName("shortText_whenNotDetecting_returnsUnknownAddressShort")
  void shortText_whenNotDetecting_returnsUnknownAddressShort() {
    when(ipDetector.noDetectPlugins()).thenReturn(false);
    when(ipDetector.isDetecting()).thenReturn(false);
    String expected = NodeL10n.getBase().getString("IPUndetectedUserAlert.unknownAddressShort");
    assertEquals(expected, alert.getShortText());
  }

  @Test
  @DisplayName("text_whenNoPlugins_returnsNoDetectorPlugins")
  void text_whenNoPlugins_returnsNoDetectorPlugins() {
    when(ipDetector.noDetectPlugins()).thenReturn(true);
    String expected = NodeL10n.getBase().getString("IPUndetectedUserAlert.noDetectorPlugins");
    assertEquals(expected, alert.getText());
  }

  @Test
  @DisplayName("text_whenDetecting_returnsDetecting")
  void text_whenDetecting_returnsDetecting() {
    when(ipDetector.noDetectPlugins()).thenReturn(false);
    when(ipDetector.isDetecting()).thenReturn(true);
    String expected = NodeL10n.getBase().getString("IPUndetectedUserAlert.detecting");
    assertEquals(expected, alert.getText());
  }

  @Test
  @DisplayName("text_whenUnknownAndSinglePort_includesPortForwardSuggestion")
  void text_whenUnknownAndSinglePort_includesPortForwardSuggestion() {
    when(ipDetector.noDetectPlugins()).thenReturn(false);
    when(ipDetector.isDetecting()).thenReturn(false);
    when(node.getDarknetPortNumber()).thenReturn(7777);
    when(node.getOpennetFNPPort()).thenReturn(-1);

    String unknown =
        NodeL10n.getBase()
            .getString("IPUndetectedUserAlert.unknownAddress", "port", Integer.toString(7777));
    String suggest =
        NodeL10n.getBase()
            .getString("IPUndetectedUserAlert.suggestForwardPort", "port", Integer.toString(7777));

    String expected = unknown + ' ' + suggest;
    assertEquals(expected, alert.getText());
  }

  @Test
  @DisplayName("text_whenUnknownAndTwoPorts_includesTwoPortSuggestionWithSpacing")
  void text_whenUnknownAndTwoPorts_includesTwoPortSuggestionWithSpacing() {
    when(ipDetector.noDetectPlugins()).thenReturn(false);
    when(ipDetector.isDetecting()).thenReturn(false);
    when(node.getDarknetPortNumber()).thenReturn(7000);
    when(node.getOpennetFNPPort()).thenReturn(8000);

    String unknown =
        NodeL10n.getBase()
            .getString("IPUndetectedUserAlert.unknownAddress", "port", Integer.toString(7000));
    String suggestTwo =
        NodeL10n.getBase()
            .getString(
                "IPUndetectedUserAlert.suggestForwardTwoPorts",
                new String[] {"port1", "port2"},
                new String[] {"7000", "8000"});

    // textPortForwardSuggestion() adds a leading space when two ports; getText() adds another space
    String expected = unknown + "  " + suggestTwo;
    assertEquals(expected, alert.getText());
  }

  @Test
  @DisplayName("priority_whenDetecting_warningElse_error")
  void priority_whenDetecting_warningElse_error() {
    when(ipDetector.isDetecting()).thenReturn(true);
    assertEquals(UserAlert.WARNING, alert.getPriorityClass());

    when(ipDetector.isDetecting()).thenReturn(false);
    assertEquals(UserAlert.ERROR, alert.getPriorityClass());
  }

  @Test
  @DisplayName("isValid_variousCombinations_followContract")
  void isValid_variousCombinations_followContract() {
    // Opennet enabled -> invalid regardless of peers/uptime/detection
    when(node.isOpennetEnabled()).thenReturn(true);
    assertFalse(alert.isValid());

    // Few peers -> valid
    when(node.isOpennetEnabled()).thenReturn(false);
    when(peers.countConnectiblePeers()).thenReturn(3);
    assertTrue(alert.isValid());

    // Enough peers, short uptime, still detecting -> invalid
    when(peers.countConnectiblePeers()).thenReturn(8);
    when(node.getUptime()).thenReturn(TimeUnit.SECONDS.toMillis(30));
    when(ipDetector.isDetecting()).thenReturn(true);
    assertFalse(alert.isValid());

    // Enough peers, long uptime, not detecting -> valid
    when(node.getUptime()).thenReturn(TimeUnit.MINUTES.toMillis(2));
    when(ipDetector.isDetecting()).thenReturn(false);
    assertTrue(alert.isValid());
  }

  @Test
  @DisplayName("htmlText_commonStructure_containsConfigLinkFormAndOptionFields")
  void htmlText_commonStructure_containsConfigLinkFormAndOptionFields() {
    when(ipDetector.isDetecting()).thenReturn(false);
    when(ipDetector.noDetectPlugins()).thenReturn(false);
    when(ipDetector.hasJSTUN()).thenReturn(true);
    when(peers.getDarknetPeers()).thenReturn(new network.crypta.node.DarknetPeerNode[1]);

    HTMLNode html = alert.getHTMLText();
    assertNotNull(html);
    String out = html.generate();

    // Intro with config link
    assertTrue(out.contains("href=\"/config/node\""), "Should link to /config/node");

    // If we have peers, we include a note that it may be detectable from peers
    String peersMsg =
        NodeL10n.getBase()
            .getString("IPUndetectedUserAlert.noIPMaybeFromPeers", "number", Integer.toString(1));
    assertTrue(out.contains(peersMsg), "Should include peers-based detection hint");

    // Port forward suggestion (single port by default setUp)
    String suggest =
        NodeL10n.getBase()
            .getString("IPUndetectedUserAlert.suggestForwardPort", "port", Integer.toString(12345));
    assertTrue(out.contains(suggest), "Should include port-forward suggestion");

    // Form action + method
    assertTrue(out.contains("<form"), "Should contain a form");
    assertTrue(out.contains("action=\"/config/node\""), "Form should post to /config/node");
    assertTrue(out.contains("method=\"post\""), "Form method should be POST");

    // Hidden inputs
    assertTrue(
        out.contains("type=\"hidden\"")
            && out.contains("name=\"formPassword\"")
            && out.contains("value=\"secret-form-pass\""),
        "Should include hidden formPassword");
    assertTrue(
        out.contains("name=\"subconfig\"") && out.contains("value=\"node\""),
        "Should include hidden subconfig");

    // Option list and fields
    assertTrue(out.contains("<ul class=\"config\">"), "Should include config UL");
    assertTrue(out.contains("class=\"configshortdesc\">ShortDesc"));
    assertTrue(
        out.contains("type=\"text\"")
            && out.contains("name=\"node.tempIPAddressHint\"")
            && out.contains("value=\"DisplayVal\""),
        "Should include text input for node.tempIPAddressHint");
    assertTrue(out.contains("class=\"configlongdesc\">LongDesc"));

    // Submit/reset button labels from l10n
    String apply = NodeL10n.getBase().getString("UserAlert.apply");
    String reset = NodeL10n.getBase().getString("UserAlert.reset");
    assertTrue(out.contains("type=\"submit\"") && out.contains("value=\"" + apply + "\""));
    assertTrue(out.contains("type=\"reset\"") && out.contains("value=\"" + reset + "\""));
  }

  @Test
  @DisplayName("htmlText_whenNoPlugins_includesLoadDetectPluginsMessageAndLinks")
  void htmlText_whenNoPlugins_includesLoadDetectPluginsMessageAndLinks() {
    when(ipDetector.noDetectPlugins()).thenReturn(true);
    when(ipDetector.isDetecting()).thenReturn(false);
    when(peers.getDarknetPeers()).thenReturn(new network.crypta.node.DarknetPeerNode[0]);

    String out = alert.getHTMLText().generate();
    // Verify links for plugins and config are present; message is rendered via substitutions
    assertTrue(out.contains("href=\"/plugins/\""));
    assertTrue(out.contains("href=\"/config/node\""));
  }

  @Test
  @DisplayName("htmlText_whenMissingJSTUNAndNotDetecting_includesLoadJSTUNMessage")
  void htmlText_whenMissingJSTUNAndNotDetecting_includesLoadJSTUNMessage() {
    when(ipDetector.noDetectPlugins()).thenReturn(false);
    when(ipDetector.isDetecting()).thenReturn(false);
    when(ipDetector.hasJSTUN()).thenReturn(false);
    when(peers.getDarknetPeers()).thenReturn(new network.crypta.node.DarknetPeerNode[0]);

    String out = alert.getHTMLText().generate();
    // Ensure the plugins link is present for loading JSTUN
    assertTrue(out.contains("href=\"/plugins/\""));
  }
}
