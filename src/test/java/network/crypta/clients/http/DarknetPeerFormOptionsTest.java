package network.crypta.clients.http;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@ResourceLock("NodeL10n.base")
class DarknetPeerFormOptionsTest {

  private static final String ATTR_CHECKED = "checked";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_VALUE = "value";
  private static final String TAG_INPUT = "input";
  private static final String TAG_OPTION = "option";

  @TempDir File tempDir;

  @BeforeEach
  void setUp() {
    new NodeL10n(LANGUAGE.ENGLISH, tempDir);
  }

  @Test
  void addTrustOptions_whenCalled_appendsTrustOptionsInReverseDisplayOrder() {
    HTMLNode selectNode = new HTMLNode("select");

    DarknetPeerFormOptions.addTrustOptions(selectNode);

    assertEquals(List.of("HIGH", "NORMAL", "LOW"), optionValues(selectNode));
  }

  @Test
  void addVisibilityOptions_whenCalled_appendsVisibilityOptionsInDeclarationOrder() {
    HTMLNode selectNode = new HTMLNode("select");

    DarknetPeerFormOptions.addVisibilityOptions(selectNode);

    assertEquals(List.of("YES", "NAME_ONLY", "NO"), optionValues(selectNode));
  }

  @Test
  void addAddPeerInputs_whenCalled_rendersTrustAndVisibilityInputsWithExpectedDefaults() {
    HTMLNode parent = new HTMLNode("div");

    DarknetPeerFormOptions.addAddPeerInputs(parent);

    List<HTMLNode> trustInputs = findInputsByName(parent, "trust");
    assertEquals(List.of("HIGH", "NORMAL", "LOW"), inputValues(trustInputs));
    assertEquals("checked", trustInputs.get(1).getAttribute(ATTR_CHECKED));

    List<HTMLNode> visibilityInputs = findInputsByName(parent, "visibility");
    assertEquals(List.of("YES", "NAME_ONLY", "NO"), inputValues(visibilityInputs));
    assertEquals("checked", visibilityInputs.getFirst().getAttribute(ATTR_CHECKED));

    String html = parent.generate();
    assertTrue(html.contains(l10n("DarknetConnectionsToadlet.peerTrustTitle")));
    assertTrue(html.contains(l10n("DarknetConnectionsToadlet.peerVisibilityTitle")));
  }

  private static List<String> optionValues(HTMLNode selectNode) {
    List<String> values = new ArrayList<>();
    for (HTMLNode child : selectNode.getChildren()) {
      if (TAG_OPTION.equals(child.getName())) {
        values.add(child.getAttribute(ATTR_VALUE));
      }
    }
    return values;
  }

  private static List<HTMLNode> findInputsByName(HTMLNode root, String name) {
    List<HTMLNode> inputs = new ArrayList<>();
    collectInputsByName(root, name, inputs);
    return inputs;
  }

  private static void collectInputsByName(HTMLNode node, String name, List<HTMLNode> inputs) {
    if (TAG_INPUT.equals(node.getName()) && name.equals(node.getAttribute(ATTR_NAME))) {
      inputs.add(node);
    }
    for (HTMLNode child : node.getChildren()) {
      collectInputsByName(child, name, inputs);
    }
  }

  private static List<String> inputValues(List<HTMLNode> inputs) {
    List<String> values = new ArrayList<>(inputs.size());
    for (HTMLNode input : inputs) {
      values.add(input.getAttribute(ATTR_VALUE));
    }
    return values;
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(key);
  }
}
