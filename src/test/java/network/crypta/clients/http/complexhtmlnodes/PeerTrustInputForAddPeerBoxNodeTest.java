package network.crypta.clients.http.complexhtmlnodes;

import java.io.File;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerTrustInputForAddPeerBoxNodeTest {

  private static final String TAG_BOLD = "b";
  private static final String TAG_BR = "br";
  private static final String TAG_INPUT = "input";
  private static final String TAG_LABEL = "label";
  private static final String TAG_TEXT = "#";

  private static final String ATTR_CHECKED = "checked";
  private static final String ATTR_FOR = "for";
  private static final String ATTR_ID = "id";
  private static final String ATTR_NAME = "name";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_VALUE = "value";

  private static final String INPUT_NAME_TRUST = "trust";
  private static final String INPUT_TYPE_RADIO = "radio";
  private static final String TRUST_ID_PREFIX = "trust";

  @TempDir File tempDir;

  @BeforeEach
  void setUpL10n() {
    // Make localization deterministic regardless of the machine running the tests.
    new NodeL10n(BaseL10n.LANGUAGE.ENGLISH, tempDir);
  }

  @Test
  void constructor_whenCalled_createsDivWithLocalizedTitleAndIntroduction() {
    // Arrange
    String expectedTitle = NodeL10n.getBase().getString("DarknetConnectionsToadlet.peerTrustTitle");
    String expectedIntro =
        NodeL10n.getBase().getString("DarknetConnectionsToadlet.peerTrustIntroduction");

    // Act
    PeerTrustInputForAddPeerBoxNode node = new PeerTrustInputForAddPeerBoxNode();

    // Assert
    assertEquals("div", node.getName());
    List<HTMLNode> children = node.getChildren();

    assertEquals(TAG_BOLD, children.get(0).getName());
    assertTextNode(children.get(0).getChildren().getFirst(), expectedTitle);

    assertTextNode(children.get(1), " ");
    assertTextNode(children.get(2), expectedIntro);
  }

  @Test
  void constructor_whenCalled_createsInputsForAllTrustValuesInReverseOrder() {
    // Arrange
    DarknetPeerNode.FRIEND_TRUST[] expectedOrder = DarknetPeerNode.FRIEND_TRUST.valuesBackwards();

    // Act
    PeerTrustInputForAddPeerBoxNode node = new PeerTrustInputForAddPeerBoxNode();

    // Assert
    List<HTMLNode> brNodes = brChildren(node);
    assertEquals(expectedOrder.length + 1, brNodes.size(), "Expected one extra trailing <br />.");

    HTMLNode trailingBr = brNodes.getLast();
    assertEquals(0, trailingBr.getChildren().size());

    List<HTMLNode> inputNodesInOrder = inputNodesFromBrNodes(brNodes);
    assertEquals(expectedOrder.length, inputNodesInOrder.size());

    for (int i = 0; i < expectedOrder.length; i++) {
      HTMLNode input = inputNodesInOrder.get(i);
      assertEquals(TAG_INPUT, input.getName());
      assertEquals(expectedOrder[i].name(), input.getAttribute(ATTR_VALUE));
    }
  }

  @ParameterizedTest
  @MethodSource("trustAndDefaultFlag")
  void constructor_whenTrustDefault_setsCheckedAttributeOnlyForDefault(
      DarknetPeerNode.FRIEND_TRUST trust, boolean expectedChecked) {
    // Arrange
    PeerTrustInputForAddPeerBoxNode node = new PeerTrustInputForAddPeerBoxNode();
    Map<DarknetPeerNode.FRIEND_TRUST, HTMLNode> inputsByTrust = inputsByTrust(node);

    // Act
    HTMLNode input = inputsByTrust.get(trust);

    // Assert
    assertNotNull(input, "Expected an input for trust=" + trust.name());
    if (expectedChecked) {
      assertEquals(ATTR_CHECKED, input.getAttribute(ATTR_CHECKED));
    } else {
      assertNull(input.getAttribute(ATTR_CHECKED));
    }
  }

  static Stream<Arguments> trustAndDefaultFlag() {
    return Stream.of(DarknetPeerNode.FRIEND_TRUST.values())
        .map(trust -> Arguments.of(trust, trust.isDefaultValue()));
  }

  @Test
  void constructor_whenCalled_setsInputAndLabelAttributesAndLocalizedText() {
    // Arrange
    PeerTrustInputForAddPeerBoxNode node = new PeerTrustInputForAddPeerBoxNode();
    DarknetPeerNode.FRIEND_TRUST[] trusts = DarknetPeerNode.FRIEND_TRUST.valuesBackwards();
    List<HTMLNode> inputNodesInOrder = inputNodesFromBrNodes(brChildren(node));

    // Act + Assert
    for (int i = 0; i < trusts.length; i++) {
      DarknetPeerNode.FRIEND_TRUST trust = trusts[i];
      HTMLNode input = inputNodesInOrder.get(i);

      assertEquals(INPUT_TYPE_RADIO, input.getAttribute(ATTR_TYPE));
      assertEquals(INPUT_NAME_TRUST, input.getAttribute(ATTR_NAME));
      assertEquals(trust.name(), input.getAttribute(ATTR_VALUE));
      assertEquals(TRUST_ID_PREFIX + trust.name(), input.getAttribute(ATTR_ID));

      List<HTMLNode> inputChildren = input.getChildren();
      assertEquals(3, inputChildren.size());

      HTMLNode label = inputChildren.getFirst();
      assertEquals(TAG_LABEL, label.getName());
      assertEquals(TRUST_ID_PREFIX + trust.name(), label.getAttribute(ATTR_FOR));
      assertEquals(1, label.getChildren().size());

      HTMLNode labelBold = label.getChildren().getFirst();
      assertEquals(TAG_BOLD, labelBold.getName());
      assertEquals(1, labelBold.getChildren().size());
      assertTextNode(
          labelBold.getChildren().getFirst(),
          NodeL10n.getBase().getString("DarknetConnectionsToadlet.peerTrust." + trust.name()));

      assertTextNode(inputChildren.get(1), ": ");
      assertTextNode(
          inputChildren.get(2),
          NodeL10n.getBase()
              .getString("DarknetConnectionsToadlet.peerTrustExplain." + trust.name()));
    }
  }

  @Test
  void constructor_whenLocalizationFails_propagatesException() {
    // Arrange
    BaseL10n original = NodeL10n.getBase();
    BaseL10n throwing = mock(BaseL10n.class);
    when(throwing.getString(anyString())).thenThrow(new IllegalStateException("boom"));

    // Act + Assert
    setNodeL10nBase(throwing);
    try {
      assertThrows(IllegalStateException.class, PeerTrustInputForAddPeerBoxNode::new);
    } finally {
      setNodeL10nBase(original);
    }
  }

  @SuppressWarnings("java:S3011")
  private static void setNodeL10nBase(BaseL10n base) {
    try {
      Field baseField = NodeL10n.class.getDeclaredField("b");
      baseField.setAccessible(true);
      baseField.set(null, base);
    } catch (ReflectiveOperationException e) {
      throw linkageError("Failed to set NodeL10n base via reflection", e);
    }
  }

  private static LinkageError linkageError(String message, ReflectiveOperationException e) {
    LinkageError error = new LinkageError(message);
    error.initCause(e);
    return error;
  }

  private static List<HTMLNode> brChildren(HTMLNode node) {
    List<HTMLNode> matches = new ArrayList<>();
    for (HTMLNode child : node.getChildren()) {
      if (TAG_BR.equals(child.getName())) {
        matches.add(child);
      }
    }
    return matches;
  }

  private static List<HTMLNode> inputNodesFromBrNodes(List<HTMLNode> brNodes) {
    List<HTMLNode> inputs = new ArrayList<>();
    for (HTMLNode br : brNodes) {
      if (br.getChildren().isEmpty()) {
        continue;
      }
      inputs.add(br.getChildren().getFirst());
    }
    return inputs;
  }

  private static Map<DarknetPeerNode.FRIEND_TRUST, HTMLNode> inputsByTrust(
      PeerTrustInputForAddPeerBoxNode node) {
    EnumMap<DarknetPeerNode.FRIEND_TRUST, HTMLNode> result =
        new EnumMap<>(DarknetPeerNode.FRIEND_TRUST.class);
    for (HTMLNode input : inputNodesFromBrNodes(brChildren(node))) {
      String value = input.getAttribute(ATTR_VALUE);
      if (value == null) {
        continue;
      }
      result.put(DarknetPeerNode.FRIEND_TRUST.valueOf(value), input);
    }
    return result;
  }

  private static void assertTextNode(HTMLNode node, String expectedContent) {
    assertEquals(TAG_TEXT, node.getName());
    assertEquals(expectedContent, node.getContent());
  }
}
