package network.crypta.clients.http.complexhtmlnodes;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.DarknetPeerNode;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@ResourceLock("NodeL10n.base")
class PeerVisibilityInputForAddPeerBoxNodeTest {

  private static final String TAG_INPUT = "input";
  private static final String ATTR_CHECKED = "checked";

  @TempDir File tempDir;

  @BeforeEach
  void setUp() {
    new NodeL10n(LANGUAGE.ENGLISH, tempDir);
  }

  @Test
  void constructor_whenCreated_expectDivWithTitleIntroAndInputsForEachVisibility() {
    // Arrange
    String title = l10n("DarknetConnectionsToadlet.peerVisibilityTitle");
    String intro = l10n("DarknetConnectionsToadlet.peerVisibilityIntroduction");

    // Act
    PeerVisibilityInputForAddPeerBoxNode node = new PeerVisibilityInputForAddPeerBoxNode();

    // Assert
    List<HTMLNode> children = node.getChildren();
    int expectedChildCount = 3 + DarknetPeerNode.FRIEND_VISIBILITY.values().length + 1;
    assertEquals("div", node.getName());
    assertEquals(expectedChildCount, children.size());

    HTMLNode titleNode = children.get(0);
    HTMLNode spaceNode = children.get(1);
    HTMLNode introNode = children.get(2);

    assertAll(
        () -> assertEquals("b", titleNode.getName()),
        () -> assertTrue(titleNode.generate().contains(title)),
        () -> assertEquals("#", spaceNode.getName()),
        () -> assertEquals(" ", spaceNode.getContent()),
        () -> assertEquals("#", introNode.getName()),
        () -> assertEquals(intro, introNode.getContent()));
  }

  @Test
  void constructor_whenCreated_expectDefaultVisibilityCheckedAndOthersUnchecked() {
    // Arrange
    PeerVisibilityInputForAddPeerBoxNode node = new PeerVisibilityInputForAddPeerBoxNode();

    // Act
    long checkedCount =
        node.getChildren().stream()
            .filter(child -> "br".equals(child.getName()))
            .flatMap(br -> br.getChildren().stream())
            .filter(child -> TAG_INPUT.equals(child.getName()))
            .filter(input -> input.getAttribute(ATTR_CHECKED) != null)
            .count();

    // Assert
    assertEquals(1L, checkedCount, "Exactly one radio input should be checked by default");

    DarknetPeerNode.FRIEND_VISIBILITY defaultVisibility =
        Stream.of(DarknetPeerNode.FRIEND_VISIBILITY.values())
            .filter(DarknetPeerNode.FRIEND_VISIBILITY::isDefaultValue)
            .findFirst()
            .orElseThrow();
    assertTrue(
        node.generate().contains("id=\"visibility" + defaultVisibility.name() + "\""),
        "Generated HTML should contain the default visibility input id");
    assertTrue(
        node.generate().contains("checked=\"checked\""),
        "Generated HTML should contain checked attribute for default visibility");
  }

  static Stream<DarknetPeerNode.FRIEND_VISIBILITY> visibilityValues() {
    return Stream.of(DarknetPeerNode.FRIEND_VISIBILITY.values());
  }

  @ParameterizedTest
  @MethodSource("visibilityValues")
  void constructor_whenCreated_expectRadioInputAndLabelForVisibility(
      DarknetPeerNode.FRIEND_VISIBILITY visibility) {
    // Arrange
    PeerVisibilityInputForAddPeerBoxNode node = new PeerVisibilityInputForAddPeerBoxNode();
    String expectedId = "visibility" + visibility.name();
    String expectedTitleKey = "DarknetConnectionsToadlet.peerVisibility." + visibility.name();
    String expectedExplainKey =
        "DarknetConnectionsToadlet.peerVisibilityExplain." + visibility.name();

    // Act
    HTMLNode input = findInputById(node, expectedId);

    // Assert
    Map<String, String> attrs = input.getAttributes();
    assertAll(
        () -> assertEquals(TAG_INPUT, input.getName()),
        () -> assertNull(input.getContent(), "Input should not have direct content"),
        () -> assertEquals("radio", attrs.get("type")),
        () -> assertEquals("visibility", attrs.get("name")),
        () -> assertEquals(visibility.name(), attrs.get("value")),
        () -> assertEquals(expectedId, attrs.get("id")));

    if (visibility.isDefaultValue()) {
      assertEquals(ATTR_CHECKED, attrs.get(ATTR_CHECKED));
    } else {
      assertNull(attrs.get(ATTR_CHECKED));
    }

    List<HTMLNode> inputChildren = input.getChildren();
    assertFalse(inputChildren.isEmpty(), "Input should contain label and text nodes as children");

    HTMLNode label = inputChildren.getFirst();
    assertEquals("label", label.getName());
    assertEquals(expectedId, label.getAttribute("for"));

    String renderedLabel = label.generate();
    assertTrue(renderedLabel.contains(l10n(expectedTitleKey)));

    HTMLNode separator = inputChildren.get(1);
    assertEquals("#", separator.getName());
    assertEquals(": ", separator.getContent());

    HTMLNode explanation = inputChildren.get(2);
    assertEquals("#", explanation.getName());
    assertEquals(l10n(expectedExplainKey), explanation.getContent());
  }

  @Test
  void generate_whenCalled_expectContainsVisibilityInputsInEnumOrder() {
    // Arrange
    PeerVisibilityInputForAddPeerBoxNode node = new PeerVisibilityInputForAddPeerBoxNode();

    // Act
    String html = node.generate();

    // Assert
    int lastIndex = -1;
    for (DarknetPeerNode.FRIEND_VISIBILITY visibility :
        DarknetPeerNode.FRIEND_VISIBILITY.values()) {
      String marker = "id=\"visibility" + visibility.name() + "\"";
      int index = html.indexOf(marker);
      assertTrue(index > lastIndex, "Expected visibility marker to appear after the previous one");
      lastIndex = index;
    }
  }

  private static HTMLNode findInputById(PeerVisibilityInputForAddPeerBoxNode node, String id) {
    for (HTMLNode child : node.getChildren()) {
      if (!"br".equals(child.getName())) {
        continue;
      }
      for (HTMLNode brChild : child.getChildren()) {
        if (TAG_INPUT.equals(brChild.getName()) && id.equals(brChild.getAttribute("id"))) {
          return brChild;
        }
      }
    }
    throw new AssertionError("Unable to find input with id=" + id);
  }

  private static String l10n(String key) {
    String value = NodeL10n.getBase().getString(key);
    assertNotNull(value, "Localization should return a non-null string for key " + key);
    return value;
  }
}
