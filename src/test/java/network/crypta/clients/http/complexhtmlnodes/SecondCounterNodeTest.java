package network.crypta.clients.http.complexhtmlnodes;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import network.crypta.support.HTMLNode;
import network.crypta.support.TimeUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SecondCounterNodeTest {

  private static final String TAG_INPUT = "input";
  private static final String TAG_SPAN = "span";
  private static final String TAG_TEXT = "#";

  private static final String ATTR_CLASS = "class";
  private static final String ATTR_TYPE = "type";
  private static final String ATTR_VALUE = "value";

  private static final String INPUT_TYPE_HIDDEN = "hidden";

  @Test
  void constructor_whenAscendingAndTextWithoutPlaceholder_createsIncrementingCounterStructure() {
    // Arrange
    long initialValue = 65_000L;
    String text = "Elapsed: ";

    // Act
    SecondCounterNode node = new SecondCounterNode(initialValue, true, text);

    // Assert
    assertEquals(TAG_SPAN, node.getName());
    assertEquals(1, node.getAttributes().size());
    assertEquals("needsIncrement", node.getAttribute(ATTR_CLASS));

    List<HTMLNode> children = node.getChildren();
    assertEquals(3, children.size());

    assertHiddenInput(children.getFirst(), initialValue);
    assertSpanWithText(children.get(1), text);
    assertSpanWithText(children.get(2), TimeUtil.formatTime(initialValue));
  }

  @ParameterizedTest
  @CsvSource({
    "true, needsIncrement",
    "false, needsDecrement",
  })
  void constructor_whenAscendingFlagProvided_setsCssClass(boolean ascending, String expectedClass) {
    // Arrange
    long initialValue = 1_000L;
    String text = "t";

    // Act
    SecondCounterNode node = new SecondCounterNode(initialValue, ascending, text);

    // Assert
    assertEquals(TAG_SPAN, node.getName());
    assertEquals(expectedClass, node.getAttribute(ATTR_CLASS));
  }

  @Test
  void constructor_whenTextContainsPlaceholder_splitsAroundFirstOccurrence() {
    // Arrange
    long initialValue = 5_000L;
    String text = "Time left: {0} remaining";

    // Act
    SecondCounterNode node = new SecondCounterNode(initialValue, false, text);

    // Assert
    List<HTMLNode> children = node.getChildren();
    assertEquals(4, children.size());

    assertHiddenInput(children.getFirst(), initialValue);
    assertSpanWithText(children.get(1), "Time left: ");
    assertSpanWithText(children.get(2), TimeUtil.formatTime(initialValue));
    assertSpanWithText(children.get(3), " remaining");
  }

  @Test
  void constructor_whenPlaceholderAtStart_createsEmptyPrefixSpan() {
    // Arrange
    long initialValue = 1_234L;
    String text = "{0} elapsed";

    // Act
    SecondCounterNode node = new SecondCounterNode(initialValue, true, text);

    // Assert
    List<HTMLNode> children = node.getChildren();
    assertEquals(4, children.size());

    assertHiddenInput(children.getFirst(), initialValue);
    assertSpanWithText(children.get(1), "");
    assertSpanWithText(children.get(2), TimeUtil.formatTime(initialValue));
    assertSpanWithText(children.get(3), " elapsed");
  }

  @Test
  void constructor_whenPlaceholderAtEnd_createsEmptySuffixSpan() {
    // Arrange
    long initialValue = 12_000L;
    String text = "Elapsed {0}";

    // Act
    SecondCounterNode node = new SecondCounterNode(initialValue, true, text);

    // Assert
    List<HTMLNode> children = node.getChildren();
    assertEquals(4, children.size());

    assertHiddenInput(children.getFirst(), initialValue);
    assertSpanWithText(children.get(1), "Elapsed ");
    assertSpanWithText(children.get(2), TimeUtil.formatTime(initialValue));
    assertSpanWithText(children.get(3), "");
  }

  @Test
  void constructor_whenMultiplePlaceholders_replacesOnlyFirstOccurrence() {
    // Arrange
    long initialValue = 15_000L;
    String text = "A{0}B{0}C";

    // Act
    SecondCounterNode node = new SecondCounterNode(initialValue, false, text);

    // Assert
    List<HTMLNode> children = node.getChildren();
    assertEquals(4, children.size());

    assertHiddenInput(children.getFirst(), initialValue);
    assertSpanWithText(children.get(1), "A");
    assertSpanWithText(children.get(2), TimeUtil.formatTime(initialValue));
    assertSpanWithText(children.get(3), "B{0}C");
  }

  @Test
  void constructor_whenTextNull_throwsNullPointerException() {
    // Arrange
    long initialValue = 0L;

    // Act + Assert
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> new SecondCounterNode(initialValue, true, null));
  }

  @ParameterizedTest
  @MethodSource("initialValues")
  void constructor_whenCalled_setsHiddenInputAndFormattedTime(long initialValue) {
    // Arrange
    String text = "Elapsed: ";

    // Act
    SecondCounterNode node = new SecondCounterNode(initialValue, true, text);

    // Assert
    List<HTMLNode> children = node.getChildren();
    assertEquals(3, children.size());

    HTMLNode input = children.getFirst();
    assertHiddenInput(input, initialValue);

    HTMLNode formattedTimeSpan = children.get(2);
    assertSpanWithText(formattedTimeSpan, TimeUtil.formatTime(initialValue));
  }

  static Stream<Arguments> initialValues() {
    return Stream.of(
        Arguments.of(0L),
        Arguments.of(999L),
        Arguments.of(1_000L),
        Arguments.of(65_000L),
        Arguments.of(-1L),
        Arguments.of(Long.MIN_VALUE));
  }

  private static void assertHiddenInput(HTMLNode node, long expectedValue) {
    assertNotNull(node);
    assertEquals(TAG_INPUT, node.getName());

    Map<String, String> attributes = node.getAttributes();
    assertEquals(2, attributes.size());
    assertEquals(INPUT_TYPE_HIDDEN, node.getAttribute(ATTR_TYPE));
    assertEquals(String.valueOf(expectedValue), node.getAttribute(ATTR_VALUE));

    assertEquals(0, node.getChildren().size());
  }

  private static void assertSpanWithText(HTMLNode node, String expectedText) {
    assertNotNull(node);
    assertEquals(TAG_SPAN, node.getName());

    List<HTMLNode> children = node.getChildren();
    assertEquals(1, children.size());
    assertTextNode(children.getFirst(), expectedText);
  }

  private static void assertTextNode(HTMLNode node, String expectedText) {
    assertNotNull(node);
    assertEquals(TAG_TEXT, node.getName());
    assertEquals(expectedText, node.getContent());
    assertEquals(0, node.getChildren().size());
  }
}
