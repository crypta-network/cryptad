package network.crypta.support;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // test method naming: method_whenCondition_expectOutcome
class HTMLNodeTest {

  // Common fixtures
  private static final String NON_EMPTY = "sampleNode";
  private static final String EMPTY_TAG = "area"; // listed in EmptyTag
  private static final String ATTR_NAME = "sampleAttributeName";
  private static final String ATTR_VALUE = "sampleAttributεValue";
  private static final String CONTENT = "sampleNodeCοntent";

  private HTMLNode node;

  @BeforeEach
  void setup() {
    // Arrange
    node = new HTMLNode(NON_EMPTY);
  }

  // ---------- Constructors & validation ----------

  @ParameterizedTest
  @ValueSource(strings = {"div", "DIV", "x123", "αβ"})
  void constructor_whenValidName_expectLowercasedAndNoException(String name) {
    // Act
    HTMLNode n = new HTMLNode(name);
    // Assert: generated string starts with lower-cased name
    String out = n.generate();
    assertTrue(out.startsWith("<" + name.toLowerCase(java.util.Locale.ENGLISH)));
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "1bad", "bad name", "s\u03a2mpleNode"})
  void constructor_whenInvalidName_expectIllegalArgumentException(String name) {
    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> new HTMLNode(name));
  }

  @Test
  void constructor_whenAttributeArraysDifferentLengths_expectIllegalArgumentException() {
    // Arrange
    String[] names = {"a", "b"};
    String[] values = {"1"};
    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> new HTMLNode("div", names, values, null));
  }

  @Test
  void constructor_whenNullAttributeNameInArray_expectIllegalArgumentException() {
    // Arrange
    String[] names = {"a", null};
    String[] values = {"1", "2"};
    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> new HTMLNode("div", names, values, null));
  }

  @Test
  void constructor_whenSingleNullAttributeValue_expectIllegalArgumentException() {
    // Act + Assert
    assertThrows(
        IllegalArgumentException.class, () -> new HTMLNode("div", ATTR_NAME, null, CONTENT));
  }

  @Test
  void constructor_whenAttributesArray_expectAllAttributesPresent() {
    // Arrange
    int size = 20;
    String[] names = new String[size];
    String[] values = new String[size];
    for (int i = 0; i < size; i++) {
      names[i] = "n" + i;
      values[i] = "v" + i;
    }
    // Act
    HTMLNode n = new HTMLNode(NON_EMPTY, names, values, CONTENT);
    // Assert
    for (int i = 0; i < size; i++) {
      assertEquals(values[i], n.getAttribute(names[i]));
    }
    assertEquals(size, n.getAttributes().size());
  }

  // ---------- Attributes API ----------

  @Test
  void addAttribute_whenDuplicateName_expectSingleEntryWithLastValue() {
    // Arrange
    node.addAttribute(ATTR_NAME, "v1");
    // Act
    node.addAttribute(ATTR_NAME, "v2");
    // Assert
    assertEquals(Map.of(ATTR_NAME, "v2"), node.getAttributes());
  }

  @Test
  void addAttribute_whenNullName_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> node.addAttribute(null, "v"));
  }

  @Test
  void addAttribute_whenNullValue_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> node.addAttribute("x", null));
  }

  @Test
  void getAttributes_whenAttemptToModify_expectUnsupportedOperationException() {
    node.addAttribute("k", "v");
    Map<String, String> unmodifiable = node.getAttributes();
    assertThrows(UnsupportedOperationException.class, () -> unmodifiable.put("a", "b"));
  }

  // ---------- Children API ----------

  @Test
  void addChild_whenSelf_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> node.addChild(node));
  }

  @Test
  void addChild_whenNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> node.addChild((HTMLNode) null));
  }

  @Test
  void addChild_whenDuplicateInstance_expectIllegalArgumentException() {
    HTMLNode child = new HTMLNode("span");
    node.addChild(child);
    assertThrows(IllegalArgumentException.class, () -> node.addChild(child));
  }

  @Test
  void addChildren_whenArrayContainsSelf_expectIllegalArgumentException() {
    HTMLNode[] arr = {new HTMLNode("x"), node, new HTMLNode("y")};
    assertThrows(IllegalArgumentException.class, () -> node.addChildren(arr));
  }

  @Test
  void removeChildren_whenChildrenPresent_expectCleared() {
    node.addChild("span");
    node.addChild("i");
    // Act
    node.removeChildren();
    // Assert
    assertTrue(node.getChildren().isEmpty());
  }

  // ---------- Rendering / generate() ----------

  @Test
  void generate_whenEmptyElement_expectSelfClosing() {
    // Arrange
    HTMLNode n = new HTMLNode(EMPTY_TAG);
    // Act
    String html = n.generate();
    // Assert
    assertEquals("<" + EMPTY_TAG + " />", html);
  }

  @Test
  void generate_whenNonEmptyElementWithContent_expectOpenContentClose() {
    // Arrange
    HTMLNode nodeLocal = new HTMLNode(NON_EMPTY, CONTENT);
    // Act
    String html = nodeLocal.generate();
    // Assert
    String lowered = NON_EMPTY.toLowerCase(java.util.Locale.ENGLISH);
    assertEquals("<" + lowered + ">" + CONTENT + "</" + lowered + ">", html);
  }

  @Test
  void generate_whenAttributeAndContentNeedEscaping_expectEncoded() {
    // Arrange
    HTMLNode n = new HTMLNode("p", "data", "\"fish & chips <ok>\"", "Tom & Jerry <3");
    // Act
    String html = n.generate();
    // Assert (attributes and content encoded via HTMLEncoder). Replace &quot; to make assertion
    // stable.
    assertEquals(
        "<p data=\"quotfish &amp; chips &lt;ok&gt;quot\">Tom &amp; Jerry &lt;3</p>",
        html.replace("&quot;", "quot"));
  }

  @ParameterizedTest
  @CsvSource({"div,true", "form,true", "html,true", "table,true", "ul,true", "span,false"})
  @DisplayName("generate() adds newline/indent around children for container tags")
  void generate_whenContainerTagWithChild_expectNewlinesAndTabs(
      String tag, boolean expectNewlines) {
    // Arrange
    HTMLNode parent = new HTMLNode(tag, ATTR_NAME, ATTR_VALUE, "");
    parent.addChild(new HTMLNode("b", "class", "x", "Y"));
    // Act
    String html = parent.generate();
    // Assert
    if (expectNewlines) {
      // Expect newline after open tag, two tabs of indent for first child, newline before close
      String expectedPrefix = "<" + tag + " " + ATTR_NAME + "=\"" + ATTR_VALUE + "\">\n\t\t";
      String expectedSuffix = "\n\t</" + tag + ">\n\t";
      assertTrue(html.startsWith(expectedPrefix));
      assertTrue(html.endsWith(expectedSuffix));
    } else {
      assertFalse(html.contains("\n"));
    }
  }

  @Test
  void generate_whenTextNodeHash_encodesContentOnly() {
    // Arrange
    HTMLNode text = HTMLNode.text("5 > 3 & \"q\"");
    // Act + Assert
    assertEquals("5 &gt; 3 &amp; quotqquot", text.generate().replace("&quot;", "quot"));
  }

  @Test
  void generate_whenRawPercentNode_appendsRawContent() {
    // Arrange
    HTMLNode raw = new HTMLNode("%", "<b>& not encoded</b>");
    // Act + Assert
    assertEquals("<b>& not encoded</b>", raw.generate());
  }

  @Test
  void generateChildren_whenContentPresent_returnsContentVerbatim() {
    // Arrange: node with inline content stored as child (#) should return content on
    // generateChildren()
    HTMLNode n = new HTMLNode("p", CONTENT);
    // Act + Assert
    assertEquals(CONTENT, n.generateChildren());
  }

  @Test
  void generateChildren_whenOnlyChildrenPresent_rendersChildren() {
    // Arrange
    HTMLNode root = new HTMLNode("div");
    root.addChild("span", "class", "x");
    root.addChild("b", "hi");
    // Act
    String out = root.generateChildren();
    // Assert
    assertEquals("<span class=\"x\"></span><b>hi</b>", out);
  }

  // ---------- Traversal ----------

  @Test
  void getFirstTag_whenRootIsText_returnsFirstRealTag() {
    // Arrange
    HTMLNode root = HTMLNode.text("t");
    root.addChild("div");
    // Act + Assert
    assertEquals("div", root.getFirstTag());
  }

  @Test
  void getFirstTag_whenOnlyTextNodes_returnsNull() {
    // Arrange
    HTMLNode root = HTMLNode.text("hello");
    root.addChild(HTMLNode.text("world"));
    // Act + Assert
    assertNull(root.getFirstTag());
  }

  // ---------- Factories ----------

  @Test
  void link_whenPathProvided_expectHrefAttributeOnly() {
    // Act
    HTMLNode a = HTMLNode.link("/p");
    // Assert
    assertEquals("/p", a.getAttribute("href"));
    assertEquals("<a href=\"/p\"></a>", a.generate());
  }

  @Test
  void linkInNewWindow_whenPathProvided_expectTargetAndRel() {
    // Act
    HTMLNode a = HTMLNode.linkInNewWindow("/x");
    // Assert
    assertEquals("/x", a.getAttribute("href"));
    assertEquals("_blank", a.getAttribute("target"));
    assertEquals("noreferrer noopener", a.getAttribute("rel"));
  }

  @Test
  void textFactories_whenPrimitiveCounts_expectStringifiedContent() {
    assertEquals("5", HTMLNode.text(5).getContent());
    assertEquals("7", HTMLNode.text(7L).getContent());
    assertEquals("3", HTMLNode.text((short) 3).getContent());
  }

  // ---------- Read-only & cloning ----------

  @Test
  void setReadOnly_whenMutating_expectIllegalArgumentException() {
    // Arrange
    HTMLNode ro = new HTMLNode("div").setReadOnly();
    // Assert
    assertThrows(IllegalArgumentException.class, () -> ro.addAttribute("k", "v"));
    assertThrows(IllegalArgumentException.class, () -> ro.addChild("span"));
    HTMLNode b = new HTMLNode("b");
    List<HTMLNode> single = List.of(b);
    assertThrows(IllegalArgumentException.class, () -> ro.addChildren(single));
    assertThrows(IllegalArgumentException.class, () -> ro.setContent("x"));
  }

  @Test
  void clone_whenOriginalReadOnly_expectCloneWritableAndCopiesState() {
    // Arrange
    HTMLNode original = new HTMLNode("div");
    original.addAttribute("k", "v");
    original.addChild(new HTMLNode("span", "class", "c", null));
    original.setReadOnly();

    // Act
    HTMLNode copy = original.copy();

    // Assert: attributes and children copied; clone is writable (readOnly cleared)
    assertEquals("v", copy.getAttribute("k"));
    assertEquals(1, copy.getChildren().size());
    copy.addAttribute("k2", "v2"); // should not throw
    copy.addChild("b"); // should not throw
  }

  // ---------- Name pattern (protected) ----------

  @ParameterizedTest
  @CsvSource({"a,true", "a1,true", "A9,true", "-not,false", "1bad,false", "bad name,false"})
  void checkNamePattern_variousInputs_expectAccordingToSpec(String candidate, boolean expected) {
    // Arrange
    HTMLNode util = new HTMLNode("div");
    // Act + Assert
    assertEquals(expected, util.checkNamePattern(candidate));
  }

  // ---------- Doctype ----------

  @Test
  void doctype_generate_whenSingleChild_expectDocTypeThenHtml() {
    // Arrange
    HTMLNode.HTMLDoctype doc = new HTMLNode.HTMLDoctype("html", "-//W3C//DTD XHTML 1.1//EN");
    doc.addChild("html");
    // Act
    String out = doc.generate();
    // Assert: starts with doctype and then <html></html> on the same builder
    String firstLine = out.split("\n", 2)[0];
    assertEquals("<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\">", firstLine);
    assertTrue(out.contains("</html>"));
  }
}
