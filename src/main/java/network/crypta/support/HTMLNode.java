package network.crypta.support;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Lightweight, mutable HTML node builder and renderer.
 *
 * <p>This class models a minimal tree of HTML elements and text. It supports attributes, nested
 * children, and HTML generation with optional indentation. Content is encoded with {@link
 * HTMLEncoder} unless the node uses the raw-content sentinel name {@code "%"}.
 *
 * <p>Special node names:
 *
 * <ul>
 *   <li>{@code "#"} — text node: {@code content} is encoded and emitted without a tag.
 *   <li>{@code "%"} — raw HTML node: {@code content} is appended without encoding.
 * </ul>
 *
 * <p>Thread-safety: Instances are not thread-safe.
 */
public class HTMLNode {

  private static final Pattern namePattern =
      Pattern.compile("^[" + XMLCharacterClasses.NAME + "]*$");
  private static final Pattern simpleNamePattern = Pattern.compile("^[A-Za-z][A-Za-z0-9]*$");

  /** Shared, read-only {@code <strong>} element convenience instance. Do not mutate. */
  public static final HTMLNode STRONG = new HTMLNode("strong").setReadOnly();

  /** Element/tag name in lower case (or {@code "#"}/{@code "%"} sentinels). */
  protected final String tagName;

  private boolean readOnly;

  /**
   * Marks this node as read-only; further mutating calls will throw {@link
   * IllegalArgumentException}.
   *
   * @return this node for chaining
   */
  public HTMLNode setReadOnly() {
    readOnly = true;
    return this;
  }

  /**
   * Text to be inserted between tags, or raw HTML for {@code "%"} nodes.
   *
   * <p>Only non-null when the node name is {@code "#"} (text) or {@code "%"} (raw HTML). For normal
   * elements, non-null content is stored as a separate text child so it is properly encoded during
   * generation.
   */
  private String content;

  /** Attribute map keyed by attribute name; values are unencoded. */
  private final Map<String, String> attributes = new HashMap<>();

  /** Direct children of this node, in insertion order. */
  protected final List<HTMLNode> children = new ArrayList<>();

  /**
   * Creates an element with the given name and no attributes or content.
   *
   * @param name Element name (or special {@code "#"}/{@code "%"})
   * @throws IllegalArgumentException if {@code name} is null or invalid
   */
  public HTMLNode(String name) {
    this(validateConstructionState(name, null, null, null));
  }

  private static final ArrayList<String> EmptyTag = new ArrayList<>(10);
  private static final ArrayList<String> OpenTags = new ArrayList<>(12);
  private static final ArrayList<String> CloseTags = new ArrayList<>(12);

  static {
    /* HTML elements which are allowed to be empty */
    EmptyTag.add("area");
    EmptyTag.add("base");
    EmptyTag.add("br");
    EmptyTag.add("col");
    EmptyTag.add("hr");
    EmptyTag.add("img");
    EmptyTag.add("input");
    EmptyTag.add("link");
    EmptyTag.add("meta");
    EmptyTag.add("param");
    /* HTML elements for which we should add a newline following the open tag. */
    OpenTags.add("body");
    OpenTags.add("div");
    OpenTags.add("form");
    OpenTags.add("head");
    OpenTags.add("html");
    OpenTags.add("input");
    OpenTags.add("ol");
    OpenTags.add("script");
    OpenTags.add("table");
    OpenTags.add("td");
    OpenTags.add("tr");
    OpenTags.add("ul");
    /* HTML elements for which we should add a newline following the close tag. */
    CloseTags.add("h1");
    CloseTags.add("h2");
    CloseTags.add("h3");
    CloseTags.add("h4");
    CloseTags.add("h5");
    CloseTags.add("h6");
    CloseTags.add("li");
    CloseTags.add("link");
    CloseTags.add("meta");
    CloseTags.add("noscript");
    CloseTags.add("option");
    CloseTags.add("title");
  }

  // Returns whether an HTML element is permitted to be empty (self-closing) per XHTML rules.
  private boolean isEmptyElement(String name) {
    return EmptyTag.contains(name);
  }

  // Returns whether to append a newline after the opening tag for readability.
  boolean newlineOpen(String name) {
    return OpenTags.contains(name);
  }

  // Returns whether to append a newline after the closing tag for readability. Tags that request
  // an opening newline also request a closing newline.
  private boolean newlineClose(String name) {
    return (newlineOpen(name) || CloseTags.contains(name));
  }

  // Returns the end of a start tag: either ">" or " />" for empty elements.
  private String openSuffix(String name) {
    if (isEmptyElement(name)) {
      return " />";
    } else {
      return ">";
    }
  }

  // Returns the full closing tag for the element, or an empty string if none is required.
  private String closeTag(String name) {
    if (isEmptyElement(name)) {
      return "";
    } else {
      return "</" + name + ">";
    }
  }

  private String indentString(int indentDepth) {
    StringBuilder indentLine = new StringBuilder();

    for (int indentIndex = 0, indentCount = indentDepth + 1;
        indentIndex < indentCount;
        indentIndex++) {
      indentLine.append('\t');
    }
    return indentLine.toString();
  }

  /**
   * Creates a node with optional content.
   *
   * <p>For normal elements, non-null {@code content} becomes a single text child so it is properly
   * encoded; for {@code "#"}/{@code "%"} the content is stored directly.
   *
   * @param name Element or sentinel name
   * @param content Optional content
   * @throws IllegalArgumentException if {@code name} is invalid
   */
  public HTMLNode(String name, String content) {
    this(validateConstructionState(name, null, null, content));
  }

  /**
   * Creates an element with a single attribute.
   *
   * @param name Element name
   * @param attributeName Attribute key
   * @param attributeValue Attribute value
   * @throws IllegalArgumentException if an argument is invalid
   */
  public HTMLNode(String name, String attributeName, String attributeValue) {
    this(
        validateConstructionState(
            name, new String[] {attributeName}, new String[] {attributeValue}, null));
  }

  /**
   * Creates an element with a single attribute and optional content.
   *
   * @param name Element name
   * @param attributeName Attribute key
   * @param attributeValue Attribute value
   * @param content Optional content
   * @throws IllegalArgumentException if an argument is invalid
   */
  public HTMLNode(String name, String attributeName, String attributeValue, String content) {
    this(
        validateConstructionState(
            name, new String[] {attributeName}, new String[] {attributeValue}, content));
  }

  /**
   * Creates an element with multiple attributes.
   *
   * @param name Element name
   * @param attributeNames Attribute keys
   * @param attributeValues Attribute values; must have the same length as {@code attributeNames}
   * @throws IllegalArgumentException if names/values are invalid or lengths differ
   */
  public HTMLNode(String name, String[] attributeNames, String[] attributeValues) {
    this(validateConstructionState(name, attributeNames, attributeValues, null));
  }

  /**
   * Copy constructor.
   *
   * <p>Performs a shallow copy of attributes and children references and copies {@code content} and
   * {@code tagName}. The new instance's read-only flag is preserved from {@code node} unless {@code
   * clearReadOnly} is {@code true}.
   *
   * @param node Source node
   * @param clearReadOnly If {@code true}, the copy is writable regardless of the source state
   */
  protected HTMLNode(HTMLNode node, boolean clearReadOnly) {
    attributes.putAll(node.attributes);
    children.addAll(node.children);
    content = node.content;
    tagName = node.tagName;
    if (clearReadOnly) readOnly = false;
    else readOnly = node.readOnly;
  }

  /**
   * Returns a writable copy of this node.
   *
   * <p>The copy shares child node references (no deep traversal); use this when you need to mutate
   * a snapshot of the original structure.
   *
   * @return new {@link HTMLNode} instance with copied state
   */
  public HTMLNode copy() {
    return new HTMLNode(this, true);
  }

  /**
   * Validates a candidate name for elements/attributes.
   *
   * <p>Performs a fast-path check for simple ASCII names, otherwise falls back to regular
   * expressions based on {@link XMLCharacterClasses}.
   *
   * @param str Candidate name
   * @return {@code true} if valid; {@code false} otherwise
   */
  protected boolean checkNamePattern(String str) {
    return checkNamePatternStatic(str);
  }

  private static boolean checkNamePatternStatic(String str) {
    if (str.isEmpty()) return false;
    if (isSimpleAsciiName(str)) return true;
    return matchesNamePatterns(str);
  }

  private static boolean isAsciiLetter(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
  }

  private static boolean isAsciiLetterOrDigit(char c) {
    return isAsciiLetter(c) || (c >= '0' && c <= '9');
  }

  private static boolean isSimpleAsciiName(String str) {
    char first = str.charAt(0);
    if (!isAsciiLetter(first)) return false;
    for (int i = 1; i < str.length(); i++) {
      if (!isAsciiLetterOrDigit(str.charAt(i))) return false;
    }
    return true;
  }

  private static boolean matchesNamePatterns(String str) {
    // Regex-based match. Probably more expensive; fallback for non-simple ASCII cases.
    return simpleNamePattern.matcher(str).matches() || namePattern.matcher(str).matches();
  }

  public HTMLNode(String name, String[] attributeNames, String[] attributeValues, String content) {
    this(validateConstructionState(name, attributeNames, attributeValues, content));
  }

  private HTMLNode(ConstructionState state) {
    this.tagName = state.tagName;
    this.attributes.putAll(state.attributes);
    this.content = state.content;
    if (state.textChild != null) {
      this.children.add(state.textChild);
    }
  }

  private static ConstructionState validateConstructionState(
      String name, String[] attributeNames, String[] attributeValues, String content) {
    validateNameOrThrow(name);
    Map<String, String> validatedAttributes =
        validateAndCollectAttributes(attributeNames, attributeValues);
    String lowerTagName = name.toLowerCase(Locale.ENGLISH);
    if (content != null && !"#".equals(name) && !"%".equals(name)) {
      // Encode as a dedicated text child to preserve generation behavior.
      return new ConstructionState(
          lowerTagName, validatedAttributes, null, new HTMLNode("#", content));
    }
    return new ConstructionState(lowerTagName, validatedAttributes, content, null);
  }

  private static void validateNameOrThrow(String name) {
    if ((name == null)
        || (!"#".equals(name) && !"%".equals(name) && !checkNamePatternStatic(name))) {
      throw new IllegalArgumentException("element name is not legal");
    }
  }

  private static Map<String, String> validateAndCollectAttributes(
      String[] attributeNames, String[] attributeValues) {
    Map<String, String> collected = new HashMap<>();
    if ((attributeNames != null) && (attributeValues != null)) {
      if (attributeNames.length != attributeValues.length) {
        throw new IllegalArgumentException("attribute names and values differ in length");
      }
      for (int attributeIndex = 0, attributeCount = attributeNames.length;
          attributeIndex < attributeCount;
          attributeIndex++) {
        String attrName = attributeNames[attributeIndex];
        if ((attrName == null) || !checkNamePatternStatic(attrName)) {
          throw new IllegalArgumentException("attributeName is not legal");
        }
        String attrValue = attributeValues[attributeIndex];
        if (attrValue == null)
          throw new IllegalArgumentException("Cannot add an attribute with a null value");
        collected.put(attrName, attrValue);
      }
    }
    return collected;
  }

  private record ConstructionState(
      String tagName, Map<String, String> attributes, String content, HTMLNode textChild) {}

  /** Returns the node's content, or {@code null} when unset. */
  public String getContent() {
    return content;
  }

  /** Returns the element/tag name including the special {@code "#"} or {@code "%"} sentinels. */
  public String getName() {
    return tagName;
  }

  public void addAttribute(String attributeName, String attributeValue) {
    if (readOnly) throw new IllegalArgumentException("Read only");
    if (attributeName == null)
      throw new IllegalArgumentException("Cannot add an attribute with a null name");
    if (attributeValue == null)
      throw new IllegalArgumentException("Cannot add an attribute with a null value");
    attributes.put(attributeName, attributeValue);
  }

  /** Returns an unmodifiable view of the attributes. */
  public Map<String, String> getAttributes() {
    return Collections.unmodifiableMap(attributes);
  }

  /** Returns the value for {@code attributeName}, or {@code null} if absent. */
  public String getAttribute(String attributeName) {
    return attributes.get(attributeName);
  }

  /**
   * Adds an existing node as a child.
   *
   * @param childNode Node to append (must be non-null and not already present)
   * @return the appended child
   * @throws IllegalArgumentException if this node is read-only, the child equals {@code this}, or
   *     the child is already present
   * @throws NullPointerException if {@code childNode} is {@code null}
   */
  public HTMLNode addChild(HTMLNode childNode) {
    if (readOnly) throw new IllegalArgumentException("Read only");
    if (childNode == null) throw new NullPointerException();
    // since an efficient algorithm to check the loop presence
    // is not present, at least it checks if we are trying to
    // addChild the node itself as a child
    if (childNode == this)
      throw new IllegalArgumentException("A HTMLNode cannot be child of himself");
    if (children.contains(childNode))
      throw new IllegalArgumentException("Cannot add twice the same HTMLNode as child");
    children.add(childNode);
    return childNode;
  }

  /** Adds multiple children from an array, preserving order. */
  public void addChildren(HTMLNode[] childNodes) {
    addChildren(Arrays.asList(childNodes));
  }

  /** Adds multiple children from a list, preserving order. */
  public void addChildren(List<HTMLNode> childNodes) {
    if (readOnly) throw new IllegalArgumentException("Read only");
    for (HTMLNode childNode : childNodes) {
      addChild(childNode);
    }
  }

  /** Adds a new element child with no content or attributes. */
  public HTMLNode addChild(String nodeName) {
    return addChild(nodeName, null);
  }

  /** Adds a new child with optional text content ({@code "#"} for content-only). */
  public HTMLNode addChild(String nodeName, String content) {
    return addChild(nodeName, null, (String[]) null, content);
  }

  /** Adds a new child with a single attribute. */
  public HTMLNode addChild(String nodeName, String attributeName, String attributeValue) {
    return addChild(nodeName, attributeName, attributeValue, null);
  }

  /** Adds a new child with a single attribute and optional content. */
  public HTMLNode addChild(
      String nodeName, String attributeName, String attributeValue, String content) {
    return addChild(nodeName, new String[] {attributeName}, new String[] {attributeValue}, content);
  }

  /** Adds a new child with multiple attributes and no content. */
  public HTMLNode addChild(String nodeName, String[] attributeNames, String[] attributeValues) {
    return addChild(nodeName, attributeNames, attributeValues, null);
  }

  /** Adds a new child with multiple attributes and optional content. */
  public HTMLNode addChild(
      String nodeName, String[] attributeNames, String[] attributeValues, String content) {
    return addChild(new HTMLNode(nodeName, attributeNames, attributeValues, content));
  }

  /** Returns the first element tag name beneath this node, or {@code null} if none exists. */
  public String getFirstTag() {
    if (!"#".equals(tagName)) {
      return tagName;
    }
    for (HTMLNode childNode : children) {
      String tag = childNode.getFirstTag();
      if (tag != null) {
        return tag;
      }
    }
    return null;
  }

  /** Renders this node and its descendants to a new string. */
  public String generate() {
    StringBuilder tagBuffer = new StringBuilder();
    return generate(tagBuffer).toString();
  }

  /** Appends rendered HTML to {@code tagBuffer} with no indentation. */
  public StringBuilder generate(StringBuilder tagBuffer) {
    return generate(tagBuffer, 0);
  }

  /**
   * Appends rendered HTML to {@code tagBuffer}.
   *
   * @param tagBuffer Destination buffer
   * @param indentDepth Logical indentation level used for pretty printing
   * @return the same buffer for chaining
   */
  public StringBuilder generate(StringBuilder tagBuffer, int indentDepth) {
    if ("#".equals(tagName)) {
      return generateTextNode(tagBuffer);
    }
    if ("%".equals(tagName)) {
      return generateRawNode(tagBuffer);
    }
    startOpenTag(tagBuffer);
    appendAttributes(tagBuffer);
    tagBuffer.append(openSuffix(tagName));
    appendContents(tagBuffer, indentDepth);
    appendClosing(tagBuffer, indentDepth);
    return tagBuffer;
  }

  private StringBuilder generateTextNode(StringBuilder tagBuffer) {
    if (content != null) {
      HTMLEncoder.encodeToBuffer(content, tagBuffer);
      return tagBuffer;
    }
    for (HTMLNode childNode : children) {
      childNode.generate(tagBuffer);
    }
    return tagBuffer;
  }

  private StringBuilder generateRawNode(StringBuilder tagBuffer) {
    tagBuffer.append(content);
    return tagBuffer;
  }

  private void startOpenTag(StringBuilder tagBuffer) {
    tagBuffer.append('<').append(tagName);
  }

  private void appendAttributes(StringBuilder tagBuffer) {
    Set<Map.Entry<String, String>> attributeSet = attributes.entrySet();
    for (Map.Entry<String, String> attributeEntry : attributeSet) {
      String attributeName = attributeEntry.getKey();
      String attributeValue = attributeEntry.getValue();
      tagBuffer.append(' ');
      HTMLEncoder.encodeToBuffer(attributeName, tagBuffer);
      tagBuffer.append("=\"");
      HTMLEncoder.encodeToBuffer(attributeValue, tagBuffer);
      tagBuffer.append('"');
    }
  }

  private void appendContents(StringBuilder tagBuffer, int indentDepth) {
    if (children.isEmpty()) {
      if (content != null) {
        HTMLEncoder.encodeToBuffer(content, tagBuffer);
      }
      return;
    }
    if (newlineOpen(tagName)) {
      tagBuffer.append('\n');
      tagBuffer.append(indentString(indentDepth + 1));
    }
    for (HTMLNode childNode : children) {
      childNode.generate(tagBuffer, indentDepth + 1);
    }
  }

  private void appendClosing(StringBuilder tagBuffer, int indentDepth) {
    if (newlineOpen(tagName)) {
      tagBuffer.append('\n');
      tagBuffer.append(indentString(indentDepth));
    }
    tagBuffer.append(closeTag(tagName));
    if (newlineClose(tagName)) {
      tagBuffer.append('\n');
      tagBuffer.append(indentString(indentDepth));
    }
  }

  /** Renders only the children of this node (or {@code content} for text/raw nodes). */
  public String generateChildren() {
    if (content != null) {
      return content;
    }
    StringBuilder tagBuffer = new StringBuilder();
    for (HTMLNode childNode : children) {
      childNode.generate(tagBuffer);
    }
    return tagBuffer.toString();
  }

  /**
   * Sets node content.
   *
   * @param newContent New content (encoded or raw depending on node type)
   * @throws IllegalArgumentException if this node is read-only
   */
  public void setContent(String newContent) {
    if (readOnly) throw new IllegalArgumentException("Read only");
    content = newContent;
  }

  /**
   * Returns the live list of children.
   *
   * <p>Modifications to the returned list affect this node directly and are not validated. Prefer
   * using {@link #addChild(HTMLNode)} and related helpers.
   */
  public List<HTMLNode> getChildren() {
    return children;
  }

  /**
   * Special HTML node for the DOCTYPE declaration. This node differs from a normal HTML node in
   * that it's child (and it should only have exactly one child, the "html" node) is rendered
   * <em>after</em> this node.
   *
   * @author David 'Bombe' Roden &lt;bombe@freenetproject.org&gt;
   * @version $Id$
   */
  public static class HTMLDoctype extends HTMLNode {

    private final String systemUri;

    /**
     * Creates a DOCTYPE node.
     *
     * @param doctype Root element name for the document (e.g., {@code "html"})
     * @param systemUri Public or system identifier used in the declaration
     */
    public HTMLDoctype(String doctype, String systemUri) {
      super(doctype);
      this.systemUri = systemUri;
    }

    /**
     * Appends a {@code <!DOCTYPE ...>} declaration then renders the single child.
     *
     * <p>Precondition: exactly one child is present and represents the document root.
     *
     * @param tagBuffer Destination buffer
     * @return the same buffer, for chaining
     * @throws IndexOutOfBoundsException if no child is present
     * @implNote Implementation should validate the child count and raise a meaningful exception.
     * @see HTMLNode#generate(StringBuilder)
     */
    @Override
    public StringBuilder generate(StringBuilder tagBuffer) {
      tagBuffer
          .append("<!DOCTYPE ")
          .append(tagName)
          .append(" PUBLIC \"")
          .append(systemUri)
          .append("\">\n");
      // A meaningful exception should be raised when invoking this for a
      // HTMLDoctype with a number of children different from 1.
      return children.getFirst().generate(tagBuffer);
    }
  }

  /** Creates an {@code <a href="...">} element. */
  public static HTMLNode link(String path) {
    return new HTMLNode("a", "href", path);
  }

  /**
   * Creates an {@code <a>} element that opens in a new window/tab and uses {@code rel="noreferrer
   * noopener"} for safety.
   */
  public static HTMLNode linkInNewWindow(String path) {
    return new HTMLNode(
        "a",
        new String[] {"href", "target", "rel"},
        new String[] {path, "_blank", "noreferrer noopener"});
  }

  /** Creates a text node (equivalent to {@code name == "#"}). */
  public static HTMLNode text(String text) {
    return new HTMLNode("#", text);
  }

  /** Creates a text node for an {@code int} value. */
  public static HTMLNode text(int count) {
    return new HTMLNode("#", Integer.toString(count));
  }

  /** Creates a text node for a {@code long} value. */
  public static HTMLNode text(long count) {
    return new HTMLNode("#", Long.toString(count));
  }

  /** Creates a text node for a {@code short} value. */
  public static HTMLNode text(short count) {
    return new HTMLNode("#", Short.toString(count));
  }

  /** Removes all children from this node. */
  public void removeChildren() {
    if (readOnly) throw new IllegalArgumentException("Read only");
    children.clear();
  }
}
