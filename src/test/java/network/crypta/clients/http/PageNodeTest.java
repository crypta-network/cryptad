package network.crypta.clients.http;

import java.util.List;
import java.util.Map;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;

@SuppressWarnings("java:S100")
class PageNodeTest {

  @Test
  void getHeadNode_whenCalled_returnsInjectedHeadNode() {
    HTMLNode head = new HTMLNode("head");
    PageNode pageNode = new PageNode(new HTMLNode("html"), head, new HTMLNode("div"));

    HTMLNode result = pageNode.getHeadNode();

    assertSame(head, result);
  }

  @Test
  void addCustomStyleSheet_whenCalled_addsStylesheetLinkWithTypeAndMedia() {
    PageNode pageNode = newPageNode();
    String stylesheetUrl = "https://example.com/styles.css";

    pageNode.addCustomStyleSheet(stylesheetUrl);

    List<HTMLNode> children = pageNode.getHeadNode().getChildren();
    assertEquals(1, children.size());

    HTMLNode linkNode = children.getFirst();
    Map<String, String> attributes = linkNode.getAttributes();
    assertEquals("link", linkNode.getFirstTag());
    assertEquals("stylesheet", attributes.get("rel"));
    assertEquals(stylesheetUrl, attributes.get("href"));
    assertEquals("text/css", attributes.get("type"));
    assertEquals("screen", attributes.get("media"));
  }

  @Test
  void addForwardLink_whenTypeAndMediaProvided_addsAllAttributes() {
    PageNode pageNode = newPageNode();

    pageNode.addForwardLink("shortcut icon", "/favicon.ico", "image/x-icon", "all");

    HTMLNode linkNode = pageNode.getHeadNode().getChildren().getFirst();
    Map<String, String> attributes = linkNode.getAttributes();

    assertEquals("shortcut icon", attributes.get("rel"));
    assertEquals("/favicon.ico", attributes.get("href"));
    assertEquals("image/x-icon", attributes.get("type"));
    assertEquals("all", attributes.get("media"));
  }

  @Test
  void addForwardLink_whenTypeProvidedButMediaMissing_omitsMediaAttribute() {
    PageNode pageNode = newPageNode();

    pageNode.addForwardLink("prefetch", "/resource", "application/json", null);

    HTMLNode linkNode = pageNode.getHeadNode().getChildren().getFirst();
    Map<String, String> attributes = linkNode.getAttributes();

    assertEquals("application/json", attributes.get("type"));
    assertFalse(attributes.containsKey("media"));
  }

  @Test
  void addForwardLink_whenMediaProvidedButTypeMissing_omitsTypeAttribute() {
    PageNode pageNode = newPageNode();

    pageNode.addForwardLink("stylesheet", "/print.css", null, "print");

    HTMLNode linkNode = pageNode.getHeadNode().getChildren().getFirst();
    Map<String, String> attributes = linkNode.getAttributes();

    assertEquals("print", attributes.get("media"));
    assertFalse(attributes.containsKey("type"));
    assertEquals("stylesheet", attributes.get("rel"));
    assertEquals("/print.css", attributes.get("href"));
  }

  @Test
  void addForwardLink_whenTypeAndMediaMissing_addsOnlyRelAndHref() {
    PageNode pageNode = newPageNode();

    pageNode.addForwardLink("prefetch", "https://example.com/data", null, null);

    HTMLNode linkNode = pageNode.getHeadNode().getChildren().getFirst();
    Map<String, String> attributes = linkNode.getAttributes();

    assertEquals(2, attributes.size());
    assertEquals("prefetch", attributes.get("rel"));
    assertEquals("https://example.com/data", attributes.get("href"));
    assertFalse(attributes.containsKey("type"));
    assertFalse(attributes.containsKey("media"));
  }

  private PageNode newPageNode() {
    HTMLNode page = new HTMLNode("html");
    HTMLNode head = new HTMLNode("head");
    HTMLNode content = new HTMLNode("div");
    page.addChild(head);
    page.addChild(content);
    return new PageNode(page, head, content);
  }
}
