package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class InfoboxNodeTest {

  @Mock private HTMLNode outerMock;

  @Mock private HTMLNode contentMock;

  @Test
  void constructor_whenGivenNodes_preservesReferences() {
    HTMLNode outer = new HTMLNode("div");
    HTMLNode content = new HTMLNode("span");

    InfoboxNode infoboxNode = new InfoboxNode(outer, content);

    assertSame(outer, infoboxNode.getOuterNode());
    assertSame(content, infoboxNode.getContentNode());
    assertSame(outer, infoboxNode.outer);
    assertSame(content, infoboxNode.content);
  }

  @Test
  void generate_whenOuterNodeGeneratesHtml_returnsHtmlFromOuter() {
    InfoboxNode infoboxNode = new InfoboxNode(outerMock, contentMock);
    when(outerMock.generate()).thenReturn("<div>generated</div>");

    String generated = infoboxNode.generate();

    assertEquals("<div>generated</div>", generated);
    verify(outerMock).generate();
    verifyNoInteractions(contentMock);
  }

  @Test
  void generate_whenOuterIsMutatedAfterConstruction_reflectsLatestStructure() {
    HTMLNode outer = new HTMLNode("section");
    HTMLNode content = new HTMLNode("div");
    InfoboxNode infoboxNode = new InfoboxNode(outer, content);

    outer.addChild("p", "first");
    assertEquals("<section><p>first</p></section>", infoboxNode.generate());

    outer.addChild("p", "second");
    assertEquals("<section><p>first</p><p>second</p></section>", infoboxNode.generate());
  }
}
