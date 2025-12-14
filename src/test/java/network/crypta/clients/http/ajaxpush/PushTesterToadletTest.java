package network.crypta.clients.http.ajaxpush;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.same;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.PageMaker;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.clients.http.PageNode;
import network.crypta.clients.http.RedirectException;
import network.crypta.clients.http.ToadletContext;
import network.crypta.clients.http.ToadletContextClosedException;
import network.crypta.clients.http.updateableelements.TesterElement;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // Test method naming convention: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class PushTesterToadletTest {

  private static final String TITLE = "Push tester";

  @SuppressWarnings("java:S1075")
  private static final String TOADLET_PATH = "/pushtester/";

  private static final int ELEMENT_COUNT = 600;
  private static final int ELEMENT_MAX_STATUS = 100;
  private static final String GENERATED_HTML = "<html>generated</html>";

  @Mock private HighLevelSimpleClient client;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;
  @Mock private PageMaker pageMaker;
  @Mock private PageNode pageNode;

  private HTMLNode contentNode;

  @Test
  void path_whenCalled_expectStableMountPath() {
    PushTesterToadlet toadlet = new PushTesterToadlet(client);

    assertEquals(TOADLET_PATH, toadlet.path());
  }

  @Test
  void handleMethodGET_whenInvoked_expectBuild600ElementsAndWriteOkHtmlReply()
      throws ToadletContextClosedException, RedirectException, IOException {
    // Arrange
    CapturingPushTesterToadlet toadlet = new CapturingPushTesterToadlet(client);
    URI uri = URI.create(TOADLET_PATH);
    contentNode = stubPageTemplate();
    List<List<Object>> constructedArguments = new ArrayList<>();

    try (MockedConstruction<TesterElement> mockedConstruction =
        mockConstruction(
            TesterElement.class,
            (mock, context) -> constructedArguments.add(List.copyOf(context.arguments())))) {
      // Act
      toadlet.handleMethodGET(uri, request, ctx);

      // Assert (page chrome configuration)
      ArgumentCaptor<RenderParameters> renderParamsCaptor =
          ArgumentCaptor.forClass(RenderParameters.class);
      verify(pageMaker).getPageNode(eq(TITLE), same(ctx), renderParamsCaptor.capture());
      RenderParameters renderParameters = renderParamsCaptor.getValue();
      assertNotNull(renderParameters);
      assertFalse(renderParameters.isRenderNavigationLinks());
      assertTrue(renderParameters.isRenderStatus());
      assertTrue(renderParameters.isRenderModeSwitch());

      // Assert (constructed elements are deterministic and bounded)
      assertEquals(ELEMENT_COUNT, constructedArguments.size());
      assertEquals(ELEMENT_COUNT, mockedConstruction.constructed().size());
      assertEquals(ELEMENT_COUNT, contentNode.getChildren().size());
      for (int i = 0; i < ELEMENT_COUNT; i++) {
        List<?> args = constructedArguments.get(i);
        assertEquals(3, args.size());
        assertEquals(ctx, args.get(0));
        assertEquals(String.valueOf(i), args.get(1));
        assertEquals(ELEMENT_MAX_STATUS, args.get(2));
      }

      // Assert (HTTP reply)
      assertEquals(1, toadlet.writeCount);
      assertEquals(ctx, toadlet.lastContext);
      assertEquals(200, toadlet.lastCode);
      assertEquals("OK", toadlet.lastDescription);
      assertEquals(GENERATED_HTML, toadlet.lastReply);
    }
  }

  @Test
  void handleMethodGET_whenWriteHtmlReplyThrows_expectPropagatesIOException() {
    // Arrange
    PushTesterToadlet toadlet = new FailingWriteHtmlReplyPushTesterToadlet(client);
    URI uri = URI.create(TOADLET_PATH);
    stubPageTemplate();

    try (MockedConstruction<TesterElement> mockedConstruction =
        mockConstruction(TesterElement.class)) {
      // Act
      IOException thrown =
          assertThrows(IOException.class, () -> toadlet.handleMethodGET(uri, request, ctx));

      // Assert
      assertEquals("write failed", thrown.getMessage());
      assertEquals(ELEMENT_COUNT, mockedConstruction.constructed().size());
    }
  }

  private HTMLNode stubPageTemplate() {
    contentNode = new HTMLNode("div");

    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(pageMaker.getPageNode(eq(TITLE), same(ctx), org.mockito.ArgumentMatchers.any()))
        .thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn(GENERATED_HTML);

    return contentNode;
  }

  private static final class CapturingPushTesterToadlet extends PushTesterToadlet {
    private int writeCount;
    private ToadletContext lastContext;
    private int lastCode;
    private String lastDescription;
    private String lastReply;

    private CapturingPushTesterToadlet(HighLevelSimpleClient client) {
      super(client);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply) {
      writeCount++;
      lastContext = ctx;
      lastCode = code;
      lastDescription = desc;
      lastReply = reply;
    }
  }

  private static final class FailingWriteHtmlReplyPushTesterToadlet extends PushTesterToadlet {
    private FailingWriteHtmlReplyPushTesterToadlet(HighLevelSimpleClient client) {
      super(client);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply)
        throws IOException {
      throw new IOException("write failed");
    }
  }
}
