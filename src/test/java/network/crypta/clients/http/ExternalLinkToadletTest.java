package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.PageMaker.RenderParameters;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ExternalLinkToadletTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private Node node;
  @Mock private NodeClientCore nodeClientCore;
  @Mock private SimpleToadletServer toadletContainer;
  @Mock private ToadletContext context;
  @Mock private PageMaker pageMaker;
  @Mock private HTTPRequest request;

  private ExternalLinkToadlet toadlet;

  @BeforeEach
  void setUp() throws Exception {
    toadlet = new ExternalLinkToadlet(client, node);

    when(context.getPageMaker()).thenReturn(pageMaker);
    when(node.getClientCore()).thenReturn(nodeClientCore);
    when(nodeClientCore.getToadletContainer()).thenReturn(toadletContainer);

    doNothing()
        .when(context)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
    doNothing()
        .when(context)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong(), anyBoolean());
    doNothing().when(context).writeData(any(byte[].class), anyInt(), anyInt());
  }

  @Test
  void path_whenCalled_returnsExternalLinkPath() {
    assertEquals(ExternalLinkToadlet.EXTERNAL_LINK_PATH, toadlet.path());
  }

  @Test
  void escape_whenUriProvided_prependsMagicParameter() {
    String input = "http://example.com/resource";

    String result = ExternalLinkToadlet.escape(input);

    assertEquals(
        ExternalLinkToadlet.EXTERNAL_LINK_PATH
            + "?"
            + ExternalLinkToadlet.MAGIC_HTTP_ESCAPE_STRING
            + '='
            + input,
        result);
  }

  @Test
  void handleMethodPOST_whenGoParameterEmpty_redirectsToWelcome() throws Exception {
    when(request.getPartAsStringFailsafe(
            eq(ExternalLinkToadlet.MAGIC_HTTP_ESCAPE_STRING), anyInt()))
        .thenReturn("http://example.com");
    when(request.getPartAsStringFailsafe(eq("Go"), anyInt())).thenReturn("");

    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(multiValueTableClass());

    toadlet.handleMethodPOST(URI.create(ExternalLinkToadlet.EXTERNAL_LINK_PATH), request, context);

    verify(context)
        .sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    assertEquals(WelcomeToadlet.ROOT_PATH, headersCaptor.getValue().getFirst("Location"));
  }

  @Test
  void handleMethodPOST_whenUrlProvided_redirectsToTarget() throws Exception {
    String target = "http://example.org/page";
    when(request.getPartAsStringFailsafe(
            eq(ExternalLinkToadlet.MAGIC_HTTP_ESCAPE_STRING), anyInt()))
        .thenReturn(target);
    when(request.getPartAsStringFailsafe(eq("Go"), anyInt())).thenReturn("submit");

    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(multiValueTableClass());

    toadlet.handleMethodPOST(URI.create(ExternalLinkToadlet.EXTERNAL_LINK_PATH), request, context);

    verify(context)
        .sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    assertEquals(target, headersCaptor.getValue().getFirst("Location"));
  }

  @Test
  void handleMethodGET_whenParamMissing_redirectsToWelcome() throws Exception {
    when(request.getParam(ExternalLinkToadlet.MAGIC_HTTP_ESCAPE_STRING)).thenReturn("");

    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(multiValueTableClass());

    toadlet.handleMethodGET(URI.create(ExternalLinkToadlet.EXTERNAL_LINK_PATH), request, context);

    verify(context)
        .sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), isNull(), eq(0L));
    verify(context, never()).writeData(any(byte[].class), anyInt(), anyInt());
    assertEquals(WelcomeToadlet.ROOT_PATH, headersCaptor.getValue().getFirst("Location"));
  }

  @Test
  void handleMethodGET_whenParamProvided_rendersConfirmationForm() throws Exception {
    String target = "http://external.example/path";
    when(request.getParam(ExternalLinkToadlet.MAGIC_HTTP_ESCAPE_STRING)).thenReturn(target);
    when(toadletContainer.fproxyHasCompletedWizard()).thenReturn(false);

    HTMLNode page = new HTMLNode("html");
    HTMLNode head = new HTMLNode("head");
    HTMLNode content = new HTMLNode("div");
    page.addChild(head);
    page.addChild(content);
    PageNode pageNode = new PageNode(page, head, content);

    AtomicReference<RenderParameters> renderParameters = new AtomicReference<>();

    when(pageMaker.getPageNode(anyString(), eq(context), any(RenderParameters.class)))
        .thenAnswer(
            invocation -> {
              RenderParameters params = invocation.getArgument(2);
              renderParameters.set(params);
              return pageNode;
            });

    when(pageMaker.getInfobox(
            anyString(), anyString(), any(HTMLNode.class), anyString(), anyBoolean()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              HTMLNode infobox = new HTMLNode("div");
              parent.addChild(infobox);
              return infobox;
            });

    when(context.addFormChild(
            any(HTMLNode.class),
            eq(ExternalLinkToadlet.EXTERNAL_LINK_PATH),
            eq("confirmExternalLinkForm")))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              HTMLNode form = new HTMLNode("form");
              parent.addChild(form);
              return form;
            });

    ArgumentCaptor<byte[]> dataCaptor = ArgumentCaptor.forClass(byte[].class);

    try (MockedStatic<NodeL10n> nodeL10n = mockStatic(NodeL10n.class)) {
      BaseL10n baseL10n = mock(BaseL10n.class);
      nodeL10n.when(NodeL10n::getBase).thenReturn(baseL10n);
      when(baseL10n.getString(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
      when(baseL10n.getString(anyString(), any(String[].class), any(String[].class)))
          .thenAnswer(
              invocation -> {
                String key = invocation.getArgument(0);
                String[] values = invocation.getArgument(2);
                return key + ":" + values[0];
              });

      toadlet.handleMethodGET(URI.create(ExternalLinkToadlet.EXTERNAL_LINK_PATH), request, context);
    }

    verify(context)
        .sendReplyHeaders(
            eq(200), eq("OK"), isNull(), eq("text/html; charset=utf-8"), anyLong(), eq(true));
    verify(context).writeData(dataCaptor.capture(), anyInt(), anyInt());

    String html = new String(dataCaptor.getValue(), StandardCharsets.UTF_8);
    assertTrue(html.contains(target));
    assertTrue(html.contains(ExternalLinkToadlet.MAGIC_HTTP_ESCAPE_STRING));

    RenderParameters params = renderParameters.get();
    assertNotNull(params);
    assertFalse(params.isRenderNavigationLinks());
    assertFalse(params.isRenderStatus());
  }

  @SuppressWarnings("unchecked")
  private Class<MultiValueTable<String, String>> multiValueTableClass() {
    return (Class<MultiValueTable<String, String>>) (Class<?>) MultiValueTable.class;
  }
}
