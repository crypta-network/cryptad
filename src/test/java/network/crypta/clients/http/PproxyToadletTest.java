package network.crypta.clients.http;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.pluginmanager.DownloadPluginHTTPException;
import network.crypta.pluginmanager.PluginManager;
import network.crypta.pluginmanager.RedirectPluginHTTPException;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PproxyToadletTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private network.crypta.node.Node node;
  @Mock private PluginManager pluginManager;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  private PproxyToadlet toadlet;

  @BeforeEach
  void setUp() throws Exception {
    toadlet = new PproxyToadlet(client, node);

    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    lenient().when(node.services()).thenReturn(services);
    lenient().when(services.pluginManager()).thenReturn(pluginManager);
    lenient().when(ctx.checkFullAccess(any())).thenReturn(true);
    lenient().when(ctx.checkFormPassword(any())).thenReturn(true);
    lenient().when(ctx.checkFormPassword(any(), anyString())).thenReturn(true);
    lenient().when(request.getPath()).thenReturn("/plugins/");
  }

  @Test
  void allowPOSTWithoutPassword_whenCalled_returnsTrue() {
    assertTrue(toadlet.allowPOSTWithoutPassword());
  }

  @Test
  void path_whenCalled_returnsPluginsPath() {
    assertEquals(PproxyToadlet.PLUGINS_PATH, toadlet.path());
  }

  @Test
  void handleMethodPOST_withPluginPath_sendsHtmlReplyFromPlugin() throws Exception {
    when(request.getPath()).thenReturn("/plugins/TestPlugin/action");
    when(pluginManager.handleHTTPPost("TestPlugin", request)).thenReturn("<html>ok</html>");

    toadlet.handleMethodPOST(
        URI.create("http://localhost/plugins/TestPlugin/action"), request, ctx);

    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor = multiValueTableCaptor();
    ArgumentCaptor<byte[]> bodyCaptor = ArgumentCaptor.forClass(byte[].class);

    verify(pluginManager).handleHTTPPost("TestPlugin", request);
    verify(ctx)
        .sendReplyHeaders(
            eq(200),
            eq("OK"),
            headersCaptor.capture(),
            eq("text/html; charset=utf-8"),
            eq((long) "<html>ok</html>".getBytes(StandardCharsets.UTF_8).length));
    verify(ctx)
        .writeData(
            bodyCaptor.capture(),
            eq(0),
            eq("<html>ok</html>".getBytes(StandardCharsets.UTF_8).length));

    assertArrayEquals("<html>ok</html>".getBytes(StandardCharsets.UTF_8), bodyCaptor.getValue());
    assertTrue(headersCaptor.getValue() == null || headersCaptor.getValue().countAll("any") == 0);
  }

  @Test
  void handleMethodPOST_whenPluginRequestsDownload_streamsAttachment() throws Exception {
    when(request.getPath()).thenReturn("/plugins/AttachPlugin");
    byte[] payload = "data".getBytes(StandardCharsets.UTF_8);
    when(pluginManager.handleHTTPPost("AttachPlugin", request))
        .thenThrow(
            new DownloadPluginHTTPException(payload, "file.bin", "application/octet-stream"));

    toadlet.handleMethodPOST(URI.create("http://localhost/plugins/AttachPlugin"), request, ctx);

    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor = multiValueTableCaptor();
    ArgumentCaptor<byte[]> bodyCaptor = ArgumentCaptor.forClass(byte[].class);

    verify(ctx)
        .sendReplyHeaders(
            eq(
                (int)
                    new DownloadPluginHTTPException(payload, "file.bin", "application/octet-stream")
                        .code()),
            eq("Found"),
            headersCaptor.capture(),
            eq("application/octet-stream"),
            eq((long) payload.length));
    verify(ctx).writeData(bodyCaptor.capture());

    assertEquals(
        "attachment; filename=\"file.bin\"",
        headersCaptor.getValue().getAllAsList("Content-Disposition").getFirst());
    assertArrayEquals(payload, bodyCaptor.getValue());
  }

  @Test
  void handleMethodPOST_withReloadConfirmMissingPlugin_sends404ErrorPage() throws Exception {
    PproxyToadlet spyToadlet = spy(new PproxyToadlet(client, node));
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    doReturn(pluginManager).when(services).pluginManager();

    doNothing().when(spyToadlet).sendErrorPage(eq(ctx), eq(404), anyString(), anyString());

    when(request.getPath()).thenReturn("/plugins/");
    lenient().when(request.isPartSet(anyString())).thenReturn(false);
    lenient().when(request.getPartAsStringFailsafe(anyString(), anyInt())).thenReturn("");
    when(request.getPartAsStringFailsafe(eq("reloadconfirm"), anyInt()))
        .thenReturn("missing-plugin");
    when(pluginManager.getPlugins()).thenReturn(Collections.emptySet());

    spyToadlet.handleMethodPOST(URI.create("http://localhost/plugins/"), request, ctx);

    verify(spyToadlet).sendErrorPage(eq(ctx), eq(404), anyString(), anyString());
  }

  @Test
  void handleMethodGET_withPluginPath_sendsPluginHtml() throws Exception {
    when(request.getPath()).thenReturn("/plugins/Example");
    when(pluginManager.handleHTTPGet("Example", request)).thenReturn("<html>plugin</html>");

    toadlet.handleMethodGET(URI.create("http://localhost/plugins/Example"), request, ctx);

    verify(pluginManager).handleHTTPGet("Example", request);
    verify(ctx)
        .sendReplyHeaders(
            eq(200),
            eq("OK"),
            any(),
            eq("text/html; charset=utf-8"),
            eq((long) "<html>plugin</html>".getBytes(StandardCharsets.UTF_8).length));
  }

  @Test
  void handleMethodGET_whenPluginRedirects_writesTemporaryRedirect() throws Exception {
    PproxyToadlet spyToadlet = spy(new PproxyToadlet(client, node));
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.pluginManager()).thenReturn(pluginManager);
    when(request.getPath()).thenReturn("/plugins/Redirector");
    when(pluginManager.handleHTTPGet("Redirector", request))
        .thenThrow(new RedirectPluginHTTPException("move", "/target"));

    doNothing().when(spyToadlet).writeTemporaryRedirect(eq(ctx), anyString(), eq("/target"));

    spyToadlet.handleMethodGET(URI.create("http://localhost/plugins/Redirector"), request, ctx);

    verify(spyToadlet).writeTemporaryRedirect(eq(ctx), anyString(), eq("/target"));
  }

  private static ArgumentCaptor<MultiValueTable<String, String>> multiValueTableCaptor() {
    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> captor =
        ArgumentCaptor.forClass(
            (Class<MultiValueTable<String, String>>) (Class<?>) MultiValueTable.class);
    return captor;
  }
}
