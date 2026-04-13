package network.crypta.clients.http;

import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FProxyToadletTest {

  @Mock private HighLevelSimpleClient client;

  @Mock private FProxyRuntimeSupport runtimeSupport;

  @Mock private FProxyFetchTracker fetchTracker;

  @Mock private ClientContext clientContext;

  @Mock private ToadletContainer container;

  @Test
  void constructor_setsMaxLengthsOnClient() {
    when(runtimeSupport.clientContext()).thenReturn(clientContext);

    new FProxyToadlet(client, runtimeSupport, fetchTracker);

    verify(client).setMaxLength(FProxyToadlet.getMaxLengthNoProgress());
    verify(client).setMaxIntermediateLength(FProxyToadlet.getMaxLengthNoProgress());
    verify(runtimeSupport).clientContext();
  }

  @Test
  void create_whenInvoked_returnsConfiguredToadlet() {
    when(runtimeSupport.clientContext()).thenReturn(clientContext);

    FProxyToadlet toadlet = FProxyToadlet.create(client, runtimeSupport, fetchTracker);

    assertEquals("/", toadlet.path());
    verify(client).setMaxLength(FProxyToadlet.getMaxLengthNoProgress());
    verify(client).setMaxIntermediateLength(FProxyToadlet.getMaxLengthNoProgress());
    verify(runtimeSupport).clientContext();
  }

  @Test
  void allowPOSTWithoutPassword_alwaysReturnsTrue() {
    FProxyToadlet toadlet = newFProxy();

    assertTrue(toadlet.allowPOSTWithoutPassword());
  }

  @Test
  void handleMethodPOST_rootPath_redirectsToWelcome() {
    FProxyToadlet toadlet = newFProxy();
    URI uri = URI.create("/");

    RedirectException exception =
        assertThrows(
            RedirectException.class,
            () ->
                toadlet.handleMethodPOST(uri, mock(HTTPRequest.class), mock(ToadletContext.class)));

    assertEquals(URI.create("/welcome/"), exception.getTarget());
  }

  @Test
  void handleMethodPOST_servletPath_redirectsToWelcome() {
    FProxyToadlet toadlet = newFProxy();
    URI uri = URI.create("/servlet/sample");

    RedirectException exception =
        assertThrows(
            RedirectException.class,
            () ->
                toadlet.handleMethodPOST(uri, mock(HTTPRequest.class), mock(ToadletContext.class)));

    assertEquals(URI.create("/welcome/"), exception.getTarget());
  }

  @Test
  void handleMethodPOST_otherPath_doesNothing() {
    FProxyToadlet toadlet = newFProxy();
    URI uri = URI.create("/other");

    assertDoesNotThrow(
        () -> toadlet.handleMethodPOST(uri, mock(HTTPRequest.class), mock(ToadletContext.class)));
  }

  @Test
  void handleMethodGET_whenFeedPathRequested_writesAtomFromConcreteAlertManager() throws Exception {
    FProxyToadlet toadlet = newFProxy();
    ToadletContext ctx = mock(ToadletContext.class);
    HTTPRequest request = mock(HTTPRequest.class);
    UserAlertManager alertManager = mock(UserAlertManager.class);
    SubConfig fProxyConfig = mock(SubConfig.class);
    @SuppressWarnings("rawtypes")
    Option portOption = mock(Option.class);
    @SuppressWarnings("rawtypes")
    Option bindToOption = mock(Option.class);
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    String atom = "<feed/>";
    byte[] atomBytes = atom.getBytes(StandardCharsets.UTF_8);

    toadlet.container = container;
    when(container.publicGatewayMode()).thenReturn(false);
    when(runtimeSupport.fproxyConfig()).thenReturn(fProxyConfig);
    doReturn(portOption).when(fProxyConfig).getOption("port");
    doReturn(bindToOption).when(fProxyConfig).getOption("bindTo");
    when(portOption.getValueString()).thenReturn("8888");
    when(bindToOption.getValueString()).thenReturn("example.test");
    when(ctx.getHeaders()).thenReturn(headers);
    when(ctx.getUri()).thenReturn(URI.create("http://example.test/feed"));
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(alertManager.getAtom("http://example.test")).thenReturn(atom);

    toadlet.handleMethodGET(URI.create("http://example.test/feed"), request, ctx);

    verify(alertManager).getAtom("http://example.test");
    verify(ctx).sendReplyHeadersFProxy(200, "OK", null, "application/atom+xml", atomBytes.length);
    ArgumentCaptor<byte[]> dataCaptor = ArgumentCaptor.forClass(byte[].class);
    verify(ctx).writeData(dataCaptor.capture(), eq(0), eq(atomBytes.length));
    assertArrayEquals(atomBytes, dataCaptor.getValue());
  }

  @Test
  void parseRange_withExplicitEnd_returnsBounds() throws Exception {
    long[] result = invokeParseRange("bytes=0-499");

    assertArrayEquals(new long[] {0L, 499L}, result);
  }

  @Test
  void parseRange_withoutEnd_setsMinusOne() throws Exception {
    long[] result = invokeParseRange("bytes=500-");

    assertArrayEquals(new long[] {500L, -1L}, result);
  }

  @Test
  void parseRange_withInvalidUnit_throwsException() {
    assertThrows(HTTPRangeException.class, () -> invokeParseRange("items=0-10"));
  }

  @Test
  void parseRange_whenFromExceedsTo_throwsException() {
    assertThrows(HTTPRangeException.class, () -> invokeParseRange("bytes=10-5"));
  }

  @Test
  void lifecycleFlags_returnExpectedValues() {
    FProxyToadlet toadlet = newFProxy();

    assertTrue(toadlet.realTimeFlag());
    assertEquals("/", toadlet.path());
    assertFalse(toadlet.persistent());
  }

  private FProxyToadlet newFProxy() {
    when(runtimeSupport.clientContext()).thenReturn(clientContext);
    return new FProxyToadlet(client, runtimeSupport, fetchTracker);
  }

  private long[] invokeParseRange(String value) throws Exception {
    Method parseRange = FProxyToadlet.class.getDeclaredMethod("parseRange", String.class);
    parseRange.setAccessible(true);
    try {
      return (long[]) parseRange.invoke(null, value);
    } catch (Exception e) {
      if (e.getCause() != null && e.getCause() instanceof Exception cause) {
        throw cause;
      }

      throw e;
    }
  }
}
