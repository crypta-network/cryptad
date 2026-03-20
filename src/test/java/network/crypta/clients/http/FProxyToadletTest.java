package network.crypta.clients.http;

import java.lang.reflect.Method;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

  @Test
  void constructor_setsMaxLengthsOnClient() {
    when(runtimeSupport.clientContext()).thenReturn(clientContext);

    new FProxyToadlet(client, runtimeSupport, fetchTracker);

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
