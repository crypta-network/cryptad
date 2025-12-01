package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class ToadletContextImplTest {

  @Mock private BucketFactory bucketFactory;
  @Mock private PageMaker pageMaker;
  @Mock private ToadletContainer container;
  @Mock private UserAlertManager alertManager;
  @Mock private BookmarkManager bookmarkManager;
  @Mock private HTTPRequest request;

  private ByteArrayOutputStream outputStream;
  private ToadletContextImpl context;

  @BeforeEach
  void setUp() throws Exception {
    outputStream = new ByteArrayOutputStream();
    Socket socket = new FakeSocket(outputStream, InetAddress.getLoopbackAddress());

    // Minimal stubbing used across tests
    org.mockito.Mockito.when(container.getFormPassword()).thenReturn("secret");
    org.mockito.Mockito.when(container.isFProxyJavascriptEnabled()).thenReturn(false);
    org.mockito.Mockito.when(container.isSSL()).thenReturn(false);

    context =
        new ToadletContextImpl(
            socket,
            new MultiValueTable<>(),
            bucketFactory,
            pageMaker,
            container,
            alertManager,
            bookmarkManager,
            new URI("http://example.com/"),
            1L);
  }

  @Test
  void parseHTTPDate_whenValidString_parsesEpoch() throws Exception {
    Date parsed = ToadletContextImpl.parseHTTPDate("Thu, 01 Jan 1970 00:00:00 GMT");
    assertEquals(0L, parsed.getTime());
  }

  @Test
  void parseHTTPDate_whenInvalid_throwsParseException() {
    assertThrows(ParseException.class, () -> ToadletContextImpl.parseHTTPDate("not a date"));
  }

  @Test
  void shouldDisconnectAfterHandled_withCloseHeader_returnsTrue() {
    MultiValueTable<String, String> headers = MultiValueTable.from("connection", "close");
    assertTrue(
        invokeShouldDisconnectAfterHandled(false, headers),
        "close header must force disconnect regardless of version");
  }

  @Test
  void shouldDisconnectAfterHandled_http11WithoutHeader_returnsFalse() {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    assertFalse(invokeShouldDisconnectAfterHandled(false, headers));
  }

  @Test
  void shouldDisconnectAfterHandled_http10WithoutHeader_returnsTrue() {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    assertTrue(invokeShouldDisconnectAfterHandled(true, headers));
  }

  @Test
  void hasFormPassword_whenMatches_returnsTrue() {
    org.mockito.Mockito.when(request.getPartAsStringFailsafe("formPassword", 32))
        .thenReturn("secret");

    assertTrue(context.hasFormPassword(request));
  }

  @Test
  void hasFormPassword_whenMismatch_returnsFalse() {
    org.mockito.Mockito.when(request.getPartAsStringFailsafe("formPassword", 32))
        .thenReturn("wrong");

    assertFalse(context.hasFormPassword(request));
  }

  @Test
  void checkFormPassword_whenMissing_redirectsAndReturnsFalse() throws Exception {
    org.mockito.Mockito.when(request.getPartAsStringFailsafe("formPassword", 32)).thenReturn("bad");

    boolean result = context.checkFormPassword(request, "/redirect");

    assertFalse(result);
    Map<String, List<String>> headers = parseHeaders(outputStream.toString(StandardCharsets.UTF_8));
    assertEquals("302", headers.get("__status").getFirst());
    assertEquals("/redirect", headers.get("location").getFirst());
  }

  @Test
  void sendReplyHeaders_withoutModifiedTime_setsNoCacheAndCsp() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();

    ToadletContextImpl.sendReplyHeaders(
        outputStream, 200, "OK", headers, "text/plain", 10, null, true, false, false);

    Map<String, List<String>> parsed = parseHeaders(outputStream.toString(StandardCharsets.UTF_8));

    assertEquals("200", parsed.get("__status").getFirst());
    assertEquals("close", parsed.get("connection").getFirst());
    assertEquals("text/plain", parsed.get("content-type").getFirst());
    assertEquals("10", parsed.get("content-length").getFirst());
    assertEquals("Thu, 01 Jan 1970 00:00:00 GMT", parsed.get("expires").getFirst());
    assertTrue(parsed.get("cache-control").getFirst().contains("no-cache"));
    assertEquals("DENY", parsed.get("x-frame-options").getFirst());
    String csp = parsed.get("content-security-policy").getFirst();
    assertTrue(csp.contains("frame-src 'none'"));
    assertTrue(csp.contains("sha256-RY9OjosvFxocXEmcUqBJ2v1KByDRdUgnGHYSL3Qx/t8="));
    String scriptDirective = getScriptDirective(csp);
    assertFalse(
        scriptDirective.contains("unsafe-inline"),
        "inline scripts must be forbidden when disabled");
  }

  @Test
  void sendReplyHeaders_withModifiedTime_allowsCachingAndScripts() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    Date modified = new Date(0L);

    ToadletContextImpl.sendReplyHeaders(
        outputStream, 200, "OK", headers, "text/html", 5, modified, false, true, true);

    Map<String, List<String>> parsed = parseHeaders(outputStream.toString(StandardCharsets.UTF_8));

    assertEquals("keep-alive", parsed.get("connection").getFirst());
    assertEquals("text/html; charset=UTF-8", parsed.get("content-type").getFirst());
    assertTrue(parsed.get("cache-control").getFirst().startsWith("public"));
    assertEquals(
        ToadletContextImpl.parseHTTPDate(parsed.get("last-modified").getFirst()).getTime(),
        modified.getTime());
    String csp = parsed.get("content-security-policy").getFirst();
    assertTrue(csp.contains("frame-src 'self'"));
    assertTrue(csp.contains("unsafe-inline"));
    assertTrue(csp.contains("unsafe-eval"));
  }

  @Test
  void sendReplyHeaders_whenCalledTwice_throwsIllegalState() throws Exception {
    context.sendReplyHeaders(200, "OK", null, "text/plain", 0);

    assertThrows(
        IllegalStateException.class, () -> context.sendReplyHeaders(200, "OK", null, null, 0));
  }

  @Test
  void writeData_whenClosed_throwsToadletContextClosedException() throws Exception {
    java.lang.reflect.Field closedField = ToadletContextImpl.class.getDeclaredField("closed");
    closedField.setAccessible(true);
    closedField.set(context, true);

    assertThrows(ToadletContextClosedException.class, () -> context.writeData(new byte[] {1, 2}));
  }

  private static boolean invokeShouldDisconnectAfterHandled(
      boolean isHttp10, MultiValueTable<String, String> headers) {
    try {
      java.lang.reflect.Method m =
          ToadletContextImpl.class.getDeclaredMethod(
              "shouldDisconnectAfterHandled", boolean.class, MultiValueTable.class);
      m.setAccessible(true);
      return (boolean) m.invoke(null, isHttp10, headers);
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }

  private static Map<String, List<String>> parseHeaders(String raw) {
    Map<String, List<String>> map = new LinkedHashMap<>();
    String[] lines = raw.split("\\r?\\n");
    if (lines.length == 0) return map;
    String statusLine = lines[0];
    String[] statusParts = statusLine.split(" ");
    if (statusParts.length >= 2) {
      map.put("__status", List.of(statusParts[1]));
    }
    for (int i = 1; i < lines.length; i++) {
      String line = lines[i];
      if (line.trim().isEmpty()) {
        continue;
      }
      int idx = line.indexOf(':');
      if (idx <= 0) continue;
      String key = line.substring(0, idx).toLowerCase(Locale.ROOT);
      String value = line.substring(idx + 1).trim();
      map.computeIfAbsent(key, k -> new java.util.ArrayList<>()).add(value);
    }
    return map;
  }

  private static String getScriptDirective(String csp) {
    final String prefix = "script-src";
    for (String part : csp.split(";")) {
      String trimmed = part.trim();
      if (trimmed.startsWith(prefix)) {
        return trimmed;
      }
    }
    return "";
  }

  private static class FakeSocket extends Socket {
    private final ByteArrayOutputStream os;
    private final InetAddress inetAddress;

    FakeSocket(ByteArrayOutputStream os, InetAddress inetAddress) {
      this.os = os;
      this.inetAddress = inetAddress;
    }

    @Override
    public ByteArrayOutputStream getOutputStream() {
      return os;
    }

    @Override
    public InetAddress getInetAddress() {
      return inetAddress;
    }

    @Override
    public void close() {
      // no-op for tests
    }
  }
}
