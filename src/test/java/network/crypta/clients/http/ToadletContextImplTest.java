package network.crypta.clients.http;

import java.io.ByteArrayOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.runtime.alerts.UserAlertManager;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    ToadletRequestServices services =
        new ToadletRequestServices(container, pageMaker, alertManager, bookmarkManager);
    context =
        new ToadletContextImpl(
            socket,
            new MultiValueTable<>(),
            bucketFactory,
            services,
            new URI("http://example.com/"),
            1L);
  }

  @Test
  void parseHTTPDate_whenValidString_parsesEpoch() throws Exception {
    Instant parsed = ToadletContextImpl.parseHTTPDate("Thu, 01 Jan 1970 00:00:00 GMT").toInstant();
    assertEquals(Instant.EPOCH, parsed);
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

    ReplyHeaders replyHeaders = ReplyHeaders.of(200, "OK", "text/plain", headers);
    ReplyHeaderOptions options = new ReplyHeaderOptions(10, null, true, false, false);
    ToadletContextImpl.sendReplyHeaders(outputStream, replyHeaders, options);

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
    Instant modified = Instant.EPOCH;

    ReplyHeaders replyHeaders = ReplyHeaders.of(200, "OK", "text/html", headers);
    ReplyHeaderOptions options = new ReplyHeaderOptions(5, modified, false, true, true);
    ToadletContextImpl.sendReplyHeaders(outputStream, replyHeaders, options);

    Map<String, List<String>> parsed = parseHeaders(outputStream.toString(StandardCharsets.UTF_8));

    assertEquals("keep-alive", parsed.get("connection").getFirst());
    assertEquals("text/html; charset=UTF-8", parsed.get("content-type").getFirst());
    assertTrue(parsed.get("cache-control").getFirst().startsWith("public"));
    Instant lastModified =
        ToadletContextImpl.parseHTTPDate(parsed.get("last-modified").getFirst()).toInstant();
    assertEquals(modified, lastModified);
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
    List<String> lines = splitLines(raw);
    if (lines.isEmpty()) return map;
    String statusLine = lines.get(0);
    String[] statusParts = splitOnChar(statusLine, ' ');
    if (statusParts.length >= 2) {
      map.put("__status", List.of(statusParts[1]));
    }
    for (int i = 1; i < lines.size(); i++) {
      String line = lines.get(i);
      if (line.trim().isEmpty()) {
        continue;
      }
      int idx = line.indexOf(':');
      if (idx <= 0) continue;
      String key = line.substring(0, idx).toLowerCase(Locale.ROOT);
      String value = line.substring(idx + 1).trim();
      map.computeIfAbsent(key, _ -> new java.util.ArrayList<>()).add(value);
    }
    return map;
  }

  private static String getScriptDirective(String csp) {
    final String prefix = "script-src";
    for (String part : splitOnChar(csp, ';')) {
      String trimmed = part.trim();
      if (trimmed.startsWith(prefix)) {
        return trimmed;
      }
    }
    return "";
  }

  private static List<String> splitLines(String raw) {
    List<String> lines = new ArrayList<>();
    int start = 0;
    for (int i = 0; i < raw.length(); i++) {
      if (raw.charAt(i) == '\n') {
        int end = i;
        if (end > start && raw.charAt(end - 1) == '\r') {
          end--;
        }
        lines.add(raw.substring(start, end));
        start = i + 1;
      }
    }
    lines.add(raw.substring(start));
    while (!lines.isEmpty() && lines.get(lines.size() - 1).isEmpty()) {
      lines.remove(lines.size() - 1);
    }
    return lines;
  }

  private static String[] splitOnChar(String value, char delimiter) {
    int segments = 1;
    for (int i = 0; i < value.length(); i++) {
      if (value.charAt(i) == delimiter) {
        segments++;
      }
    }
    String[] parts = new String[segments];
    int start = 0;
    int partIndex = 0;
    for (int i = 0; i < value.length(); i++) {
      if (value.charAt(i) == delimiter) {
        parts[partIndex++] = value.substring(start, i);
        start = i + 1;
      }
    }
    parts[partIndex] = value.substring(start, value.length());

    int end = parts.length;
    while (end > 0 && parts[end - 1].isEmpty()) {
      end--;
    }
    return end == parts.length ? parts : java.util.Arrays.copyOf(parts, end);
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
