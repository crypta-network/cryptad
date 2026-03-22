package network.crypta.clients.http;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import javax.naming.SizeLimitExceededException;
import network.crypta.clients.http.HTTPRequestImpl.HTTPUploadedFileImpl;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class HTTPRequestImplTest {

  @Mock private BucketFactory bucketFactory;

  @Test
  void parseUriParameters_whenNullOrEmpty_returnsEmptyMap() {
    Map<String, List<String>> nullResult = HTTPRequestImpl.parseUriParameters(null, true);
    Map<String, List<String>> emptyResult = HTTPRequestImpl.parseUriParameters("", true);

    assertTrue(nullResult.isEmpty());
    assertTrue(emptyResult.isEmpty());
  }

  @Test
  void parseUriParameters_whenMixedTokens_decodesAndGroupsValues() {
    Map<String, List<String>> result =
        HTTPRequestImpl.parseUriParameters("a=one&b=two+three&b=abc%40def.de&lonely&empty=", true);

    assertEquals(List.of("one"), result.get("a"));
    assertEquals(List.of("two three", "abc@def.de"), result.get("b"));
    assertEquals(List.of(""), result.get("lonely"));
    assertEquals(List.of(""), result.get("empty"));
  }

  @Test
  void createQueryString_whenEncodingEnabled_encodesKeysAndValues() {
    Map<String, List<String>> params = new LinkedHashMap<>();
    params.put("sp ace", List.of("1+2", "ä"));
    params.put("safe", List.of("ok"));

    String query = HTTPRequestImpl.createQueryString(params, true);

    assertEquals("sp%20ace=1%2b2&sp%20ace=%c3%a4&safe=ok", query);
  }

  @Test
  void constructor_withPathAndQuery_parsesParameters() throws URISyntaxException {
    HTTPRequestImpl request = new HTTPRequestImpl("/test/path", "a=1&b=two", "GET");

    assertEquals("/test/path", request.getPath());
    assertTrue(request.hasParameters());
    assertTrue(request.isParameterSet("a"));
    assertEquals("1", request.getParam("a"));
    assertEquals("default", request.getParam("missing", "default"));
    assertEquals(2, request.getIntParam("b", 2));
    assertEquals(0, request.getIntParam("c", 0));
  }

  @Test
  void getMultipleIntParam_whenMixedValidity_returnsOnlyParsableValues() throws URISyntaxException {
    HTTPRequestImpl request = new HTTPRequestImpl("/m", "n=1&n=bad&n=3", "GET");

    assertArrayEquals(new int[] {1, 3}, request.getMultipleIntParam("n"));
  }

  @Test
  void getLongParam_whenInvalid_fallsBackToDefault() throws URISyntaxException {
    HTTPRequestImpl request = new HTTPRequestImpl("/m", "value=notalong", "GET");

    assertEquals(42L, request.getLongParam("value", 42L));
  }

  @Test
  void isIncognito_whenFlagPresent_parsesBooleanValue() throws URISyntaxException {
    HTTPRequestImpl request = new HTTPRequestImpl("/m", "incognito=true", "GET");

    assertTrue(request.isIncognito());
  }

  @Test
  void isChrome_whenUserAgentContainsChrome_returnsTrue() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    headers.put("user-agent", "Mozilla Chrome Something");
    HTTPRequestImpl request =
        new HTTPRequestImpl(new URI("/m"), new DummyBucket(""), buildContext(headers), "POST");

    assertTrue(request.isChrome());
  }

  @Test
  void getContentLength_withHeader_returnsParsedValue() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    headers.put("content-type", "application/x-www-form-urlencoded");
    headers.put("content-length", "11");
    HTTPRequestImpl request =
        new HTTPRequestImpl(
            new URI("/m"), new DummyBucket("a=1&b=2"), buildContext(headers), "POST");

    assertEquals(11, request.getContentLength());
  }

  @Test
  void parts_whenUrlEncodedBody_areAvailableAsPartBuckets() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    headers.put("content-type", "application/x-www-form-urlencoded");
    DummyBucket body = new DummyBucket("partValue=hello");
    HTTPRequestImpl request =
        new HTTPRequestImpl(new URI("/upload"), body, buildContext(headers), "POST");

    assertTrue(request.isPartSet("partValue"));
    assertArrayEquals(new String[] {"partValue"}, request.getParts());
    assertEquals("hello", request.getPartAsStringThrowing("partValue", 32));
  }

  @Test
  void getPartAsStringThrowing_whenMissingPart_throwsNoSuchElement() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    headers.put("content-type", "application/x-www-form-urlencoded");
    HTTPRequestImpl request =
        new HTTPRequestImpl(
            new URI("/upload"), new DummyBucket("one=1"), buildContext(headers), "POST");

    assertThrows(
        NoSuchElementException.class, () -> request.getPartAsStringThrowing("missing", 10));
  }

  @Test
  void getPartAsBytesThrowing_whenTooLarge_throwsSizeLimitExceeded() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    headers.put("content-type", "application/x-www-form-urlencoded");
    HTTPRequestImpl request =
        new HTTPRequestImpl(
            new URI("/upload"), new DummyBucket("big=12345"), buildContext(headers), "POST");

    assertThrows(SizeLimitExceededException.class, () -> request.getPartAsBytesThrowing("big", 3));
  }

  @Test
  void freeParts_marksAsFreed_andSubsequentAccessThrows() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    headers.put("content-type", "application/x-www-form-urlencoded");
    HTTPRequestImpl request =
        new HTTPRequestImpl(
            new URI("/upload"), new DummyBucket("p=v"), buildContext(headers), "POST");

    request.freeParts();

    assertThrows(IllegalStateException.class, () -> request.isPartSet("p"));
    assertThrows(IllegalStateException.class, () -> request.getPart("p"));
  }

  @Test
  void uploadedFileImpl_exposesProvidedData() {
    DummyBucket data = new DummyBucket("file");
    HTTPUploadedFileImpl file = new HTTPUploadedFileImpl("name.txt", "text/plain", data);

    assertEquals("name.txt", file.getFilename());
    assertEquals("text/plain", file.getContentType());
    assertEquals(data, file.getData());
  }

  private ToadletContext buildContext(MultiValueTable<String, String> headers) {
    return new ToadletContext() {
      @Override
      public MultiValueTable<String, String> getHeaders() {
        return headers;
      }

      @Override
      public BucketFactory getBucketFactory() {
        return bucketFactory;
      }

      // --- Unused methods below ---
      @Override
      public void sendReplyHeaders(
          int code,
          String desc,
          MultiValueTable<String, String> mvt,
          String mimeType,
          long length) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void sendReplyHeaders(
          int code,
          String desc,
          MultiValueTable<String, String> mvt,
          String mimeType,
          long length,
          boolean forceDisableJavascript) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void sendReplyHeadersStatic(
          int code,
          String desc,
          MultiValueTable<String, String> mvt,
          String mimeType,
          long length,
          Instant mTime) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void sendReplyHeadersFProxy(
          int code,
          String desc,
          MultiValueTable<String, String> mvt,
          String mimeType,
          long length) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void writeData(byte[] data, int offset, int length) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void forceDisconnect() {
        throw new UnsupportedOperationException();
      }

      @Override
      public void writeData(byte[] data) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void writeData(Bucket data) {
        throw new UnsupportedOperationException();
      }

      @Override
      public PageMaker getPageMaker() {
        throw new UnsupportedOperationException();
      }

      @Override
      public String getFormPassword() {
        throw new UnsupportedOperationException();
      }

      @Override
      public boolean checkFormPassword(
          network.crypta.support.api.HTTPRequest request, String redirectTo) {
        throw new UnsupportedOperationException();
      }

      @Override
      public boolean checkFormPassword(network.crypta.support.api.HTTPRequest request) {
        throw new UnsupportedOperationException();
      }

      @Override
      public boolean hasFormPassword(network.crypta.support.api.HTTPRequest request) {
        throw new UnsupportedOperationException();
      }

      @Override
      public boolean checkFullAccess(Toadlet toadlet) {
        throw new UnsupportedOperationException();
      }

      @Override
      public network.crypta.node.useralerts.UserAlertManager getAlertManager() {
        throw new UnsupportedOperationException();
      }

      @Override
      public network.crypta.clients.http.bookmark.BookmarkManager getBookmarkManager() {
        throw new UnsupportedOperationException();
      }

      @Override
      public FProxyFetchInProgress.REFILTER_POLICY getReFilterPolicy() {
        return FProxyFetchInProgress.REFILTER_POLICY.ACCEPT_OLD;
      }

      @Override
      public network.crypta.clients.http.ReceivedCookie getCookie(
          URI domain, URI path, String name) {
        throw new UnsupportedOperationException();
      }

      @Override
      public void setCookie(network.crypta.clients.http.Cookie newCookie) {
        throw new UnsupportedOperationException();
      }

      @Override
      public URI getUri() {
        return URI.create("/");
      }

      @Override
      public String getUniqueId() {
        return "test-id";
      }

      @Override
      public Toadlet activeToadlet() {
        return null;
      }

      @Override
      public ToadletContainer getContainer() {
        return null;
      }

      @Override
      public boolean disableProgressPage() {
        return false;
      }

      @Override
      public boolean doRobots() {
        return false;
      }

      @Override
      public boolean isAdvancedModeEnabled() {
        return false;
      }

      @Override
      public boolean isAllowedFullAccess() {
        return false;
      }

      @Override
      public network.crypta.support.HTMLNode addFormChild(
          network.crypta.support.HTMLNode parentNode, String target, String id) {
        return null;
      }
    };
  }

  /**
   * Minimal in-memory Bucket suitable for exercising the parsing code paths without involving
   * filesystem IO.
   */
  @SuppressWarnings("ClassCanBeRecord")
  private static final class DummyBucket implements RandomAccessBucket {
    private final byte[] data;

    DummyBucket(String content) {
      this.data = content.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public java.io.OutputStream getOutputStream() {
      throw new UnsupportedOperationException();
    }

    @Override
    public java.io.OutputStream getOutputStreamUnbuffered() {
      throw new UnsupportedOperationException();
    }

    @Override
    public java.io.InputStream getInputStream() {
      return new java.io.ByteArrayInputStream(data);
    }

    @Override
    public java.io.InputStream getInputStreamUnbuffered() {
      return getInputStream();
    }

    @Override
    public String getName() {
      return "Dummy";
    }

    @Override
    public long size() {
      return data.length;
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }

    @Override
    public void setReadOnly() {
      // already read-only
    }

    @Override
    public void free() {
      // nothing to free
    }

    @Override
    public RandomAccessBucket createShadow() {
      return this;
    }

    @Override
    public void onResume(network.crypta.support.api.ResumeContext context) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void storeTo(java.io.DataOutputStream dos) {
      throw new UnsupportedOperationException();
    }

    @Override
    public network.crypta.support.api.LockableRandomAccessBuffer toRandomAccessBuffer() {
      throw new UnsupportedOperationException();
    }
  }
}
