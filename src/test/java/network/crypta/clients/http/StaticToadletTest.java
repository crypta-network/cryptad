package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.Objects;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class StaticToadletTest {

  @Mock private ToadletContext ctx;

  @Test
  void path_returnsRootUrl() {
    StaticToadlet toadlet = new StaticToadlet();

    assertEquals(StaticToadlet.ROOT_URL, toadlet.path());
  }

  @Test
  void haveFile_whenResourceExists_returnsTrue() {
    assertTrue(StaticToadlet.haveFile("base.css"));
  }

  @Test
  void haveFile_whenResourceMissing_returnsFalse() {
    assertFalse(StaticToadlet.haveFile("does-not-exist.unknown"));
  }

  @Test
  void handleMethodGET_whenPathOutsideRoot_returnsWithoutInteraction() throws Exception {
    TestStaticToadlet toadlet = new TestStaticToadlet();

    toadlet.handleMethodGET(new URI("/other"), mock(HTTPRequest.class), ctx);

    verifyNoInteractions(ctx);
    assertNull(toadlet.lastError());
  }

  @Test
  void handleMethodGET_whenPathHasInvalidCharacters_sendsErrorPage() throws Exception {
    TestStaticToadlet toadlet = new TestStaticToadlet();

    toadlet.handleMethodGET(new URI("/static/../file.css"), mock(HTTPRequest.class), ctx);

    assertEquals(404, toadlet.lastError().status());
    assertEquals(
        NodeL10n.getBase().getString("StaticToadlet.pathNotFoundTitle"),
        toadlet.lastError().desc());
    assertEquals(
        NodeL10n.getBase().getString("StaticToadlet.pathInvalidChars"),
        toadlet.lastError().message());
    verifyNoInteractions(ctx);
  }

  @Test
  void handleMethodGET_whenResourceMissing_sendsNotFoundError() throws Exception {
    TestStaticToadlet toadlet = new TestStaticToadlet();

    toadlet.handleMethodGET(new URI("/static/missing.file"), mock(HTTPRequest.class), ctx);

    assertEquals(404, toadlet.lastError().status());
    assertEquals(
        NodeL10n.getBase().getString("StaticToadlet.pathNotFound"), toadlet.lastError().message());
    verifyNoInteractions(ctx);
  }

  @Test
  void handleMethodGET_whenResourceExists_streamsFromClasspath() throws Exception {
    URL resourceUrl =
        Objects.requireNonNull(
            StaticToadlet.class.getResource(StaticToadlet.ROOT_PATH + "base.css"));
    Path resourcePath = Path.of(resourceUrl.toURI());
    byte[] expectedBytes = Files.readAllBytes(resourcePath);
    Date expectedMtime = new Date(resourcePath.toFile().lastModified());

    InMemoryBucketFactory bucketFactory = new InMemoryBucketFactory();
    when(ctx.getBucketFactory()).thenReturn(bucketFactory);
    doNothing()
        .when(ctx)
        .sendReplyHeadersStatic(
            anyInt(), any(String.class), any(), any(String.class), anyLong(), any());
    doNothing().when(ctx).writeData(any(RandomAccessBucket.class));

    TestStaticToadlet toadlet = new TestStaticToadlet();

    toadlet.handleMethodGET(new URI("/static/base.css"), mock(HTTPRequest.class), ctx);

    RandomAccessBucket writtenBucket = bucketFactory.lastCreated;
    assertEquals(expectedBytes.length, writtenBucket.size());

    ArgumentCaptor<Date> dateCaptor = ArgumentCaptor.forClass(Date.class);
    ArgumentCaptor<Long> lengthCaptor = ArgumentCaptor.forClass(Long.class);
    ArgumentCaptor<String> mimeCaptor = ArgumentCaptor.forClass(String.class);

    verify(ctx)
        .sendReplyHeadersStatic(
            eq(200),
            eq("OK"),
            isNull(),
            mimeCaptor.capture(),
            lengthCaptor.capture(),
            dateCaptor.capture());

    assertEquals(DefaultMIMETypes.guessMIMEType("base.css", false), mimeCaptor.getValue());
    assertEquals(expectedBytes.length, lengthCaptor.getValue());
    assertEquals(expectedMtime, dateCaptor.getValue());
    verify(ctx, times(1)).writeData(writtenBucket);
  }

  @Test
  void handleMethodGET_whenOverrideFilePresent_servesFromOverride() throws Exception {
    Path overrideDir = Files.createTempDirectory("static-toadlet-override");
    Path parent = overrideDir.resolve("overrides");
    Files.createDirectories(parent);
    Path marker = parent.resolve("marker.txt");
    Files.writeString(marker, "marker");
    Path overrideFile = parent.resolve("custom.txt");
    Files.writeString(overrideFile, "override-content");

    ToadletContainer container = mock(ToadletContainer.class);
    when(container.getOverrideFile()).thenReturn(marker.toFile());

    TestStaticToadlet toadlet = new TestStaticToadlet();
    toadlet.container = container;

    doNothing()
        .when(ctx)
        .sendReplyHeadersStatic(
            anyInt(), any(String.class), any(), any(String.class), anyLong(), any());
    doNothing().when(ctx).writeData(any(Bucket.class));

    toadlet.handleMethodGET(new URI("/static/override/custom.txt"), mock(HTTPRequest.class), ctx);

    verify(container, times(1)).getOverrideFile();
    verify(ctx)
        .sendReplyHeadersStatic(
            eq(200),
            eq("OK"),
            isNull(),
            eq(DefaultMIMETypes.guessMIMEType("custom.txt", false)),
            eq(overrideFile.toFile().length()),
            any(Date.class));
    verify(ctx).writeData(any(Bucket.class));
    assertNull(toadlet.lastError());
  }

  private static final class TestStaticToadlet extends StaticToadlet {
    private ErrorCall lastError;

    @Override
    protected void sendErrorPage(ToadletContext ctx, int code, String desc, String message) {
      this.lastError = new ErrorCall(code, desc, message);
    }

    ErrorCall lastError() {
      return lastError;
    }
  }

  private record ErrorCall(int status, String desc, String message) {}

  private static final class InMemoryBucketFactory implements BucketFactory {
    private InMemoryRandomAccessBucket lastCreated;

    @Override
    public RandomAccessBucket makeBucket(long size) {
      lastCreated = new InMemoryRandomAccessBucket();
      return lastCreated;
    }
  }

  private static final class InMemoryRandomAccessBucket implements RandomAccessBucket {
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private boolean readOnly;

    @Override
    public OutputStream getOutputStream() throws IOException {
      if (readOnly) {
        throw new IOException("Bucket is read only");
      }
      return buffer;
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() throws IOException {
      return getOutputStream();
    }

    @Override
    public InputStream getInputStream() {
      return new ByteArrayInputStream(buffer.toByteArray());
    }

    @Override
    public InputStream getInputStreamUnbuffered() {
      return getInputStream();
    }

    @Override
    public String getName() {
      return "in-memory-bucket";
    }

    @Override
    public long size() {
      return buffer.size();
    }

    @Override
    public boolean isReadOnly() {
      return readOnly;
    }

    @Override
    public void setReadOnly() {
      this.readOnly = true;
    }

    @Override
    public void free() {
      buffer.reset();
    }

    @Override
    public RandomAccessBucket createShadow() {
      return null;
    }

    @Override
    public void onResume(network.crypta.client.async.ClientContext context) {
      // No-op: test bucket does not persist across runs, resume lifecycle is irrelevant here.
    }

    @Override
    public void storeTo(java.io.DataOutputStream dos) {
      throw new UnsupportedOperationException("Not implemented for test bucket");
    }

    @Override
    public LockableRandomAccessBuffer toRandomAccessBuffer() {
      throw new UnsupportedOperationException("Not implemented for test bucket");
    }
  }
}
