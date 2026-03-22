package network.crypta.clients.http;

import java.awt.Graphics2D;
import java.awt.font.FontRenderContext;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ImageCreatorToadletTest {

  private static final String TEXT = "Test";

  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;
  @Mock private BucketFactory bucketFactory;

  private ImageCreatorToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new ImageCreatorToadlet(null);
  }

  @Test
  void specifyMaximumFontSizeThatFitsInImage_respectsBounds() {
    Graphics2D g2 =
        new BufferedImage(
                ImageCreatorToadlet.DEFAULT_WIDTH,
                ImageCreatorToadlet.DEFAULT_HEIGHT,
                BufferedImage.TYPE_INT_RGB)
            .createGraphics();
    FontRenderContext fc = g2.getFontRenderContext();

    toadlet.specifyMaximumFontSizeThatFitsInImage(
        g2, fc, ImageCreatorToadlet.DEFAULT_WIDTH, ImageCreatorToadlet.DEFAULT_HEIGHT, TEXT);

    Rectangle2D bounds = g2.getFont().getStringBounds(TEXT, fc);
    assertTrue(bounds.getWidth() <= ImageCreatorToadlet.DEFAULT_WIDTH);
    assertTrue(bounds.getHeight() <= ImageCreatorToadlet.DEFAULT_HEIGHT);

    g2.setFont(g2.getFont().deriveFont((float) g2.getFont().getSize() + 1));
    bounds = g2.getFont().getStringBounds(TEXT, fc);
    assertFalse(bounds.getWidth() <= ImageCreatorToadlet.DEFAULT_WIDTH);
  }

  @Test
  void specifyMaximumFontSizeThatFitsInImage_handlesTightHeight() {
    int narrowHeight = 12;
    Graphics2D g2 =
        new BufferedImage(60, narrowHeight, BufferedImage.TYPE_INT_RGB).createGraphics();
    FontRenderContext fc = g2.getFontRenderContext();

    toadlet.specifyMaximumFontSizeThatFitsInImage(g2, fc, 60, narrowHeight, TEXT);

    Rectangle2D bounds = g2.getFont().getStringBounds(TEXT, fc);
    assertTrue(bounds.getHeight() <= narrowHeight);
  }

  @Test
  void handleMethodGET_whenIfModifiedSinceMatches_sendsNotModified() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    DateTimeFormatter formatter =
        DateTimeFormatter.ofPattern("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US)
            .withZone(ZoneOffset.UTC);
    headers.put("if-modified-since", formatter.format(ImageCreatorToadlet.LAST_MODIFIED));
    when(ctx.getHeaders()).thenReturn(headers);

    toadlet.handleMethodGET(new URI("/imagecreator/"), request, ctx);

    verify(ctx)
        .sendReplyHeadersStatic(
            eq(304),
            eq("Not Modified"),
            any(),
            eq("image/png"),
            eq(0L),
            eq(ImageCreatorToadlet.LAST_MODIFIED));
    verify(ctx, never()).writeData(any(Bucket.class));
  }

  @Test
  void handleMethodGET_withPxDimensions_generatesImageAndWritesResponse() throws Exception {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    when(ctx.getHeaders()).thenReturn(headers);
    when(request.getParam("text")).thenReturn(TEXT);
    when(request.getParam("width")).thenReturn("120px");
    when(request.getParam("height")).thenReturn("80px");

    InMemoryBucket bucket = new InMemoryBucket();
    when(ctx.getBucketFactory()).thenReturn(bucketFactory);
    when(bucketFactory.makeBucket(anyLong())).thenReturn(bucket);

    toadlet.handleMethodGET(new URI("/imagecreator/"), request, ctx);

    ArgumentCaptor<Long> lengthCaptor = ArgumentCaptor.forClass(Long.class);
    verify(ctx)
        .sendReplyHeadersStatic(
            eq(200),
            eq("OK"),
            any(),
            eq("image/png"),
            lengthCaptor.capture(),
            eq(ImageCreatorToadlet.LAST_MODIFIED));
    verify(ctx).writeData(bucket);
    assertTrue(bucket.size() > 0);
    assertEquals(bucket.size(), lengthCaptor.getValue());
    assertArrayEquals(new byte[] {(byte) 0x89, 0x50, 0x4E, 0x47}, bucket.peekSignature());
  }

  @Test
  void handleMethodGET_withInvalidDimensions_triggersErrorReply() {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    when(ctx.getHeaders()).thenReturn(headers);
    when(request.getParam("text")).thenReturn(TEXT);
    when(request.getParam("width")).thenReturn("-5");
    when(request.getParam("height")).thenReturn("10");

    ShortCircuitToadlet failingToadlet = new ShortCircuitToadlet();

    ToadletContextClosedException thrown =
        assertThrows(
            ToadletContextClosedException.class,
            () -> failingToadlet.handleMethodGET(new URI("/imagecreator/"), request, ctx));

    assertTrue(failingToadlet.htmlReplyCalled);
    assertEquals(ToadletContextClosedException.class, thrown.getClass());
  }

  @Test
  void path_returnsRootUrl() {
    assertEquals("/imagecreator/", toadlet.path());
  }

  private static final class InMemoryBucket implements RandomAccessBucket {
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    @Override
    public OutputStream getOutputStream() {
      return buffer;
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() {
      return new OutputStream() {
        @Override
        public void write(int b) {
          buffer.write(b);
        }

        @Override
        public void write(byte @NotNull [] b, int off, int len) {
          buffer.write(b, off, len);
        }

        @Override
        public void close() {
          // align with unbuffered semantics: leave buffer reusable for assertions
        }
      };
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
      return false;
    }

    @Override
    public void setReadOnly() {
      // no-op
    }

    @Override
    public void free() {
      buffer.reset();
    }

    @Override
    public RandomAccessBucket createShadow() {
      return this;
    }

    @Override
    public void onResume(network.crypta.support.api.ResumeContext context) {
      // no-op
    }

    @Override
    public void storeTo(java.io.DataOutputStream dos) throws IOException {
      dos.write(buffer.toByteArray());
    }

    @Override
    public LockableRandomAccessBuffer toRandomAccessBuffer() {
      throw new UnsupportedOperationException("not required for tests");
    }

    byte[] peekSignature() {
      byte[] data = buffer.toByteArray();
      int length = Math.min(4, data.length);
      byte[] signature = new byte[length];
      System.arraycopy(data, 0, signature, 0, length);
      return signature;
    }
  }

  private static final class ShortCircuitToadlet extends ImageCreatorToadlet {
    boolean htmlReplyCalled = false;

    ShortCircuitToadlet() {
      super(null);
    }

    @Override
    protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply)
        throws ToadletContextClosedException {
      htmlReplyCalled = true;
      throw new ToadletContextClosedException();
    }
  }
}
