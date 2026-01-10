package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.OutputStream;
import java.io.Serial;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.ContentFilter.FilterStatus;
import network.crypta.client.filter.ContentFilterCallbacks;
import network.crypta.client.filter.ContentFilterRequest;
import network.crypta.client.filter.FilterOperation;
import network.crypta.client.filter.UnsafeContentTypeException;
import network.crypta.node.ClientEndpoints;
import network.crypta.node.NodeClientCore;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ContentFilterToadletTest {

  private HighLevelSimpleClient client;
  private NodeClientCore core;
  private SimpleToadletServer container;
  private ToadletContext ctx;
  private BucketFactory bucketFactory;

  @BeforeEach
  void setUp() {
    client = mock(HighLevelSimpleClient.class);
    core = mock(NodeClientCore.class);
    container = mock(SimpleToadletServer.class);
    ctx = mock(ToadletContext.class);
    bucketFactory = mock(BucketFactory.class);
    ClientEndpoints endpoints = mock(ClientEndpoints.class);
    lenient().when(core.getEndpoints()).thenReturn(endpoints);
    lenient().when(endpoints.getToadletContainer()).thenReturn(container);
  }

  @Test
  void isEnabled_whenAdvancedAndPrivateMode_returnsTrue() {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client, core);
    toadlet.container = container;

    when(container.publicGatewayMode()).thenReturn(false);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);

    assertTrue(toadlet.isEnabled(ctx));
  }

  @Test
  void isEnabled_whenPublicGatewayWithoutFullAccess_returnsFalse() {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client, core);
    toadlet.container = container;

    when(container.publicGatewayMode()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(ctx.isAllowedFullAccess()).thenReturn(false);

    assertFalse(toadlet.isEnabled(ctx));
  }

  @Test
  void getFilterOperation_whenInvalidValue_throwsBadRequestException() throws Exception {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client, core);
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringFailsafe("filter-operation", 100)).thenReturn("not-an-enum");

    Method method =
        ContentFilterToadlet.class.getDeclaredMethod("getFilterOperation", HTTPRequest.class);
    method.setAccessible(true);

    assertThrows(BadRequestException.class, () -> invokeWithException(method, toadlet, request));
  }

  @Test
  void handleFilter_whenDisplayHandling_writesHeadersAndBucket() throws Exception {
    ContentFilterToadlet toadlet = spy(new ContentFilterToadlet(client, core));
    toadlet.container = container;
    try (ArrayBucket inputBucket = new ArrayBucket("input".getBytes(StandardCharsets.UTF_8));
        ArrayBucket resultBucket = new ArrayBucket()) {
      when(ctx.getBucketFactory()).thenReturn(bucketFactory);
      when(bucketFactory.makeBucket(-1)).thenReturn(resultBucket);

      byte[] filtered = "filtered".getBytes(StandardCharsets.UTF_8);

      try (MockedStatic<ContentFilter> mockedFilter =
          org.mockito.Mockito.mockStatic(ContentFilter.class)) {
        mockedFilter
            .when(
                () ->
                    ContentFilter.filter(
                        any(ContentFilterRequest.class), any(ContentFilterCallbacks.class)))
            .thenAnswer(
                invocation -> {
                  ContentFilterRequest request = invocation.getArgument(0);
                  OutputStream output = request.output();
                  output.write(filtered);
                  try {
                    return newFilterStatus("utf-8", "text/plain");
                  } catch (Exception e) {
                    throw new RuntimeException(e);
                  }
                });

        invokeHandleFilter(
            toadlet,
            inputBucket,
            "text/plain",
            FilterOperation.BOTH,
            ContentFilterToadlet.ResultHandling.DISPLAY,
            "result.txt");
      }

      assertEquals(filtered.length, resultBucket.size());
      verify(ctx).sendReplyHeaders(200, "OK", null, "text/plain", resultBucket.size());
      verify(ctx).writeData(resultBucket);
    }
  }

  @Test
  void handleFilter_whenSaveHandling_setsAttachmentHeaders() throws Exception {
    ContentFilterToadlet toadlet = spy(new ContentFilterToadlet(client, core));
    toadlet.container = container;
    try (ArrayBucket inputBucket = new ArrayBucket("input".getBytes(StandardCharsets.UTF_8));
        ArrayBucket resultBucket = new ArrayBucket()) {
      when(ctx.getBucketFactory()).thenReturn(bucketFactory);
      when(bucketFactory.makeBucket(-1)).thenReturn(resultBucket);

      byte[] filtered = "bytes".getBytes(StandardCharsets.UTF_8);

      try (MockedStatic<ContentFilter> mockedFilter =
          org.mockito.Mockito.mockStatic(ContentFilter.class)) {
        mockedFilter
            .when(
                () ->
                    ContentFilter.filter(
                        any(ContentFilterRequest.class), any(ContentFilterCallbacks.class)))
            .thenAnswer(
                invocation -> {
                  ContentFilterRequest request = invocation.getArgument(0);
                  OutputStream output = request.output();
                  output.write(filtered);
                  try {
                    return newFilterStatus(null, "application/octet-stream");
                  } catch (Exception e) {
                    throw new RuntimeException(e);
                  }
                });

        invokeHandleFilter(
            toadlet,
            inputBucket,
            "application/octet-stream",
            FilterOperation.READ,
            ContentFilterToadlet.ResultHandling.SAVE,
            "file.filtered.bin");
      }

      @SuppressWarnings("unchecked")
      ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
          ArgumentCaptor.forClass(MultiValueTable.class);
      verify(ctx)
          .sendReplyHeaders(
              eq(200),
              eq("OK"),
              headersCaptor.capture(),
              eq("application/force-download"),
              eq(resultBucket.size()));
      MultiValueTable<String, String> captured = headersCaptor.getValue();
      assertEquals(
          "attachment; filename=\"file.filtered.bin\"", captured.getFirst("Content-Disposition"));
      assertEquals("private", captured.getFirst("Cache-Control"));
      assertEquals("binary", captured.getFirst("Content-Transfer-Encoding"));
      verify(ctx).writeData(resultBucket);
    }
  }

  @Test
  void handleFilter_whenResultHandlingUnknown_throwsBadRequestException() throws Exception {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client, core);
    toadlet.container = container;
    try (ArrayBucket inputBucket = new ArrayBucket();
        ArrayBucket resultBucket = new ArrayBucket()) {
      when(ctx.getBucketFactory()).thenReturn(bucketFactory);
      when(bucketFactory.makeBucket(-1)).thenReturn(resultBucket);

      assertThrows(
          BadRequestException.class,
          () ->
              invokeHandleFilter(
                  toadlet, inputBucket, "text/plain", FilterOperation.WRITE, null, "result.txt"));
    }
  }

  @Test
  void handleFilter_whenFilterMarksUnsafe_sendsErrorPage() throws Exception {
    ContentFilterToadlet toadlet = spy(new ContentFilterToadlet(client, core));
    toadlet.container = container;
    try (ArrayBucket inputBucket = new ArrayBucket();
        ArrayBucket resultBucket = new ArrayBucket()) {
      when(ctx.getBucketFactory()).thenReturn(bucketFactory);
      when(bucketFactory.makeBucket(-1)).thenReturn(resultBucket);
      doNothing().when(toadlet).sendErrorPage(any(), anyInt(), anyString(), anyString());

      try (MockedStatic<ContentFilter> mockedFilter =
          org.mockito.Mockito.mockStatic(ContentFilter.class)) {
        mockedFilter
            .when(
                () ->
                    ContentFilter.filter(
                        any(ContentFilterRequest.class), any(ContentFilterCallbacks.class)))
            .thenThrow(
                new UnsafeContentTypeException() {
                  @Serial private static final long serialVersionUID = 1L;

                  @Override
                  public String getHTMLEncodedTitle() {
                    return "unsafe";
                  }

                  @Override
                  public String getRawTitle() {
                    return "unsafe";
                  }

                  @Override
                  public String getMessage() {
                    return "unsafe";
                  }
                });

        invokeHandleFilter(
            toadlet,
            inputBucket,
            "text/plain",
            FilterOperation.READ,
            ContentFilterToadlet.ResultHandling.DISPLAY,
            "result.txt");
      }

      verify(toadlet).sendErrorPage(eq(ctx), eq(200), anyString(), anyString());
      verify(ctx, never()).sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
      verify(ctx, never()).writeData(any(Bucket.class));
    }
  }

  private FilterStatus newFilterStatus(String charset, String mimeType) throws Exception {
    Constructor<FilterStatus> constructor =
        FilterStatus.class.getDeclaredConstructor(String.class, String.class);
    constructor.setAccessible(true);
    return constructor.newInstance(charset, mimeType);
  }

  private void invokeHandleFilter(
      ContentFilterToadlet toadlet,
      Bucket data,
      String mimeType,
      FilterOperation operation,
      ContentFilterToadlet.ResultHandling handling,
      String resultFilename)
      throws Exception {
    Method method =
        ContentFilterToadlet.class.getDeclaredMethod(
            "handleFilter",
            Bucket.class,
            String.class,
            FilterOperation.class,
            ContentFilterToadlet.ResultHandling.class,
            String.class,
            ToadletContext.class,
            NodeClientCore.class);
    method.setAccessible(true);
    try {
      method.invoke(toadlet, data, mimeType, operation, handling, resultFilename, ctx, core);
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof Exception exception) {
        throw exception;
      }
      throw e;
    }
  }

  private void invokeWithException(Method method, Object target, Object... args) throws Exception {
    try {
      method.invoke(target, args);
    } catch (InvocationTargetException e) {
      Throwable cause = e.getCause();
      if (cause instanceof Exception exception) {
        throw exception;
      }
      throw e;
    }
  }
}
