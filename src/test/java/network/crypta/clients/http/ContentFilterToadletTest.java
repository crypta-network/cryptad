package network.crypta.clients.http;

import java.io.OutputStream;
import java.io.Serial;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.DefaultMIMETypes;
import network.crypta.client.filter.ContentFilter.FilterStatus;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.ContentFilterCallbacks;
import network.crypta.client.filter.ContentFilterRequest;
import network.crypta.client.filter.FilterOperation;
import network.crypta.client.filter.UnsafeContentTypeException;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.api.HTTPUploadedFile;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ContentFilterToadletTest {
  private static final String FILTER_URI_PROPERTY =
      "network.crypta.clients.http.ContentFilterToadlet.loopbackUri";
  private static final URI DEFAULT_FILTER_URI = URI.create("http://127.0.0.1:8888/");

  private BrowseContentClient client;
  private SimpleToadletServer container;
  private ToadletContext ctx;
  private BucketFactory bucketFactory;
  private PageMaker pageMaker;
  private PageNode pageNode;
  private HTMLNode contentNode;
  private UserAlertManager alertManager;

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() {
    client = mock(BrowseContentClient.class);
    container = mock(SimpleToadletServer.class);
    ctx = mock(ToadletContext.class);
    bucketFactory = mock(BucketFactory.class);
    pageMaker = mock(PageMaker.class);
    pageNode = mock(PageNode.class);
    contentNode = mock(HTMLNode.class);
    alertManager = mock(UserAlertManager.class);
  }

  @AfterEach
  void tearDown() {
    System.clearProperty(FILTER_URI_PROPERTY);
  }

  @Test
  void isEnabled_whenAdvancedAndPrivateMode_returnsTrue() {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
    toadlet.container = container;

    when(container.publicGatewayMode()).thenReturn(false);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);

    assertTrue(toadlet.isEnabled(ctx));
  }

  @Test
  void isEnabled_whenPublicGatewayWithoutFullAccess_returnsFalse() {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
    toadlet.container = container;

    when(container.publicGatewayMode()).thenReturn(true);
    when(ctx.isAdvancedModeEnabled()).thenReturn(true);
    when(ctx.isAllowedFullAccess()).thenReturn(false);

    assertFalse(toadlet.isEnabled(ctx));
  }

  @Test
  void isEnabled_whenContextIsNull_returnsFalse() {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
    toadlet.container = container;

    assertFalse(toadlet.isEnabled(null));
  }

  @Test
  void path_whenInvoked_returnsContentFilterPath() {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);

    assertEquals(ContentFilterToadlet.CONTENT_FILTER_PATH, toadlet.path());
  }

  @Test
  void getFilterOperation_whenInvalidValue_throwsBadRequestException() throws Exception {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringFailsafe("filter-operation", 100)).thenReturn("not-an-enum");

    Method method =
        ContentFilterToadlet.class.getDeclaredMethod("getFilterOperation", HTTPRequest.class);
    method.setAccessible(true);

    assertThrows(BadRequestException.class, () -> invokeWithException(method, toadlet, request));
  }

  @Test
  void getResultHandling_whenInvalidValue_throwsBadRequestException() throws Exception {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getPartAsStringFailsafe("result-handling", 100)).thenReturn("not-an-enum");

    Method method =
        ContentFilterToadlet.class.getDeclaredMethod("getResultHandling", HTTPRequest.class);
    method.setAccessible(true);

    assertThrows(BadRequestException.class, () -> invokeWithException(method, toadlet, request));
  }

  @Test
  void handleMethodGET_whenPublicGatewayWithoutFullAccess_sendsUnauthorizedPage() throws Exception {
    ContentFilterToadlet toadlet = spy(new ContentFilterToadlet(client));
    toadlet.container = container;
    when(container.publicGatewayMode()).thenReturn(true);
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    doNothing().when(toadlet).sendUnauthorizedPage(ctx);

    toadlet.handleMethodGET(
        URI.create("http://localhost" + ContentFilterToadlet.CONTENT_FILTER_PATH),
        mock(HTTPRequest.class),
        ctx);

    verify(toadlet).sendUnauthorizedPage(ctx);
    verify(ctx, never()).getPageMaker();
  }

  @Test
  void handleMethodGET_whenAllowed_rendersFilterPage() throws Exception {
    ContentFilterToadlet toadlet = spy(new ContentFilterToadlet(client));
    toadlet.container = container;
    HTMLNode summaryNode = new HTMLNode("div", "summary");
    HTMLNode infoboxOuter = new HTMLNode("div");
    HTMLNode infoboxContent = infoboxOuter.addChild("div");
    InfoboxNode infobox = new InfoboxNode(infoboxOuter, infoboxContent);
    HTMLNode formNode = new HTMLNode("form");
    String generatedHtml = "<html>filter-page</html>";

    when(container.publicGatewayMode()).thenReturn(false);
    when(ctx.isAllowedFullAccess()).thenReturn(true);
    when(ctx.getPageMaker()).thenReturn(pageMaker);
    when(ctx.getAlertManager()).thenReturn(alertManager);
    when(alertManager.createSummary()).thenReturn(summaryNode);
    when(pageMaker.getPageNode(ContentFilterToadlet.l10n("pageTitle"), ctx)).thenReturn(pageNode);
    when(pageNode.getContentNode()).thenReturn(contentNode);
    when(pageNode.generate()).thenReturn(generatedHtml);
    when(pageMaker.getInfobox(ContentFilterToadlet.l10n("filterFile"), "filter-file", true))
        .thenReturn(infobox);
    when(ctx.addFormChild(infoboxContent, ContentFilterToadlet.CONTENT_FILTER_PATH, "filterForm"))
        .thenReturn(formNode);
    doNothing()
        .when(toadlet)
        .writeHTMLReply(ctx, ReplyHeaders.of(200, "OK", "text/html; charset=utf-8"), generatedHtml);

    toadlet.handleMethodGET(
        URI.create("http://localhost" + ContentFilterToadlet.CONTENT_FILTER_PATH),
        mock(HTTPRequest.class),
        ctx);

    verify(contentNode).addChild(summaryNode);
    verify(ctx)
        .addFormChild(infoboxContent, ContentFilterToadlet.CONTENT_FILTER_PATH, "filterForm");
    verify(contentNode).addChild(infoboxOuter);
    verify(toadlet)
        .writeHTMLReply(ctx, ReplyHeaders.of(200, "OK", "text/html; charset=utf-8"), generatedHtml);
  }

  @Test
  void handleMethodPOST_whenPublicGatewayWithoutFullAccess_sendsUnauthorizedPage()
      throws Exception {
    ContentFilterToadlet toadlet = spy(new ContentFilterToadlet(client));
    HTTPRequest request = mock(HTTPRequest.class);
    toadlet.container = container;
    when(container.publicGatewayMode()).thenReturn(true);
    when(ctx.isAllowedFullAccess()).thenReturn(false);
    doNothing().when(toadlet).sendUnauthorizedPage(ctx);

    toadlet.handleMethodPOST(
        URI.create("http://localhost" + ContentFilterToadlet.CONTENT_FILTER_PATH), request, ctx);

    verify(toadlet).sendUnauthorizedPage(ctx);
  }

  @Test
  void handleMethodPOST_whenBrowseRequested_redirectsToLocalFileBrowserAndFreesParts()
      throws Exception {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
    HTTPRequest request = mock(HTTPRequest.class);
    toadlet.container = container;
    when(container.publicGatewayMode()).thenReturn(false);
    when(request.isPartSet("filter-local")).thenReturn(true);
    when(request.getPartAsStringFailsafe("filter-operation", 100))
        .thenReturn(FilterOperation.BOTH.toString());
    when(request.getPartAsStringFailsafe("result-handling", 100))
        .thenReturn(ContentFilterToadlet.ResultHandling.DISPLAY.toString());
    when(request.getPartAsStringFailsafe("mime-type", 100)).thenReturn("text/plain");

    @SuppressWarnings("unchecked")
    ArgumentCaptor<MultiValueTable<String, String>> headersCaptor =
        ArgumentCaptor.forClass(MultiValueTable.class);

    toadlet.handleMethodPOST(
        URI.create("http://localhost" + ContentFilterToadlet.CONTENT_FILTER_PATH), request, ctx);

    verify(ctx).sendReplyHeaders(eq(302), eq("Found"), headersCaptor.capture(), eq(null), eq(0L));
    assertEquals(
        LocalFileFilterToadlet.BROWSE_PATH
            + "?filter-operation=BOTH&result-handling=DISPLAY&mime-type=text/plain",
        headersCaptor.getValue().getFirst("Location"));
    verify(request).freeParts();
  }

  @Test
  void handleMethodPOST_whenNoActionParts_delegatesToGetAndFreesParts() throws Exception {
    ContentFilterToadlet toadlet = spy(new ContentFilterToadlet(client));
    HTTPRequest request = mock(HTTPRequest.class);
    URI uri = URI.create("http://localhost" + ContentFilterToadlet.CONTENT_FILTER_PATH);
    toadlet.container = container;
    when(container.publicGatewayMode()).thenReturn(false);
    doNothing().when(toadlet).handleMethodGET(eq(uri), any(HTTPRequest.class), eq(ctx));
    ArgumentCaptor<HTTPRequest> requestCaptor = ArgumentCaptor.forClass(HTTPRequest.class);

    toadlet.handleMethodPOST(uri, request, ctx);

    verify(toadlet).handleMethodGET(eq(uri), requestCaptor.capture(), eq(ctx));
    assertInstanceOf(HTTPRequestImpl.class, requestCaptor.getValue());
    verify(request).freeParts();
  }

  @Test
  void handleMethodPOST_whenUploadRequested_filtersUploadedFileUsingUploadedMimeTypeAndDefaultUri()
      throws Exception {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
    HTTPRequest request = mock(HTTPRequest.class);
    HTTPUploadedFile uploadedFile = mock(HTTPUploadedFile.class);
    toadlet.container = container;
    when(container.publicGatewayMode()).thenReturn(false);
    when(request.isPartSet("filter-local")).thenReturn(false);
    when(request.isPartSet(LocalFileBrowserToadlet.SELECT_FILE)).thenReturn(false);
    when(request.isPartSet("filter-upload")).thenReturn(true);
    when(request.getPartAsStringFailsafe("filter-operation", 100))
        .thenReturn(FilterOperation.READ.toString());
    when(request.getPartAsStringFailsafe("result-handling", 100))
        .thenReturn(ContentFilterToadlet.ResultHandling.DISPLAY.toString());
    when(request.getPartAsStringFailsafe("mime-type", 100)).thenReturn("");
    when(request.getUploadedFile("filename")).thenReturn(uploadedFile);
    when(uploadedFile.getFilename()).thenReturn("upload.txt");
    when(uploadedFile.getContentType()).thenReturn("text/uploaded");
    AtomicReference<ContentFilterRequest> capturedRequest = new AtomicReference<>();
    AtomicReference<ContentFilterCallbacks> capturedCallbacks = new AtomicReference<>();
    byte[] filtered = "filtered-upload".getBytes(StandardCharsets.UTF_8);

    try (ArrayBucket uploadData = new ArrayBucket("input".getBytes(StandardCharsets.UTF_8));
        ArrayBucket resultBucket = new ArrayBucket()) {
      when(uploadedFile.getData()).thenReturn(uploadData);
      when(ctx.getBucketFactory()).thenReturn(bucketFactory);
      when(bucketFactory.makeBucket(-1)).thenReturn(resultBucket);
      System.setProperty(FILTER_URI_PROPERTY, "not a uri");

      try (MockedStatic<ContentFilter> mockedFilter =
          org.mockito.Mockito.mockStatic(ContentFilter.class)) {
        stubFilter(mockedFilter, filtered, "text/filtered", capturedRequest, capturedCallbacks);

        toadlet.handleMethodPOST(
            URI.create("http://localhost" + ContentFilterToadlet.CONTENT_FILTER_PATH),
            request,
            ctx);
      }

      assertEquals("text/uploaded", capturedRequest.get().typeName());
      assertEquals(DEFAULT_FILTER_URI, capturedCallbacks.get().baseURI());
      assertSame(container, capturedCallbacks.get().linkFilterExceptionProvider());
      verify(ctx).sendReplyHeaders(200, "OK", null, "text/filtered", resultBucket.size());
      verify(ctx).writeData(resultBucket);
      verify(request).freeParts();
    }
  }

  @Test
  void handleMethodPOST_whenLocalFileSelected_filtersExistingFileUsingGuessedMimeType()
      throws Exception {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
    HTTPRequest request = mock(HTTPRequest.class);
    toadlet.container = container;
    when(container.publicGatewayMode()).thenReturn(false);
    when(request.isPartSet("filter-local")).thenReturn(false);
    when(request.isPartSet(LocalFileBrowserToadlet.SELECT_FILE)).thenReturn(true);
    when(request.getPartAsStringFailsafe("filter-operation", 100))
        .thenReturn(FilterOperation.READ.toString());
    when(request.getPartAsStringFailsafe("result-handling", 100))
        .thenReturn(ContentFilterToadlet.ResultHandling.DISPLAY.toString());
    when(request.getPartAsStringFailsafe("mime-type", 100)).thenReturn("");
    Path inputFile = tempDir.resolve("page.html");
    Files.writeString(inputFile, "<html>input</html>", StandardCharsets.UTF_8);
    when(request.getPartAsStringFailsafe("filename", QueueToadlet.MAX_FILENAME_LENGTH))
        .thenReturn(inputFile.toString());
    String expectedMimeType = DefaultMIMETypes.guessMIMEType(inputFile.toString(), false);
    AtomicReference<ContentFilterRequest> capturedRequest = new AtomicReference<>();
    byte[] filtered = "filtered-local".getBytes(StandardCharsets.UTF_8);

    try (ArrayBucket resultBucket = new ArrayBucket()) {
      when(ctx.getBucketFactory()).thenReturn(bucketFactory);
      when(bucketFactory.makeBucket(-1)).thenReturn(resultBucket);

      try (MockedStatic<ContentFilter> mockedFilter =
          org.mockito.Mockito.mockStatic(ContentFilter.class)) {
        stubFilter(mockedFilter, filtered, "text/html", capturedRequest, new AtomicReference<>());

        toadlet.handleMethodPOST(
            URI.create("http://localhost" + ContentFilterToadlet.CONTENT_FILTER_PATH),
            request,
            ctx);
      }

      assertEquals(expectedMimeType, capturedRequest.get().typeName());
      verify(ctx).sendReplyHeaders(200, "OK", null, "text/html", resultBucket.size());
      verify(ctx).writeData(resultBucket);
      verify(request).freeParts();
    }
  }

  @Test
  void handleFilter_whenDisplayHandling_writesHeadersAndBucket() throws Exception {
    ContentFilterToadlet toadlet = spy(new ContentFilterToadlet(client));
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
                  //noinspection resource
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
    ContentFilterToadlet toadlet = spy(new ContentFilterToadlet(client));
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
                  //noinspection resource
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
  void handleFilter_whenContainerMissing_throwsIllegalStateException() throws Exception {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
    try (ArrayBucket inputBucket = new ArrayBucket();
        ArrayBucket resultBucket = new ArrayBucket()) {
      when(ctx.getBucketFactory()).thenReturn(bucketFactory);
      when(bucketFactory.makeBucket(-1)).thenReturn(resultBucket);

      assertThrows(
          IllegalStateException.class,
          () ->
              invokeHandleFilter(
                  toadlet,
                  inputBucket,
                  "text/plain",
                  FilterOperation.READ,
                  ContentFilterToadlet.ResultHandling.DISPLAY,
                  "result.txt"));
    }
  }

  @Test
  void handleFilter_whenContainerDoesNotProvideLinkExceptions_throwsIllegalStateException()
      throws Exception {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
    toadlet.container = mock(ToadletContainer.class);
    try (ArrayBucket inputBucket = new ArrayBucket();
        ArrayBucket resultBucket = new ArrayBucket()) {
      when(ctx.getBucketFactory()).thenReturn(bucketFactory);
      when(bucketFactory.makeBucket(-1)).thenReturn(resultBucket);

      assertThrows(
          IllegalStateException.class,
          () ->
              invokeHandleFilter(
                  toadlet,
                  inputBucket,
                  "text/plain",
                  FilterOperation.READ,
                  ContentFilterToadlet.ResultHandling.DISPLAY,
                  "result.txt"));
    }
  }

  @Test
  void handleFilter_whenResultHandlingUnknown_throwsBadRequestException() throws Exception {
    ContentFilterToadlet toadlet = new ContentFilterToadlet(client);
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
    ContentFilterToadlet toadlet = spy(new ContentFilterToadlet(client));
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

  private void stubFilter(
      MockedStatic<ContentFilter> mockedFilter,
      byte[] filtered,
      String resultMimeType,
      AtomicReference<ContentFilterRequest> capturedRequest,
      AtomicReference<ContentFilterCallbacks> capturedCallbacks) {
    mockedFilter
        .when(
            () ->
                ContentFilter.filter(
                    any(ContentFilterRequest.class), any(ContentFilterCallbacks.class)))
        .thenAnswer(
            invocation -> {
              capturedRequest.set(invocation.getArgument(0));
              capturedCallbacks.set(invocation.getArgument(1));
              ContentFilterRequest request = invocation.getArgument(0);
              //noinspection resource
              OutputStream output = request.output();
              output.write(filtered);
              try {
                return newFilterStatus(null, resultMimeType);
              } catch (Exception e) {
                throw new RuntimeException(e);
              }
            });
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
            ToadletContext.class);
    method.setAccessible(true);
    try {
      method.invoke(toadlet, data, mimeType, operation, handling, resultFilename, ctx);
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
