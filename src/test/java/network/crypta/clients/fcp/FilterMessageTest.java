package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.async.ClientContext;
import network.crypta.client.filter.ContentFilter;
import network.crypta.client.filter.ContentFilter.FilterStatus;
import network.crypta.client.filter.ContentFilterCallbacks;
import network.crypta.client.filter.ContentFilterRequest;
import network.crypta.client.filter.FilterOperation;
import network.crypta.client.filter.UnsafeContentTypeException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.ArrayBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FilterMessageTest {

  private static final BucketFactory ARRAY_BUCKET_FACTORY = new ArrayBucketFactory();

  @TempDir Path tempDir;

  @Test
  void constructor_directSourceWithoutMimeType_expectMissingField() {
    SimpleFieldSet fs = baseFieldSet("req-direct-mime", DataSource.DIRECT);
    fs.put("DataLength", 5L);

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class, () -> new FilterMessage(fs, ARRAY_BUCKET_FACTORY));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("req-direct-mime", exception.ident);
  }

  @Test
  void constructor_directSourceWithNonNumericDataLength_expectParsingError() {
    SimpleFieldSet fs = baseFieldSet("req-direct-length", DataSource.DIRECT);
    fs.putSingle("MimeType", "text/plain");
    fs.putSingle("DataLength", "abc");

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class, () -> new FilterMessage(fs, ARRAY_BUCKET_FACTORY));

    assertEquals(ProtocolErrorMessage.ERROR_PARSING_NUMBER, exception.protocolCode);
    assertEquals("req-direct-length", exception.ident);
  }

  @Test
  void constructor_diskSourceWithoutFilename_expectMissingField() {
    SimpleFieldSet fs = baseFieldSet("req-disk-filename", DataSource.DISK);

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class, () -> new FilterMessage(fs, ARRAY_BUCKET_FACTORY));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("req-disk-filename", exception.ident);
  }

  @Test
  void constructor_diskSourceWithMissingFile_expectFileNotFound() {
    SimpleFieldSet fs = baseFieldSet("req-disk-missing", DataSource.DISK);
    Path missingFile = tempDir.resolve("missing-file.bin");
    fs.putSingle("Filename", missingFile.toString());

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class, () -> new FilterMessage(fs, ARRAY_BUCKET_FACTORY));

    assertEquals(ProtocolErrorMessage.FILE_NOT_FOUND, exception.protocolCode);
    assertEquals("req-disk-missing", exception.ident);
  }

  @Test
  void constructor_diskSourceWithoutMimeType_guessFromExtension()
      throws IOException, MessageInvalidException {
    Path htmlFile = Files.createTempFile(tempDir, "sample", ".html");
    Files.writeString(htmlFile, "<html/>", StandardCharsets.UTF_8);
    SimpleFieldSet fs = baseFieldSet("req-disk-guess", DataSource.DISK);
    fs.putSingle("Filename", htmlFile.toString());

    FilterMessage message = new FilterMessage(fs, ARRAY_BUCKET_FACTORY);
    SimpleFieldSet serialized = message.getFieldSet();

    assertEquals("text/html", serialized.get("MimeType"));
    assertEquals(-1, serialized.getLong("DataLength", 0));
  }

  @Test
  void constructor_diskSourceWithoutDetectableMime_expectBadMimeType() throws IOException {
    Path binaryFile = Files.createTempFile(tempDir, "sample", ".unknownext");
    Files.write(binaryFile, new byte[] {1, 2, 3});
    SimpleFieldSet fs = baseFieldSet("req-disk-badmime", DataSource.DISK);
    fs.putSingle("Filename", binaryFile.toString());

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class, () -> new FilterMessage(fs, ARRAY_BUCKET_FACTORY));

    assertEquals(ProtocolErrorMessage.BAD_MIME_TYPE, exception.protocolCode);
    assertEquals("req-disk-badmime", exception.ident);
  }

  @Test
  void getFieldSet_directSourceContainsSuppliedValues() throws MessageInvalidException {
    SimpleFieldSet fs = baseFieldSet("req-fieldset", DataSource.DIRECT);
    fs.putSingle("MimeType", "text/plain");
    fs.put("DataLength", 3L);
    fs.putSingle("Filename", "/tmp/example.txt");

    FilterMessage message = new FilterMessage(fs, ARRAY_BUCKET_FACTORY);
    SimpleFieldSet serialized = message.getFieldSet();

    assertEquals("req-fieldset", serialized.get("Identifier"));
    assertEquals(FilterOperation.BOTH.name(), serialized.get("Operation"));
    assertEquals(DataSource.DIRECT.name(), serialized.get("DataSource"));
    assertEquals("text/plain", serialized.get("MimeType"));
    assertEquals("/tmp/example.txt", serialized.get("Filename"));
    assertEquals(3, serialized.getLong("DataLength", -1));
  }

  @Test
  void run_whenBucketMissing_expectMissingField() throws MessageInvalidException {
    FilterMessage message = createDirectMessage("req-run-nobucket", new byte[] {1, 2, 3});
    message.bucket = null;

    FCPConnectionHandler handler = handlerWithContext(Mockito.mock(ClientContext.class));

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class,
            () ->
                message.run(
                    handler, Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS)));

    assertEquals(ProtocolErrorMessage.MISSING_FIELD, exception.protocolCode);
    assertEquals("req-run-nobucket", exception.ident);
    Mockito.verify(handler, Mockito.never()).send(Mockito.any());
  }

  @Test
  void run_whenBucketFactoryFails_expectInternalError() throws MessageInvalidException {
    SimpleFieldSet fs = baseFieldSet("req-run-bf", DataSource.DIRECT);
    fs.putSingle("MimeType", "text/plain");
    fs.put("DataLength", 4L);
    BucketFactory failingFactory = Mockito.mock(BucketFactory.class);
    try {
      Mockito.when(failingFactory.makeBucket(Mockito.anyLong()))
          .thenThrow(new IOException("disk full"));
    } catch (IOException e) {
      fail(e);
    }
    FilterMessage message = new FilterMessage(fs, failingFactory);
    message.bucket = new SimpleReadOnlyArrayBucket(new byte[] {9, 9, 9, 9});

    FCPConnectionHandler handler = handlerWithContext(Mockito.mock(ClientContext.class));

    MessageInvalidException exception =
        assertThrows(
            MessageInvalidException.class,
            () ->
                message.run(
                    handler, Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS)));

    assertEquals(ProtocolErrorMessage.INTERNAL_ERROR, exception.protocolCode);
    assertEquals("req-run-bf", exception.ident);
    Mockito.verify(handler, Mockito.never()).send(Mockito.any());
  }

  @Test
  void run_whenContentFilterSucceeds_sendsResultMessage() throws Exception {
    byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
    FilterMessage message = createDirectMessage("req-run-success", payload);

    ClientContext clientContext = Mockito.mock(ClientContext.class);
    FCPConnectionHandler handler = handlerWithContext(clientContext);
    ArgumentCaptor<FilterResultMessage> responseCaptor =
        ArgumentCaptor.forClass(FilterResultMessage.class);

    FilterStatus status = filterStatusUtf8Text();

    try (MockedStatic<ContentFilter> staticFilter = Mockito.mockStatic(ContentFilter.class)) {
      staticFilter
          .when(
              () ->
                  ContentFilter.filter(
                      Mockito.any(ContentFilterRequest.class),
                      Mockito.any(ContentFilterCallbacks.class)))
          .thenAnswer(
              invocation -> {
                ContentFilterRequest request = invocation.getArgument(0);
                InputStream input = request.input();
                OutputStream output = request.output();
                output.write(input.readAllBytes());
                return status;
              });

      message.run(handler, Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS));
    }

    Mockito.verify(handler).send(responseCaptor.capture());
    FilterResultMessage response = responseCaptor.getValue();

    assertEquals("req-run-success", response.getIdentifier());
    assertFalse(response.getFieldSet().getBoolean("UnsafeContentType", true));
    assertEquals("UTF-8", response.getFieldSet().get("Charset"));
    assertEquals("text/plain", response.getFieldSet().get("MimeType"));
    assertEquals(payload.length, response.dataLength());
    assertNotNull(response.bucket);
    try (InputStream stored = response.bucket.getInputStream()) {
      assertArrayEquals(payload, stored.readAllBytes());
    } catch (IOException e) {
      fail(e);
    }
  }

  @Test
  void run_whenContentFilterSignalsUnsafe_setsUnsafeFlag() throws Exception {
    byte[] payload = "unsafe".getBytes(StandardCharsets.UTF_8);
    FilterMessage message = createDirectMessage("req-run-unsafe", payload);

    ClientContext clientContext = Mockito.mock(ClientContext.class);
    FCPConnectionHandler handler = handlerWithContext(clientContext);
    ArgumentCaptor<FilterResultMessage> responseCaptor =
        ArgumentCaptor.forClass(FilterResultMessage.class);

    UnsafeContentTypeException unsafe =
        new UnsafeContentTypeException() {
          @Override
          public String getMessage() {
            return "unsafe";
          }

          @Override
          public String getHTMLEncodedTitle() {
            return "unsafe";
          }

          @Override
          public String getRawTitle() {
            return "unsafe";
          }
        };

    try (MockedStatic<ContentFilter> staticFilter = Mockito.mockStatic(ContentFilter.class)) {
      staticFilter
          .when(
              () ->
                  ContentFilter.filter(
                      Mockito.any(ContentFilterRequest.class),
                      Mockito.any(ContentFilterCallbacks.class)))
          .thenThrow(unsafe);

      message.run(handler, Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS));
    }

    Mockito.verify(handler).send(responseCaptor.capture());
    FilterResultMessage response = responseCaptor.getValue();

    assertEquals("req-run-unsafe", response.getIdentifier());
    assertTrue(response.getFieldSet().getBoolean("UnsafeContentType", false));
    assertEquals(-1, response.dataLength());
    assertNull(response.bucket);
  }

  private FilterMessage createDirectMessage(String identifier, byte[] payload)
      throws MessageInvalidException {
    SimpleFieldSet fs = baseFieldSet(identifier, DataSource.DIRECT);
    fs.putSingle("MimeType", "text/plain");
    fs.put("DataLength", payload.length);
    FilterMessage message = new FilterMessage(fs, ARRAY_BUCKET_FACTORY);
    message.bucket = new SimpleReadOnlyArrayBucket(payload);
    return message;
  }

  private SimpleFieldSet baseFieldSet(String identifier, DataSource dataSource) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(FCPMessage.IDENTIFIER, identifier);
    fs.putSingle("Operation", FilterOperation.BOTH.name());
    fs.putSingle("DataSource", dataSource.name());
    return fs;
  }

  private FCPConnectionHandler handlerWithContext(ClientContext context) {
    FCPConnectionHandler handler = Mockito.mock(FCPConnectionHandler.class);
    FCPServer server = Mockito.mock(FCPServer.class);
    NodeClientCore core = Mockito.mock(NodeClientCore.class);
    Mockito.lenient().when(handler.getServer()).thenReturn(server);
    Mockito.lenient().when(server.getCore()).thenReturn(core);
    Mockito.lenient().when(core.getClientContext()).thenReturn(context);
    return handler;
  }

  @SuppressWarnings("java:S3011")
  private FilterStatus filterStatusUtf8Text() {
    try {
      Constructor<FilterStatus> constructor =
          ContentFilter.FilterStatus.class.getDeclaredConstructor(String.class, String.class);
      constructor.setAccessible(true);
      return constructor.newInstance("UTF-8", "text/plain");
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Unable to construct FilterStatus", e);
    }
  }
}
