package network.crypta.clients.fcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import network.crypta.client.filter.FilterOperation;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.SimpleReadOnlyArrayBucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.ArrayBucketFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FilterMessageTest {

  private static final BucketFactory ARRAY_BUCKET_FACTORY = new ArrayBucketFactory();
  private static final String FILTER_URI_PROPERTY =
      "network.crypta.clients.fcp.FilterMessage.loopbackUri";
  private static final URI DEFAULT_FILTER_URI = URI.create("http://127.0.0.1:8888/");

  @TempDir Path tempDir;

  @AfterEach
  void clearFilterUriProperty() {
    System.clearProperty(FILTER_URI_PROPERTY);
  }

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

    FcpMessageRuntimeSupport runtimeSupport = Mockito.mock(FcpMessageRuntimeSupport.class);
    FCPConnectionHandler handler = handlerWithRuntimeSupport(runtimeSupport);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

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

    FcpMessageRuntimeSupport runtimeSupport = Mockito.mock(FcpMessageRuntimeSupport.class);
    FCPConnectionHandler handler = handlerWithRuntimeSupport(runtimeSupport);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.INTERNAL_ERROR, exception.protocolCode);
    assertEquals("req-run-bf", exception.ident);
    Mockito.verify(handler, Mockito.never()).send(Mockito.any());
  }

  @Test
  void run_whenContentFilterSucceeds_sendsResultMessage() throws Exception {
    byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
    FilterMessage message = createDirectMessage("req-run-success", payload);

    FcpMessageRuntimeSupport runtimeSupport = Mockito.mock(FcpMessageRuntimeSupport.class);
    FCPConnectionHandler handler = handlerWithRuntimeSupport(runtimeSupport);
    ArgumentCaptor<FilterResultMessage> responseCaptor =
        ArgumentCaptor.forClass(FilterResultMessage.class);
    ArgumentCaptor<URI> uriCaptor = ArgumentCaptor.forClass(URI.class);

    Mockito.when(
            runtimeSupport.filterContent(
                Mockito.any(InputStream.class),
                Mockito.any(OutputStream.class),
                Mockito.anyString(),
                uriCaptor.capture()))
        .thenAnswer(
            invocation -> {
              InputStream input = invocation.getArgument(0);
              OutputStream output = invocation.getArgument(1);
              output.write(input.readAllBytes());
              return FcpFilterResult.safe("UTF-8", "text/plain");
            });

    message.run(handler);

    Mockito.verify(handler).send(responseCaptor.capture());
    Mockito.verify(runtimeSupport)
        .filterContent(
            Mockito.any(InputStream.class),
            Mockito.any(OutputStream.class),
            Mockito.eq("text/plain"),
            Mockito.any(URI.class));
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
    assertEquals(DEFAULT_FILTER_URI, uriCaptor.getValue());
  }

  @Test
  void run_whenFilterUriPropertyValid_usesConfiguredUri() throws Exception {
    byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
    FilterMessage message = createDirectMessage("req-run-custom-uri", payload);
    URI configuredUri = URI.create("http://127.0.0.1:9999/filter");

    System.setProperty(FILTER_URI_PROPERTY, configuredUri.toString());

    FcpMessageRuntimeSupport runtimeSupport = Mockito.mock(FcpMessageRuntimeSupport.class);
    FCPConnectionHandler handler = handlerWithRuntimeSupport(runtimeSupport);
    ArgumentCaptor<URI> uriCaptor = ArgumentCaptor.forClass(URI.class);

    Mockito.when(
            runtimeSupport.filterContent(
                Mockito.any(InputStream.class),
                Mockito.any(OutputStream.class),
                Mockito.anyString(),
                uriCaptor.capture()))
        .thenAnswer(
            invocation -> {
              OutputStream output = invocation.getArgument(1);
              output.write(invocation.getArgument(0, InputStream.class).readAllBytes());
              return FcpFilterResult.safe("UTF-8", "text/plain");
            });

    message.run(handler);

    assertEquals(configuredUri, uriCaptor.getValue());
  }

  @Test
  void run_whenFilterUriPropertyInvalid_fallsBackToDefaultUri() throws Exception {
    byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
    FilterMessage message = createDirectMessage("req-run-context", payload);

    System.setProperty(FILTER_URI_PROPERTY, "not a uri");

    FcpMessageRuntimeSupport runtimeSupport = Mockito.mock(FcpMessageRuntimeSupport.class);
    FCPConnectionHandler handler = handlerWithRuntimeSupport(runtimeSupport);
    ArgumentCaptor<URI> uriCaptor = ArgumentCaptor.forClass(URI.class);

    Mockito.when(
            runtimeSupport.filterContent(
                Mockito.any(InputStream.class),
                Mockito.any(OutputStream.class),
                Mockito.anyString(),
                uriCaptor.capture()))
        .thenAnswer(
            invocation -> {
              OutputStream output = invocation.getArgument(1);
              output.write(invocation.getArgument(0, InputStream.class).readAllBytes());
              return FcpFilterResult.safe("UTF-8", "text/plain");
            });

    message.run(handler);

    assertEquals(DEFAULT_FILTER_URI, uriCaptor.getValue());
  }

  @Test
  void run_whenRuntimeFilterThrowsIo_expectInternalError() throws Exception {
    byte[] payload = "payload".getBytes(StandardCharsets.UTF_8);
    FilterMessage message = createDirectMessage("req-run-io", payload);
    IOException ioException = new IOException("filter failed");

    FcpMessageRuntimeSupport runtimeSupport = Mockito.mock(FcpMessageRuntimeSupport.class);
    FCPConnectionHandler handler = handlerWithRuntimeSupport(runtimeSupport);
    Mockito.when(
            runtimeSupport.filterContent(
                Mockito.any(InputStream.class),
                Mockito.any(OutputStream.class),
                Mockito.anyString(),
                Mockito.any(URI.class)))
        .thenThrow(ioException);

    MessageInvalidException exception =
        assertThrows(MessageInvalidException.class, () -> message.run(handler));

    assertEquals(ProtocolErrorMessage.INTERNAL_ERROR, exception.protocolCode);
    assertEquals("IO error running content filter", exception.getMessage());
    assertEquals("req-run-io", exception.ident);
    assertEquals(ioException, exception.getCause());
    Mockito.verify(handler, Mockito.never()).send(Mockito.any());
  }

  @Test
  void run_whenContentFilterSignalsUnsafe_setsUnsafeFlag() throws Exception {
    byte[] payload = "unsafe".getBytes(StandardCharsets.UTF_8);
    FilterMessage message = createDirectMessage("req-run-unsafe", payload);

    FcpMessageRuntimeSupport runtimeSupport = Mockito.mock(FcpMessageRuntimeSupport.class);
    FCPConnectionHandler handler = handlerWithRuntimeSupport(runtimeSupport);
    ArgumentCaptor<FilterResultMessage> responseCaptor =
        ArgumentCaptor.forClass(FilterResultMessage.class);

    Mockito.when(
            runtimeSupport.filterContent(
                Mockito.any(InputStream.class),
                Mockito.any(OutputStream.class),
                Mockito.anyString(),
                Mockito.any(URI.class)))
        .thenReturn(FcpFilterResult.unsafe());

    message.run(handler);

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

  private FCPConnectionHandler handlerWithRuntimeSupport(FcpMessageRuntimeSupport runtimeSupport) {
    FCPConnectionHandler handler = Mockito.mock(FCPConnectionHandler.class);
    FCPServer server = Mockito.mock(FCPServer.class);
    Mockito.lenient().when(handler.getServer()).thenReturn(server);
    Mockito.lenient().when(server.messageRuntimeSupport()).thenReturn(runtimeSupport);
    return handler;
  }
}
