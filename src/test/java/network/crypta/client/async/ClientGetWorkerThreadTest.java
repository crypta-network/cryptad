package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import network.crypta.client.ClientMetadata;
import network.crypta.client.FetchException;
import network.crypta.crypt.HashResult;
import network.crypta.crypt.HashType;
import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100") // Test method naming convention per project rules
@ExtendWith(MockitoExtension.class)
class ClientGetWorkerThreadTest {
  private static ClientGetWorkerThread newThread(
      InputStream input,
      ByteArrayOutputStream output,
      FreenetURI uri,
      String mimeType,
      String schemeHostAndPort,
      HashResult[] hashes,
      boolean filterData,
      String charset)
      throws URISyntaxException {
    return new ClientGetWorkerThread(
        input,
        output,
        uri,
        hashes,
        new ClientGetWorkerThread.Options(
            mimeType, schemeHostAndPort, filterData, charset, null, null, null));
  }

  @Test
  void run_withoutFilter_writesOutputAndNoError() throws Throwable {
    // Arrange
    byte[] data = "hello world".getBytes(StandardCharsets.UTF_8);
    InputStream input = new ByteArrayInputStream(data);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    FreenetURI uri = new FreenetURI("KSK", "test");

    ClientGetWorkerThread t =
        newThread(
            input,
            output,
            uri,
            null, // mimeType not needed when filterData = false
            null, // schemeHostAndPort
            null, // hashes
            false, // filterData
            null // charset
            );

    // Act
    t.start();
    assertDoesNotThrow(t::waitFinished);

    // Assert
    assertArrayEquals(data, output.toByteArray());
    ClientMetadata md = t.getClientMetadata();
    // When not filtering, ClientGetWorkerThread does not set metadata
    // ClientMetadata#getMIMEType() returns default if null; verify raw object is null instead
    // to avoid coupling to DefaultMIMETypes here.
    // Using toString() would force default; we check the backing field via API contract instead.
    // md may be null when filter is off
    assertNull(md);
  }

  @Test
  void run_withFilter_textPlain_setsClientMetadataAndCopies() throws Throwable {
    // Arrange
    String payload = "some text payload";
    byte[] data = payload.getBytes(StandardCharsets.UTF_8);
    InputStream input = new ByteArrayInputStream(data);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    FreenetURI uri = new FreenetURI("KSK", "doc");

    ClientGetWorkerThread t =
        newThread(
            input,
            output,
            uri,
            "text/plain",
            "localhost:12345",
            null, // hashes
            true, // filterData
            null // charset => let filter default
            );

    // Act
    t.start();
    assertDoesNotThrow(t::waitFinished);

    // Assert
    assertArrayEquals(data, output.toByteArray());
    ClientMetadata md = t.getClientMetadata();
    // ContentFilter returns FilterStatus with the given type name; no charset added when null
    assertEquals("text/plain", md.getMIMEType());
  }

  @Test
  void run_withFilter_xhtmlMapped_setsClientMetadataToTextHtmlWithCharset() throws Throwable {
    // Arrange
    String html = "<html><head><title>x</title></head><body>hi</body></html>";
    byte[] data = html.getBytes(StandardCharsets.UTF_8);
    InputStream input = new ByteArrayInputStream(data);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    FreenetURI uri = new FreenetURI("KSK", "page");

    // Pass application/xhtml+xml to constructor; it maps to text/html internally
    ClientGetWorkerThread t =
        newThread(
            input,
            output,
            uri,
            "application/xhtml+xml",
            "localhost:8080",
            null,
            true, // filter enabled so metadata is set
            "UTF-8" // force a stable charset path
            );

    // Act
    t.start();
    assertDoesNotThrow(t::waitFinished);

    // Assert
    assertArrayEquals(data, output.toByteArray());
    ClientMetadata md = t.getClientMetadata();
    // Expect mapping to text/html and default charset selected by the filter
    assertEquals("text/html; charset=iso-8859-1", md.getMIMEType());
  }

  @Test
  void run_withMismatchedHash_throwsFetchExceptionAndPreservesMode() throws Exception {
    // Arrange
    byte[] data = "abcdef".getBytes(StandardCharsets.UTF_8);
    InputStream input = new ByteArrayInputStream(data);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    FreenetURI uri = new FreenetURI("KSK", "hash");

    // Provide an incorrect expected SHA-256 to force mismatch
    MessageDigest sha256 = HashType.SHA256.get();
    byte[] wrong = sha256.digest("other".getBytes(StandardCharsets.UTF_8));
    HashResult[] expected = new HashResult[] {new HashResult(HashType.SHA256, wrong)};

    ClientGetWorkerThread t =
        newThread(
            input, output, uri, null, null, expected, false, // no filtering; only hashing matters
            null);

    // Act + Assert
    t.start();
    Throwable thrown = assertThrows(Throwable.class, t::waitFinished);
    FetchException fe = assertInstanceOf(FetchException.class, thrown);
    assertEquals(FetchException.FetchExceptionMode.CONTENT_HASH_FAILED, fe.getMode());
  }

  @Test
  void run_withCorrectHash_succeedsAndCopies() throws Exception {
    // Arrange
    byte[] data = "verify me".getBytes(StandardCharsets.UTF_8);
    InputStream input = new ByteArrayInputStream(data);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    FreenetURI uri = new FreenetURI("KSK", "hash-ok");

    MessageDigest sha256 = HashType.SHA256.get();
    byte[] correct = sha256.digest(data);
    HashResult[] expected = new HashResult[] {new HashResult(HashType.SHA256, correct)};

    ClientGetWorkerThread t = newThread(input, output, uri, null, null, expected, false, null);

    // Act
    t.start();
    assertDoesNotThrow(t::waitFinished);

    // Assert
    assertArrayEquals(data, output.toByteArray());
  }

  @Test
  void run_filterWithoutURI_throwsIOExceptionViaWaitFinished() throws URISyntaxException {
    // Arrange: filter enabled but missing URI triggers insufficient arguments path
    byte[] data = "x".getBytes(StandardCharsets.UTF_8);
    InputStream input = new ByteArrayInputStream(data);
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    ClientGetWorkerThread t =
        newThread(
            input,
            output,
            null, // URI is required when filtering
            "text/plain",
            null,
            null,
            true,
            null);

    // Act + Assert
    t.start();
    Throwable thrown = assertThrows(Throwable.class, t::waitFinished);
    assertInstanceOf(java.io.IOException.class, thrown);
  }

  @Test
  void setError_whenCalled_waitFinishedThrowsSameInstance() throws Exception {
    // Arrange
    byte[] data = new byte[] {1, 2, 3};
    InputStream input = new ByteArrayInputStream(data);
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    FreenetURI uri = new FreenetURI("KSK", "err");
    ClientGetWorkerThread t = newThread(input, output, uri, null, null, null, false, null);

    RuntimeException boom = new RuntimeException("boom");

    // Act
    t.setError(boom);

    // Assert
    Throwable thrown = assertThrows(Throwable.class, t::waitFinished);
    assertSame(boom, thrown);
  }
}
