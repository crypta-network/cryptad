package network.crypta.runtime.spi;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class DarknetUploadedFileTest {

  @Test
  void constructor_whenFilenameIsNull_throwsNullPointerException() {
    DarknetUploadedFile.StreamSource streamSource =
        () -> new ByteArrayInputStream(new byte[] {1, 2, 3});

    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> new DarknetUploadedFile(null, "text/plain", 3, streamSource));

    assertEquals("filename", exception.getMessage());
  }

  @Test
  void constructor_whenStreamSourceIsNull_throwsNullPointerException() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () -> new DarknetUploadedFile("upload.txt", "text/plain", 3, null));

    assertEquals("streamSource", exception.getMessage());
  }

  @Test
  void constructor_whenSizeIsNegative_throwsIllegalArgumentException() {
    DarknetUploadedFile.StreamSource streamSource =
        () -> new ByteArrayInputStream(new byte[] {1, 2, 3});

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () -> new DarknetUploadedFile("upload.txt", "text/plain", -1, streamSource));

    assertEquals("size", exception.getMessage());
  }

  @Test
  void accessors_whenContentTypeMissing_returnDetachedMetadata() {
    byte[] data = "payload".getBytes(StandardCharsets.UTF_8);
    DarknetUploadedFile upload =
        new DarknetUploadedFile(
            "upload.txt", null, data.length, () -> new ByteArrayInputStream(data));

    assertAll(
        () -> assertEquals("upload.txt", upload.filename()),
        () -> assertNull(upload.contentType()),
        () -> assertEquals(data.length, upload.size()));
  }

  @Test
  void openStream_whenCalledRepeatedly_reopensFreshStreams() throws Exception {
    byte[] data = "payload".getBytes(StandardCharsets.UTF_8);
    AtomicInteger openCount = new AtomicInteger();
    DarknetUploadedFile upload =
        new DarknetUploadedFile(
            "upload.txt",
            "text/plain",
            data.length,
            () -> {
              openCount.incrementAndGet();
              return new ByteArrayInputStream(data);
            });

    byte[] firstRead;
    byte[] secondRead;
    try (var firstStream = upload.openStream();
        var secondStream = upload.openStream()) {
      firstRead = firstStream.readAllBytes();
      secondRead = secondStream.readAllBytes();
    }

    assertAll(
        () -> assertEquals(2, openCount.get()),
        () -> assertArrayEquals(data, firstRead),
        () -> assertArrayEquals(data, secondRead));
  }

  @Test
  void openStream_whenSourceThrows_propagatesIOException() {
    IOException failure = new IOException("boom");
    DarknetUploadedFile upload =
        new DarknetUploadedFile(
            "upload.txt",
            "text/plain",
            7,
            () -> {
              throw failure;
            });

    IOException thrown = assertThrows(IOException.class, upload::openStream);

    assertSame(failure, thrown);
  }

  @Test
  void toString_whenCalled_includesDetachedMetadata() {
    DarknetUploadedFile upload =
        new DarknetUploadedFile(
            "upload.txt", "text/plain", 7, () -> new ByteArrayInputStream(new byte[] {1}));

    assertEquals(
        "DarknetUploadedFile[filename=upload.txt, contentType=text/plain, size=7]",
        upload.toString());
  }
}
