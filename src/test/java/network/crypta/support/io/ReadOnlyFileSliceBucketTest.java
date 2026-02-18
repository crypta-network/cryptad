package network.crypta.support.io;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.stream.Stream;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link ReadOnlyFileSliceBucket}.
 *
 * <p>Uses AAA style and deterministic file content. Parameterized tests cover common slice
 * combinations and error paths.
 */
class ReadOnlyFileSliceBucketTest {

  @TempDir Path tmpDir;

  private static byte[] sequentialBytes(int length) {
    byte[] data = new byte[length];
    for (int i = 0; i < length; i++) data[i] = (byte) (i & 0xFF);
    return data;
  }

  private Path newDataFile(byte[] content) throws IOException {
    Path p = tmpDir.resolve("data.bin");
    Files.write(p, content);
    return p;
  }

  private static Stream<Arguments> sliceProvider() {
    // startAt, length, total size
    int total = 64;
    return Stream.of(
        Arguments.of(0L, 0L, total),
        Arguments.of(0L, 1L, total),
        Arguments.of(0L, (long) total, total),
        Arguments.of(1L, (long) total - 1, total),
        Arguments.of(10L, 5L, total),
        Arguments.of((long) total - 1, 1L, total),
        Arguments.of((long) total, 0L, total));
  }

  @ParameterizedTest
  @MethodSource("sliceProvider")
  @DisplayName("readUnbuffered_whenUsingSlices_expectExactBytes")
  void readUnbufferedWhenUsingSlicesExpectExactBytes(long startAt, long length, int total)
      throws IOException {
    // Arrange
    byte[] content = sequentialBytes(total);
    Path file = newDataFile(content);
    // Act
    byte[] read;
    try (ReadOnlyFileSliceBucket bucket =
            new ReadOnlyFileSliceBucket(file.toFile(), startAt, length);
        InputStream is = bucket.getInputStreamUnbuffered()) {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      byte[] buf = new byte[17]; // prime sized buffer to exercise boundaries
      int x;
      while ((x = is.read(buf, 0, buf.length)) != -1) {
        bos.write(buf, 0, x);
      }
      read = bos.toByteArray();
    }

    // Assert
    byte[] expected = Arrays.copyOfRange(content, (int) startAt, (int) (startAt + length));
    assertArrayEquals(expected, read);
  }

  @ParameterizedTest
  @MethodSource("sliceProvider")
  @DisplayName("readBuffered_whenUsingSlices_expectExactBytes")
  void readBufferedWhenUsingSlicesExpectExactBytes(long startAt, long length, int total)
      throws IOException {
    // Arrange
    byte[] content = sequentialBytes(total);
    Path file = newDataFile(content);
    // Act & Assert (also assert we get a BufferedInputStream)
    try (ReadOnlyFileSliceBucket bucket =
            new ReadOnlyFileSliceBucket(file.toFile(), startAt, length);
        InputStream is = bucket.getInputStream()) {
      assertInstanceOf(BufferedInputStream.class, is);
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      int b;
      while ((b = is.read()) != -1) {
        bos.write(b);
      }
      byte[] expected = Arrays.copyOfRange(content, (int) startAt, (int) (startAt + length));
      assertArrayEquals(expected, bos.toByteArray());
    }
  }

  @Test
  @DisplayName("readUnbuffered_whenReadingBeyondSlice_expectEOF")
  void readUnbufferedWhenReadingBeyondSliceExpectEOF() throws IOException {
    // Arrange
    byte[] content = sequentialBytes(32);
    Path file = newDataFile(content);
    // Act
    try (ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(file.toFile(), 4, 8);
        InputStream is = bucket.getInputStreamUnbuffered()) {
      byte[] buf = new byte[64];
      int first = is.read(buf, 0, buf.length);
      int second = is.read(buf, 0, buf.length);

      // Assert
      assertEquals(8, first);
      assertEquals(-1, second);
    }
  }

  // Intentionally skip negative offset/length read() bound tests here.
  // Behavior is delegated to RandomAccessFile and may vary across JDKs.

  @Test
  @DisplayName("getOutputStream_whenCalled_expectIOException")
  void getOutputStreamWhenCalledExpectIOException() throws IOException {
    // Arrange
    Path file = newDataFile(sequentialBytes(1));
    // Act & Assert
    try (ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(file.toFile(), 0, 1)) {
      IOException ex = assertThrows(IOException.class, bucket::getOutputStream);
      assertEquals("Bucket is read-only", ex.getMessage());
    }
  }

  @Test
  @DisplayName("getOutputStreamUnbuffered_whenCalled_expectIOException")
  void getOutputStreamUnbufferedWhenCalledExpectIOException() throws IOException {
    // Arrange
    Path file = newDataFile(sequentialBytes(1));
    // Act & Assert
    try (ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(file.toFile(), 0, 1)) {
      IOException ex = assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);
      assertEquals("Bucket is read-only", ex.getMessage());
    }
  }

  @Test
  @DisplayName("getName_whenCalled_expectROFSFormat")
  void getNameWhenCalledExpectROFSFormat() throws IOException {
    // Arrange
    Path file = newDataFile(sequentialBytes(8));
    long startAt = 3L;
    long length = 4L;
    try (ReadOnlyFileSliceBucket bucket =
        new ReadOnlyFileSliceBucket(file.toFile(), startAt, length)) {
      // Act
      String name = bucket.getName();
      // Assert
      assertEquals("ROFS:" + file.toFile().getAbsolutePath() + ":" + startAt + ":" + length, name);
    }
  }

  @Test
  @DisplayName("size_whenConstructed_expectLength")
  void sizeWhenConstructedExpectLength() throws IOException {
    // Arrange
    Path file = newDataFile(sequentialBytes(8));
    try (ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(file.toFile(), 2, 5)) {
      // Act & Assert
      assertEquals(5, bucket.size());
    }
  }

  @Test
  @DisplayName("setReadOnly_whenCalled_stillReadOnly")
  void setReadOnlyWhenCalledStillReadOnly() throws IOException {
    // Arrange
    Path file = newDataFile(sequentialBytes(8));
    try (ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(file.toFile(), 0, 1)) {
      // Act
      assertTrue(bucket.isReadOnly());
      bucket.setReadOnly();
      // Assert
      assertTrue(bucket.isReadOnly());
    }
  }

  @Test
  @DisplayName("createShadow_whenCalled_expectEquivalentSlice")
  void createShadowWhenCalledExpectEquivalentSlice() throws IOException {
    // Arrange
    byte[] content = sequentialBytes(32);
    Path file = newDataFile(content);
    try (ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(file.toFile(), 4, 12);
        Bucket shadow = bucket.createShadow();
        InputStream a = bucket.getInputStreamUnbuffered();
        InputStream b = shadow.getInputStreamUnbuffered()) {
      // Assert
      assertNotSame(bucket, shadow);
      assertInstanceOf(ReadOnlyFileSliceBucket.class, shadow);
      assertEquals(bucket.getName(), shadow.getName());
      byte[] ra = a.readAllBytes();
      byte[] rb = b.readAllBytes();
      assertArrayEquals(ra, rb);
    }
  }

  @Test
  @DisplayName("storeTo_whenCalled_expectMagicVersionAndFields")
  void storeToWhenCalledExpectMagicVersionAndFields() throws IOException {
    // Arrange
    byte[] content = sequentialBytes(10);
    Path file = newDataFile(content);
    long startAt = 2L;
    long length = 5L;
    try (ReadOnlyFileSliceBucket bucket =
            new ReadOnlyFileSliceBucket(file.toFile(), startAt, length);
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos)) {
      // Act
      bucket.storeTo(dos);
      dos.flush();

      // Assert
      DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
      assertEquals(ReadOnlyFileSliceBucket.MAGIC, dis.readInt());
      assertEquals(ReadOnlyFileSliceBucket.VERSION, dis.readInt());
      assertEquals(file.toFile().toString(), dis.readUTF());
      assertEquals(startAt, dis.readLong());
      assertEquals(length, dis.readLong());
    }
  }

  @Test
  @DisplayName("deserialize_whenValid_expectBucket")
  void deserializeWhenValidExpectBucket() throws Exception {
    // Arrange: write only what the protected ctor expects (no MAGIC!)
    byte[] content = sequentialBytes(20);
    Path file = newDataFile(content);
    long startAt = 5L;
    long length = 7L;
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(ReadOnlyFileSliceBucket.VERSION);
      dos.writeUTF(file.toString());
      dos.writeLong(startAt);
      dos.writeLong(length);
    }

    // Act & Assert
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
        ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(dis)) {
      assertEquals(length, bucket.size());
      assertEquals(
          "ROFS:" + file.toFile().getAbsolutePath() + ":" + startAt + ":" + length,
          bucket.getName());
    }
  }

  @Test
  @DisplayName("deserialize_whenBadVersion_expectStorageFormatException")
  void deserializeWhenBadVersionExpectStorageFormatException() throws IOException {
    // Arrange
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(ReadOnlyFileSliceBucket.VERSION + 1);
      dos.writeUTF("/does/not/matter");
      dos.writeLong(0L);
      dos.writeLong(0L);
    }

    // Act & Assert
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
      StorageFormatException ex =
          assertThrows(StorageFormatException.class, () -> new ReadOnlyFileSliceBucket(dis));
      assertEquals("Bad version", ex.getMessage());
    }
  }

  @Test
  @DisplayName("deserialize_whenNegativeStart_expectStorageFormatException")
  void deserializeWhenNegativeStartExpectStorageFormatException() throws IOException {
    // Arrange
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(ReadOnlyFileSliceBucket.VERSION);
      dos.writeUTF(tmpDir.resolve("f.bin").toString());
      dos.writeLong(-1L);
      dos.writeLong(0L);
    }

    // Act & Assert
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
      StorageFormatException ex =
          assertThrows(StorageFormatException.class, () -> new ReadOnlyFileSliceBucket(dis));
      assertEquals("Bad start at", ex.getMessage());
    }
  }

  @Test
  @DisplayName("deserialize_whenNegativeLength_expectStorageFormatException")
  void deserializeWhenNegativeLengthExpectStorageFormatException() throws IOException {
    // Arrange
    Path file = newDataFile(sequentialBytes(1));
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(ReadOnlyFileSliceBucket.VERSION);
      dos.writeUTF(file.toString());
      dos.writeLong(0L);
      dos.writeLong(-5L);
    }

    // Act & Assert
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
      StorageFormatException ex =
          assertThrows(StorageFormatException.class, () -> new ReadOnlyFileSliceBucket(dis));
      assertEquals("Bad length", ex.getMessage());
    }
  }

  @Test
  @DisplayName("deserialize_whenMissingFile_expectStorageFormatException")
  void deserializeWhenMissingFileExpectStorageFormatException() throws IOException {
    // Arrange
    String path = tmpDir.resolve("missing.bin").toString();
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(ReadOnlyFileSliceBucket.VERSION);
      dos.writeUTF(path);
      dos.writeLong(0L);
      dos.writeLong(0L);
    }

    // Act & Assert
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
      StorageFormatException ex =
          assertThrows(StorageFormatException.class, () -> new ReadOnlyFileSliceBucket(dis));
      assertEquals("File does not exist any more", ex.getMessage());
    }
  }

  @Test
  @DisplayName("deserialize_whenSliceTooLarge_expectStorageFormatException")
  void deserializeWhenSliceTooLargeExpectStorageFormatException() throws IOException {
    // Arrange
    Path file = newDataFile(sequentialBytes(4));
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(ReadOnlyFileSliceBucket.VERSION);
      dos.writeUTF(file.toString());
      dos.writeLong(0L);
      dos.writeLong(10L);
    }

    // Act & Assert
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
      StorageFormatException ex =
          assertThrows(StorageFormatException.class, () -> new ReadOnlyFileSliceBucket(dis));
      assertEquals("Slice does not fit in file", ex.getMessage());
    }
  }

  @Test
  @DisplayName("getInputStreamUnbuffered_whenFileMissing_expectWrappedException")
  void getInputStreamUnbufferedWhenFileMissingExpectWrappedException() {
    // Arrange
    File missing = tmpDir.resolve("nope.bin").toFile();
    // Act & Assert
    try (ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(missing, 0, 1)) {
      ReadOnlyFileSliceBucket.ReadOnlyFileSliceBucketException ex =
          assertThrows(
              ReadOnlyFileSliceBucket.ReadOnlyFileSliceBucketException.class,
              bucket::getInputStreamUnbuffered);
      assertNotNull(ex.getCause());
      assertInstanceOf(FileNotFoundException.class, ex.getCause());
      assertTrue(ex.getMessage().startsWith("File not found:"));
    }
  }

  @Test
  @DisplayName("getInputStreamUnbuffered_whenSliceTooLarge_expectWrappedException")
  void getInputStreamUnbufferedWhenSliceTooLargeExpectWrappedException() throws IOException {
    // Arrange
    Path file = newDataFile(sequentialBytes(3));
    // Act & Assert
    try (ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(file.toFile(), 0, 10)) {
      ReadOnlyFileSliceBucket.ReadOnlyFileSliceBucketException ex =
          assertThrows(
              ReadOnlyFileSliceBucket.ReadOnlyFileSliceBucketException.class,
              bucket::getInputStreamUnbuffered);
      assertTrue(ex.getMessage().startsWith("File truncated?"));
    }
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  @DisplayName("constructor_whenNullFile_expectNullPointerException")
  void constructorWhenNullFileExpectNullPointerException() {
    // Arrange & Act & Assert
    assertThrows(
        NullPointerException.class,
        () -> {
          try (var _ = new ReadOnlyFileSliceBucket(null, 0, 0)) {
            fail("Expected NPE before entering try-with-resources");
          }
        });
  }

  @Test
  @DisplayName("free_whenCalled_expectNoThrow")
  void freeWhenCalledExpectNoThrow() throws IOException {
    // Arrange
    Path file = newDataFile(sequentialBytes(1));
    try (ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(file.toFile(), 0, 1)) {
      // Act & Assert
      assertDoesNotThrow(bucket::free);
    }
  }

  @Test
  @DisplayName("onResume_whenCalled_expectNoInteractions")
  void onResumeWhenCalledExpectNoInteractions() throws Exception {
    // Arrange
    ClientContext ctx = mock(ClientContext.class);
    Path file = newDataFile(sequentialBytes(1));
    try (ReadOnlyFileSliceBucket bucket = new ReadOnlyFileSliceBucket(file.toFile(), 0, 1)) {
      // Act
      bucket.onResume(ctx);
      // Assert
      verifyNoInteractions(ctx);
    }
  }
}
