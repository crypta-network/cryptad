package network.crypta.support.io;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.lessThanOrEqualTo;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link PaddedBucket}.
 *
 * <p>Tests follow AAA style and exercise padding semantics, I/O guards, delegation, and
 * store/restore behavior. External I/O is mocked when useful; a small in-memory {@link Bucket}
 * implementation is used to observe data written by {@link FileUtil#fill(OutputStream, long)}
 * without touching disk.
 */
class PaddedBucketTest {

  /** Simple in-memory Bucket for tests. Not serializable/persistent. */
  private static final class InMemoryBucket implements Bucket {
    private final String name;
    private boolean readOnly;
    private ByteArrayOutputStream data = new ByteArrayOutputStream();

    InMemoryBucket(String name) {
      this.name = name;
    }

    @Override
    public OutputStream getOutputStream() {
      data = new ByteArrayOutputStream();
      // Return a buffered wrapper to differ from the unbuffered variant
      return new BufferedOutputStream(data);
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() {
      // Return the raw stream without additional buffering
      data = new ByteArrayOutputStream();
      return data;
    }

    @Override
    public InputStream getInputStream() {
      return new ByteArrayInputStream(data.toByteArray());
    }

    @Override
    public InputStream getInputStreamUnbuffered() {
      return new ByteArrayInputStream(data.toByteArray());
    }

    @Override
    public String getName() {
      return name;
    }

    @Override
    public long size() {
      return data.size();
    }

    @Override
    public boolean isReadOnly() {
      return readOnly;
    }

    @Override
    public void setReadOnly() {
      readOnly = true;
    }

    @Override
    public void free() {
      // Intentionally no-op: this ephemeral in-memory bucket holds only a ByteArrayOutputStream
      // with no external resources to release, so freeing has no effect in tests.
    }

    @Override
    public Bucket createShadow() {
      // Return self for simplicity; PaddedBucket only needs a Bucket instance
      return this;
    }

    @Override
    public void onResume(ClientContext context) {
      // Intentionally no-op: this in-memory bucket has no persistent state to re-register or
      // restore after resume; tests do not rely on any tracker integration.
    }

    @Override
    public void storeTo(DataOutputStream dos) throws IOException {
      // Not used in tests that require real persistence; see dedicated round‑trip test.
      dos.writeInt(0xFEEDFACE);
    }

    byte[] toByteArray() {
      return data.toByteArray();
    }
  }

  // ---- Helpers ----

  private static long expectedPaddedLength(long actual) {
    final long min = 1024L;
    if (actual <= 0) return min;
    if (actual <= min) return min;
    long hi = min << 1; // 2048
    while (true) {
      if (actual <= hi) return hi;
      hi = hi << 1;
    }
  }

  private static byte[] patternBytes(int n) {
    byte[] b = new byte[n];
    for (int i = 0; i < n; i++) b[i] = (byte) (i & 0xFF);
    return b;
  }

  // Small helper to make SonarLint happy by extracting the creation of test data from
  // longer test methods. Keeps AAA blocks compact and intention‑revealing.
  private static byte[] newTestData(int n) {
    return patternBytes(n);
  }

  @SuppressWarnings("java:S1144")
  private static Stream<Arguments> sizes() {
    return Stream.of(
        Arguments.of(0),
        Arguments.of(1),
        Arguments.of(1023),
        Arguments.of(1024),
        Arguments.of(1025),
        Arguments.of(1500),
        Arguments.of(2048),
        Arguments.of(2049));
  }

  @Nested
  @DisplayName("OutputStream padding and guards")
  class OutputStreamTests {

    @ParameterizedTest
    @MethodSource("network.crypta.support.io.PaddedBucketTest#sizes")
    void close_whenDataWritten_padsToExpectedLength(int n) throws IOException {
      // Arrange
      InMemoryBucket underlying = new InMemoryBucket("mem");
      PaddedBucket padded = new PaddedBucket(underlying);
      byte[] data;

      // Act
      try (OutputStream os = padded.getOutputStream()) {
        data = writeDataInMixedChunks(os, n);
      }

      // Assert
      long expectedPadded = expectedPaddedLength(n);
      assertEquals(n, padded.size(), "size() must reflect only actual data, not padding");
      assertEquals(
          expectedPadded,
          underlying.size(),
          "Underlying stored bytes must be padded to next power‑of‑two (min 1024)");

      byte[] stored = underlying.toByteArray();
      assertThat(
          "Underlying must be at least expected padded length",
          stored.length,
          is((int) expectedPadded));
      // Content prefix is exact
      assertArrayEquals(data, java.util.Arrays.copyOf(stored, n));
    }

    @Test
    void getOutputStream_whenCalledTwiceWithoutClose_expectIOException() throws IOException {
      // Arrange
      InMemoryBucket underlying = new InMemoryBucket("mem");
      PaddedBucket padded = new PaddedBucket(underlying);

      // Act
      OutputStream os = padded.getOutputStream();
      IOException ex = assertThrows(IOException.class, padded::getOutputStream);

      // Assert
      assertThat(ex.getMessage(), org.hamcrest.Matchers.startsWith("Already have an OutputStream"));
      os.close();
    }

    @Test
    void getOutputStreamUnbuffered_whenUsed_behavesLikeBuffered() throws IOException {
      // Arrange
      InMemoryBucket underlying = new InMemoryBucket("mem");
      PaddedBucket padded = new PaddedBucket(underlying);
      byte[] data = patternBytes(17);

      // Act
      try (OutputStream os = padded.getOutputStreamUnbuffered()) {
        os.write(data);
      }

      // Assert
      assertEquals(17, padded.size());
      assertEquals(expectedPaddedLength(17), underlying.size());
    }
  }

  /**
   * Writes {@code n} bytes using a mix of OutputStream overloads to exercise size tracking paths.
   * Returns the deterministic byte array used for writing so callers can assert stored content.
   */
  private static byte[] writeDataInMixedChunks(OutputStream os, int n) throws IOException {
    byte[] data = newTestData(n);
    if (n > 0) {
      os.write(data, 0, 1); // single byte via array
      if (n > 1) {
        int remaining = n - 1;
        int chunk = Math.min(3, remaining);
        os.write(data, 1, chunk); // offset/length
        int left = remaining - chunk;
        if (left > 0) os.write(data, 1 + chunk, left); // bulk write
      }
    }
    return data;
  }

  @Nested
  @DisplayName("InputStream semantics")
  class InputStreamTests {

    @Test
    void read_whenUnderlyingHasPadding_returnsOnlyActualData() throws IOException {
      // Arrange
      InMemoryBucket underlying = new InMemoryBucket("mem");
      PaddedBucket padded = new PaddedBucket(underlying);
      byte[] data = patternBytes(2000); // spans multiple padding boundaries (expect 2048)
      try (OutputStream os = padded.getOutputStream()) {
        os.write(data);
      }

      // Act
      ByteArrayOutputStream read = new ByteArrayOutputStream();
      try (InputStream is = padded.getInputStream()) {
        byte[] buf = new byte[512];
        int r;
        while ((r = is.read(buf)) != -1) {
          read.write(buf, 0, r);
        }
      }

      // Assert
      byte[] got = read.toByteArray();
      assertEquals(data.length, got.length);
      assertArrayEquals(data, got);
    }

    @Test
    void available_afterPartialRead_isCappedToRemaining() throws IOException {
      // Arrange
      InMemoryBucket underlying = new InMemoryBucket("mem");
      PaddedBucket padded = new PaddedBucket(underlying);
      byte[] data = patternBytes(1500);
      try (OutputStream os = padded.getOutputStream()) {
        os.write(data);
      }

      // Act
      try (InputStream is = padded.getInputStream()) {
        byte[] tmp = new byte[1000];
        int n = is.read(tmp); // consume 1000
        assertEquals(1000, n);

        int avail = is.available();
        // Assert: available must not exceed remaining = 500 and never be negative
        assertThat(avail, allOf(greaterThanOrEqualTo(0), lessThanOrEqualTo(500)));
      }
    }

    @Test
    void skip_whenAtEof_returnsMinusOne() throws IOException {
      // Arrange
      InMemoryBucket underlying = new InMemoryBucket("mem");
      PaddedBucket padded = new PaddedBucket(underlying);
      byte[] data = patternBytes(32);
      try (OutputStream os = padded.getOutputStream()) {
        os.write(data);
      }

      // Act & Assert
      try (InputStream is = padded.getInputStream()) {
        // Consume all
        assertEquals(32, is.read(new byte[64]));
        assertEquals(-1, is.read());
        // Now skip should return -1 per implementation
        assertEquals(-1, is.skip(1));
      }
    }
  }

  @Nested
  @DisplayName("Delegation & metadata")
  class DelegationTests {

    @Test
    void getName_whenCalled_returnsPrefixedUnderlyingName() {
      // Arrange
      Bucket underlying = mock(Bucket.class);
      when(underlying.getName()).thenReturn("Under");
      PaddedBucket padded = new PaddedBucket(underlying);

      // Act / Assert
      assertEquals("Padded:Under", padded.getName());
    }

    @Test
    void createShadow_whenCalled_returnsReadOnlyCopyWithSameSize() throws IOException {
      // Arrange
      Bucket underlying = mock(Bucket.class);
      Bucket shadow = mock(Bucket.class);
      when(underlying.createShadow()).thenReturn(shadow);
      when(underlying.getOutputStream()).thenReturn(new ByteArrayOutputStream());
      when(underlying.getOutputStreamUnbuffered()).thenReturn(new ByteArrayOutputStream());

      PaddedBucket padded = new PaddedBucket(underlying);
      try (OutputStream os = padded.getOutputStream()) {
        os.write(patternBytes(123));
      }

      // Act
      Bucket copy = padded.createShadow();

      // Assert
      assertInstanceOf(PaddedBucket.class, copy);
      PaddedBucket pb = (PaddedBucket) copy;
      assertEquals(123, pb.size());
      assertTrue(pb.isReadOnly());
      verify(underlying, times(1)).createShadow();
    }

    @Test
    void free_whenCalled_forwardsToUnderlying() {
      // Arrange
      Bucket underlying = mock(Bucket.class);
      PaddedBucket padded = new PaddedBucket(underlying);

      // Act
      padded.free();

      // Assert
      verify(underlying, times(1)).free();
    }

    @Test
    void onResume_whenCalled_forwardsToUnderlying() throws ResumeFailedException {
      // Arrange
      Bucket underlying = mock(Bucket.class);
      PaddedBucket padded = new PaddedBucket(underlying);
      ClientContext ctx = mock(ClientContext.class);

      // Act
      padded.onResume(ctx);

      // Assert
      verify(underlying, times(1)).onResume(ctx);
    }
  }

  @Nested
  @DisplayName("Store/restore")
  class StoreRestoreTests {

    @Test
    void storeTo_whenCalled_writesHeaderAndDelegates() throws IOException {
      // Arrange
      Bucket underlying = mock(Bucket.class);
      when(underlying.getOutputStream()).thenReturn(new ByteArrayOutputStream());
      when(underlying.getOutputStreamUnbuffered()).thenReturn(new ByteArrayOutputStream());
      doAnswer(
              inv -> {
                DataOutputStream dos = inv.getArgument(0);
                dos.writeInt(0x12345678); // sentinel from underlying
                return null;
              })
          .when(underlying)
          .storeTo(org.mockito.ArgumentMatchers.any(DataOutputStream.class));

      PaddedBucket padded = new PaddedBucket(underlying);
      try (OutputStream os = padded.getOutputStream()) {
        os.write(patternBytes(10));
      }
      padded.setReadOnly();

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DataOutputStream dos = new DataOutputStream(baos);

      // Act
      padded.storeTo(dos);

      // Assert
      DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
      assertEquals(PaddedBucket.MAGIC, dis.readInt());
      assertEquals(1, dis.readInt()); // VERSION
      assertEquals(10L, dis.readLong());
      assertTrue(dis.readBoolean());
      assertEquals(0x12345678, dis.readInt());
    }

    @Test
    void restoreFrom_roundTrip_returnsPaddedBucketWithFields() throws Exception {
      // Arrange: create a tiny real file and wrap as ReadOnlyFileSliceBucket (restorable)
      Path tmp = Files.createTempFile("paddedbucket-test", ".bin");
      Files.write(tmp, patternBytes(32));
      ReadOnlyFileSliceBucket ro = new ReadOnlyFileSliceBucket(tmp.toFile(), 0, 16);

      PaddedBucket original = new PaddedBucket(ro, 16);
      original.setReadOnly();

      ByteArrayOutputStream baos = new ByteArrayOutputStream();
      DataOutputStream dos = new DataOutputStream(baos);
      original.storeTo(dos);

      // Act: restore via BucketTools
      DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));
      // BucketTools expects the first int to be the MAGIC; we already wrote it via storeTo
      Bucket restored =
          BucketTools.restoreFrom(
              dis,
              new FilenameGenerator(new java.util.Random(1234L), false, null, "test-"),
              mock(PersistentFileTracker.class),
              null);

      // Assert
      assertInstanceOf(PaddedBucket.class, restored);
      PaddedBucket roundTrip = (PaddedBucket) restored;
      assertEquals(16L, roundTrip.size());
      assertTrue(roundTrip.isReadOnly());
      assertThat(roundTrip.getName(), org.hamcrest.Matchers.startsWith("Padded:"));

      // Cleanup
      Files.deleteIfExists(tmp);
    }
  }
}
