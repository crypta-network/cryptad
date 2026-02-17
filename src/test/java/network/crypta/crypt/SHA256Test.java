package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import org.bouncycastle.util.encoders.Hex;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentMatchers;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SHA256Test {

  private static void ignoreInt(int ignored) {}

  // ---- Test vectors ----
  static java.util.stream.Stream<Arguments> knownVectors() {
    return java.util.stream.Stream.of(
        Arguments.of("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        Arguments.of("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        Arguments.of(
            "The quick brown fox jumps over the lazy dog",
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
        Arguments.of(
            "The quick brown fox jumps over the lazy dog.",
            "ef537f25c895bfa782526529a9b63d97aa631564d5d789c2b765448c8635fb6c"));
  }

  @ParameterizedTest(name = "digest(byte[]) matches vector for \"{0}\"")
  @MethodSource("knownVectors")
  void digest_whenKnownVectors_expectExpectedHex(String msg, String expectedHex) {
    // Arrange
    byte[] data = msg.getBytes(StandardCharsets.UTF_8);
    byte[] expected = Hex.decode(expectedHex);
    // Act
    byte[] actual = SHA256.digest(data);
    // Assert
    assertArrayEquals(expected, actual);
  }

  @Test
  void getMessageDigest_whenCalled_expectSha256AndNewInstances() {
    // Act
    MessageDigest md1 = SHA256.getMessageDigest();
    MessageDigest md2 = SHA256.getMessageDigest();
    // Assert
    assertNotNull(md1);
    assertNotNull(md2);
    assertNotSame(md1, md2);
    assertEquals("SHA-256", md1.getAlgorithm());
    assertEquals(32, md1.getDigestLength());
  }

  @Test
  void getDigestLength_whenCalled_expect32() {
    assertEquals(32, SHA256.getDigestLength());
  }

  @Test
  void hash_whenEmptyStream_expectEmptyDigestAndClosed() throws Exception {
    // Arrange: mock InputStream to return -1 immediately
    InputStream is = Mockito.mock(InputStream.class);
    Mockito.when(is.read(ArgumentMatchers.any(byte[].class))).thenReturn(-1);
    MessageDigest md = SHA256.getMessageDigest();
    byte[] expectedEmpty = SHA256.digest(new byte[0]);

    // Act
    SHA256.hash(is, md);

    // Assert
    assertArrayEquals(expectedEmpty, md.digest());
    Mockito.verify(is, Mockito.times(1)).close();
    ignoreInt(Mockito.verify(is, Mockito.atLeastOnce()).read(ArgumentMatchers.any(byte[].class)));
  }

  @Test
  void hash_whenRandomShortReads_expectSameAsSingleShotAndClosed() throws Exception {
    // Arrange: deterministic data larger than the internal buffer (4096)
    byte[] data = new byte[10000];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i % 251);
    byte[] expected = SHA256.digest(data);

    CloseTrackingInputStream tracker = new CloseTrackingInputStream(new ByteArrayInputStream(data));
    InputStream shortReads =
        new DeterministicShortReadInputStream(tracker, new int[] {13, 4096, 7, 512, 3, 2048});
    MessageDigest md = SHA256.getMessageDigest();

    // Act
    SHA256.hash(shortReads, md);

    // Assert
    assertArrayEquals(expected, md.digest());
    assertTrue(tracker.wasClosed(), "input stream should be closed");
  }

  @Test
  void hash_whenIOExceptionOnFirstRead_expectExceptionAndNoUpdateAndClosed() throws Exception {
    // Arrange
    InputStream is = Mockito.mock(InputStream.class);
    Mockito.when(is.read(ArgumentMatchers.any(byte[].class))).thenThrow(new IOException("boom"));
    MessageDigest md = SHA256.getMessageDigest();
    byte[] expectedEmpty = SHA256.digest(new byte[0]);

    // Act + Assert
    assertThrows(IOException.class, () -> SHA256.hash(is, md));
    Mockito.verify(is, Mockito.times(1)).close();
    assertArrayEquals(expectedEmpty, md.digest());
  }

  @Test
  void hash_whenIOExceptionAfterPartialRead_expectPartialUpdateAndClosed() throws Exception {
    // Arrange: first chunk then fail
    byte[] first = new byte[1024];
    for (int i = 0; i < first.length; i++) first[i] = (byte) (i * 3 + 7);
    MessageDigest md = SHA256.getMessageDigest();
    byte[] expected = SHA256.digest(first);

    try (FailingAfterFirstReadInputStream is = new FailingAfterFirstReadInputStream(first)) {
      // Act + Assert
      assertThrows(IOException.class, () -> SHA256.hash(is, md));
      // Verify closure before try-with-resources would close it again
      assertTrue(is.wasClosed, "input stream should be closed even on failure");
      assertArrayEquals(expected, md.digest());
    }
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void hash_whenNullInputStream_expectNpe() {
    MessageDigest md = SHA256.getMessageDigest();
    assertThrows(NullPointerException.class, () -> SHA256.hash(null, md));
  }

  @Test
  void hash_whenNullMessageDigest_expectNpeAndClosed() throws Exception {
    // Arrange: ensure at least one successful read so md.update() is attempted
    InputStream is = Mockito.mock(InputStream.class);
    Mockito.when(is.read(ArgumentMatchers.any(byte[].class))).thenReturn(1, -1);

    // Act + Assert
    assertThrows(NullPointerException.class, () -> SHA256.hash(is, null));
    Mockito.verify(is, Mockito.times(1)).close();
  }

  // The deprecated no-op SHA256.returnMessageDigest(...) was removed.

  // ---- Helpers ----

  /** Tracks whether {@link #close()} was called. */
  private static final class CloseTrackingInputStream extends FilterInputStream {
    private boolean closed;

    CloseTrackingInputStream(InputStream in) {
      super(in);
    }

    boolean wasClosed() {
      return closed;
    }

    @Override
    public void close() throws IOException {
      closed = true;
      super.close();
    }
  }

  /** Returns data once, then throws on the next read; tracks closure. */
  private static class FailingAfterFirstReadInputStream extends InputStream {
    private final byte[] first;
    private boolean served;
    boolean wasClosed;

    FailingAfterFirstReadInputStream(byte[] first) {
      this.first = first.clone();
    }

    @Override
    public int read() {
      throw new UnsupportedOperationException("unused in tests");
    }

    @Override
    public void close() throws IOException {
      wasClosed = true;
      super.close();
    }

    @Override
    public int read(byte @NotNull [] b, int off, int len) throws IOException {
      if (!served) {
        System.arraycopy(first, 0, b, off, first.length);
        served = true;
        return first.length;
      }
      throw new IOException("fail on subsequent read");
    }
  }

  /** Short-read wrapper with a deterministic chunk size pattern. */
  private static final class DeterministicShortReadInputStream extends FilterInputStream {
    private final int[] chunkSizes;
    private int index;

    DeterministicShortReadInputStream(InputStream in, int[] chunkSizes) {
      super(in);
      this.chunkSizes = chunkSizes.clone();
    }

    @Override
    public int read(byte @NotNull [] b, int off, int len) throws IOException {
      int n = Math.min(len, chunkSizes[index % chunkSizes.length]);
      index++;
      return in.read(b, off, n);
    }
  }
}
