package network.crypta.crypt;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.LongStream;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings({"java:S100", "java:S5778"})
class MultiHashInputStreamTest {
  private static final byte[] MESSAGE = "Hello, World!".getBytes(StandardCharsets.UTF_8);
  private static final String MESSAGE_MD5 = "65a8e27d8879283831b664bd8b7f0ad4";

  private static MultiHashInputStream newHasher(InputStream in, long bitmask) {
    return new MultiHashInputStream(in, bitmask);
  }

  @Test
  void read_whenMixingSingleAndBulk_expectAllBytesCountedAndHashed() throws IOException {
    ByteArrayInputStream input = new ByteArrayInputStream(MESSAGE);
    MultiHashInputStream hash = newHasher(input, HashType.MD5.bitmask);

    byte[] buf = new byte[MESSAGE.length];
    buf[0] = (byte) hash.read();
    assertEquals(buf.length - 1, hash.read(buf, 1, buf.length - 1));
    assertEquals(-1, hash.read());
    assertEquals(MESSAGE.length, hash.getReadBytes());
    assertArrayEquals(MESSAGE, buf);

    HashResult[] results = hash.getResults();
    assertEquals(1, results.length);
    assertEquals(HashType.MD5, results[0].type);
    assertEquals(MESSAGE_MD5, results[0].hashAsHex());
  }

  @Test
  void markResetNotSupported() {
    ByteArrayInputStream input = new ByteArrayInputStream(MESSAGE);
    MultiHashInputStream hash = newHasher(input, HashType.MD5.bitmask);

    assertFalse(hash.markSupported());
    assertThrows(IOException.class, hash::reset);
    // mark() is a no-op and must not throw
    hash.mark(1);
  }

  @Test
  void read_withZeroLength_doesNotAdvanceOrHash() throws IOException {
    ByteArrayInputStream input = new ByteArrayInputStream(MESSAGE);
    MultiHashInputStream hash = newHasher(input, HashType.MD5.bitmask);

    byte[] buf = new byte[0];
    assertEquals(0, hash.read(buf, 0, 0));
    assertEquals(0, hash.getReadBytes());

    // MD5 of an empty string
    MessageDigest md5 = HashType.MD5.get();
    byte[] emptyDigest = md5.digest();
    HashResult[] results = hash.getResults();
    assertEquals(1, results.length);
    assertEquals(HashType.MD5, results[0].type);
    assertArrayEquals(emptyDigest, HashResult.get(results, HashType.MD5));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void read_withNullBuffer_throwsNPE() {
    ByteArrayInputStream input = new ByteArrayInputStream(MESSAGE);
    MultiHashInputStream hash = newHasher(input, HashType.MD5.bitmask);

    assertThrows(
        NullPointerException.class,
        () -> {
          network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(hash.read(null, 0, 1));
        });
  }

  @Test
  void read_withInvalidBounds_throwsIndexOutOfBounds() {
    ByteArrayInputStream input = new ByteArrayInputStream(MESSAGE);
    MultiHashInputStream hash = newHasher(input, HashType.MD5.bitmask);

    byte[] buf = new byte[4];
    int invalidOffset = Integer.parseInt("-1");
    assertThrows(
        IndexOutOfBoundsException.class,
        () -> {
          network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(
              hash.read(buf, invalidOffset, 1));
        });
    assertThrows(
        IndexOutOfBoundsException.class,
        () -> {
          network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(hash.read(buf, 0, -1));
        });
    assertThrows(
        IndexOutOfBoundsException.class,
        () -> {
          network.crypta.testsupport.SpotBugsTestSupport.ignoreValue(hash.read(buf, 3, 2));
        });
  }

  @Test
  void getResults_whenNoAlgorithmsSelected_returnsEmptyArray() throws IOException {
    ByteArrayInputStream input = new ByteArrayInputStream(MESSAGE);
    MultiHashInputStream hash = newHasher(input, 0);

    // Read everything to exercise the stream despite no digests being active
    byte[] buf = new byte[16];
    int total = 0;
    int read;
    while ((read = hash.read(buf, 0, buf.length)) > 0) {
      total += read; // accumulate to avoid an empty loop body warning
    }
    assertEquals(MESSAGE.length, total);

    assertEquals(MESSAGE.length, hash.getReadBytes());
    assertEquals(0, hash.getResults().length);
  }

  @Test
  void skip_whenPositive_countsAsReadAndAffectsDigest() throws IOException {
    byte[] data = new byte[10_000];
    // Deterministic content: repeated pattern of 0..255
    for (int i = 0; i < data.length; i++) {
      data[i] = (byte) (i & 0xFF);
    }

    ByteArrayInputStream input = new ByteArrayInputStream(data);
    MultiHashInputStream hash = newHasher(input, HashType.SHA256.bitmask);

    // Read first 123 bytes
    byte[] first = new byte[123];
    assertEquals(123, hash.read(first, 0, first.length));

    // Skip the rest in a loop using the shielding skip() (which internally calls read(...))
    long totalSkipped = 0;
    long skipped;
    do {
      skipped = hash.skip(Integer.MAX_VALUE);
      totalSkipped += skipped;
    } while (skipped > 0);

    assertEquals(data.length, hash.getReadBytes());
    assertEquals(data.length - first.length, totalSkipped);

    // Expected SHA-256 over the entire data
    MessageDigest sha256 = HashType.SHA256.get();
    byte[] expected = sha256.digest(data);
    assertArrayEquals(expected, HashResult.get(hash.getResults(), HashType.SHA256));
  }

  @Test
  void skip_whenNegative_returnsZeroAndDoesNotAffectDigestOrCount() throws IOException {
    ByteArrayInputStream input = new ByteArrayInputStream(MESSAGE);
    MultiHashInputStream hash = newHasher(input, HashType.MD5.bitmask);

    assertEquals(0, hash.skip(-1));
    assertEquals(0, hash.getReadBytes());

    // MD5 over empty input
    MessageDigest md5 = HashType.MD5.get();
    byte[] expected = md5.digest();
    assertArrayEquals(expected, HashResult.get(hash.getResults(), HashType.MD5));
  }

  @Test
  void getResults_whenCalledMidStream_startsNewComputationAfterReset() throws IOException {
    ByteArrayInputStream input = new ByteArrayInputStream(MESSAGE);
    MultiHashInputStream hash = newHasher(input, HashType.SHA1.bitmask);

    // Read the first half and capture digest
    int half = MESSAGE.length / 2;
    byte[] buf = new byte[half];
    assertEquals(half, hash.read(buf, 0, buf.length));
    HashResult[] firstHalf = hash.getResults();

    // Compute expected SHA-1 over the first half
    MessageDigest sha1 = HashType.SHA1.get();
    byte[] expectedFirst = sha1.digest(Arrays.copyOfRange(MESSAGE, 0, half));
    assertArrayEquals(expectedFirst, HashResult.get(firstHalf, HashType.SHA1));

    // Read remaining bytes; the internal digests were reset by getResults()
    byte[] rest = new byte[MESSAGE.length - half];
    assertEquals(rest.length, hash.read(rest, 0, rest.length));
    HashResult[] secondHalf = hash.getResults();

    // Expected digest is only over the second segment
    MessageDigest sha1Again = HashType.SHA1.get();
    byte[] expectedSecond = sha1Again.digest(Arrays.copyOfRange(MESSAGE, half, MESSAGE.length));
    assertArrayEquals(expectedSecond, HashResult.get(secondHalf, HashType.SHA1));
  }

  @ParameterizedTest
  @MethodSource("bitmasksForMultiAlgorithm")
  void getResults_withMultipleAlgorithms_returnsOrderedAndCorrectValues(long bitmask)
      throws IOException {
    ByteArrayInputStream input = new ByteArrayInputStream(MESSAGE);
    MultiHashInputStream hash = newHasher(input, bitmask);

    // Read all at once
    byte[] buf = new byte[MESSAGE.length];
    assertEquals(buf.length, hash.read(buf, 0, buf.length));

    HashResult[] results = hash.getResults();

    // Build expected results in HashType.values() order filtered by bitmask
    List<HashResult> expected = new ArrayList<>();
    for (HashType t : HashType.values()) {
      if ((bitmask & t.bitmask) == t.bitmask) {
        MessageDigest d = t.get();
        expected.add(new HashResult(t, d.digest(MESSAGE)));
      }
    }

    assertEquals(expected.size(), results.length);
    for (int i = 0; i < expected.size(); i++) {
      HashType type = expected.get(i).type;
      assertEquals(type, results[i].type, "hash type order");
      byte[] expectedBytes = HashResult.get(new HashResult[] {expected.get(i)}, type);
      byte[] actualBytes = HashResult.get(results, type);
      assertArrayEquals(expectedBytes, actualBytes);
    }
  }

  private static LongStream bitmasksForMultiAlgorithm() {
    long md5Sha1 = HashType.MD5.bitmask | HashType.SHA1.bitmask;
    long sha256Sha512 = HashType.SHA256.bitmask | HashType.SHA512.bitmask;
    long all = 0;
    for (HashType t : HashType.values()) all |= t.bitmask;
    return LongStream.of(md5Sha1, sha256Sha512, all);
  }

  @Test
  void read_whenUnderlyingReturnsZero_doesNotHashOrCountUntilDataArrives() throws IOException {
    // Underlying stream returns 0 on the first read(byte[],off,len), then delegates normally
    class FirstZeroInputStream extends InputStream {
      private final ByteArrayInputStream delegate = new ByteArrayInputStream(MESSAGE);
      private boolean first = true;

      @Override
      public int read(byte @NotNull [] b, int off, int len) {
        if (first) {
          first = false;
          return 0; // Simulate a non-blocking stream that returns 0
        }
        return delegate.read(b, off, len);
      }

      @Override
      public int read() {
        return delegate.read();
      }
    }

    MultiHashInputStream hash = newHasher(new FirstZeroInputStream(), HashType.MD5.bitmask);
    byte[] buf = new byte[MESSAGE.length];

    assertEquals(0, hash.read(buf, 0, buf.length));
    assertEquals(0, hash.getReadBytes());

    assertEquals(MESSAGE.length, hash.read(buf, 0, buf.length));
    assertEquals(MESSAGE.length, hash.getReadBytes());

    MessageDigest md5 = HashType.MD5.get();
    byte[] expected = md5.digest(MESSAGE);
    assertArrayEquals(expected, HashResult.get(hash.getResults(), HashType.MD5));
  }
}
