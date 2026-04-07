package network.crypta.support.io;

import java.io.IOException;
import java.util.Arrays;
import java.util.Random;
import network.crypta.support.api.RandomAccessBuffer;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Base JUnit test harness for {@link RandomAccessBuffer} implementations.
 *
 * <p>This abstract class centralizes common behaviors that every random-access buffer should
 * satisfy in Crypta's test suite. Subclasses supply concrete construction logic via {@link
 * #construct(long)} and provide size lists that define small and large test cases. The helpers
 * exercise size reporting, sequential and random read/write patterns, boundary conditions, and
 * post-close behavior. Data correctness is verified either through a deterministic {@link Formula}
 * or by comparing randomly generated payloads read back from the buffer.
 *
 * <p>Each helper follows a lifecycle of construct, read/write, close, then free. Implementations
 * are expected to honor the size invariant, reject out-of-range access, and fail I/O after close.
 * Randomness only selects slice boundaries, so assertions remain deterministic for a given random
 * source. These tests are single-threaded and assume exclusive access to the buffer under test,
 * which keeps concurrency concerns out of scope for this harness.
 *
 * <ul>
 *   <li>Validate size invariants and boundary behavior for read/write operations.
 *   <li>Verify content round-trips for formula-driven and random payloads.
 *   <li>Assert failure modes for closed buffers and out-of-range access.
 * </ul>
 *
 * @see RandomAccessBuffer
 */
public abstract class RandomAccessBufferTestBase {

  /**
   * Initializes the test harness using a single list of small sizes.
   *
   * <p>The provided sizes are treated as byte counts and are used for both the small-size and
   * full-size test passes. This is convenient for implementations that only need in-memory coverage
   * or do not distinguish between small and large storage thresholds. The input array is stored
   * directly as {@link #sizeList}, while a long-valued copy is created for full-size use. This
   * constructor performs no validation; negative or zero values are left to later test failures.
   *
   * @param allSmallTests size values in bytes used for all test tiers; must be non-null.
   */
  protected RandomAccessBufferTestBase(int[] allSmallTests) {
    this(allSmallTests, toLongArray(allSmallTests));
  }

  /**
   * Initializes the test harness with explicit small and large size lists.
   *
   * <p>Use this constructor when the implementation has distinct thresholds, such as in-memory and
   * on-disk transitions, that benefit from separate test coverage. The {@code smallTests} values
   * should represent sizes that are inexpensive to allocate, while {@code bigTests} can include
   * larger values that stress paging or storage. The arrays are stored as provided without
   * defensive copying, so callers should treat them as immutable for the lifetime of the test
   * instance. No validation or sorting is performed.
   *
   * @param smallTests small-size byte counts for fast, in-memory-oriented test cases.
   * @param bigTests full-size byte counts for large or threshold-oriented test cases.
   */
  protected RandomAccessBufferTestBase(int[] smallTests, long[] bigTests) {
    sizeList = smallTests;
    fullSizeList = bigTests;
  }

  private static long[] toLongArray(int[] values) {
    long[] result = new long[values.length];
    for (int i = 0; i < values.length; i++) {
      result[i] = values[i];
    }
    return result;
  }

  /**
   * Verifies that a buffer range matches an expected byte array segment, optionally writing data.
   *
   * <p>The method first reads {@code [start, end)} from {@code raf} into a temporary array and
   * compares each byte against {@code buf}. If {@code readOnly} is false, it then writes the
   * expected bytes back to the buffer and re-reads the same range to confirm persistence. The
   * method treats a zero-length range as a no-op. Callers are responsible for ensuring that the
   * indices fall within both the array and buffer bounds; out-of-range values will surface as I/O
   * errors from the underlying implementation.
   *
   * <pre>{@code
   * RandomAccessBufferTestBase.checkArraySectionEqualsReadData(
   *     data, raf, 0, data.length, false);
   * }</pre>
   *
   * @param buf expected data source whose bytes are compared against the buffer contents.
   * @param raf random-access buffer under test, open and ready for I/O.
   * @param start start index (inclusive) within {@code buf} and buffer, in bytes.
   * @param end end index (exclusive) within {@code buf} and buffer, in bytes.
   * @param readOnly when true, skips the write-back phase and only verifies reads.
   * @throws IOException if the buffer reports an I/O failure for any read or write.
   */
  public static void checkArraySectionEqualsReadData(
      byte[] buf, RandomAccessBuffer raf, int start, int end, boolean readOnly) throws IOException {
    int len = end - start;
    if (len == 0) {
      return;
    }
    byte[] expected = Arrays.copyOfRange(buf, start, end);
    byte[] actual = new byte[len];
    raf.pread(start, actual, 0, len);
    assertArrayEquals(expected, actual);
    if (!readOnly) {
      raf.pwrite(start, buf, start, len);
    }
    Arrays.fill(actual, (byte) 0);
    raf.pread(start, actual, 0, len);
    assertArrayEquals(expected, actual);
  }

  /**
   * Test that we can create and free a RandomAccessBuffer of various sizes, and it returns the
   * correct size.
   */
  @Test
  void testSize() throws IOException {
    for (long size : fullSizeList) {
      innerTestSize(size);
    }
  }

  @Test
  void testFormula() throws IOException {
    Random r = new Random(0x5EED_5EED_5EED_5EEDL);
    Formula modulo256 = offset -> (byte) offset;
    Formula modulo57 = offset -> (byte) (offset % 57);
    for (long size : fullSizeList) {
      innerTestFormula(size, r, modulo256);
      innerTestFormula(size, r, modulo57);
    }
  }

  /** Test that we can't write or read after the size limit */
  @Test
  void testWriteOverLimit() throws IOException {
    Random r = new Random(0x1BAD_C0DE_1BAD_C0DEL);
    innerTestWriteOverLimit(0L, 1);
    innerTestWriteOverLimit(1, 1);
    innerTestWriteOverLimit(1, 1024);
    for (int i = 0; i < 10; i++) {
      innerTestWriteOverLimit(1024L * 1024 + 1, r.nextInt(1024));
    }
    innerTestWriteOverLimit(1024L * 1024 + 1, 1024 * 1024);
    innerTestWriteOverLimit(1024L * 1024 + 1, 1024 * 1024 + 2);
    for (long size : fullSizeList) {
      innerTestWriteOverLimit(size, 1024);
    }
    for (int size : sizeList) {
      innerTestWriteOverLimit(size, size);
      innerTestWriteOverLimit(size, size + 1);
    }
  }

  @Test
  void testClose() throws IOException {
    // Try to cover any thresholds for e.g. moving to disk.
    // Implementations should add their own tests according to known thresholds (white box).
    for (long size : fullSizeList) {
      innerTestClose(size);
    }
  }

  @Test
  void testArray() throws IOException {
    Random r = new Random(0xC0FF_EE00_C0FF_EE00L);
    for (int size : sizeList) {
      innerTestArray(size, r);
    }
  }

  /**
   * Constructs a {@link RandomAccessBuffer} of a specified size in bytes.
   *
   * <p>Subclasses must provide a new buffer instance that reports {@code size} from {@link
   * RandomAccessBuffer#size()} and supports random-access reads and writes across the full range.
   * The returned buffer should be in an open, usable state suitable for immediate I/O. This method
   * is called by multiple helper tests which will close and free the buffer after use, so
   * implementations must ensure those operations are supported for every constructed instance.
   *
   * @param size requested buffer size in bytes, typically non-negative and test-specific.
   * @return a newly constructed buffer instance sized to {@code size}.
   * @throws IOException if allocation or initialization fails for the requested size.
   */
  protected abstract RandomAccessBuffer construct(long size) throws IOException;

  /**
   * Writes and validates a buffer using a deterministic byte formula with randomized chunking.
   *
   * <p>This helper constructs a buffer of {@code sz}, then writes the expected content in randomly
   * sized chunks derived from {@code r}. After each write, the method reads the same range back and
   * asserts that {@link Formula} still matches. It then performs a second pass of random reads over
   * the entire buffer to verify persistence. The random generator only influences chunk boundaries;
   * the expected bytes are fully determined by {@code f} and the offset. The method closes and
   * frees the buffer before returning.
   *
   * @param sz buffer size in bytes to construct and exercise.
   * @param r random source used to choose chunk sizes; must be non-null.
   * @param f formula that maps byte offsets to expected values; must be deterministic.
   * @throws IOException if underlying buffer I/O fails during reads or writes.
   */
  protected void innerTestFormula(long sz, Random r, Formula f) throws IOException {
    RandomAccessBuffer raf = construct(sz);
    assertEquals(raf.size(), sz);
    long x = 0L;
    // Write (and check as go)
    while (x < sz) {
      int maxRead = (int) Math.min(BUFFER_SIZE, sz - x);
      int toRead = maxRead == 1 ? 1 : r.nextInt(maxRead - 1) + 1;
      byte[] expected = new byte[toRead];
      for (int i = 0; i < expected.length; i++) {
        expected[i] = f.getByte(i + x);
      }
      raf.pwrite(x, expected, 0, toRead);
      byte[] actual = new byte[toRead];
      raf.pread(x, actual, 0, toRead);
      assertArrayEquals(expected, actual);
      x += toRead;
    }
    // Read
    x = 0L;
    while (x < sz) {
      int maxRead = (int) Math.min(BUFFER_SIZE, sz - x);
      int toRead = maxRead == 1 ? 1 : r.nextInt(maxRead - 1) + 1;
      byte[] actual = new byte[toRead];
      raf.pread(x, actual, 0, toRead);
      byte[] expected = new byte[toRead];
      for (int i = 0; i < expected.length; i++) {
        expected[i] = f.getByte(i + x);
      }
      assertArrayEquals(expected, actual);
      x += toRead;
    }
    raf.close();
    raf.free();
  }

  /**
   * Validates that a closed buffer rejects subsequent read and write operations.
   *
   * <p>The method constructs a buffer of {@code sz}, closes it immediately, and then attempts a
   * read and write at offset {@code 0}. Both operations must fail with an {@link IOException} for
   * the test to pass, which is enforced by {@code readWriteMustFail}. Finally, the method frees the
   * buffer to complete the lifecycle. The behavior is intended to ensure that close transitions the
   * buffer into a non-operational state regardless of size.
   *
   * @param sz buffer size in bytes used to create the instance being closed.
   * @throws IOException if buffer allocation fails prior to the close operation.
   */
  protected void innerTestClose(long sz) throws IOException {
    RandomAccessBuffer raf = construct(sz);
    raf.close();
    byte[] buf = new byte[(int) Math.min(1024, sz)];
    readWriteMustFail(raf, 0L, buf, buf.length);
    raf.free();
  }

  /**
   * Writes random data to a buffer and verifies it via randomized reads.
   *
   * <p>The method allocates a byte array of {@code len}, fills it using {@code r}, and writes it
   * sequentially to the buffer. It then performs repeated random range checks to ensure that reads
   * match the expected content, followed by full-range and near-full-range checks. The read
   * patterns are randomized but always validated against the same data, so failures are
   * deterministic for a given random generator state. The buffer is closed and freed before the
   * method returns.
   *
   * @param len size of the data set and buffer, in bytes; zero is a no-op.
   * @param r random source used for data generation and read slicing; must be non-null.
   * @throws IOException if buffer I/O fails during any read or write operation.
   */
  protected void innerTestArray(int len, Random r) throws IOException {
    if (len == 0) {
      return;
    }
    byte[] buf = new byte[len];
    r.nextBytes(buf);
    RandomAccessBuffer raf = construct(len);
    raf.pwrite(0L, buf, 0, buf.length);
    for (int i = 0; i < 100; i++) {
      int end = len == 1 ? 1 : r.nextInt(len) + 1;
      int start = r.nextInt(end);
      checkArraySectionEqualsReadData(buf, raf, start, end, false);
    }
    checkArraySectionEqualsReadData(buf, raf, 0, len, false);
    if (len > 1) {
      checkArraySectionEqualsReadData(buf, raf, 1, len - 1, false);
    }
    raf.close();
    raf.free();
  }

  private void innerTestSize(long sz) throws IOException {
    RandomAccessBuffer raf = construct(sz);
    assertEquals(raf.size(), sz);
    raf.close();
    raf.free();
  }

  private void innerTestWriteOverLimit(long sz, int choppedBytes) throws IOException {
    RandomAccessBuffer raf = construct(sz);
    assertEquals(raf.size(), sz);
    long startAt = sz - choppedBytes;
    byte[] buf = new byte[choppedBytes];
    if (sz != 0 && choppedBytes < sz) {
      if (startAt >= 0) {
        readWriteMustSucceed(raf, startAt, buf, buf.length); // Read, write up to the end work.
      } else {
        try {
          readWriteMustSucceed(raf, startAt, buf, buf.length); // Read, write up to the end work.
          fail("Should fail to read at negative index");
        } catch (IllegalArgumentException _) {
          // Ok.
        }
      }
    }
    if (startAt + 1 >= 0) {
      readWriteMustFail(raf, startAt + 1, buf, buf.length); // Read, write over the end fail.
    } else {
      try {
        readWriteMustSucceed(raf, startAt + 1, buf, buf.length); // Read, write up to the end work.
        fail("Should fail to read at negative index");
      } catch (IllegalArgumentException _) {
        // Ok.
      }
    }
    readWriteMustFail(raf, sz, buf, buf.length); // Read, write at the end fail.
    readWriteMustFail(raf, sz + 1, buf, buf.length); // One byte into end
    readWriteMustFail(raf, sz + 1025, buf, buf.length); // 1KB in
    readWriteMustFail(raf, sz + buf.length, buf, buf.length);
    raf.close();
    raf.free();
  }

  private void readWriteMustSucceed(RandomAccessBuffer raf, long startAt, byte[] buf, int length)
      throws IOException {
    raf.pread(startAt, buf, 0, length); // Should work
    raf.pwrite(startAt, buf, 0, length); // Should work
  }

  private void readWriteMustFail(RandomAccessBuffer raf, long startAt, byte[] buf, int length) {
    if (length == 0) {
      return; // NOP.
    }
    try {
      raf.pread(startAt, buf, 0, length); // Should work
      fail("Must throw!");
    } catch (IOException _) {
      // Ok.
    }
    try {
      raf.pwrite(startAt, buf, 0, length); // Should work
      fail("Must throw!");
    } catch (IOException _) {
      // Ok.
    }
  }

  /**
   * Functional contract for producing expected bytes based on a logical offset.
   *
   * <p>This interface is used by {@link #innerTestFormula(long, Random, Formula)} to generate
   * deterministic test data without allocating full buffers in advance. Implementations should be
   * pure functions of the provided offset, returning consistent values across calls and avoiding
   * side effects. Because the formula is applied repeatedly during both write and read validation
   * phases, any stateful or non-deterministic behavior would lead to spurious failures. Offsets are
   * expressed in bytes and are expected to fall within the constructed buffer size.
   */
  protected interface Formula {
    /**
     * Computes the expected byte value for a logical offset within a buffer.
     *
     * <p>Implementations should be deterministic and side-effect free, returning the same result
     * for the same offset across calls. The offset is expressed in bytes and may range from {@code
     * 0} to the buffer size minus one, depending on the active test. This function is used by
     * {@link #innerTestFormula(long, Random, Formula)} to generate expected content for both writes
     * and subsequent reads.
     *
     * @param offset zero-based byte offset within the logical buffer under test.
     * @return the expected byte value for the supplied offset.
     */
    byte getByte(long offset);
  }

  private static final int BUFFER_SIZE = 65536;

  /**
   * Size list for small tests, expressed as byte counts that fit comfortably in memory.
   *
   * <p>Values in this array are used to exercise fast, in-memory scenarios across a variety of
   * sizes. The array reference is supplied by subclasses and is not defensively copied, so it
   * should be treated as immutable once passed to the constructor. Individual tests iterate over
   * these values to validate size reporting and I/O behavior.
   */
  protected final int[] sizeList;

  /** Size list for big tests i.e. stuff that might not fit in RAM */
  private final long[] fullSizeList;
}
