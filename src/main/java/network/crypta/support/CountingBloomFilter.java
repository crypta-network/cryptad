package network.crypta.support;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel.MapMode;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Counting Bloom filter with 2-bit per-position counters.
 *
 * <p>This implementation stores four 2-bit counters per byte, allowing limited multiplicity and
 * stable removals. Each position represents a counter in {@code [0,3]} where the value {@code 3} is
 * a saturation sentinel. Membership checks treat any non-zero counter as present.
 *
 * <h2>Storage layout</h2>
 *
 * <ul>
 *   <li>Logical length is measured in bits/positions and rounded down to a multiple of 8 by the
 *       {@link BloomFilter} base class.
 *   <li>Backing buffer size is {@code length / 4} bytes (four counters per byte).
 *   <li>For a given {@code offset}, the 2-bit field resides at {@code (offset % 4) * 2} within byte
 *       {@code offset / 4}.
 * </ul>
 *
 * <h2>Semantics</h2>
 *
 * <ul>
 *   <li>{@link #setBit(int)} increments a counter up to {@code 3} and then saturates.
 *   <li>{@link #unsetBit(int)} decrements counters {@code 1 -> 0} and {@code 2 -> 1}. Values {@code
 *       0} (underflow) and {@code 3} (saturated) are left unchanged.
 *   <li>{@link #getBit(int)} returns {@code true} when the counter is non-zero.
 * </ul>
 *
 * <h2>Threading</h2>
 *
 * <p>Public APIs such as {@link #fork(int)} are thread-safe. Low-level overrides ({@link
 * #getBit(int)}, {@link #setBit(int)}, {@link #unsetBit(int)}) are invoked by the base class under
 * its read/write locks and are not intended for external concurrent use.
 *
 * @author sdiz
 */
public final class CountingBloomFilter extends BloomFilter {

  private static final Logger LOG = LoggerFactory.getLogger(CountingBloomFilter.class);

  private boolean warnOnRemoveFromEmpty;

  /**
   * Enables error logging when attempting to decrement a zero counter.
   *
   * <p>When enabled, {@link #unsetBit(int)} logs an error via SLF4J if called on a position whose
   * counter is {@code 0}. This helps detect double-removal bugs that can otherwise lead to false
   * negatives. No exception is thrown; behavior of the counter remains unchanged.
   */
  public void setWarnOnRemoveFromEmpty() {
    warnOnRemoveFromEmpty = true;
  }

  /**
   * Creates an in-memory counting Bloom filter.
   *
   * <p>The {@code length} is rounded down to a multiple of 8 by {@link BloomFilter}. The backing
   * buffer capacity is {@code length / 4} bytes.
   *
   * @param length filter length in bits
   * @param k number of hash functions to apply per key; must be non-negative
   * @throws IllegalArgumentException if {@code length < 0} or {@code k < 0}
   */
  public CountingBloomFilter(int length, int k) {
    super(requireNonNegativeLength(length), requireNonNegativeHashCount(k));
    filter = ByteBuffer.allocate(this.length / 4);
  }

  /**
   * Creates a file-backed counting Bloom filter mapped into memory.
   *
   * <p>The method resizes {@code file} to {@code length / 4} bytes and memory-maps it in read/write
   * mode. If the file is missing or has an unexpected size on entry, the one-shot {@link
   * #needRebuild()} flag is set.
   *
   * @param file target backing file; created/resized as needed
   * @param length filter length in bits
   * @param k number of hash functions to apply per key; must be non-negative
   * @throws IOException if the file cannot be created, resized, or mapped
   * @throws IllegalArgumentException if {@code length < 0} or {@code k < 0}
   */
  CountingBloomFilter(File file, int length, int k) throws IOException {
    super(requireNonNegativeLength(length), requireNonNegativeHashCount(k));
    int fileLength = length / 4;
    if (!file.exists() || file.length() != fileLength) needRebuild = true;

    try (RandomAccessFile raf = new RandomAccessFile(file, "rw");
        FileChannel channel = raf.getChannel()) {
      raf.setLength(fileLength);
      filter = channel.map(MapMode.READ_WRITE, 0, fileLength).load();
    }
  }

  /**
   * Creates an in-memory filter view over a provided buffer.
   *
   * <p>The buffer is wrapped (zero-copy) and must have a capacity of exactly {@code length / 4}
   * bytes. Callers should not modify the array concurrently.
   *
   * @param length filter length in bits
   * @param k number of hash functions to apply per key; must be non-negative
   * @param buffer backing array of size {@code length / 4}
   * @throws NullPointerException if {@code buffer} is {@code null}
   * @throws IllegalArgumentException if {@code buffer.length != length / 4}
   * @throws IllegalArgumentException if {@code length < 0} or {@code k < 0}
   */
  public CountingBloomFilter(int length, int k, byte[] buffer) {
    super(requireNonNegativeLength(length), requireNonNegativeHashCount(k));
    if (buffer == null) {
      throw new NullPointerException("buffer");
    }
    int expected = length / 4;
    if (buffer.length != expected) {
      throw new IllegalArgumentException(
          "Invalid buffer length: " + buffer.length + " (expected " + expected + ")");
    }
    filter = ByteBuffer.wrap(buffer);
  }

  /**
   * Returns whether the counter at {@code offset} is non-zero.
   *
   * <p>Time complexity is {@code O(1)}. This method is called under the read lock by the base
   * class. External callers should prefer {@link #checkFilter(byte[])} on {@link BloomFilter}.
   *
   * @param offset position in {@code [0, length)}
   * @return {@code true} when the 2-bit counter is not zero; {@code false} otherwise
   */
  @Override
  public boolean getBit(int offset) {
    int index = offset / 4;
    int shift = (offset % 4) * 2;
    int b = filter.get(index) & 0xFF;
    int v = (b >>> shift) & 0x03;
    return v != 0;
  }

  /**
   * Increments the 2-bit counter at {@code offset} up to saturation.
   *
   * <p>Values {@code 0 -> 1}, {@code 1 -> 2}, and {@code 2 -> 3}; {@code 3} remains unchanged. This
   * method is called under the write lock by the base class.
   *
   * @param offset position in {@code [0, length)}
   */
  @Override
  public void setBit(int offset) {
    int index = offset / 4;
    int shift = (offset % 4) * 2;
    int b = filter.get(index) & 0xFF;
    int v = (b >>> shift) & 0x03;

    if (v == 3) return; // overflow (saturated at 3)

    b &= ~(0x03 << shift); // clear existing 2-bit field
    b |= ((v + 1) & 0x03) << shift; // increment and set

    filter.put(index, (byte) b);
  }

  /**
   * Decrements the 2-bit counter at {@code offset} when in {@code {1,2}}.
   *
   * <p>Values {@code 1 -> 0} and {@code 2 -> 1} change; {@code 0} (underflow) and {@code 3}
   * (saturated) are unchanged. When {@link #setWarnOnRemoveFromEmpty()} has been called, attempts
   * to decrement {@code 0} log an error. This method is called under the write lock by the base
   * class.
   *
   * @param offset position in {@code [0, length)}
   */
  @Override
  public void unsetBit(int offset) {
    int index = offset / 4;
    int shift = (offset % 4) * 2;
    int b = filter.get(index) & 0xFF;
    int v = (b >>> shift) & 0x03;

    if (v == 0 && warnOnRemoveFromEmpty)
      LOG.error(
          "Unsetting bit but already unset - probable double remove, can cause false negatives, is"
              + " very bad!",
          new Exception("error"));

    if (v == 0 || v == 3) return; // underflow guard or saturated value

    b &= ~(0x03 << shift); // clear existing 2-bit field
    b |= ((v - 1) & 0x03) << shift; // decrement and set

    filter.put(index, (byte) b);
  }

  /**
   * Creates a forked filter and starts mirroring updates.
   *
   * <p>Under a write lock, attempts to create a secure, file-backed fork via a temporary file. If
   * file mapping fails, falls back to an in-memory fork. The fork accumulates staged changes until
   * {@link #merge()} or {@link #discard()} is called on the base class.
   *
   * @param k number of hash functions for the fork (typically equal to {@link #getK()})
   */
  @Override
  public void fork(int k) {
    try (var _ = new LockResource(lock.writeLock())) {
      try {
        File tempFile = createSecureTempFile();
        tempFile.deleteOnExit();
        forkedFilter = new CountingBloomFilter(tempFile, length, k);
      } catch (IOException _) {
        forkedFilter = new CountingBloomFilter(length, k);
      }
    }
  }

  private static File createSecureTempFile() throws IOException {
    try {
      // Prefer POSIX-restricted temp files when available
      if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
        FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);
        Path p = Files.createTempFile("bloom-", ".tmp", attr);
        File f = p.toFile();
        f.deleteOnExit();
        return f;
      }
    } catch (UnsupportedOperationException _) {
      // Fall through to generic path below
    }

    // Generic platforms (e.g., Windows): create under a user-private directory
    Path base = Paths.get(System.getProperty("user.home", "."), ".cryptad", "tmp");
    Files.createDirectories(base);
    File baseFile = base.toFile();
    boolean br = baseFile.setReadable(true, true);
    boolean bw = baseFile.setWritable(true, true);
    boolean bx = baseFile.setExecutable(true, true);
    if (!br || !bw || !bx) {
      LOG.debug(
          "Best-effort permission adjustment on temp directory {} did not fully apply (r={}, w={},"
              + " x={}).",
          baseFile,
          br,
          bw,
          bx);
    }
    Path p = Files.createTempFile(base, "bloom-", ".tmp");
    File f = p.toFile();
    boolean r = f.setReadable(true, true);
    boolean w = f.setWritable(true, true);
    boolean x = f.setExecutable(false, false);
    if (!r || !w || !x) {
      LOG.debug(
          "Best-effort permission adjustment on temp file {} did not fully apply (r={}, w={},"
              + " x={}).",
          f,
          r,
          w,
          x);
    }
    f.deleteOnExit();
    return f;
  }

  private static class LockResource implements Closeable {
    private final java.util.concurrent.locks.Lock w;

    LockResource(java.util.concurrent.locks.Lock w) {
      this.w = w;
      this.w.lock();
    }

    @Override
    public void close() {
      w.unlock();
    }
  }
}
