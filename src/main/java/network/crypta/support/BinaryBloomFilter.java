package network.crypta.support;

import java.io.Closeable;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Bloom filter backed by a compact bit array.
 *
 * <p>This implementation stores one bit per position and uses the hashing and concurrency
 * orchestration provided by {@link BloomFilter}. Instances can be purely in-memory (heap {@link
 * ByteBuffer}) or file-backed via a memory-mapped buffer. File-backed filters set the one‑shot
 * {@link #needRebuild} flag when the on-disk file is missing or has an unexpected size.
 *
 * <h2>Threading</h2>
 *
 * <p>All public operations are thread-safe through the base class’ read/write lock. Membership
 * checks acquire the read lock; updates and fork/merge operations acquire the write lock.
 *
 * <h2>Usage</h2>
 *
 * <p>Prefer constructing instances via {@link BloomFilter#createFilter(int, int, boolean)} or
 * {@link BloomFilter#createFilter(File, int, int, boolean)} which select this variant when {@code
 * counting == false}. The factories also return {@link NullBloomFilter} for zero-length requests.
 *
 * @author sdiz
 */
public final class BinaryBloomFilter extends BloomFilter {
  private static final Logger LOG = LoggerFactory.getLogger(BinaryBloomFilter.class);

  /**
   * Creates an in-memory binary Bloom filter.
   *
   * <p>Allocates a heap {@link ByteBuffer} sized to {@code length / 8} bytes after the rounding
   * performed by the {@link BloomFilter} constructor.
   *
   * @param length length in bits; rounded down to a multiple of 8
   * @param k number of hash functions (non-negative)
   * @throws IllegalArgumentException if {@code length < 0} or {@code k < 0}
   */
  protected BinaryBloomFilter(int length, int k) {
    super(length, k);
    filter = ByteBuffer.allocate(this.length / 8);
  }

  /**
   * Creates a file-backed binary Bloom filter.
   *
   * <p>Ensures the file length matches the expected size ({@code length / 8}) and memory-maps it in
   * read/write mode. When the file does not exist or has a different size, the one-shot flag {@link
   * #needRebuild} is set for callers to observe.
   *
   * @param file target file (created or resized as needed)
   * @param length length in bits; rounded down to a multiple of 8
   * @param k number of hash functions (non-negative)
   * @throws IOException if the file cannot be created, resized, or mapped
   * @throws IllegalArgumentException if {@code length < 0} or {@code k < 0}
   */
  protected BinaryBloomFilter(File file, int length, int k) throws IOException {
    super(length, k);
    if (!file.exists() || file.length() != length / 8) needRebuild = true;

    try (RandomAccessFile raf = new RandomAccessFile(file, "rw");
        FileChannel channel = raf.getChannel()) {
      raf.setLength(length / 8);
      filter = channel.map(MapMode.READ_WRITE, 0, length / 8).load();
    }
  }

  /**
   * Creates a binary Bloom filter backed by the provided buffer slice.
   *
   * <p>This constructor does not copy the data; callers must ensure the buffer’s capacity is at
   * least {@code length / 8} and that its lifetime covers the filter’s usage. No ownership is
   * taken; changes are written into the given buffer.
   *
   * @param slice backing buffer; must be writable and large enough for {@code length / 8} bytes
   * @param length length in bits; rounded down to a multiple of 8
   * @param k number of hash functions (non-negative)
   * @throws IllegalArgumentException if {@code length < 0} or {@code k < 0}
   */
  public BinaryBloomFilter(ByteBuffer slice, int length, int k) {
    super(length, k);
    filter = slice;
  }

  /**
   * No-op for the binary variant.
   *
   * <p>{@inheritDoc}
   *
   * @param key ignored
   */
  @Override
  public void removeKey(byte[] key) {
    // ignore
  }

  /**
   * Returns whether the bit at {@code offset} is set.
   *
   * @param offset position in {@code [0, length)}
   * @return {@code true} if the bit is set; otherwise {@code false}
   */
  @Override
  protected boolean getBit(int offset) {
    int value = filter.get(offset / 8) & 0xFF;
    int mask = 1 << (offset % 8);
    return (value & mask) != 0;
  }

  /**
   * Sets the bit at {@code offset}.
   *
   * @param offset position in {@code [0, length)}
   */
  @Override
  protected void setBit(int offset) {
    int index = offset / 8;
    int b = filter.get(index) & 0xFF;
    b |= 1 << (offset % 8);
    filter.put(index, (byte) b);
  }

  /**
   * No-op. The binary variant does not support decrements.
   *
   * @param offset ignored
   */
  @Override
  protected void unsetBit(int offset) {
    // NO-OP
  }

  /**
   * Starts mirroring updates to a forked filter.
   *
   * <p>Attempts to create a file-backed fork under a secure temporary location. If that fails,
   * falls back to an in-memory fork. The write lock is held during fork creation to ensure
   * consistent state.
   *
   * @param k number of hash functions to use in the fork
   */
  @Override
  public void fork(int k) {
    try (var _ = new LockResource(lock.writeLock())) {
      try {
        File tempFile = createSecureTempFile();
        forkedFilter = new BinaryBloomFilter(tempFile, length, k);
      } catch (IOException _) {
        // Fallback: in‑memory fork while still holding the write lock to preserve synchronization.
        forkedFilter = new BinaryBloomFilter(length, k);
      }
    }
  }

  private static class LockResource implements Closeable {
    private final Lock w;

    LockResource(Lock w) {
      this.w = w;
      this.w.lock();
    }

    @Override
    public void close() {
      w.unlock();
    }
  }

  /**
   * Creates a temporary file with best-effort user-only permissions.
   *
   * <p>On POSIX filesystems, applies {@code rw-------}. On non-POSIX platforms, attempts to place
   * the file under a user-private directory and restrict basic flags. Returns a file scheduled for
   * deletion at JVM exit.
   *
   * @return newly created temporary file
   * @throws IOException if file creation fails
   */
  private static File createSecureTempFile() throws IOException {
    try {
      // Use POSIX permissions when supported to restrict to owner read/write.
      if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
        Set<PosixFilePermission> perms = PosixFilePermissions.fromString("rw-------");
        FileAttribute<Set<PosixFilePermission>> attr = PosixFilePermissions.asFileAttribute(perms);
        Path p = Files.createTempFile("bloom-", ".tmp", attr);
        File f = p.toFile();
        f.deleteOnExit();
        return f;
      }
    } catch (UnsupportedOperationException _) {
      // Fall through to generic creation path below.
    }

    // Generic platforms (e.g., Windows) — create under a stable user-private directory and
    // best‑effort restrict. Avoid per-call directories to prevent directory leaks.
    Path base = Paths.get(System.getProperty("user.home", "."), ".cryptad", "tmp");
    Files.createDirectories(base);
    // Best-effort to restrict directory to current user only (non-POSIX platforms ignore perms).
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
}
