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
 * @author sdiz
 */
public class BinaryBloomFilter extends BloomFilter {
  private static final Logger LOG = LoggerFactory.getLogger(BinaryBloomFilter.class);

  /**
   * Constructor
   *
   * @param length length in bits
   */
  protected BinaryBloomFilter(int length, int k) {
    super(length, k);
    filter = ByteBuffer.allocate(this.length / 8);
  }

  /**
   * Constructor
   *
   * @param file disk file
   * @param length length in bits
   * @throws IOException
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

  public BinaryBloomFilter(ByteBuffer slice, int length, int k) {
    super(length, k);
    filter = slice;
  }

  @Override
  public void removeKey(byte[] key) {
    // ignore
  }

  @Override
  protected boolean getBit(int offset) {
    int value = filter.get(offset / 8) & 0xFF;
    int mask = 1 << (offset % 8);
    return (value & mask) != 0;
  }

  @Override
  protected void setBit(int offset) {
    int index = offset / 8;
    int b = filter.get(index) & 0xFF;
    b |= 1 << (offset % 8);
    filter.put(index, (byte) b);
  }

  @Override
  protected void unsetBit(int offset) {
    // NO-OP
  }

  @Override
  public void fork(int k) {
    try (LockResource ignored = new LockResource(lock.writeLock())) {
      try {
        File tempFile = createSecureTempFile();
        forkedFilter = new BinaryBloomFilter(tempFile, length, k);
      } catch (IOException e) {
        // Fallback: in‑memory fork while still holding the write lock, preserving synchronization
        forkedFilter = new BinaryBloomFilter(length, k);
      }
    }
  }

  private static final class LockResource implements Closeable {
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
    } catch (UnsupportedOperationException ignored) {
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
