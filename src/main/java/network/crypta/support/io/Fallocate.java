package network.crypta.support.io;

import com.sun.jna.Native;
import com.sun.jna.Platform;
import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Pre-allocates file space using platform facilities and falls back to a portable writer.
 *
 * <p>This utility wraps native {@code fallocate(2)} on Linux and {@code posix_fallocate(3)} on
 * other POSIX platforms when possible. If a native call is unsupported or fails, it performs a
 * legacy fill that extends the file by writing zeros. On Windows, where sparse files are not
 * created by default, the legacy behavior writes a single byte at {@code newLength - 1} to extend
 * the file.
 *
 * <p>Usage is a small fluent builder:
 *
 * <pre>{@code
 * Fallocate.forChannel(channel, sizeBytes)
 *          .fromOffset(0)
 *          .execute();
 * }</pre>
 *
 * <p>Notes and constraints:
 *
 * <ul>
 *   <li>Instances are not thread-safe. Use a separate instance per file/channel.
 *   <li>{@link FileChannel} must be open and writable. Behavior is undefined if the channel is
 *       closed during execution.
 *   <li>The implementation uses reflection to get the underlying file descriptor. If the descriptor
 *       cannot be accessed, the code silently falls back to the legacy fill path.
 *   <li>Native calls are made via JNA to the platform C library.
 * </ul>
 *
 * <p>External reference: “Pre-allocating drive space for file storage” — <a
 * href="https://stackoverflow.com/questions/18031841/pre-allocating-drive-space-for-file-storage">...</a>
 */
public final class Fallocate {
  private static final Logger LOG = LoggerFactory.getLogger(Fallocate.class);

  private static final boolean IS_LINUX = Platform.isLinux();
  private static final boolean IS_WINDOWS = Platform.isWindows();
  private static final boolean IS_POSIX =
      !Platform.isWindows() && !Platform.isMac() && !Platform.isOpenBSD();
  private static final boolean IS_ANDROID = Platform.isAndroid();

  private final int fd;
  private long offset;
  private final long finalFilesize;
  private final FileChannel channel;

  /**
   * Constructs a new instance bound to a channel and a resolved file descriptor.
   *
   * @param channel target channel to operate on; must be open and writable
   * @param fd platform file descriptor number; a value {@code <= 2} forces legacy behavior
   * @param finalFilesize desired file size in bytes after allocation completes
   */
  private Fallocate(FileChannel channel, int fd, long finalFilesize) {
    this.fd = fd;
    this.finalFilesize = finalFilesize;
    this.channel = channel;
  }

  /**
   * Creates an instance for the given channel and desired final size.
   *
   * <p>Attempts to discover the native file descriptor behind the channel via reflection. If this
   * discovery fails due to platform or security restrictions, later execution falls back to the
   * legacy writer.
   *
   * @param channel target channel; must be open and writable
   * @param finalFilesize desired file size in bytes after allocation completes
   * @return a new {@link Fallocate} bound to {@code channel}
   */
  public static Fallocate forChannel(FileChannel channel, long finalFilesize) {
    return new Fallocate(channel, getDescriptor(channel), finalFilesize);
  }

  /**
   * Creates an instance using an explicit file descriptor when available.
   *
   * <p>If {@code fd} is {@code null} or cannot be accessed, the instance behaves as if the
   * descriptor were unavailable and will fall back to the legacy writer.
   *
   * @param channel target channel; must be open and writable
   * @param fd optional descriptor; when inaccessible, legacy behavior is used
   * @param finalFilesize desired file size in bytes after allocation completes
   * @return a new {@link Fallocate} bound to {@code channel}
   */
  public static Fallocate forChannel(FileChannel channel, FileDescriptor fd, long finalFilesize) {
    return new Fallocate(channel, getDescriptor(fd), finalFilesize);
  }

  /**
   * Sets the starting byte offset for allocation.
   *
   * <p>The offset must be within {@code [0, finalFilesize]}. The default offset is {@code 0}.
   *
   * @param offset first byte to allocate (inclusive)
   * @return this instance for fluent chaining
   * @throws IllegalArgumentException if {@code offset < 0} or {@code offset > finalFilesize}
   */
  public Fallocate fromOffset(long offset) {
    if (offset < 0 || offset > finalFilesize) throw new IllegalArgumentException();
    this.offset = offset;
    return this;
  }

  /**
   * Performs the allocation using the best available strategy on the current platform.
   *
   * <p>Behavior by platform:
   *
   * <ul>
   *   <li><strong>Linux</strong>: Calls native {@code fallocate(fd, mode, offset, length)}. When
   *       the call fails (non-zero errno), falls back to the legacy writer.
   *   <li><strong>Other POSIX</strong>: Calls native {@code posix_fallocate(fd, offset, length)}.
   *       On failure, falls back to the legacy writer.
   *   <li><strong>Non-POSIX / missing descriptor</strong>: Uses the legacy writer directly.
   * </ul>
   *
   * <p>The legacy writer extends the file to {@code finalFilesize}. On Windows it writes a single
   * byte at {@code newLength - 1}. On other platforms it writes zero-filled blocks in chunks,
   * retrying partial writes until the full range is covered.
   *
   * <p>Side effects: may extend the underlying file; may log a message when a native call fails.
   *
   * @throws IOException if I/O fails during the legacy fill path
   */
  public void execute() throws IOException {
    int errno = 0;
    boolean isUnsupported = false;
    if (fd > 2) {
      if (IS_LINUX) {
        final int result = FallocateHolder.fallocate(fd, 0, offset, finalFilesize - offset);
        errno = result == 0 ? 0 : Native.getLastError();
      } else if (IS_POSIX) {
        errno = FallocateHolderPOSIX.posix_fallocate(fd, offset, finalFilesize - offset);
      } else {
        isUnsupported = true;
      }
    } else {
      isUnsupported = true;
    }

    if (isUnsupported || errno != 0) {
      if (errno != 0) {
        // OS supports fallocate() but it failed. Do not log if the OS does not support fallocate().
        LOG.info("fallocate() failed; using legacy method; errno={}", errno);
      }
      legacyFill(channel, finalFilesize, offset);
    }
  }

  private static class FallocateHolder {
    static {
      // Bind this class to the platform C library so JNA can resolve fallocate.
      Native.register(FallocateHolder.class, Platform.C_LIBRARY_NAME);
    }

    private static native int fallocate(int fd, int mode, long offset, long length);
  }

  private static class FallocateHolderPOSIX {
    static {
      // Bind POSIX variant to resolve posix_fallocate on non-Linux platforms.
      Native.register(FallocateHolderPOSIX.class, Platform.C_LIBRARY_NAME);
    }

    @SuppressWarnings("java:S100")
    private static native int posix_fallocate(int fd, long offset, long length);
  }

  /**
   * Best-effort extraction of a channel's {@link FileDescriptor} to get its native fd value.
   *
   * <p>Returns {@code 0} when the descriptor is inaccessible (e.g., different JDK implementation or
   * insufficient permissions) which forces legacy behavior for allocation.
   */
  private static int getDescriptor(FileChannel channel) {
    try {
      // FileChannel implementations typically declare a private 'fd' field holding a
      // java.io.FileDescriptor. Use reflection as a last resort to access it.
      final Field field = channel.getClass().getDeclaredField("fd");
      // Attempt to make the field accessible; fall back to legacy when forbidden.
      if (!field.canAccess(channel) && !field.trySetAccessible()) {
        return 0; // Trigger legacy path when descriptor is not accessible
      }
      return getDescriptor((FileDescriptor) field.get(channel));
    } catch (final Exception _) {
      // Intentionally fall back: descriptor is unavailable (e.g., different JDK implementation).
      return 0;
    }
  }

  /**
   * Best-effort extraction of the integer fd from a {@link FileDescriptor}.
   *
   * <p>Different VMs use different field names ({@code fd}, {@code descriptor}). When extraction
   * fails, returns {@code 0} to signal that native allocation should not be attempted.
   */
  private static int getDescriptor(FileDescriptor descriptor) {
    try {
      // Oracle/OpenJDK typically declare 'fd'; Android sometimes uses 'descriptor'.
      final Field field = descriptor.getClass().getDeclaredField(IS_ANDROID ? "descriptor" : "fd");
      // Attempt to make the field accessible; fall back to legacy when forbidden.
      if (!field.canAccess(descriptor) && !field.trySetAccessible()) {
        return 0; // Trigger legacy path when descriptor is not accessible
      }
      return (int) field.get(descriptor);
    } catch (final Exception _) {
      // Intentionally fall back: descriptor is unavailable or null; return 0 for the legacy path.
      return 0;
    }
  }

  /**
   * Portable fallback writer used when native allocation is unavailable or fails.
   *
   * <p>On Windows, extends the file by writing a single byte at {@code newLength - 1}. On other
   * platforms, writes zero-filled blocks (4 MiB) from {@code offset} to {@code newLength}, handling
   * partial writes by retrying until the requested range is fully written.
   *
   * @param fc target channel
   * @param newLength desired file size in bytes after the operation
   * @param offset starting position (inclusive)
   * @throws IOException if any channel writing fails
   */
  private static void legacyFill(FileChannel fc, long newLength, long offset) throws IOException {
    if (IS_WINDOWS) {
      // Windows does not create sparse files by default; extend by writing the last byte.
      ByteBuffer one = ByteBuffer.allocate(1);
      long pos = newLength - 1;
      int written = fc.write(one, pos);
      while (written == 0 && one.hasRemaining()) {
        one.clear();
        written = fc.write(one, pos);
      }
    } else {
      // Write zeros in 4 MiB chunks to reduce the number of IO calls.
      byte[] b = new byte[4096 * 1024];
      ByteBuffer bb = ByteBuffer.wrap(b);
      while ((offset < newLength) && (newLength - offset >= b.length)) {
        bb.rewind();
        offset += fc.write(bb, offset);
      }
      // Write any remaining tail in one buffer. Retry until all bytes are written.
      while (offset < newLength) {
        offset += fc.write(ByteBuffer.wrap(new byte[Math.toIntExact(newLength - offset)]), offset);
      }
    }
  }
}
