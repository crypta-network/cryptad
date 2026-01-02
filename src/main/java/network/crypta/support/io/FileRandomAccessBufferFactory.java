package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.util.Random;

/**
 * Factory for creating random-access buffers backed by caller-supplied files.
 *
 * <p>Implementations create {@link PooledFileRandomAccessBuffer} instances whose storage resides in
 * the given {@link File}. This interface is used when the caller must control the exact path of the
 * on-disk file (e.g., when a higher layer has already chosen a location) rather than letting a
 * factory generate a temporary filename.
 *
 * <p>Thread-safety: implementation-specific. Callers should not assume concurrent safety unless
 * explicitly documented; some implementations serialize creation to provide accurate free-space
 * checks.
 */
public interface FileRandomAccessBufferFactory {

  /**
   * Creates a new random-access buffer backed by the specified file and sized to {@code size}
   * bytes.
   *
   * <p>The returned buffer provides positional read/write access to the file and may preallocate
   * disk space so the logical length equals the requested size. Exact file creation semantics are
   * implementation-defined; some implementations expect the file to already exist and be empty, and
   * may delete it on failure.
   *
   * @param file The backing file. Must be writable when a writable buffer is created. The file’s
   *     lifecycle after creation (e.g., deleted on {@link PooledFileRandomAccessBuffer#free()}) is
   *     implementation-specific. Some implementations require the file to exist and be empty, while
   *     others may create or truncate it.
   * @param size The desired logical length of the buffer in bytes. Must be non-negative. Some
   *     implementations may preallocate up to this amount of disk space to ensure predictable
   *     usage.
   * @param random Optional RNG used by implementations that encrypt or otherwise randomize on-disk
   *     content; may be {@code null} and may be ignored.
   * @return A {@link PooledFileRandomAccessBuffer} backed by {@code file} with logical length
   *     {@code size}.
   * @throws InsufficientDiskSpaceException If there is not enough free space to allocate the
   *     buffer.
   * @throws IOException If the file cannot be created, opened, or sized; or if any other I/O error
   *     occurs.
   */
  PooledFileRandomAccessBuffer createNewRAF(File file, long size, Random random) throws IOException;
}
