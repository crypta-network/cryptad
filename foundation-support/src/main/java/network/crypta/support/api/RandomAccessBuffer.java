package network.crypta.support.api;

import java.io.Closeable;
import java.io.IOException;

/**
 * Abstraction for a fixed-size, random-access byte buffer.
 *
 * <p>Implementations provide thread-safe access: either by internally serializing operations or by
 * supporting concurrent reads (and writes where applicable). The logical length of the buffer is
 * constant for the lifetime of the instance.
 *
 * <p>Some implementations may offer a constructor that creates a zero-initialized buffer of a
 * specified size. This interface does not prescribe the storage medium; implementations may be
 * memory-backed, file-backed, or layered on another {@code RandomAccessBuffer}.
 *
 * @author toad
 */
public interface RandomAccessBuffer extends Closeable {

  /**
   * Returns the total size of the buffer in bytes.
   *
   * <p>The value is constant and does not change after construction.
   *
   * @return the number of bytes addressable by this buffer
   */
  long size();

  /**
   * Reads {@code length} bytes starting at {@code fileOffset} into {@code buf}.
   *
   * <p>The operation behaves like {@link java.io.DataInputStream#readFully(byte[], int, int)}: it
   * either reads the full requested range or throws. If this buffer has been closed, the method
   * must throw.
   *
   * @param fileOffset byte offset within the buffer to start reading
   * @param buf destination array to receive the bytes
   * @param bufOffset index in {@code buf} of the first byte to write
   * @param length number of bytes to read
   * @throws IOException if the required number of bytes cannot be read or the buffer is closed
   * @throws IllegalArgumentException if {@code fileOffset} is negative
   */
  void pread(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException;

  /**
   * Writes {@code length} bytes from {@code buf} starting at {@code bufOffset} to {@code
   * fileOffset}.
   *
   * <p>Implementations should commit all bytes or throw; partial writes are not permitted by
   * contract. If this buffer has been closed, the method must throw.
   *
   * @param fileOffset byte offset within the buffer to start writing
   * @param buf source array containing the bytes to write
   * @param bufOffset index in {@code buf} of the first byte to read
   * @param length number of bytes to write
   * @throws IOException if the required number of bytes cannot be written or the buffer is closed
   * @throws IllegalArgumentException if {@code fileOffset} is negative
   */
  void pwrite(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException;

  /**
   * Closes the buffer and releases any resources held by it.
   *
   * <p>After a call to {@code close()}, subsequent {@link #pread(long, byte[], int, int)} and
   * {@link #pwrite(long, byte[], int, int)} calls must throw an {@link IOException}.
   */
  @Override
  void close();

  /**
   * Frees underlying resources associated with the buffer.
   *
   * <p>In some implementations this may be a no-op. Callers should ensure there are no remaining
   * references so the object can be garbage collected. Behavior after {@code free()} is
   * implementation-defined; callers should not attempt further I/O through this instance.
   */
  void free();
}
