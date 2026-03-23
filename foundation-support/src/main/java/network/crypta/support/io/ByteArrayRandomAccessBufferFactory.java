package network.crypta.support.io;

import java.io.IOException;
import java.util.Arrays;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;

/**
 * Factory that produces in-memory {@link LockableRandomAccessBuffer} instances backed by byte
 * arrays.
 *
 * <p>This factory creates fixed-size buffers and range-copied buffers intended for small or
 * ephemeral data. The returned buffers expose random-access semantics and have a constant logical
 * size for their lifetime.
 *
 * <p>Threading: creation is thread-safe (no shared mutable state). Returned buffers document their
 * own synchronization guarantees.
 */
public class ByteArrayRandomAccessBufferFactory implements LockableRandomAccessBufferFactory {

  /**
   * Create a zero-initialized buffer with the given size in bytes.
   *
   * @param size number of bytes in the new buffer; may be {@code 0}
   * @return a {@link LockableRandomAccessBuffer} backed by a new array of length {@code size}
   * @throws IllegalArgumentException if {@code size < 0}
   * @throws IOException if {@code size} exceeds {@link Integer#MAX_VALUE} (message: {@code "Too
   *     big"})
   */
  @Override
  public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
    if (size < 0) throw new IllegalArgumentException();
    // Guard against arrays larger than the JVM can index with an int.
    if (size > Integer.MAX_VALUE) throw new IOException("Too big");
    byte[] buf = new byte[(int) size];
    return new ByteArrayRandomAccessBuffer(buf);
  }

  /**
   * Create a buffer by copying a window from the provided array.
   *
   * <p>The new buffer's content equals {@code initialContents[offset..offset+size)}. The copy is
   * deep; subsequent mutations of {@code initialContents} do not affect the buffer. The returned
   * buffer's read-only flag is set according to {@code readOnly}.
   *
   * @param initialContents source array to copy from (must not be {@code null})
   * @param offset starting index within {@code initialContents}
   * @param size number of bytes to copy; may be {@code 0}
   * @param readOnly whether writes to the returned buffer are rejected
   * @return a {@link LockableRandomAccessBuffer} whose size equals {@code size}
   * @throws IllegalArgumentException if {@code size < 0}
   * @throws ArrayIndexOutOfBoundsException if {@code offset} or {@code offset+size} lies outside
   *     {@code initialContents} (enforced by {@link Arrays#copyOfRange(byte[], int, int)})
   * @throws IOException not used by this in-memory implementation; declared for interface
   *     compatibility
   */
  @Override
  public LockableRandomAccessBuffer makeRAF(
      byte[] initialContents, int offset, int size, boolean readOnly) throws IOException {
    if (size < 0) throw new IllegalArgumentException();
    // copyOfRange validates bounds and pads with zeros when the end exceeds the source length.
    return new ByteArrayRandomAccessBuffer(
        Arrays.copyOfRange(initialContents, offset, offset + size), 0, size, readOnly);
  }
}
