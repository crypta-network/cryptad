package network.crypta.support.api;

import java.io.IOException;

/**
 * Factory for creating {@link LockableRandomAccessBuffer} instances.
 *
 * <p>Implementations may allocate memory-backed or file-backed storage, and may add behaviors such
 * as encryption, padding, or disk-space checks. Some factories produce only temporary
 * (non-persistent) buffers, while others can persist enough information for later restoration via
 * the buffer API. See concrete implementations for details.
 *
 * <p><strong>Ownership:</strong> Callers are responsible for releasing resources held by returned
 * buffers (for example, by calling {@link LockableRandomAccessBuffer#free()}) when finished.
 *
 * <p><strong>Thread-safety:</strong> Concurrency characteristics are implementation-defined;
 * consult the concrete class documentation. Concurrency guarantees for the buffers themselves are
 * documented on {@link LockableRandomAccessBuffer} and its implementations.
 *
 * <p><strong>Units:</strong> Sizes are in bytes.
 *
 * @author toad
 */
public interface LockableRandomAccessBufferFactory {

  /**
   * Creates a zero-initialized random-access buffer of fixed size.
   *
   * <p>Implementations typically pre-allocate the requested capacity; callers should not assume the
   * size can grow beyond {@code size}. Even when space is reserved up front, subsequent I/O may
   * still fail due to hardware or operating-system errors.
   *
   * @param size logical length in bytes; must be {@code >= 0}
   * @return a {@link LockableRandomAccessBuffer} of length {@code size}
   * @throws IOException if creating the buffer fails due to an I/O error
   * @throws IllegalArgumentException if {@code size < 0}
   */
  LockableRandomAccessBuffer makeRAF(long size) throws IOException;

  /**
   * Creates a random-access buffer initialized from a segment of a byte array.
   *
   * <p>The new buffer's content equals {@code initialContents[offset .. offset + size)}. Data is
   * copied into the buffer even when the underlying implementation is in-memory; callers should not
   * rely on the factory retaining a reference to {@code initialContents}.
   *
   * @param initialContents source array that contains at least {@code offset + size} bytes
   * @param offset starting index within {@code initialContents}
   * @param size number of bytes to copy; also the logical length of the returned buffer; must be
   *     {@code >= 0}
   * @param readOnly whether the returned buffer should prohibit writes if supported by the
   *     implementation
   * @return a {@link LockableRandomAccessBuffer} whose first {@code size} bytes are initialized
   *     from {@code initialContents}
   * @throws IOException if allocation or initialization fails due to an I/O error
   * @throws IllegalArgumentException if {@code size < 0}
   */
  LockableRandomAccessBuffer makeRAF(byte[] initialContents, int offset, int size, boolean readOnly)
      throws IOException;
}
