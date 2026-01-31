package network.crypta.support.io;

import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.LockableRandomAccessBuffer;

/**
 * Random-access buffer that contains only zero bytes and performs no I/O.
 *
 * <p>This implementation models a fixed-length buffer whose unread content is defined to be zeros
 * and whose writes are ignored. It is useful as a sentinel or for tests where a {@link
 * network.crypta.support.api.RandomAccessBuffer} is required but persistence is not.
 *
 * <h2>Behavior</h2>
 *
 * <ul>
 *   <li>{@link #size()} returns the length supplied at construction; it may be negative if so
 *       constructed (no validation is performed).
 *   <li>{@link #pread(long, byte[], int, int)} fills the requested range with {@code 0} bytes and
 *       ignores the {@code fileOffset}.
 *   <li>{@link #pwrite(long, byte[], int, int)} is a no-op and ignores all arguments (including a
 *       {@code null} buffer).
 *   <li>{@link #lockOpen()} returns a trivial lock whose {@link RAFLock#unlock()} may be called
 *       exactly once; a second call throws {@link IllegalStateException}.
 *   <li>Persistence is unsupported: {@link #onResume(ClientContext)} and {@link
 *       #storeTo(DataOutputStream)} throw {@link UnsupportedOperationException}.
 *   <li>Equality is by runtime class only; {@link #hashCode()} returns {@code 0} to remain
 *       consistent with that definition.
 * </ul>
 *
 * <p>Thread-safety: Methods contain no shared mutable state beyond the immutable size; they do not
 * block or perform I/O.
 */
public final class NullRandomAccessBuffer implements LockableRandomAccessBuffer {

  private final long length;

  /**
   * Creates a buffer with the provided logical length.
   *
   * @param length length reported by {@link #size()} (no validation or normalization is performed)
   */
  public NullRandomAccessBuffer(long length) {
    this.length = length;
  }

  /**
   * Returns the logical size of this buffer.
   *
   * @return the length passed to the constructor
   */
  @Override
  public long size() {
    return length;
  }

  /**
   * Reads zeros into the supplied buffer slice.
   *
   * <p>The {@code fileOffset} parameter is ignored. This method does not perform bounds checking on
   * {@code bufOffset} and {@code length}; invalid ranges will result in {@link
   * ArrayIndexOutOfBoundsException} from the array write loop.
   *
   * @param fileOffset ignored offset in the logical buffer
   * @param buf destination array to fill with zeros
   * @param bufOffset first index in {@code buf} to write
   * @param length number of bytes to write; negative values result in no writes
   * @throws IOException never thrown by this implementation
   * @throws ArrayIndexOutOfBoundsException if the buffer range is invalid
   * @throws NullPointerException if {@code buf} is {@code null}
   */
  @Override
  public void pread(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    for (int i = 0; i < length; i++) buf[bufOffset + i] = 0;
  }

  /**
   * Ignores all writes.
   *
   * <p>The write request is accepted and discarded. {@code buf} may be {@code null}. All parameters
   * are ignored, and no I/O occurs.
   *
   * @param fileOffset ignored
   * @param buf ignored; may be {@code null}
   * @param bufOffset ignored
   * @param length ignored
   * @throws IOException never thrown by this implementation
   */
  @Override
  public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    // No-op: writes are intentionally discarded.
  }

  /** Closes this buffer. No resources are held, so this is a no-op. */
  @Override
  public void close() {
    // No-op: no underlying resource to close.
  }

  /** Frees resources associated with this buffer. This implementation does nothing. */
  @Override
  public void free() {
    // No-op: nothing to free.
  }

  /**
   * Returns a trivial lock representing an "open" reference.
   *
   * <p>The returned lock has no effect on I/O (there is none) and exists to satisfy the {@link
   * LockableRandomAccessBuffer} contract. Calling {@link RAFLock#unlock()} a second time throws
   * {@link IllegalStateException}.
   *
   * @return a new {@link RAFLock}
   * @throws IOException never thrown by this implementation
   */
  @Override
  public RAFLock lockOpen() throws IOException {
    return new RAFLock() {

      @Override
      protected void innerUnlock() {
        // No-op: nothing to release.
      }
    };
  }

  /**
   * Not supported for this implementation.
   *
   * @param context client context
   * @throws ResumeFailedException always thrown: resuming is not supported
   */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    throw new UnsupportedOperationException();
  }

  /**
   * Not supported for this implementation.
   *
   * @param dos destination stream
   * @throws IOException never thrown by this implementation
   * @throws UnsupportedOperationException always thrown: persistence is not supported
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    throw new UnsupportedOperationException();
  }

  /**
   * Returns a constant hash code consistent with class-only equality.
   *
   * @return {@code 0}
   */
  @Override
  public int hashCode() {
    return 0;
  }

  /**
   * Compares by runtime class only.
   *
   * <p>Two instances are considered equal if and only if they are instances of the same runtime
   * class. The configured length is intentionally ignored.
   *
   * @param o the object to compare
   * @return {@code true} when {@code o} has the same runtime class; {@code false} otherwise
   */
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    return o instanceof NullRandomAccessBuffer;
  }
}
