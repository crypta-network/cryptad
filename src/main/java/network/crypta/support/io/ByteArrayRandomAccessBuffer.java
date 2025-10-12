package network.crypta.support.io;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.LockableRandomAccessBuffer;

/**
 * In-memory {@link LockableRandomAccessBuffer} backed by a fixed-size {@code byte[]}.
 *
 * <p>This implementation provides constant-time indexed reads and writes on a pre-allocated array
 * and is intended for small or ephemeral data. The logical size equals the underlying array length
 * and never changes. Accessor methods validate bounds rigorously and either complete the entire
 * operation or throw.
 *
 * <p>Threading: {@link #pread(long, byte[], int, int)} and {@link #pwrite(long, byte[], int, int)}
 * are {@code synchronized} to serialize access. The lock returned by {@link #lockOpen()} signals
 * liveness only and does not add concurrency guarantees.
 *
 * <p>Lifecycle: {@link #close()} marks the buffer closed; subsequent I/O throws {@link
 * IOException}. {@link #free()} performs no action; the buffer is eligible for GC when no
 * references remain.
 */
public class ByteArrayRandomAccessBuffer implements LockableRandomAccessBuffer, Serializable {

  @Serial private static final long serialVersionUID = 1L;
  private final byte[] data;
  private boolean readOnly;
  private boolean closed;

  /**
   * Create a buffer that directly wraps the supplied array.
   *
   * <p>No copying occurs; callers must not mutate the array in ways that break expected invariants.
   * The buffer's size equals {@code padded.length}.
   *
   * @param padded backing array to use as storage (must not be {@code null})
   */
  public ByteArrayRandomAccessBuffer(byte[] padded) {
    this.data = padded;
  }

  /**
   * Create a zero-filled buffer of the given size.
   *
   * @param size number of bytes to allocate; may be zero
   * @throws NegativeArraySizeException if {@code size < 0}
   */
  public ByteArrayRandomAccessBuffer(int size) {
    this.data = new byte[size];
  }

  /**
   * Create a buffer by copying a range from an existing array.
   *
   * <p>The new buffer's content equals {@code initialContents[offset..offset+size)} (copied), and
   * its {@linkplain #isReadOnly() read-only} state is set from the parameter.
   *
   * @param initialContents source array
   * @param offset starting offset in {@code initialContents}
   * @param size number of bytes to copy
   * @param readOnly whether the resulting buffer rejects writes
   * @throws ArrayIndexOutOfBoundsException if the range {@code [offset, offset+size)} falls outside
   *     {@code initialContents}
   */
  public ByteArrayRandomAccessBuffer(
      byte[] initialContents, int offset, int size, boolean readOnly) {
    data = Arrays.copyOfRange(initialContents, offset, offset + size);
    this.readOnly = readOnly;
  }

  /**
   * No-arg constructor for serialization frameworks.
   *
   * <p>Not intended for direct use in application code. The {@link #data} field is left {@code
   * null} and is expected to be populated by a deserialization mechanism.
   */
  protected ByteArrayRandomAccessBuffer() {
    // Intentionally empty: for serialization only.
    data = null;
  }

  @Override
  public void close() {
    // Mark closed; subsequent I/O methods will refuse to operate.
    closed = true;
  }

  @Override
  public synchronized void pread(long fileOffset, byte[] buf, int bufOffset, int length)
      throws IOException {
    // Validate state and bounds; either read the full range or throw.
    if (closed) throw new IOException("Closed");
    if (fileOffset < 0) throw new IllegalArgumentException("Cannot read before zero");
    if (fileOffset + length > data.length)
      throw new IOException(
          "Cannot read after end: trying to read from "
              + fileOffset
              + " to "
              + (fileOffset + length)
              + " on block length "
              + data.length);
    System.arraycopy(data, (int) fileOffset, buf, bufOffset, length);
  }

  @Override
  public synchronized void pwrite(long fileOffset, byte[] buf, int bufOffset, int length)
      throws IOException {
    // Validate state and bounds; either write the full range or throw.
    if (closed) throw new IOException("Closed");
    if (fileOffset < 0) throw new IllegalArgumentException("Cannot write before zero");
    if (fileOffset + length > data.length)
      throw new IOException(
          "Cannot write after end: trying to write from "
              + fileOffset
              + " to "
              + (fileOffset + length)
              + " on block length "
              + data.length);
    if (readOnly) throw new IOException("Read-only");
    System.arraycopy(buf, bufOffset, data, (int) fileOffset, length);
  }

  /**
   * Return the fixed logical size of this buffer.
   *
   * @return number of addressable bytes
   */
  @Override
  public long size() {
    return data.length;
  }

  /**
   * Set the buffer to read-only mode.
   *
   * <p>After calling this method, any subsequent {@link #pwrite(long, byte[], int, int)} fails with
   * {@link IOException}. Reads are unaffected.
   */
  public synchronized void setReadOnly() {
    readOnly = true;
  }

  /**
   * Return whether the buffer rejects writes.
   *
   * @return {@code true} if writes are not permitted
   */
  public synchronized boolean isReadOnly() {
    return readOnly;
  }

  /**
   * Acquire a lightweight lock that indicates the buffer should remain open.
   *
   * <p>The returned lock does not provide mutual exclusion or visibility semantics; it exists only
   * to integrate with callers that track "open" usage. Closing the lock via {@link
   * RAFLock#unlock()} has no side effects here.
   *
   * @return a lock token that can be {@linkplain RAFLock#unlock() released}
   */
  @Override
  public RAFLock lockOpen() {
    return new RAFLock() {

      @Override
      protected void innerUnlock() {
        // No-op: this implementation is always open while referenced.
      }
    };
  }

  /**
   * Release any underlying resources.
   *
   * <p>No action is required for this in-memory implementation.
   */
  @Override
  public void free() {
    // No resources to release.
  }

  /** Package-local! */
  byte[] getBuffer() {
    return data;
  }

  /**
   * Reconnect any external state after deserialization.
   *
   * <p>No action is required for this in-memory implementation.
   *
   * @param context the client context requesting resume
   */
  @Override
  public void onResume(ClientContext context) {
    // No-op.
  }

  /**
   * Persist enough information to reconstruct the buffer later.
   *
   * <p>This operation is intentionally unsupported; callers should persist their own higher-level
   * state instead.
   *
   * @param dos destination stream
   * @throws UnsupportedOperationException always
   */
  @Override
  public void storeTo(DataOutputStream dos) {
    throw new UnsupportedOperationException();
  }

  // Default hashCode() and equals() are correct for this type.

}
