package com.onionnetworks.io;

import java.io.File;
import java.io.IOException;

/**
 * Abstract decorator that forwards every {@link RAF} operation to another instance while allowing
 * subclasses to insert filtering, journaling, or synchronization policies around the delegated
 * calls.
 *
 * <p>Use this base when you need to wrap an existing random-access file with cross-cutting
 * behavior—such as journaling, commit tracking, or blocking semantics—without reimplementing the
 * underlying cursor and file-lifecycle logic. Each public method remains synchronized so that a
 * single {@code FilterRAF} can safely coordinate concurrent callers; subclasses are expected to
 * honor that contract and avoid leaking the delegate in an inconsistent state. The delegated
 * instance is supplied during construction and kept for the lifetime of the wrapper; closing the
 * wrapper closes the delegate. Callers typically subclass this type, override a subset of methods
 * to add pre-/post-processing, and otherwise rely on the default pass-through behavior to preserve
 * semantics and positioning.
 *
 * <ul>
 *   <li>Delegates all file operations to a provided {@link RAF}.
 *   <li>Maintains synchronized access so cursor movements remain serialized.
 *   <li>Intended for layered behaviors such as journaling or commit-aware reads.
 * </ul>
 */
public abstract class FilterRAF extends RAF {

  /**
   * Target {@link RAF} that receives all delegated calls; never {@code null} after construction and
   * closed when this wrapper is closed.
   */
  protected final RAF delegateRaf;

  /**
   * Creates a new filtered view that forwards to the supplied random-access file wrapper.
   *
   * <p>No ownership transfer occurs beyond delegation: subclasses may add state, but callers should
   * assume that closing this wrapper closes the provided delegate as well. The wrapper does not
   * change the delegate's mode or length; it simply intercepts calls so that subclasses can enforce
   * additional invariants or record-keeping.
   *
   * @param raf non-null {@link RAF} to delegate all operations to; must already be open and in the
   *     desired access mode for the lifetime of this wrapper.
   */
  protected FilterRAF(RAF raf) {
    this.delegateRaf = raf;
  }

  /**
   * Writes a slice of the provided buffer at the given absolute position, forwarding directly to
   * the delegate.
   *
   * <p>The call retains the synchronization guarantees of {@link RAF#seekAndWrite(long, byte[],
   * int, int)} so subclasses can safely layer additional bookkeeping without interleaving cursor
   * movement. No buffering or retries are performed; any checked exception from the delegate is
   * propagated unchanged.
   *
   * @param pos zero-based offset where writing begins; negative values are invalid and delegated
   *     calls will fail accordingly.
   * @param b source byte array containing data to write; must remain valid for the duration of the
   *     call and obey the offset and length bounds.
   * @param off starting index within {@code b} from which bytes are taken; must be non-negative and
   *     allow {@code len} bytes to fit within the array.
   * @param len number of bytes to write from the buffer slice; may be zero to perform a no-op that
   *     still validates arguments.
   * @throws IOException if the delegate cannot seek or write at the requested position or if the
   *     underlying file handle rejects the operation.
   */
  @Override
  public synchronized void seekAndWrite(long pos, byte[] b, int off, int len) throws IOException {
    delegateRaf.seekAndWrite(pos, b, off, len);
  }

  /**
   * Reads up to {@code len} bytes from the delegate starting at the specified absolute position.
   *
   * <p>The method keeps the synchronized, cursor-serializing semantics of the base implementation
   * and performs no additional buffering or translation. Subclasses can override to apply filtering
   * before or after delegation but should preserve the return contract of returning the number of
   * bytes read or {@code -1} on end of file.
   *
   * @param pos absolute offset to seek before reading; must be non-negative to avoid delegate
   *     errors.
   * @param b destination buffer that receives data; must have capacity for the requested slice and
   *     remain mutable for the duration of the call.
   * @param off starting index in {@code b} where read bytes are placed; must satisfy array bounds
   *     constraints.
   * @param len maximum number of bytes to read; negative values are invalid and will surface as
   *     delegate failures.
   * @return count of bytes actually read, or {@code -1} if positioned at end of file before any
   *     data is read; never larger than {@code len}.
   * @throws IOException if seeking or reading fails in the delegate, including when the file is
   *     closed or not open for reading.
   */
  @Override
  public synchronized int seekAndRead(long pos, byte[] b, int off, int len) throws IOException {

    return delegateRaf.seekAndRead(pos, b, off, len);
  }

  /**
   * Reads exactly {@code len} bytes from the delegate beginning at the provided absolute offset.
   *
   * <p>This pass-through keeps the blocking behavior of {@link RAF#seekAndReadFully(long, byte[],
   * int, int)}: it loops until the buffer slice is filled or an {@link IOException} is raised. It
   * is suitable for callers expecting fixed-length records and needing deterministic completion or
   * failure semantics.
   *
   * @param pos absolute file position at which reading starts; must be non-negative and within the
   *     addressable range of the underlying file.
   * @param b destination byte array that will hold all requested bytes; must not be {@code null}
   *     and should be sized appropriately for the offset and length.
   * @param off index in {@code b} where storage begins; must allow the subsequent {@code len} bytes
   *     to fit without exceeding array bounds.
   * @param len number of bytes to read; must be positive for meaningful work, though zero is
   *     permitted as a no-op validation pass.
   * @throws IOException if insufficient data is available, the delegate cannot seek, or any I/O
   *     error occurs while filling the buffer slice.
   */
  @Override
  public synchronized void seekAndReadFully(long pos, byte[] b, int off, int len)
      throws IOException {
    delegateRaf.seekAndReadFully(pos, b, off, len);
  }

  /**
   * Renames the underlying file to the requested destination using the delegate's move semantics.
   *
   * <p>Callers can rely on the delegate to close and reopen the underlying handle as needed. This
   * wrapper performs no additional checks beyond serialization; subclasses may override to track
   * journal entries or to enforce policy before deferring to the delegate.
   *
   * @param destFile target path for the rename operation; must refer to a writable location or the
   *     delegate will signal failure.
   * @throws IOException if the delegate encounters an error while closing, copying, or reopening
   *     the file during the rename process.
   */
  @Override
  public synchronized void renameTo(File destFile) throws IOException {
    delegateRaf.renameTo(destFile);
  }

  /**
   * Returns the access mode string currently used by the delegate random-access file.
   *
   * <p>The value is whatever the delegate reports; this wrapper does not alter or cache it. Typical
   * results include {@code "r"} for read-only access and {@code "rw"} for read/write access.
   *
   * @return non-null mode string describing the delegate's current open mode.
   */
  @Override
  public synchronized String getMode() {
    return delegateRaf.getMode();
  }

  /**
   * Indicates whether the delegate has already been closed.
   *
   * <p>This is a pass-through convenience that preserves synchronized visibility. Subclasses should
   * respect the delegate's closed state when layering additional behavior.
   *
   * @return {@code true} if the delegate reports a closed state; otherwise {@code false}.
   */
  @Override
  public synchronized boolean isClosed() {
    return delegateRaf.isClosed();
  }

  /**
   * Exposes the current {@link File} that backs the delegated random-access handle.
   *
   * <p>The reference reflects any renames performed by the delegate. Mutating the returned {@code
   * File} does not affect this wrapper; callers should treat it as a snapshot and avoid external
   * deletion that would violate the delegate's lifecycle.
   *
   * @return non-null {@link File} pointing to the delegate's current on-disk location.
   */
  @Override
  public synchronized File getFile() {
    return delegateRaf.getFile();
  }

  /**
   * Reopens the delegate in read-only mode when supported, preventing further writes.
   *
   * <p>The method defers to the delegate to perform any necessary handle recreation. It remains
   * synchronized to serialize mode changes with concurrent reads and writes.
   *
   * @throws IOException if the delegate cannot transition to read-only access or the underlying
   *     file system rejects the change.
   */
  @Override
  public synchronized void setReadOnly() throws IOException {
    delegateRaf.setReadOnly();
  }

  /**
   * Marks the delegate for deletion when the stream is closed.
   *
   * <p>Only the delegate's internal flag is updated; no deletion occurs until {@link #close()} is
   * invoked. Subclasses may override to coordinate journal cleanup before deferring here.
   */
  @Override
  public synchronized void deleteOnClose() {
    delegateRaf.deleteOnClose();
  }

  /**
   * Truncates or extends the underlying file to the specified length using the delegate.
   *
   * <p>Extending fills new bytes with zeros per platform behavior; truncating discards excess
   * content. Synchronization ensures length mutations serialize with other cursor-based operations
   * invoked through this wrapper.
   *
   * @param len new file size in bytes; must be zero or positive, otherwise the delegate will raise
   *     an {@link IOException}.
   * @throws IOException if the delegate cannot adjust the length due to filesystem constraints or a
   *     closed handle.
   */
  @Override
  public synchronized void setLength(long len) throws IOException {
    delegateRaf.setLength(len);
  }

  /**
   * Returns the current size of the underlying file in bytes.
   *
   * <p>This is a direct delegate call and therefore reflects any concurrent mutations performed
   * through other wrappers sharing the same {@link RAF}. The value is obtained under the same
   * synchronization used for other operations.
   *
   * @return non-negative file length in bytes as reported by the delegate.
   * @throws IOException if the delegate cannot query the length, such as when the handle is closed
   *     or the filesystem reports an error.
   */
  @Override
  public synchronized long length() throws IOException {
    return delegateRaf.length();
  }

  /**
   * Closes this wrapper and the underlying delegate, releasing any system resources held by the
   * random-access file.
   *
   * <p>Subclasses may extend to flush metadata before deferring to the delegate. After this call
   * returns, subsequent operations on the wrapper should be considered invalid and may throw
   * exceptions.
   *
   * @throws IOException if closing the delegate fails or the filesystem rejects final operations
   *     performed during close.
   */
  @Override
  public synchronized void close() throws IOException {
    delegateRaf.close();
  }

  /**
   * Returns the delegate's {@link Object#toString()} representation, preserving existing debug
   * output semantics.
   *
   * @return non-null string produced by the underlying delegate's {@code toString()}
   *     implementation.
   */
  @Override
  public String toString() {
    return delegateRaf.toString();
  }
}
