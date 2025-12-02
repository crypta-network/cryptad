package com.onionnetworks.io;

import com.onionnetworks.util.*;
import java.io.*;
import java.util.HashMap;
import java.util.Map;

/**
 * Random-access file wrapper that defers visibility of written bytes until callers explicitly
 * commit the corresponding ranges.
 *
 * <p>This wrapper coordinates producers writing into an underlying {@link RAF} and consumers that
 * must block until those bytes are marked committed. Reads short-circuit to the delegate when the
 * file is read-only and fully committed; otherwise they wait, optionally receiving data already
 * resident in memory through temporary buffers. Writes are rejected whenever they overlap any range
 * that has been committed previously, ensuring immutability once data is exposed.
 *
 * <p>Use {@code CommitRaf} for multipart downloads, transactional persistence, or any workflow
 * where exposing partially written data would be unsafe. Instances synchronize all public
 * operations, so a single wrapper can safely coordinate multiple reader and writer threads without
 * additional locks. Committed regions are tracked in-memory via {@link RangeSet}, and exceptions
 * injected through {@link #setException(IOException)} are propagated to subsequent callers before
 * any I/O takes place.
 *
 * <ul>
 *   <li>Writes fail if they overlap any committed byte.
 *   <li>Reads block until their starting position is committed.
 *   <li>Closing cascades to the delegate {@link RAF} and wakes blocked threads.
 * </ul>
 *
 * @see Range
 * @see RangeSet
 */
public class CommitRaf extends FilterRAF {

  RangeSet committed = new RangeSet();
  IOException e;

  // Make sure not to key buffers off of a Range, or any other non-unique
  // object, as multiple readers may be using the same key and will trash
  // each other.
  Map<Object, Tuple> buffers = new HashMap<>();

  /**
   * Creates a commit-aware wrapper around the provided random-access file.
   *
   * <p>The wrapper shares the delegate; it does not duplicate file descriptors and will close the
   * delegate when {@link #close()} is invoked. Use a single instance per file when coordinating
   * multithreaded producers and consumers that rely on explicit commit semantics rather than
   * immediate visibility. All operations are synchronized on this instance, simplifying external
   * locking requirements while maintaining serialized access to the delegate.
   *
   * @param raf underlying {@link RAF} providing persistent storage and positioning semantics
   */
  public CommitRaf(RAF raf) {
    super(raf);
  }

  /**
   * Writes bytes to the delegate and updates any blocked readers once the data is present.
   *
   * <p>A write is rejected if any byte in the target range has already been committed, preserving
   * immutability of committed data. A zero-length write is allowed and is used to surface any
   * pending exception without altering file contents. After a successful write, any waiting reader
   * buffers intersecting the written range are filled directly, avoiding an immediate disk read.
   *
   * @param pos absolute file position at which to begin writing, zero or greater
   * @param b source buffer containing the data to write; must not be {@code null}
   * @param off starting offset within {@code b} from which bytes are consumed
   * @param len number of bytes to write; zero triggers exception propagation without I/O
   * @throws IOException if an injected exception is pending or the range overlaps committed bytes
   */
  @Override
  public synchronized void seekAndWrite(long pos, byte[] b, int off, int len) throws IOException {
    // exception
    if (e != null) {
      throw e;
    }

    // wait on len == 0 action to allow exceptions to be thrown.
    if (len != 0) {
      // check if any of the bytes have already been committed
      Range r = new Range(pos, pos + len - 1);
      RangeSet rs = new RangeSet();
      rs.add(r);
      if (!committed.intersect(rs).isEmpty()) {
        throw new IOException(
            "Illegal write attempt.  Parts of range " + "already committed. :" + r);
      }
    }

    delegateRaf.seekAndWrite(pos, b, off, len);

    // call this after seekAndWrite() to allow exceptions to be thrown, if
    // there are any.
    if (len == 0) {
      return;
    }

    fillBlockedBuffers(pos, b, off, len);
  }

  /**
   * Marks the supplied range as committed and notifies any waiting threads.
   *
   * <p>Once committed, bytes in the specified range become immutable to future writes and eligible
   * for readers that were blocked waiting for visibility. Ranges are merged with existing committed
   * regions, and the method wakes all waiters so they can recheck their conditions.
   *
   * @param r contiguous byte range that has finished writing and is now immutable
   */
  public synchronized void commit(Range r) {
    committed.add(r);
    this.notifyAll();
  }

  /**
   * Commits all ranges contained in the provided set and awakens waiting threads.
   *
   * <p>Each range is merged into the internal committed set, expanding the visible portion of the
   * file for readers. The operation is atomic with respect to the synchronized monitor, ensuring
   * that notifications occur after the ranges are recorded.
   *
   * @param rs collection of ranges that are fully written and ready for readers
   */
  public synchronized void commit(RangeSet rs) {
    committed.add(rs);
    this.notifyAll();
  }

  private synchronized void fillBlockedBuffers(long pos, byte[] b, int off, int len) {
    if (buffers.isEmpty()) {
      return;
    }

    Range r = new Range(pos, pos + len - 1);

    // Iterate through the blocked readers and fill their buffers.
    for (Map.Entry<Object, Tuple> entry : buffers.entrySet()) {
      Tuple t = entry.getValue();
      Range r2 = (Range) t.getLeft();
      Buffer buf = (Buffer) t.getRight();

      // Get the range in common.
      long min = Math.max(r.getMin(), r2.getMin());
      long max = Math.min(r.getMax(), r2.getMax());

      if (min <= max) {
        // there is something in common

        // copy the data to the proper place in the buffer
        //
        // (int) casts are safe because they can't be larger than len
        System.arraycopy(
            b,
            (int) (off + (min - r.getMin())),
            buf.b,
            (int) (buf.off + (min - r2.getMin())),
            (int) (max - min + 1));
      }
    }
  }

  /**
   * Unsupported convenience method for reading an exact byte count.
   *
   * <p>This wrapper relies on commit-tracking semantics that are incompatible with a traditional
   * "read fully" contract. Callers should instead invoke {@link #seekAndRead(long, byte[], int,
   * int)} and handle partial reads and blocking behavior. This method always throws to prevent
   * accidental misuse that could mask blocked reads or uncommitted regions.
   *
   * @param pos absolute position to begin reading
   * @param b destination buffer to receive data
   * @param off offset within {@code b} where bytes should be written
   * @param len exact number of bytes requested by the caller
   * @throws IOException always thrown to signal the operation is not supported here
   */
  @Override
  public synchronized void seekAndReadFully(long pos, byte[] b, int off, int len)
      throws IOException {
    throw new IOException("unsupported operation");
  }

  /**
   * Reads from the delegate, blocking if necessary until the requested position becomes committed.
   *
   * <p>When the file is read-only and fully committed, reads are delegated directly. Otherwise, the
   * call waits until the starting position is marked committed, optionally having data copied
   * directly into the provided buffer if a concurrent write satisfies part of the range. The method
   * returns as soon as a contiguous committed region beginning at {@code pos} is available, so the
   * byte count may be smaller than {@code len}. Pending exceptions or closure are surfaced before
   * any data is returned.
   *
   * <pre>{@code
   * // Example: block until the first kilobyte is committed
   * int read = raf.seekAndRead(0, buffer, 0, 1024);
   * }</pre>
   *
   * @param pos absolute position from which to read
   * @param b destination buffer that will receive committed data
   * @param off offset within {@code b} where bytes should be placed
   * @param len maximum number of bytes requested; method may return fewer
   * @return number of bytes transferred from the underlying {@link RAF} or in-memory buffers
   * @throws IOException if a pending exception exists, the wrapper is closed, or the delegate fails
   */
  @Override
  public synchronized int seekAndRead(long pos, byte[] b, int off, int len) throws IOException {

    // Will the bytes be written directly to the buffer?
    boolean directWrite = false;

    // This is the range we are currently interested in.
    Range r = null;
    // This is the key we use to access the buffers when stored
    // for direct write.
    Object key = new Object();

    while (!isClosed() && e == null && len != 0) {

      if (isReadOnlyAndFullyCommitted()) {

        return delegateRaf.seekAndRead(pos, b, off, len);
      }

      r = initRangeIfNeeded(r, pos, len);

      Range first = firstCommittedOverlap(r);

      if (committed.contains(pos)) {

        return readCommittedBytes(pos, b, off, directWrite, first);
      }

      // The data will be written directly to the buffer.
      directWrite = true;
      r = pendingPortionRange(pos, r, first);
      waitForCommit(key, r, b, off, len, pos);
    }

    return finalizeRead(len);
  }

  /**
   * Injects an exception that will be rethrown by subsequent read or write attempts.
   *
   * <p>Use this to propagate fatal upstream failures to threads currently blocked on commit
   * notifications. The stored exception is returned on the very next operation, after which normal
   * commit checks are skipped. All waiting threads are notified so they can observe the new state.
   *
   * @param e exception to propagate to future callers; must not be cleared once set
   */
  public synchronized void setException(IOException e) {
    this.e = e;
    this.notifyAll();
  }

  /**
   * Closes the underlying {@link RAF} and wakes any waiting threads.
   *
   * <p>Readers blocked waiting for commits will receive a closure signal and throw an {@link
   * IOException}. The delegate is closed first, and the monitor notification allows threads to exit
   * promptly rather than remain blocked indefinitely.
   *
   * @throws IOException if closing the delegate random-access file fails
   */
  @Override
  public synchronized void close() throws IOException {
    delegateRaf.close();
    this.notifyAll();
  }

  private boolean isReadOnlyAndFullyCommitted() throws IOException {
    return getMode().equals("r")
        && (length() == 0 || committed.equals(new RangeSet(new Range(0, length() - 1))));
  }

  private Range initRangeIfNeeded(Range current, long pos, int len) {
    if (current != null) {
      return current;
    }
    return new Range(pos, pos + len - 1);
  }

  private Range firstCommittedOverlap(Range interestedRange) {
    RangeSet rs = new RangeSet();
    rs.add(interestedRange);
    RangeSet avail = committed.intersect(rs);
    if (avail.isEmpty()) {
      return null;
    }
    return avail.iterator().next();
  }

  private int readCommittedBytes(long pos, byte[] b, int off, boolean directWrite, Range first)
      throws IOException {
    if (directWrite) {
      // The data was written directly to the buffer.
      return (int) first.size();
    }
    return delegateRaf.seekAndRead(pos, b, off, (int) first.size());
  }

  private Range pendingPortionRange(long pos, Range interestedRange, Range firstOverlap) {
    if (firstOverlap == null) {
      return interestedRange;
    }
    // Change the range of interest to only include bytes which
    // have yet to be committed.
    return new Range(pos, firstOverlap.getMin() - 1);
  }

  private synchronized void waitForCommit(
      Object key, Range interestedRange, byte[] b, int off, int len, long pos)
      throws InterruptedIOException {
    // Make the buffer available to be written to.
    buffers.put(key, new Tuple(interestedRange, new Buffer(b, off, len)));

    try {
      while (!isClosed() && e == null && !committed.contains(pos)) {
        this.wait();
      }
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      throw new InterruptedIOException(ie.getMessage());
    } finally {
      buffers.remove(key);
    }
  }

  private int finalizeRead(int len) throws IOException {
    // exception
    if (e != null) {
      throw e;
    }

    // RAF closed
    if (isClosed()) {
      throw new IOException("RAF closed");
    }

    // zero len read.  exceptions take priority.
    if (len == 0) {
      return 0;
    }

    // This should never happen.
    throw new IllegalStateException("Method should have already " + "returned.");
  }
}
