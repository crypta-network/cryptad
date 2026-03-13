package com.onionnetworks.io;

import com.onionnetworks.util.Buffer;
import com.onionnetworks.util.Range;
import com.onionnetworks.util.RangeSet;
import com.onionnetworks.util.Tuple;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Random-access file wrapper that intentionally blocks readers until requested ranges become
 * available. The wrapper collects pending read requests, writes arriving data directly into the
 * caller-provided buffers when possible, and coordinates with writers using intrinsic locking and
 * {@link Object#wait()} / {@link Object#notifyAll()} to avoid busy waiting.
 *
 * <p>Use this class when a consumer thread must wait for producers to append data to a shared
 * random-access file without polling. A typical flow is:
 *
 * <ol>
 *   <li>Reader calls {@link #seekAndRead(long, byte[], int, int)}; the call blocks and registers
 *       its desired range.
 *   <li>Writer calls {@link #seekAndWrite(long, byte[], int, int)}; data is copied into any waiting
 *       buffers and the write is persisted to the delegate {@link RAF}.
 *   <li>Reader wakes when its start position is written, returning the number of bytes now
 *       available.
 * </ol>
 *
 * <p>State is guarded by the instance monitor; methods are synchronized to preserve invariants
 * around {@code written} ranges and the {@code buffers} registry. The class is mutable and not
 * thread-safe outside its own synchronization. Exceptions set via {@link
 * #setException(IOException)} are propagated to readers and writers to fail fast. Closing or
 * switching to read-only mode wakes blocked threads so they can react promptly.
 */
public class BlockingRAF extends FilterRAF {

  RangeSet written = new RangeSet();
  IOException e;

  // Make sure not to key buffers off of a Range, or any other non-unique
  // object, as multiple readers may be using the same key and will trash
  // each other.
  Map<Object, Tuple> buffers = new HashMap<>();

  /**
   * Creates a blocking wrapper around the supplied random-access file.
   *
   * @param raf delegate {@link RAF} instance that performs the actual I/O; must be non-null and
   *     already configured with the desired mode.
   */
  public BlockingRAF(RAF raf) {
    super(raf);
  }

  /**
   * Writes data to the delegate and wakes any blocked readers whose requested ranges intersect the
   * write. The written range is recorded so subsequent reads can bypass blocking.
   *
   * @param pos absolute position in the underlying file where the write begins; zero-based and
   *     non-negative.
   * @param b source byte array containing the data to write; must not be null.
   * @param off offset within {@code b} to start reading bytes from; must satisfy {@code 0 <= off <=
   *     b.length}.
   * @param len number of bytes to write from the array; zero is allowed and results in no range
   *     tracking.
   * @throws IOException if the delegate refuses the write, an exception was set via {@link
   *     #setException(IOException)}, or the RAF is closed.
   */
  @Override
  public synchronized void seekAndWrite(long pos, byte[] b, int off, int len) throws IOException {
    // exception
    if (e != null) {
      throw e;
    }

    delegateRaf.seekAndWrite(pos, b, off, len);

    // call this after seekAndWrite() to allow exceptions to be thrown, if
    // there are any.
    if (len == 0) {
      return;
    }

    fillBlockedBuffers(pos, b, off, len);

    written.add(pos, pos + len - 1);
    this.notifyAll();
  }

  private synchronized void fillBlockedBuffers(long pos, byte[] b, int off, int len) {
    if (buffers.isEmpty()) {
      return;
    }

    Range r = new Range(pos, pos + len - 1);

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
   * Unsupported operation in this wrapper; always throws an {@link IOException}. Use {@link
   * #seekAndRead(long, byte[], int, int)} instead for partial reads that coordinate with the
   * blocking semantics.
   *
   * @param pos absolute position to read from; ignored because the method always fails.
   * @param b destination buffer that would have received data; ignored in this implementation.
   * @param off offset into {@code b}; ignored because the call fails.
   * @param len number of bytes requested; ignored because the call fails.
   * @throws IOException unconditionally, to signal that full reads are not supported by this class.
   */
  @Override
  public synchronized void seekAndReadFully(long pos, byte[] b, int off, int len)
      throws IOException {
    throw new IOException("unsupported operation");
  }

  /**
   * Attempts to read a range of bytes, blocking until the requested start position becomes
   * available or an exceptional condition occurs. When the data arrives while blocked, bytes are
   * copied directly into the caller's buffer without an intermediate allocation.
   *
   * @param pos absolute position in the file to begin reading; must be non-negative.
   * @param b destination array supplied by the caller to receive data; must not be null.
   * @param off offset into {@code b} where bytes are stored; must be within the array bounds.
   * @param len maximum number of bytes to read; zero yields an immediate return of zero.
   * @return the number of bytes made available starting at {@code pos}; equals the written segment
   *     length when direct write occurs.
   * @throws IOException if the RAF is closed, set to read-only during the wait, or an exception was
   *     injected with {@link #setException(IOException)}.
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

    while (shouldBlock(len)) {

      if (r == null) {
        r = new Range(pos, pos + len - 1);
      }

      Range first = firstAvailableRange(r);

      if (written.contains(pos)) {
        return readAvailable(directWrite, first, pos, b, off);
      }

      directWrite = true;
      r = pendingRange(pos, r, first);
      waitForData(key, pos, r, b, off, len);
    }

    // exception
    if (e != null) {
      throw e;
    }

    // We only block during r/w mode.  For read-only we use the
    // normal behavior.
    if (getMode().equals("r")) {
      return delegateRaf.seekAndRead(pos, b, off, len);
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

  /**
   * Switches the underlying RAF to read-only mode and unblocks any waiting threads so they can
   * resume using delegate reads. Readers still pending will wake and delegate to the underlying RAF
   * on their next iteration.
   *
   * @throws IOException if the delegate fails to enter read-only mode.
   */
  @Override
  public synchronized void setReadOnly() throws IOException {
    delegateRaf.setReadOnly();
    this.notifyAll();
  }

  /**
   * Records an exception that will be thrown by future read or write attempts and wakes any blocked
   * threads so they observe it promptly. The stored exception remains until another call replaces
   * it or the RAF is closed.
   *
   * @param e exception to surface to waiting or subsequent operations; must not be null to avoid
   *     masking the intended failure signal.
   */
  public synchronized void setException(IOException e) {
    this.e = e;
    this.notifyAll();
  }

  /**
   * Closes the underlying RAF and wakes all blocked threads. Further reads or writes will fail with
   * an {@link IOException}.
   *
   * @throws IOException if the delegate refuses to close.
   */
  @Override
  public synchronized void close() throws IOException {
    delegateRaf.close();
    this.notifyAll();
  }

  private Range firstAvailableRange(Range range) {
    RangeSet requested = new RangeSet();
    requested.add(range);
    RangeSet available = written.intersect(requested);
    return available.isEmpty() ? null : available.iterator().next();
  }

  private boolean shouldBlock(int len) {
    return !isClosed() && e == null && !getMode().equals("r") && len != 0;
  }

  private int readAvailable(boolean directWrite, Range first, long pos, byte[] b, int off)
      throws IOException {
    if (directWrite) {
      return (int) first.size();
    }
    return delegateRaf.seekAndRead(pos, b, off, (int) first.size());
  }

  private Range pendingRange(long pos, Range currentRange, Range firstAvailable) {
    if (firstAvailable == null) {
      return currentRange;
    }
    return new Range(pos, firstAvailable.getMin() - 1);
  }

  private synchronized void waitForData(
      Object key, long startPos, Range range, byte[] b, int off, int len)
      throws InterruptedIOException {
    boolean wasEmpty = buffers.isEmpty();
    buffers.put(key, new Tuple(range, new Buffer(b, off, len)));
    if (wasEmpty) {
      // Wake up any waiters (e.g., tests) that need to know a buffer was registered.
      this.notifyAll();
    }
    try {
      while (shouldBlock(len) && !written.contains(startPos)) {
        this.wait();
      }
    } catch (InterruptedException ie) {
      Thread.currentThread().interrupt();
      throw new InterruptedIOException(ie.getMessage());
    } finally {
      buffers.remove(key);
    }
  }
}
