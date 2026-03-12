package com.onionnetworks.io;

import com.onionnetworks.util.*;
import java.io.*;
import java.util.*;

/**
 * Enforces write-once semantics on a delegated random-access file.
 *
 * <p>WriteOnceRaf tracks which byte positions have not yet been persisted and only forwards the
 * initial write for each position to the underlying {@link RAF}. Subsequent attempts to write the
 * same offsets are silently ignored, making it suitable for assembling sparse or chunked payloads
 * where duplicate arrivals are possible. The class extends {@link WriteCommitRaf}, so callers
 * retain the normal commit/flush behavior provided by the parent implementation.
 *
 * <p>Use this wrapper when the producer may retry individual chunks or when concurrent download
 * sources could send overlapping data. The instance keeps a range set of unwritten bytes and
 * removes ranges as they are committed, avoiding unnecessary I/O and preserving the first-write
 * policy. It does not attempt to resequence or compact writes; callers are responsible for seeking
 * to the correct offsets and for managing any higher-level integrity checks.
 *
 * <p>Thread safety is limited to method-level synchronization on this instance. External
 * synchronization is still recommended if multiple threads share the same {@code RAF}, especially
 * if other operations bypass this wrapper. Writes are permanent for this object's lifetime; there
 * is no API to reset or reopen positions once they have been consumed.
 *
 * <ul>
 *   <li>Responsibilities: gate duplicate writes; delegate storage and commits to {@link RAF}.
 *   <li>Notable behavior: zero-length writes still pass through to allow upstream validation.
 * </ul>
 *
 * @see WriteCommitRaf
 * @see com.onionnetworks.util.RangeSet
 */
public class WriteOnceRaf extends WriteCommitRaf {

  // This range set contains all possible unwritten bytes.
  RangeSet unwritten = new RangeSet().complement();

  /**
   * Creates a write-once wrapper over the provided random-access file handle.
   *
   * <p>The underlying {@link RAF} is expected to represent the full target file and should already
   * be positioned or resized as needed by the caller. The constructor initializes the internal set
   * of unwritten bytes to include the entire addressable range, so the first write to any offset
   * will be forwarded while all subsequent writes to the same offset are ignored.
   *
   * @param raf backing random-access file receiving first write per position; must be non-null.
   */
  public WriteOnceRaf(RAF raf) {
    super(raf);
  }

  /**
   * Writes data while discarding any bytes that have already been written previously.
   *
   * <p>The method examines the requested span and forwards only the still-unwritten subranges to
   * the underlying {@link RAF}. It keeps the original offset and length semantics, so callers may
   * supply buffers containing both new and duplicate bytes without pre-filtering. A zero-length
   * request is delegated to the superclass to surface any validation exceptions. The call is
   * synchronized to keep the tracked unwritten ranges consistent across overlapping writes;
   * nevertheless, sharing the same instance across threads still requires external coordination to
   * avoid conflicting seek operations.
   *
   * @param pos zero-based file offset for the first byte; must be non-negative.
   * @param b source buffer holding candidate bytes; duplicates are skipped during forwarding.
   * @param off start index within {@code b} to read; obeys standard array bounds.
   * @param len count of bytes to attempt; zero-length calls only validate arguments.
   * @throws IOException if delegated write fails or underlying {@link RAF} reports an I/O error.
   */
  @Override
  public synchronized void seekAndWrite(long pos, byte[] b, int off, int len) throws IOException {
    if (len == 0) {
      // Do 0 length write to allow exceptions to be thrown.
      super.seekAndWrite(pos, b, off, len);
      return;
    }

    Range r = new Range(pos, pos + len - 1);
    for (Iterator<Range> it = unwritten.intersect(new RangeSet(r)).iterator(); it.hasNext(); ) {
      Range r2 = it.next();
      // (int) casts are safe because they will never be larger than len
      super.seekAndWrite(r2.getMin(), b, off + (int) (r2.getMin() - pos), (int) r2.size());
      unwritten.remove(r2);
    }
  }
}
