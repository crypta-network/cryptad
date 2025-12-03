package com.onionnetworks.io;

import com.onionnetworks.util.*;
import java.io.*;

/**
 * Random-access wrapper that commits each written region as soon as the write succeeds.
 *
 * <p>{@code WriteCommitRaf} builds on {@link CommitRaf} by automatically marking bytes committed
 * immediately after they are persisted to the delegate {@link RAF}. This makes new data visible to
 * readers without requiring the caller to invoke {@link #commit(Range)} manually, while still
 * preserving the underlying guarantees that committed ranges become immutable and unblock waiting
 * readers. Zero-length writes are allowed so pending exceptions surface consistently, but only
 * nonzero writes trigger commits. When the file transitions to read-only mode, the wrapper commits
 * the entire length so consumers can read to end-of-file without coordinating additional commit
 * calls.
 *
 * <p>Use this class when producers do not need fine-grained transaction boundaries and prefer that
 * durability implies visibility. All public operations synchronize on the instance, mirroring the
 * thread-safety model of {@code CommitRaf}. Writes that overlap any previously committed byte are
 * still rejected by the superclass, ensuring immutability once data is exposed. The automatic
 * commit path is therefore best suited to append-heavy or forward-only write patterns where each
 * region becomes readable immediately after it is written.
 *
 * <ul>
 *   <li>Automatic commit of every successful nonzero write.
 *   <li>Full-file commit when switching to read-only mode.
 *   <li>Retains {@code CommitRaf}'s blocking read semantics and overlap checks.
 * </ul>
 *
 * @author Justin Chapweske
 * @see CommitRaf
 * @see Range
 */
public class WriteCommitRaf extends CommitRaf {

  /**
   * Creates an auto-committing wrapper around the provided random-access file.
   *
   * <p>The wrapper delegates all I/O to the supplied {@link RAF} while automatically committing any
   * bytes written through {@link #seekAndWrite(long, byte[], int, int)}. Because the superclass
   * enforces range immutability after commit, callers typically provide a fresh, writable {@code
   * RAF} and perform writes in ascending order to avoid overlap violations. The constructor does
   * not modify the delegate's state; closing this wrapper cascades to the same underlying handle,
   * so it should not be shared elsewhere once wrapped.
   *
   * @param raf underlying {@link RAF} that persists data and maintains file positioning
   */
  public WriteCommitRaf(RAF raf) {
    super(raf);
  }

  /**
   * Writes bytes at the given position and immediately commits the affected range.
   *
   * <p>The method delegates the actual write to the underlying {@link RAF} via the superclass,
   * which also rejects attempts that overlap committed regions or surface pending exceptions. A
   * zero-length invocation performs no I/O but still allows deferred errors to propagate from the
   * delegate. After a successful nonzero write, the newly written range is marked committed so
   * blocked readers can proceed without an explicit commit call from the caller. All arguments are
   * validated by the superclass, and operations are synchronized to serialize concurrent access.
   *
   * @param pos absolute byte offset at which writing begins; must be zero or positive
   * @param b source buffer containing data to persist; must not be {@code null}
   * @param off starting offset within {@code b} from which bytes are read
   * @param len number of bytes to write; zero performs error propagation only
   * @throws IOException if the delegate fails, the range overlaps committed data, or closure occurs
   */
  @Override
  public synchronized void seekAndWrite(long pos, byte[] b, int off, int len) throws IOException {
    super.seekAndWrite(pos, b, off, len);
    // Allow 0 length write to allow exceptions to be thrown.
    if (len != 0) {
      commit(new Range(pos, pos + len - 1));
    }
  }

  /**
   * Switches the wrapper into read-only mode and commits all existing bytes.
   *
   * <p>Calling this method signals that no further writes will occur. The superclass flips the
   * internal read-only flag and propagates the state to the delegate, after which this override
   * commits the entire file range if the file is nonempty. Committing here ensures that readers
   * waiting on visibility can progress to end-of-file without the caller issuing additional commit
   * operations. Invocations are synchronized and may throw if the delegate cannot honor the
   * read-only transition.
   *
   * @throws IOException if the delegate fails while entering read-only mode or is already closed
   */
  @Override
  public synchronized void setReadOnly() throws IOException {
    // When we switch to read-only, we commit the whole file.
    super.setReadOnly();
    long fileSize = length();
    if (fileSize != 0) {
      commit(new Range(0, fileSize - 1));
    }
  }
}
