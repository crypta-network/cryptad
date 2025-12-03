package com.onionnetworks.io;

import com.onionnetworks.util.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Random-access file wrapper that journals written byte ranges for crash-aware recovery.
 *
 * <p>This decorator pairs a mutable {@link RAF} with a persistent {@link Journal} that records
 * every region successfully written through {@link #seekAndWrite(long, byte[], int, int)}. The
 * journal captures both the destination file and the set of completed byte ranges so that callers
 * can resume or verify partially written files after an unexpected shutdown. All operations remain
 * synchronized via {@link FilterRAF}, providing serialized cursor movement and predictable journal
 * updates when multiple threads share the same instance. The journal may be deleted when writes are
 * finished, allowing long-lived readers to operate without auxiliary metadata once durability is
 * established.
 *
 * <ul>
 *   <li>Tracks the underlying file path so journal consumers can locate the target data.
 *   <li>Records each successfully written byte span to support resumable downloads or rebuilds.
 *   <li>Flushes and deletes the journal during mode transitions to keep metadata consistent.
 * </ul>
 *
 * @see Journal
 * @see Range
 */
public class JournalingRAF extends FilterRAF {

  private static final Logger LOGGER = Logger.getLogger(JournalingRAF.class.getName());

  Journal journal;

  /**
   * Creates a journaling wrapper around an existing random-access file and persistent journal.
   *
   * <p>The constructor rejects read-only delegates because journaling applies only to writable
   * files. It stores the supplied {@link Journal} and immediately records the delegate's current
   * path so consumers of the journal can locate the target file even if future renames occur. The
   * wrapper does not take ownership of any existing journal contents beyond continuing to append
   * byte ranges as writes succeed.
   *
   * @param raf underlying random-access file wrapper to decorate for journaling.
   * @param journal persistent journal storing byte ranges and target file metadata.
   * @throws IllegalStateException if the provided RAF is open in read-only mode.
   */
  public JournalingRAF(RAF raf, Journal journal) {
    super(raf);
    if (raf.getMode().equals("r")) {
      throw new IllegalStateException("Can't create a journal for a " + "read-only file.");
    }

    this.journal = journal;

    // Track the initial file path.
    journal.setTargetFile(raf.getFile());
  }

  /**
   * Writes bytes at an absolute position and records the written span in the journal.
   *
   * <p>The method first delegates the write to the underlying {@link RAF}, then adds the inclusive
   * byte range to the journal if journaling is active. Recording occurs only after a successful
   * delegate write, so the journal reflects data that has actually reached the file handle. The
   * call remains synchronized to serialize pointer movement and journal updates across threads. If
   * the process terminates before the journal is flushed, callers may need to reconcile partially
   * recorded progress when resuming.
   *
   * @param pos absolute byte offset where writing begins; must be zero or positive.
   * @param b source buffer containing bytes to write; must remain unchanged during call.
   * @param off starting index within buffer; must allow requested length to fit.
   * @param len number of bytes to write from buffer slice; zero allowed.
   * @throws IOException if the delegate cannot seek or write at provided position.
   */
  @Override
  public synchronized void seekAndWrite(long pos, byte[] b, int off, int len) throws IOException {
    super.seekAndWrite(pos, b, off, len);
    // FIX flush problem, what if it crashes before data is persisted?

    if (journal != null) {
      // can be null from deleteJournal
      // Update the journal.
      journal.addByteRange(new Range(pos, pos + len - 1));
    }
  }

  /**
   * Renames the underlying file and updates the journal to track the new path.
   *
   * <p>The delegate performs the actual rename and may fall back to alternative strategies when a
   * direct move fails. After the delegate completes, the journal's target file reference is
   * refreshed using the delegate's current path to ensure future recovery uses the correct
   * location. The journal is flushed immediately after updating to minimize divergence if the
   * process terminates between the rename and subsequent writes.
   *
   * @param newFile destination file path for the rename operation; must be writable by the caller.
   * @throws IOException if the delegate fails to rename or reopen the file handle.
   */
  @Override
  public synchronized void renameTo(File newFile) throws IOException {
    super.renameTo(newFile);
    // Update the file location.

    // Can be null from deleteJournal()
    if (journal != null) {
      // Use delegateRaf.getFile() because renameTo() may have failed and was
      // forced to fall back.
      journal.setTargetFile(delegateRaf.getFile());

      // flush here because it is important that the journal stay in
      // sync on this operation.
      journal.flush();
    }
  }

  /**
   * Transitions the delegate to read-only mode and removes the associated journal.
   *
   * <p>After deferring to the delegate to enforce read-only semantics, the method deletes the
   * journal because no further writes will occur. This keeps metadata size bounded and prevents
   * stale recovery state from being misinterpreted later. The call is synchronized, preserving the
   * serialized ordering of mode changes relative to concurrent reads or pending journal updates.
   *
   * @throws IOException if the delegate cannot change to read-only access.
   */
  @Override
  public synchronized void setReadOnly() throws IOException {
    super.setReadOnly();
    // done writing, delete the journal
    deleteJournal();
  }

  /**
   * Closes the delegate and then closes any active journal.
   *
   * <p>The delegate is closed first to ensure file-system resources are released before the journal
   * attempts to flush or close its own backing file. If a journal exists, it is closed even when
   * the delegate close succeeds, allowing recovery consumers to observe a consistent snapshot of
   * completed writes. The method is synchronized to avoid races with concurrent write or rename
   * operations.
   *
   * @throws IOException if closing the delegate or the journal encounters an I/O error.
   */
  @Override
  public synchronized void close() throws IOException {
    super.close();

    // Can be null from deleteJournal
    if (journal != null) {
      journal.close();
    }
  }

  /**
   * Marks both the delegate and the journal for deletion when the stream closes.
   *
   * <p>The request is forwarded to the delegate so the underlying data file is removed on close.
   * The journal is immediately deleted to prevent future recovery attempts from referencing a file
   * scheduled for removal. Because no delete occurs until {@link #close()} runs, callers can still
   * use the instance for further writes before shutdown if desired.
   */
  @Override
  public synchronized void deleteOnClose() {
    super.deleteOnClose();
    deleteJournal();
  }

  private void deleteJournal() {
    if (journal == null) {
      return;
    }
    File file = journal.getFile();
    try {
      journal.close();
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, "Failed to close journal before deletion", e);
    }
    // FIX maybe throw exception on failed delete?
    try {
      Files.delete(file.toPath());
    } catch (NoSuchFileException e) {
      // already deleted; nothing further to do
    } catch (IOException e) {
      LOGGER.log(Level.WARNING, e, () -> "Failed to delete journal file: " + file);
    }
    journal = null;
  }
}
