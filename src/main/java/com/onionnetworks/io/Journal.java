package com.onionnetworks.io;

import com.onionnetworks.util.AsyncPersistentProps;
import com.onionnetworks.util.Range;
import com.onionnetworks.util.RangeSet;
import java.io.File;
import java.io.IOException;
import java.text.ParseException;

/**
 * Persists byte ranges written to a target file so interrupted writes can resume accurately.
 *
 * <p>A {@code Journal} backs its state with {@link AsyncPersistentProps}, storing the absolute path
 * of the tracked file and a serialized {@link RangeSet} of completed byte intervals. Clients
 * typically create one instance per download or output stream, call {@link #setTargetFile(File)}
 * once a target is known, and then invoke {@link #addByteRange(Range)} after each successful write.
 * On restart the constructor reloads the stored properties, allowing callers to query {@link
 * #getByteRanges()} and decide which segments still need to be fetched or rewritten.
 *
 * <p>The class keeps only in-memory references to the target {@link File} and {@link RangeSet};
 * state is flushed asynchronously through the parent. No internal synchronization is provided, so
 * callers should either confine instances to a single thread or protect invocations externally when
 * multiple threads record progress. The journal does not validate overlapping or unsorted ranges;
 * it delegates to {@code RangeSet} to normalize or merge intervals.
 *
 * <ul>
 *   <li>Tracks the absolute target file path and completed byte ranges.
 *   <li>Reloads persisted state automatically during construction for resuming work.
 *   <li>Expects callers to manage concurrency and range correctness when logging progress.
 * </ul>
 *
 * @see AsyncPersistentProps
 * @see RangeSet
 */
public class Journal extends AsyncPersistentProps {

  /**
   * Property key storing the absolute path of the file this journal represents, written eagerly
   * when {@link #setTargetFile(File)} is invoked to let restarts recover the intended destination.
   */
  public static final String FILE_PROP = "file";

  /**
   * Property key storing the serialized {@link RangeSet} of completed byte ranges; values use
   * {@link RangeSet#toString()} format and are reloaded at construction time to rebuild progress.
   */
  public static final String BYTES_PROP = "bytes";

  File f;
  RangeSet written;

  /**
   * Create a journal backed by a property file and reload any previously persisted ranges.
   *
   * <p>The constructor initializes the parent {@link AsyncPersistentProps} with the provided file,
   * reads stored properties, rebuilds the {@link RangeSet} if present, and rehydrates the tracked
   * target file path. If the byte-range property exists but cannot be parsed, construction fails to
   * prevent operating on corrupted progress data.
   *
   * @param f backing properties file containing journal state; must be readable and writable by the
   *     caller for persistence to succeed.
   * @throws IOException if the properties file cannot be parsed, accessed, or contains invalid
   *     range data that would make the journal unreliable.
   */
  public Journal(File f) throws IOException {
    super(f);

    // Read in the byte ranges.
    String bytes = getProperty(BYTES_PROP);
    if (bytes != null) {
      // try and read existing journal.
      try {
        written = RangeSet.parse(bytes);
      } catch (ParseException e) {
        throw new IOException("Corrupt journal.");
      }
    } else {
      // new journal.
      this.written = new RangeSet();
    }

    // Read in the target file name.
    String file = getProperty(FILE_PROP);
    if (file != null) {
      this.f = new File(file);
    }
  }

  /**
   * Set or update the file whose write progress is tracked by this journal.
   *
   * <p>The provided file reference is stored in memory and its absolute path is persisted using
   * {@link #FILE_PROP}. Subsequent calls overwrite the previous value; callers should invoke this
   * method before recording ranges to ensure the on-disk metadata references the correct output
   * location. No validation is performed on the file beyond serialization of its path.
   *
   * @param f target file whose byte ranges are being recorded; must resolve to a stable location
   *     accessible to the caller.
   */
  public void setTargetFile(File f) {
    this.f = f;
    setProperty(FILE_PROP, f.getAbsolutePath());
  }

  /**
   * Return the file currently associated with this journal, if one has been recorded.
   *
   * <p>The return value reflects the most recent call to {@link #setTargetFile(File)} or the file
   * reconstructed from persisted properties during construction. A {@code null} value indicates
   * that no target has been specified yet, which usually occurs immediately after instantiation.
   *
   * @return tracked target file instance or {@code null} when no destination has been set.
   */
  @SuppressWarnings("unused")
  public File getTargetFile() {
    return f;
  }

  /**
   * Record a byte range that has been fully written to the target file and persist progress.
   *
   * <p>This method updates the internal {@link RangeSet} with the supplied {@link Range} and writes
   * the serialized representation to the backing properties file. Callers should supply normalized
   * ranges representing successfully flushed data; overlapping or adjacent intervals are delegated
   * to {@code RangeSet} for merging. Invocations are lightweight but not synchronized, so
   * concurrent calls should be externally serialized when used across threads to avoid race
   * conditions while the underlying properties file is being updated.
   *
   * @param r byte range describing a contiguous region that finished writing; should match the
   *     portion already durable on disk.
   */
  public void addByteRange(Range r) {
    written.add(r);
    setProperty(BYTES_PROP, written.toString());
  }

  /**
   * Provide the collection of byte ranges currently marked as written for the target file.
   *
   * <p>The returned {@link RangeSet} is the live instance maintained by this journal; callers may
   * inspect or copy it to determine outstanding work. Mutating the returned object will affect the
   * journal's persisted state only after invoking {@link #addByteRange(Range)} or explicitly
   * updating properties; therefore direct modification is discouraged in favor of controlled
   * updates.
   *
   * @return live {@link RangeSet} representing recorded byte intervals, never {@code null} after
   *     construction completes.
   */
  @SuppressWarnings("unused")
  public RangeSet getByteRanges() {
    return written;
  }
}
