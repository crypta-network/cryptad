package com.onionnetworks.io;

import com.onionnetworks.util.*;
import java.io.*;

/**
 * RandomAccessFile wrapper that defers the final rename of a writable file until it is sealed as
 * read-only. This wrapper is intended for workflows that need to write data to a temporary
 * location, confirm persistence, and only then expose the file at its long-lived destination. By
 * delegating all I/O to an underlying {@link RAF} while staging the destination path, the class
 * helps avoid consumers observing partially written content and makes {@link File#deleteOnExit()}
 * safer for temporary artifacts. Instances synchronize mutating operations, so rename and read-only
 * transitions occur in a serialized order on the same object, but callers should still coordinate
 * access when sharing instances across threads. Typical usage writes to the wrapper, invokes {@link
 * #renameTo(File)} to register the final target, and completes with {@link #setReadOnly()}, which
 * performs the last hop to the destination.
 *
 * <ul>
 *   <li>Keeps the original file hidden under a temporary sibling until sealed.
 *   <li>Preserves compatibility with read-only wrappers by renaming immediately when opened in read
 *       mode.
 *   <li>Relies on {@link FileUtil#createTempFile(File)} to place temporary files alongside the
 *       destination when possible.
 * </ul>
 */
public class LazyRenameRAF extends FilterRAF {

  File destFile;

  /**
   * Creates a lazy-renaming wrapper around the provided random-access file. The underlying file
   * must be opened for reading and writing; otherwise an {@link IllegalStateException} is thrown to
   * prevent constructing an unusable wrapper. Callers typically write data through this instance,
   * register a destination via {@link #renameTo(File)}, and finish with {@link #setReadOnly()} to
   * move the data into place.
   *
   * @param raf delegate random-access file that backs all I/O for this wrapper
   * @throws IllegalStateException if the delegate is opened in read-only mode and cannot be renamed
   *     lazily
   */
  public LazyRenameRAF(RAF raf) {
    super(raf);

    if (getMode().equals("r")) {
      throw new IllegalStateException("LazyRenameRAFs are only useful " + "in read/write mode.");
    }
  }

  // setting the destination will not happen until setReadOnly() is called.
  // It is ok if this throws an IOException because the RAF
  // will revert to its previous state, no harm done.
  // document that it will create a temp file in the same directory.
  /**
   * Registers a final destination and moves the backing file to a temporary sibling until the file
   * is sealed. When opened in read-only mode the rename happens immediately. In writable mode this
   * method first records the destination, then renames the current file to a temporary path in the
   * same directory (or a fallback temp location) so that the future {@link #setReadOnly()} call can
   * atomically promote the file into place. Callers should invoke this only after all writes are
   * complete; repeated calls overwrite the previously staged destination.
   *
   * @param newFile target path for the final file; must reference a writable directory
   * @throws IOException if the delegate rename or temporary file creation fails on the filesystem
   */
  @Override
  public synchronized void renameTo(File newFile) throws IOException {
    // FIX figure out the proper semantics for this temporary same-directory
    // file.
    //
    // we set the destination before doing anything else, so that if
    // moving to the new temp location fails, we still have the destination
    // set.
    this.destFile = newFile;

    if (getMode().equals("r")) {
      delegateRaf.renameTo(destFile);
    } else {
      // create a temp file in the same directory as destFile, if
      // destFile is null, then try to create a temp file in the
      // user temp directory, then fall back to the system temp dir.
      File newTemp = FileUtil.createTempFile(destFile);

      delegateRaf.renameTo(newTemp);
    }
  }

  // This should at least by in read-only mode when it bombs, should
  // FIX parent.setReadOnly to revert as well.
  /**
   * Marks the underlying file read-only and performs the deferred rename when applicable. In
   * writable mode this final step migrates the temporary file created by {@link #renameTo(File)} to
   * the recorded destination, ensuring consumers only see a fully written, sealed artifact. When no
   * destination has been staged the method leaves the file in its current location after enforcing
   * read-only status. Subsequent write attempts through the delegate are expected to fail according
   * to the {@link RAF} implementation.
   *
   * @throws IOException if the delegate cannot be marked read-only or the final rename operation
   *     fails after sealing
   */
  @Override
  public synchronized void setReadOnly() throws IOException {
    delegateRaf.setReadOnly();
    if (destFile != null) {
      delegateRaf.renameTo(destFile);
    }
  }
}
