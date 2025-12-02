package com.onionnetworks.io;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Random-access file helper that wraps {@link java.io.RandomAccessFile} with synchronized access,
 * move-friendly semantics, and optional delete-on-close handling.
 *
 * <p>This class centralizes cursor-based read and write operations while retaining knowledge of the
 * current file path and access mode so the underlying handle can be reopened after moves. It is
 * mutable but synchronizes all public methods, allowing a single instance to be safely shared among
 * multiple threads without external locking. Rename operations mimic the Unix {@code mv}
 * command—overwriting destinations and falling back to copy-and-delete across filesystems—after
 * first closing the live handle to satisfy platforms that lock open files. The class also supports
 * delete-on-close semantics, making it suitable for temporary files that must be cleaned up when
 * work completes.
 *
 * <p>Typical usage flows include writing to a staging file and then atomically promoting it via
 * {@link #renameTo(File)}, or performing random reads while coordinating with other components that
 * assume deterministic cursor positioning. Error handling is conservative: failures during rename
 * attempt to preserve the original file, and reopen failures are surfaced to callers with
 * suppressed exceptions retained. Because the object tracks its closed state, callers can check
 * {@link #isClosed()} before performing further operations.
 *
 * <ul>
 *   <li>Maintains current file reference and mode for reopening after moves.
 *   <li>Serializes access via synchronized methods to avoid cursor races.
 *   <li>Optionally deletes the file on close for temporary data management.
 * </ul>
 *
 * @see java.io.RandomAccessFile
 */
public class RAF implements AutoCloseable {

  /**
   * Backing file associated with this random-access handle; updated when the file is renamed and
   * used for subsequent reopen operations.
   */
  protected File f;

  /**
   * Access mode string (for example {@code "r"} or {@code "rw"}) preserved for reopening after
   * renames or mode switches.
   */
  protected String mode;

  /**
   * Live {@link RandomAccessFile} instance backing all operations; closed and recreated as needed
   * to satisfy move semantics.
   */
  protected RandomAccessFile randomAccessFile;

  private boolean closed;

  /** Flag indicating whether {@link #close()} should remove the backing file from disk. */
  protected boolean deleteOnClose;

  /**
   * Creates a random-access wrapper around the provided file using the requested mode.
   *
   * <p>Construction opens the underlying {@link RandomAccessFile} immediately and records both the
   * file reference and access mode so the handle can later be reopened after move operations. The
   * instance remains mutable and must be closed by callers to release system resources.
   *
   * @param f target file to back the random-access operations; must refer to a valid path and may
   *     be created depending on the chosen mode.
   * @param mode access mode string accepted by {@link RandomAccessFile}, such as {@code "r"} for
   *     read-only or {@code "rw"} for read-write access.
   * @throws IOException if the file cannot be opened with the requested mode or the filesystem
   *     rejects the path during initialization.
   */
  public RAF(File f, String mode) throws IOException {
    this.f = f;
    this.mode = mode;
    this.randomAccessFile = new RandomAccessFile(f, mode);
  }

  /** This is only to be used by subclasses requiring more flexible constructors. */
  protected RAF() {}

  /**
   * Returns the current backing file reference used by this instance.
   *
   * <p>The returned {@link File} reflects any prior rename operations and can be inspected for path
   * details. Mutating the {@code File} object does not update internal state, and callers should
   * avoid using it to manage the open handle directly. The same {@code File} instance is also used
   * internally when reopening after a move, so external code should not assume exclusive ownership
   * or attempt to delete it outside the documented lifecycle.
   *
   * @return file object representing the path currently associated with this random-access wrapper;
   *     never {@code null} while the instance remains open.
   */
  public File getFile() {
    return f;
  }

  /**
   * Writes a slice of the provided byte array starting at the specified absolute position.
   *
   * <p>The method seeks to {@code pos} before writing {@code len} bytes from {@code b} beginning at
   * {@code off}. Access is synchronized to serialize updates to the shared file cursor. The call
   * may extend the file; newly created regions are zero-filled by the platform implementation.
   *
   * @param pos zero-based offset at which writing starts; must be non-negative and may exceed the
   *     current length to grow the file.
   * @param b source buffer containing data to write; must not be {@code null} and should remain
   *     valid for the duration of the call.
   * @param off starting index within {@code b} from which bytes are taken; must satisfy {@code off
   *     >= 0} and {@code off + len <= b.length}.
   * @param len number of bytes to write; must be non-negative and within the bounds of the buffer
   *     slice defined by {@code off}.
   * @throws IOException if the file is not open for writing, seeking fails, or any write error
   *     occurs.
   */
  public synchronized void seekAndWrite(long pos, byte[] b, int off, int len) throws IOException {
    randomAccessFile.seek(pos);
    randomAccessFile.write(b, off, len);
  }

  /**
   * Reads up to {@code len} bytes into the provided buffer starting from an absolute file offset.
   *
   * <p>The cursor is moved to {@code pos}, and the method attempts to read into {@code b} starting
   * at {@code off}. It returns the count of bytes read or {@code -1} if the end of file is reached
   * immediately. Synchronization prevents concurrent callers from interfering with the shared
   * cursor.
   *
   * @param pos zero-based absolute position to begin reading; must be non-negative.
   * @param b destination buffer that will receive data; must not be {@code null} and should have
   *     sufficient capacity.
   * @param off index within {@code b} where data storage begins; must be within buffer bounds.
   * @param len maximum number of bytes to read; must be non-negative and fit within the remaining
   *     buffer space after {@code off}.
   * @return number of bytes actually read, or {@code -1} if positioned at end of file before any
   *     data is read.
   * @throws IOException if the file is closed, not open for reading, or an I/O error occurs.
   */
  public synchronized int seekAndRead(long pos, byte[] b, int off, int len) throws IOException {
    randomAccessFile.seek(pos);
    return randomAccessFile.read(b, off, len);
  }

  /**
   * Reads exactly {@code len} bytes from the specified position, throwing if insufficient data is
   * available.
   *
   * <p>The method seeks to {@code pos} and repeatedly reads until the buffer slice is filled or an
   * exception is thrown. It is useful when a fixed-length structure is expected at a known offset
   * and partial reads would be invalid.
   *
   * @param pos absolute offset to begin reading; must be non-negative.
   * @param b destination buffer that will receive all requested bytes; must not be {@code null}.
   * @param off index in {@code b} where storage begins; must allow {@code len} bytes to fit.
   * @param len number of bytes to read; must be positive and within bounds of the buffer slice.
   * @throws IOException if the requested bytes cannot be fully read, if seeking fails, or if the
   *     file is closed or not readable.
   */
  public synchronized void seekAndReadFully(long pos, byte[] b, int off, int len)
      throws IOException {
    randomAccessFile.seek(pos);
    randomAccessFile.readFully(b, off, len);
  }

  /**
   * Renames the current file to the destination with overwrite semantics and cross-filesystem
   * fallback.
   *
   * <p>The method closes the open {@link RandomAccessFile}, deletes the destination if it exists,
   * and tries {@link File#renameTo(File)}. When a direct rename is not possible, it copies the
   * contents and removes the source to emulate {@code mv}. After the move, it reopens the file in
   * the original mode and updates the stored reference. Operations are synchronized to avoid cursor
   * races and to keep lifecycle transitions consistent across threads.
   *
   * @param destFile target location to move this file to; any existing file at that path is removed
   *     before the move proceeds.
   * @throws IOException if the instance is closed, any step of the rename or copy/delete fails, or
   *     reopening the file in its original mode cannot be completed.
   */
  public synchronized void renameTo(File destFile) throws IOException {
    if (closed) {
      throw new IOException("File closed.");
    }
    if (isSameFile(destFile)) {
      return;
    }

    IOException primaryException = null;
    RandomAccessFile originalRaf = randomAccessFile;
    randomAccessFile = null;
    try {
      originalRaf.close();

      deleteDestinationIfExists(destFile);

      if (!f.renameTo(destFile)) {
        copyToDestination(destFile);
      }

      f = destFile;
    } catch (IOException e) {
      primaryException = e;
    }

    IOException reopenFailure = null;
    try {
      randomAccessFile = new RandomAccessFile(f, mode);
    } catch (IOException e) {
      reopenFailure = e;
    }

    if (primaryException != null) {
      if (reopenFailure != null) {
        primaryException.addSuppressed(reopenFailure);
      }
      throw primaryException;
    }

    if (reopenFailure != null) {
      throw reopenFailure;
    }
  }

  /**
   * Returns the access mode string used to open the underlying file.
   *
   * <p>The value remains constant for the life of the instance, except when {@link #setReadOnly()}
   * reopens the handle in read-only mode. Typical values include {@code "r"} and {@code "rw"}.
   * Exposing the mode allows higher-level components to tailor behavior, such as avoiding writes
   * when the wrapper is read-only or skipping costly reopen cycles when the desired mode already
   * matches.
   *
   * @return the currently stored access mode for future reopen operations.
   */
  public synchronized String getMode() {
    return mode;
  }

  /**
   * Reports whether the random-access file has been closed.
   *
   * <p>Once closed, operations that require the underlying handle will fail. The flag is useful for
   * callers that need to avoid reuse after lifecycle completion. It also helps guard against logic
   * errors in long-lived components where multiple shutdown paths might race; checking the flag
   * lets those components short-circuit redundant cleanup.
   *
   * @return {@code true} if {@link #close()} has been invoked; {@code false} otherwise.
   */
  public synchronized boolean isClosed() {
    return closed;
  }

  /**
   * Reopens the file in read-only mode, preventing further writes through this API.
   *
   * <p>The method closes the current handle and immediately opens a new one with mode {@code "r"}
   * while preserving the tracked file reference. Synchronization prevents other operations from
   * interleaving during the transition. Use this when write access is no longer required, and you
   * want subsequent calls to fail fast on attempted writes without changing underlying filesystem
   * permissions.
   *
   * @throws IOException if the file is already closed or if closing or reopening the handle fails.
   */
  public synchronized void setReadOnly() throws IOException {
    if (closed) {
      throw new IOException("File closed.");
    }
    this.mode = "r";
    randomAccessFile.close();
    randomAccessFile = new RandomAccessFile(f, mode);
  }

  /**
   * Requests that the backing file be removed from disk when {@link #close()} completes.
   *
   * <p>This flag is advisory: if deletion fails during close, an {@link IOException} is thrown. The
   * request must be made before the instance is closed; otherwise an {@link IllegalStateException}
   * is raised. Use it for temporary scratch files where persistence past the active session is not
   * desired.
   */
  public synchronized void deleteOnClose() {
    if (closed) {
      throw new IllegalStateException("File already closed");
    }
    deleteOnClose = true;
  }

  /**
   * Adjusts the file length to the specified value, truncating or extending as needed.
   *
   * <p>Extending fills the intermediate bytes with zeros. Because the call is synchronized, it
   * serializes with ongoing reads and writes to prevent cursor conflicts. Repeated truncation may
   * release space immediately or lazily depending on filesystem behavior; callers should not rely
   * on instant reclamation for quota purposes.
   *
   * @param len target length in bytes; must be non-negative.
   * @throws IOException if the resize operation fails due to I/O issues or insufficient
   *     permissions.
   */
  public synchronized void setLength(long len) throws IOException {
    randomAccessFile.setLength(len);
  }

  /**
   * Returns the current size of the underlying file in bytes.
   *
   * <p>The value is read directly from the {@link RandomAccessFile}. It reflects the state at the
   * moment of invocation and is synchronized for consistency with other accessors. The call is
   * lightweight but still performs I/O, so frequent polling should be balanced against performance
   * needs.
   *
   * @return non-negative file length in bytes at call time.
   * @throws IOException if the length cannot be read, typically because the file is closed or an
   *     I/O error occurs.
   */
  public synchronized long length() throws IOException {
    return randomAccessFile.length();
  }

  /**
   * Closes the underlying random-access file and optionally deletes it.
   *
   * <p>The method sets the closed flag, closes the handle, and, if requested via {@link
   * #deleteOnClose()}, removes the file from disk. It is synchronized to prevent concurrent
   * operations during shutdown. Once closed, the instance cannot be reopened automatically; callers
   * should create a new {@code RAF} if further access is required.
   *
   * @throws IOException if closing fails or if delete-on-close cleanup cannot remove the file.
   */
  public synchronized void close() throws IOException {
    closed = true;
    randomAccessFile.close();
    if (deleteOnClose) {
      deleteFile();
    }
  }

  /**
   * Returns a diagnostic string containing the absolute file path and access mode.
   *
   * <p>The output is intended for logging and debugging and should not be parsed for control flow.
   *
   * @return human-readable description of this {@code RAF}, including its current file and mode.
   */
  public String toString() {
    return "RAF[file=" + f.getAbsolutePath() + ",mode=" + mode + "]";
  }

  private void deleteFile() throws IOException {
    try {
      Method deleteMethod = f.getClass().getMethod("delete");
      boolean overridesDelete = deleteMethod.getDeclaringClass() != File.class;

      if (overridesDelete) {
        invokeDelete(deleteMethod);
        Path path = f.toPath();
        if (Files.exists(path)) {
          Files.delete(path);
        }
      } else {
        Path path = f.toPath();
        Files.delete(path);
      }
    } catch (SecurityException | NoSuchMethodException e) {
      throw new IOException("Unable to delete file on close", e);
    }
  }

  private boolean isSameFile(File destFile) throws IOException {
    return f.getCanonicalFile().equals(destFile.getCanonicalFile());
  }

  private void deleteDestinationIfExists(File destFile) throws IOException {
    Path destinationPath = destFile.toPath();
    if (Files.exists(destinationPath)) {
      Files.delete(destinationPath);
    }
  }

  private void copyToDestination(File destFile) throws IOException {
    byte[] buffer = new byte[8192];
    try (InputStream input = new FileInputStream(f);
        OutputStream output = new FileOutputStream(destFile)) {
      int bytesRead;
      while ((bytesRead = input.read(buffer, 0, buffer.length)) != -1) {
        output.write(buffer, 0, bytesRead);
      }
    } catch (IOException e) {
      deleteDestinationQuietly(destFile, e);
      throw new IOException("Unable to move " + f + " to " + destFile + " : " + e.getMessage(), e);
    }

    try {
      Files.delete(f.toPath());
    } catch (IOException e) {
      deleteDestinationQuietly(destFile, e);
      throw new IOException("Unable to delete source post-move", e);
    }
  }

  private void deleteDestinationQuietly(File destFile, IOException cause) throws IOException {
    Path destinationPath = destFile.toPath();
    if (Files.exists(destinationPath)) {
      try {
        Files.delete(destinationPath);
      } catch (IOException deletionFailure) {
        throw new IOException(
            "Unable to delete destination after failed move : "
                + destFile
                + " : "
                + cause.getMessage(),
            deletionFailure);
      }
    }
  }

  private void invokeDelete(Method deleteMethod) throws IOException {
    try {
      boolean deleted = (boolean) deleteMethod.invoke(f);
      if (!deleted && Files.exists(f.toPath())) {
        throw new IOException("Unable to delete file on close");
      }
    } catch (ReflectiveOperationException e) {
      throw new IOException("Unable to delete file on close", e);
    }
  }
}
