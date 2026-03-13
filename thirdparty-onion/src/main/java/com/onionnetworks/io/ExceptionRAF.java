package com.onionnetworks.io;

import java.io.*;

/**
 * {@link RAF} variant that always throws a pre-supplied {@link IOException} for read/write-style
 * operations.
 *
 * <p>This wrapper is designed for tests and failure-injection scenarios where callers must observe
 * deterministic I/O failures without touching the filesystem. It stores the provided exception and
 * rethrows it from all mutating and positioning methods, letting higher-level components validate
 * error-handling branches while keeping state isolated. The mode string is retained so {@link
 * #getMode()} continues to behave like a normal {@code RAF} instance even though no file backing
 * exists. Instances are synchronized in the same manner as {@code RAF}, enabling safe reuse across
 * threads when simulating concurrent failures. Because the class never opens or owns a physical
 * file descriptor, it is effectively immutable after construction except for inherited metadata
 * fields.
 *
 * <ul>
 *   <li>Injects the same {@link IOException} into every operation that would touch disk.
 *   <li>Preserves {@code mode} for compatibility with code paths that inspect access intent.
 *   <li>Useful for unit tests that must confirm retry, logging, or cleanup logic on persistent
 *       failure.
 * </ul>
 *
 * @see RAF
 */
public class ExceptionRAF extends RAF {

  IOException e;

  /**
   * Creates a throwing wrapper that reports the supplied exception for I/O actions.
   *
   * <p>The constructor does not open any file. Instead, it records the exception to replay on each
   * subsequent operation and saves the provided mode so callers that query {@link #getMode()} see a
   * consistent value. Use this when a component depends on {@code RAF}-like semantics but the test
   * harness needs predictable failure injection without altering the filesystem.
   *
   * @param e exception instance that will be thrown by all I/O-related methods; must not be {@code
   *     null} and should already carry the desired message and cause chain.
   * @param mode access mode string (for example {@code "r"} or {@code "rw"}) retained for API
   *     compatibility even though no file is opened; null or malformed values propagate via {@link
   *     #getMode()} unchanged.
   */
  public ExceptionRAF(IOException e, String mode) {
    this.e = e;
    // FIX, this is ridiculous, but check the mode.
    this.mode = mode;
    // This is so getMode() calls will succeed.
  }

  /**
   * Always throws the injected exception instead of writing data.
   *
   * <p>The method mirrors {@link RAF#seekAndWrite(long, byte[], int, int)} in signature and
   * synchronization but immediately rethrows the stored exception to simulate a failure at a known
   * offset. Callers should treat this as a deterministic I/O error and avoid assuming that the file
   * position or contents changed.
   *
   * @param pos absolute position that would have been written; retained only for signature
   *     compatibility and not validated.
   * @param b buffer that would have supplied data; must not be {@code null} when upstream code
   *     enforces argument validation.
   * @param off start index within {@code b}; preserved for API parity but unused in this
   *     implementation.
   * @param len number of bytes requested; ignored because the exception is thrown unconditionally.
   * @throws IOException always the same instance provided to the constructor to model write
   *     failure.
   */
  @Override
  public synchronized void seekAndWrite(long pos, byte[] b, int off, int len) throws IOException {
    throw e;
  }

  /**
   * Always throws the injected exception instead of reading data.
   *
   * <p>This method emulates {@link RAF#seekAndReadFully(long, byte[], int, int)} but never touches
   * storage. It is primarily used in tests that must observe the behavior of callers when a
   * guaranteed read failure occurs at a specific offset. No buffer mutations take place before the
   * exception is propagated.
   *
   * @param pos absolute position that would have been read from; unused but preserved for signature
   *     compatibility.
   * @param b destination buffer that would have been populated; callers should not rely on its
   *     contents changing.
   * @param off starting offset within {@code b}; unused because no I/O occurs.
   * @param len number of bytes requested for the read; ignored in this implementation.
   * @throws IOException always the constructor-supplied instance to indicate read failure.
   */
  @Override
  public synchronized void seekAndReadFully(long pos, byte[] b, int off, int len)
      throws IOException {
    throw e;
  }

  /**
   * Always throws the injected exception instead of renaming the file.
   *
   * <p>The call is synchronized to match {@link RAF#renameTo(File)} but short-circuits by
   * rethrowing the stored exception. No filesystem interactions occur, making it suitable for
   * verifying how callers handle move failures without altering disk state.
   *
   * @param destFile destination path that would have been used for the rename operation; value is
   *     not examined.
   * @throws IOException always the provided exception, representing a rename failure condition.
   */
  @Override
  public synchronized void renameTo(File destFile) throws IOException {
    throw e;
  }

  /**
   * Always throws the injected exception instead of reopening in read-only mode.
   *
   * <p>This override preserves the synchronization and signature of {@link RAF#setReadOnly()} while
   * guaranteeing a controlled failure. Callers should expect the mode to remain unchanged and no
   * handles to be opened or closed.
   *
   * @throws IOException always the stored exception, simulating inability to change access mode.
   */
  @Override
  public synchronized void setReadOnly() throws IOException {
    throw e;
  }

  /**
   * Always throws the injected exception instead of resizing the underlying file.
   *
   * <p>The method keeps the synchronized contract of {@link RAF#setLength(long)} but immediately
   * fails with the stored exception, allowing callers to validate error handling around resize
   * paths without modifying the filesystem.
   *
   * @param len target length in bytes that would have been applied; ignored because no I/O occurs.
   * @throws IOException always the constructor-supplied exception to model a resize failure.
   */
  @Override
  public synchronized void setLength(long len) throws IOException {
    throw e;
  }

  /**
   * Performs no action and does not throw, simulating a clean close on a failed handle.
   *
   * <p>Unlike other overrides, this method deliberately swallows the stored exception to mirror
   * scenarios where cleanup must succeed even after earlier failures. It remains synchronized for
   * consistency with {@link RAF#close()} but leaves internal state untouched and does not attempt
   * to delete any backing file.
   *
   * @throws IOException never in this implementation, despite the signature matching the parent
   *     class.
   */
  @Override
  public synchronized void close() throws IOException {
    // Intentionally no-op to simulate successful close without throwing the injected exception.
  }
}
