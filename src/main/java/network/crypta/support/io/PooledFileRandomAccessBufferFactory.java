package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;

/**
 * Factory that creates file-backed {@link LockableRandomAccessBuffer} instances using a {@link
 * FilenameGenerator}.
 *
 * <p>This implementation allocates a unique temporary file via the provided filename generator and
 * constructs a {@link PooledFileRandomAccessBuffer} over it. If construction fails for any reason
 * (I/O or unchecked exceptions), the factory performs best-effort cleanup by deleting the freshly
 * created file before rethrowing the original exception.
 *
 * <p>Lifecycle: the returned buffer controls the lifetime of its backing file. This factory only
 * intervenes when construction fails. TODO: Document precise deletion semantics when the buffer is
 * closed or discarded.
 *
 * <p>Thread-safety: this class performs no internal synchronization and delegates filename
 * generation to the supplied {@link FilenameGenerator}. TODO: Clarify whether instances are safe
 * for concurrent use and whether the generator must be thread-safe.
 */
public class PooledFileRandomAccessBufferFactory implements LockableRandomAccessBufferFactory {

  private final FilenameGenerator fg;

  /**
   * Create a factory that uses the given {@link FilenameGenerator} to allocate backing files.
   *
   * @param filenameGenerator source of unique identifiers and files; must not be {@code null}.
   */
  public PooledFileRandomAccessBufferFactory(FilenameGenerator filenameGenerator) {
    fg = filenameGenerator;
  }

  // Encryption, if any, is handled by higher-level factories; this factory always creates
  // plain on-disk temporary files.

  /**
   * Create a zero-initialized, file-backed random-access buffer of the requested size.
   *
   * <p>The method allocates a new temporary file using the configured {@link FilenameGenerator}. If
   * buffer construction fails, the file is deleted on a best-effort basis before the exception is
   * rethrown.
   *
   * @param size desired capacity in bytes; must be non-negative.
   * @return a {@link LockableRandomAccessBuffer} backed by a newly created file.
   * @throws IOException if the file cannot be created or the buffer cannot be initialized.
   *     Unchecked exceptions from the underlying implementation may also propagate.
   */
  @Override
  public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
    long id = fg.makeRandomFilename();
    File file = fg.getFilename(id);
    try {
      return new PooledFileRandomAccessBuffer(file, false, size, id, true);
    } catch (IOException | RuntimeException e) {
      try {
        Files.deleteIfExists(file.toPath());
      } catch (IOException _) {
        // Best-effort cleanup; ignore secondary deletion failure to preserve the cause.
      }
      throw e;
    }
  }

  /**
   * Create a file-backed random-access buffer initialized from an array segment.
   *
   * <p>The content of {@code initialContents} in the half-open range {@code [offset, offset +
   * size)} is written to a newly allocated backing file before the buffer is returned. If
   * construction or initialization fails (including unchecked exceptions such as {@link
   * IndexOutOfBoundsException} or {@link NullPointerException}), the temporary file is deleted on a
   * best-effort basis and the original exception is rethrown.
   *
   * @param initialContents source array containing the initial data; must not be {@code null}.
   * @param offset start index within {@code initialContents}.
   * @param size number of bytes to copy from {@code initialContents} starting at {@code offset};
   *     must be non-negative and {@code offset + size} must not exceed the array length.
   * @param readOnly if {@code true}, the returned buffer prohibits modification operations.
   * @return a {@link LockableRandomAccessBuffer} backed by a newly created file and preloaded with
   *     the specified bytes.
   * @throws IOException if the file cannot be created or the initial contents cannot be written.
   *     Unchecked exceptions from argument validation or the underlying implementation may also
   *     propagate.
   */
  @Override
  public LockableRandomAccessBuffer makeRAF(
      byte[] initialContents, int offset, int size, boolean readOnly) throws IOException {
    long id = fg.makeRandomFilename();
    File file = fg.getFilename(id);
    try {
      return new PooledFileRandomAccessBuffer(
          file, initialContents, offset, size, id, true, readOnly);
    } catch (IOException | RuntimeException e) {
      /*
       * Constructor may throw {@link IOException}; writing initial contents may also throw
       * unchecked exceptions. Clean up the temp file then rethrow to preserve original behavior.
       */
      try {
        Files.deleteIfExists(file.toPath());
      } catch (IOException _) {
        // Best-effort cleanup; ignore secondary deletion failure to preserve the cause.
      }
      throw e;
    }
  }
}
