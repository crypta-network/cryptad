package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.io.Serial;

/**
 * Signals that a file already exists where a new file is required.
 *
 * <p>This checked exception specializes {@link IOException} to represent the "must create, do not
 * overwrite" failure mode commonly used by components that perform atomic or cautious file-creation
 * operations (for example, semantics similar to {@code CREATE_NEW}). The detail message includes
 * the path that triggered the condition (absolute or relative, as provided).
 *
 * <p>Instances are immutable and therefore thread-safe.
 */
public class FileExistsException extends IOException {

  @Serial private static final long serialVersionUID = 1L;

  /**
   * The path of the file that already exists at the time this exception is created.
   *
   * <p>May be {@code null} if the caller did not provide a {@link File} instance; in that case the
   * exception message contains {@code "null"}.
   */
  public final File file;

  /**
   * Creates a new exception for the given path that unexpectedly already exists.
   *
   * @param f the file that exists when creation without overwrite was attempted; may be {@code
   *     null}
   */
  public FileExistsException(File f) {
    super("File exists: " + f);
    this.file = f;
  }
}
