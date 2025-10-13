package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.io.Serial;

/**
 * Indicates that an expected file is missing at the moment it is about to be used.
 *
 * <p>This checked exception is a specialization of {@link IOException} used by components that
 * manipulate temporary or transient files. It helps distinguish the "file not present when
 * required" condition from other I/O failures. The detail message includes the path of the file
 * supplied at construction (absolute or relative, as given).
 *
 * <p>Instances are immutable and therefore thread-safe.
 */
public class FileDoesNotExistException extends IOException {
  @Serial private static final long serialVersionUID = 1L;

  // Reference to the file that was expected to exist when this exception was created.
  final File file;

  /**
   * Creates a new exception for the given missing file.
   *
   * @param f the file that was expected to exist; may be {@code null}, in which case the detail
   *     message contains {@code "null"}
   */
  public FileDoesNotExistException(File f) {
    super("File does not exist: " + f);
    this.file = f;
  }
}
