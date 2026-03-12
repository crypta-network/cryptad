package network.crypta.support.io;

import java.io.IOException;
import java.io.Serial;

/**
 * Indicates that persisted data does not match the expected on-disk format.
 *
 * <p>This checked exception is used when loading a stored artifact (for example, a splitfile,
 * bucket, or request state) and the bytes cannot be parsed or validated according to the expected
 * storage format. Typical causes include missing or corrupt headers, unsupported or mismatched
 * version identifiers, truncated content, or length fields that disagree with the actual file size.
 * I/O failures that are not format-related should propagate as {@link IOException} and may
 * optionally be wrapped as the cause of this exception when the boundary between I/O and validation
 * is crossed.
 */
public class StorageFormatException extends Exception {
  /** Serialization version for compatibility across releases. */
  @Serial private static final long serialVersionUID = 6953756148374736258L;

  /**
   * Creates an exception with a detail message describing the format violation.
   *
   * @param message human-readable description of the detected format problem; may be {@code null}.
   */
  public StorageFormatException(String message) {
    super(message);
  }

  /**
   * Creates an exception with a detail message and an underlying {@link IOException} cause.
   *
   * <p>Use this when an I/O error occurs while attempting to validate or parse the storage format,
   * and you want to signal a format-level failure to callers while preserving the original cause.
   *
   * @param message human-readable description of the detected problem; may be {@code null}.
   * @param e the I/O cause; may be {@code null} if unavailable.
   */
  public StorageFormatException(String message, IOException e) {
    super(message, e);
  }
}
