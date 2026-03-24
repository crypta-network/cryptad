package network.crypta.node;

import java.io.Serial;

/**
 * Exception indicating that parsing a version string failed.
 *
 * <p>Used by version-processing utilities (for example, {@link Version}) when converting a textual
 * version into numeric components such as an arbitrary build number. It is a checked exception so
 * callers explicitly handle malformed or unsupported version formats. The class is immutable and
 * carries no additional state beyond the detail message.
 *
 * @author toad
 */
public class VersionParseException extends Exception {
  // Fixed UID to keep serialization compatibility across releases.
  @Serial private static final long serialVersionUID = -19006235321212642L;

  /**
   * Creates an instance with a human-readable detail message.
   *
   * @param msg detail describing the parse error context; may be {@code null}.
   */
  public VersionParseException(String msg) {
    super(msg);
  }
}
