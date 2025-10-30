package network.crypta.node;

import java.io.Serial;

/**
 * Signals that the on-disk {@code master.keys} file size is outside supported bounds.
 *
 * <p>This exception is thrown by {@link MasterKeys#read(java.io.File, java.util.Random, String)}
 * when the file is either smaller than the minimum expected structure or larger than the maximum
 * allowed size. The {@link #isTooBig()} flag indicates which boundary was violated.
 *
 * <p>Instances are immutable and therefore thread-safe.
 */
public class MasterKeysFileSizeException extends Exception {

  @Serial private static final long serialVersionUID = -2753942792186990130L;

  /**
   * Size classification determined by the caller.
   *
   * <p>{@code true} means the file length in bytes exceeded the upper bound; {@code false} means it
   * was below the minimum size. Exact thresholds are defined in {@link
   * MasterKeys#read(java.io.File, java.util.Random, String)}.
   */
  public final boolean tooBig;

  /**
   * Creates a new exception describing which size bound was violated.
   *
   * @param tooBig {@code true} if the file is oversized; {@code false} if undersized (units:
   *     bytes). Boundaries are evaluated in {@link MasterKeys#read(java.io.File, java.util.Random,
   *     String)}.
   */
  public MasterKeysFileSizeException(boolean tooBig) {
    this.tooBig = tooBig;
  }

  /**
   * Returns whether the file exceeded the maximum allowed size.
   *
   * @return {@code true} if oversized; {@code false} if undersized.
   */
  public boolean isTooBig() {
    return tooBig;
  }

  /**
   * Returns a concise descriptor for the violated bound.
   *
   * <p>Returns {@code "big"} when {@link #isTooBig()} is {@code true}; otherwise returns {@code
   * "small"}. Intended for use in user-facing strings and logs.
   *
   * @return {@code "big"} or {@code "small"} depending on the violation.
   */
  public String sizeToString() {
    return tooBig ? "big" : "small";
  }
}
