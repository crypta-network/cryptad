package network.crypta.support.compress;

/**
 * Thrown when the achieved compression ratio is below a required minimum threshold.
 *
 * <p>Implementations of {@link Compressor} use this checked exception to abort work when the amount
 * of reduction observed so far does not justify continuing the operation. The common contract in
 * this package computes the achieved percentage as {@code 100 - (compressed * 100 / raw)} using
 * integer arithmetic and throws when it is strictly less than the caller-specified minimum.
 *
 * <p>Usage: {@link AbstractCompressor#checkCompressionEffect(long, long, int)} performs the check
 * and throws this exception. Callers may translate it to an unchecked exception when propagating
 * through third‑party callbacks (e.g., codec progress hooks) and rethrow the original cause after
 * unwrapping.
 *
 * <p>Thread-safety: instances are immutable and therefore safe to share across threads.
 */
public class CompressionRatioException extends Exception {

  /**
   * Creates a new exception with a human-readable explanation.
   *
   * @param message detail describing the failed ratio check; typically includes the computed
   *     percentage and the minimum required value.
   */
  CompressionRatioException(String message) {
    super(message);
  }
}
