package network.crypta.support.compress;

import java.io.Serial;

/**
 * Indicates that a requested compression codec identifier or descriptor is invalid.
 *
 * <p>This checked exception is thrown while parsing codec selections, such as the descriptor string
 * accepted by {@link Compressor.COMPRESSOR_TYPE#getCompressorsArray(String)} or a metadata
 * identifier parsed via {@link Compressor.COMPRESSOR_TYPE#getCompressorByMetadataID(short)}.
 * Typical causes include:
 *
 * <ul>
 *   <li>Unknown codec name (e.g., a misspelling).
 *   <li>Numeric identifier out of range or not mapped to a codec.
 *   <li>Duplicate codec entries in the descriptor.
 *   <li>Malformed or empty descriptor where a specific selection is required.
 * </ul>
 *
 * <p>Thread-safety: instances are immutable and therefore safe to share across threads.
 */
public class InvalidCompressionCodecException extends Exception {

  @Serial private static final long serialVersionUID = -1;

  /**
   * Creates an exception with the provided detail message.
   *
   * @param message human-readable detail describing why the codec selection is invalid.
   */
  public InvalidCompressionCodecException(String message) {
    super(message);
  }
}
