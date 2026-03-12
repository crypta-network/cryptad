package network.crypta.support.compress;

import java.io.Serial;

/**
 * Signals that a compressed stream declares a dictionary size larger than supported.
 *
 * <p>This exception is a specialization of {@link InvalidCompressedDataException} used when a
 * codec's metadata or header specifies a dictionary/window size that exceeds the implementation's
 * limit (for example, when an LZMA stream advertises a dictionary greater than the configured
 * maximum). Callers should treat this as a permanent data error.
 *
 * <p>Thread-safety: instances are immutable and therefore safe to share across threads.
 *
 * @see InvalidCompressedDataException
 */
public class TooBigDictionaryException extends InvalidCompressedDataException {
  @Serial private static final long serialVersionUID = -1L;
}
