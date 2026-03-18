package network.crypta.runtime.spi;

import java.util.Arrays;
import java.util.Objects;

/**
 * Detached insert option values shared by queue insert creation requests.
 *
 * <p>This value object mirrors the subset of queue form controls that materially influence how the
 * legacy daemon starts an insert. It keeps the SPI free of daemon-owned option classes while still
 * giving the runtime adapter enough information to reconstruct the older {@code
 * FcpInsertOptions}-based flow.
 *
 * <p>The instance is logically immutable. The optional override splitfile key is stored and
 * returned as supplied, so callers that share the same array across components should treat that
 * array as read-only after construction.
 */
@SuppressWarnings({"ClassCanBeRecord", "java:S6206"})
public final class QueueInsertOptions {
  private final boolean compress;
  private final String compatibilityMode;
  private final byte[] overrideSplitfileCryptoKey;

  /**
   * Creates a detached option bundle for queue insert creation.
   *
   * @param compress {@code true} when the insert should request compression
   * @param compatibilityMode compatibility-mode name expected by the legacy insert adapter
   * @param overrideSplitfileCryptoKey optional caller-supplied splitfile key bytes, or {@code null}
   *     when no override was selected
   */
  public QueueInsertOptions(
      boolean compress, String compatibilityMode, byte[] overrideSplitfileCryptoKey) {
    this.compress = compress;
    this.compatibilityMode = Objects.requireNonNull(compatibilityMode, "compatibilityMode");
    this.overrideSplitfileCryptoKey = overrideSplitfileCryptoKey;
  }

  /**
   * Returns the detached compression preference.
   *
   * @return {@code true} when the insert should request compression
   */
  public boolean compress() {
    return compress;
  }

  /**
   * Returns the compatibility mode requested by the caller.
   *
   * @return compatibility-mode name understood by the legacy adapter
   */
  public String compatibilityMode() {
    return compatibilityMode;
  }

  /**
   * Returns the optional override splitfile crypto key.
   *
   * @return caller-supplied splitfile key bytes, or {@code null} when absent
   */
  public byte[] overrideSplitfileCryptoKey() {
    return overrideSplitfileCryptoKey;
  }

  @Override
  public boolean equals(Object o) {
    if (!(o instanceof QueueInsertOptions other)) {
      return false;
    }
    return compress == other.compress
        && Objects.equals(compatibilityMode, other.compatibilityMode)
        && Arrays.equals(overrideSplitfileCryptoKey, other.overrideSplitfileCryptoKey);
  }

  @Override
  public int hashCode() {
    return 31 * Objects.hash(compress, compatibilityMode)
        + Arrays.hashCode(overrideSplitfileCryptoKey);
  }

  @Override
  public String toString() {
    return "QueueInsertOptions[compress="
        + compress
        + ", compatibilityMode="
        + compatibilityMode
        + ']';
  }
}
