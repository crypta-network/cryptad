package network.crypta.client.async;

import java.util.Arrays;
import org.jetbrains.annotations.NotNull;

/**
 * Immutable bundle of optional settings for constructing a {@link ClientPutter}.
 *
 * <p>This value object carries opt-in configuration that is read by client putter creation logic
 * but does not itself perform validation or normalization. Callers typically construct an instance
 * with the desired values and pass it to the relevant {@link ClientPutter} entry point, or they
 * start from {@link #defaults()} and replace individual components. Each component is stored
 * exactly as provided, which preserves legacy constructor behavior and keeps this type free of side
 * effects.
 *
 * <p>The instance is effectively immutable in terms of its component references, but callers should
 * treat the {@code overrideSplitfileCrypto} array as shared mutable state: its contents are not
 * copied, so later mutations will be observed by equality checks and by any consumer that reads the
 * array. For stable behavior across threads, keep the array content fixed after construction or
 * pass a defensively copied buffer.
 *
 * <ul>
 *   <li>Optional manifest filename hint for single-file inserts.
 *   <li>Binary-blob insertion toggle for alternate storage behavior.
 *   <li>Splitfile crypto override key stored verbatim without validation.
 *   <li>Metadata size threshold for compact metadata responses.
 * </ul>
 */
@SuppressWarnings("java:S6206")
public final class ClientPutterOptions {
  private final String targetFilename;
  private final boolean binaryBlob;
  private final byte[] overrideSplitfileCrypto;
  private final long metadataThreshold;

  /**
   * Creates an options bundle with the supplied component values.
   *
   * @param targetFilename optional manifest filename for single-file inserts; may be null.
   * @param binaryBlob whether to use the binary-blob insertion path.
   * @param overrideSplitfileCrypto optional 32-byte key to override random splitfile key
   *     generation.
   * @param metadataThreshold byte threshold for compact metadata; non-positive disables
   *     optimization.
   */
  public ClientPutterOptions(
      String targetFilename,
      boolean binaryBlob,
      byte[] overrideSplitfileCrypto,
      long metadataThreshold) {
    this.targetFilename = targetFilename;
    this.binaryBlob = binaryBlob;
    this.overrideSplitfileCrypto = overrideSplitfileCrypto;
    this.metadataThreshold = metadataThreshold;
  }

  public String targetFilename() {
    return targetFilename;
  }

  public boolean binaryBlob() {
    return binaryBlob;
  }

  public byte[] overrideSplitfileCrypto() {
    return overrideSplitfileCrypto;
  }

  public long metadataThreshold() {
    return metadataThreshold;
  }

  /**
   * Creates default options with all optional settings disabled.
   *
   * <p>The returned instance sets {@code targetFilename} and {@code overrideSplitfileCrypto} to
   * {@code null}, {@code binaryBlob} to {@code false}, and {@code metadataThreshold} to {@code -1}
   * to indicate that no compact-metadata threshold is active. This method is idempotent and always
   * allocates a new instance, so callers may hold onto it or create fresh defaults without
   * affecting other call sites.
   *
   * <pre>{@code
   * ClientPutterOptions options = ClientPutterOptions.defaults();
   * }</pre>
   *
   * @return a new options instance containing the standard default component values.
   */
  public static ClientPutterOptions defaults() {
    return new ClientPutterOptions(null, false, null, -1);
  }

  /**
   * Determines equality by comparing each component, including array content.
   *
   * <p>This implementation mirrors record value semantics but treats {@code
   * overrideSplitfileCrypto} specially by comparing the array contents with {@link
   * Arrays#equals(byte[], byte[])}. If the array is mutated after construction, equality results
   * may change over time; callers should treat the array as immutable for stable behavior. The
   * comparison is null-safe for all components.
   *
   * @param other the other instance to compare against, or {@code null}.
   * @return {@code true} when every component matches, including array contents.
   */
  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (!(other instanceof ClientPutterOptions options)) {
      return false;
    }
    return binaryBlob == options.binaryBlob
        && metadataThreshold == options.metadataThreshold
        && java.util.Objects.equals(targetFilename, options.targetFilename)
        && Arrays.equals(overrideSplitfileCrypto, options.overrideSplitfileCrypto);
  }

  /**
   * Computes a hash code consistent with the equality semantics for arrays.
   *
   * <p>The hash combines the non-array components with the content hash of {@code
   * overrideSplitfileCrypto} via {@link Arrays#hashCode(byte[])}. This keeps the hash code aligned
   * with {@link #equals(Object)} even when the array is non-null. If the array contents are mutated
   * after construction, the hash code will also change, so avoid mutating once used in hashed
   * collections.
   *
   * @return a hash code derived from all components and the array contents.
   */
  @Override
  public int hashCode() {
    int result = java.util.Objects.hash(targetFilename, binaryBlob, metadataThreshold);
    result = 31 * result + Arrays.hashCode(overrideSplitfileCrypto);
    return result;
  }

  /**
   * Formats the options using component names and array contents.
   *
   * <p>The output mirrors the standard record style but expands {@code overrideSplitfileCrypto}
   * using {@link Arrays#toString(byte[])} so callers can see the array contents without additional
   * tooling. When the array is {@code null}, the rendered value is {@code "null"}. This method does
   * not redact or validate values and is intended for debugging or logging where the raw components
   * are acceptable.
   *
   * @return a non-null string representation of the current component values.
   */
  @Override
  public @NotNull String toString() {
    return "ClientPutterOptions["
        + "targetFilename="
        + targetFilename
        + ", binaryBlob="
        + binaryBlob
        + ", overrideSplitfileCrypto="
        + Arrays.toString(overrideSplitfileCrypto)
        + ", metadataThreshold="
        + metadataThreshold
        + "]";
  }
}
