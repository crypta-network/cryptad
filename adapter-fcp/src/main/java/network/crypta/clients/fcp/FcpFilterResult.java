package network.crypta.clients.fcp;

/**
 * Adapter-owned outcome of a single FCP content-filter pass.
 *
 * <p>{@code FilterMessage} uses this detached record to receive only the protocol-visible parts of
 * filtering while the concrete runtime implementation remains behind the {@code
 * FcpMessageRuntimeSupport} seam. That keeps {@code :adapter-fcp} independent of runtime-owned
 * filter classes without changing the wire behavior seen by FCP clients. The record deliberately
 * carries a small surface: the effective charset, the effective MIME type, and an explicit flag
 * describing whether the runtime rejected the payload as unsafe.
 *
 * <p>The value is immutable and therefore safe to pass across message-handling boundaries without
 * additional synchronization. Safe results may still contain {@code null} charset or MIME values
 * when the runtime has nothing more specific to report. Unsafe results follow a stronger invariant:
 * callers should expect {@code unsafeContentType()} to be {@code true} and both metadata fields to
 * be {@code null}, so reply construction can stay deterministic.
 *
 * <ul>
 *   <li>Represents one filter attempt, not a reusable session or mutable accumulator.
 *   <li>Exposes only FCP-visible metadata needed to build a {@code FilterResultMessage}.
 *   <li>Allows the bridge layer to translate runtime exceptions into a stable adapter contract.
 * </ul>
 *
 * @param charset charset reported by the filter, or {@code null} when the runtime does not provide
 *     one or when the payload is rejected as unsafe
 * @param mimeType MIME type reported by the filter, or {@code null} when the runtime does not
 *     provide one or when the payload is rejected as unsafe
 * @param unsafeContentType whether the runtime rejected the payload as unsafe and therefore
 *     suppressed MIME and charset output
 */
public record FcpFilterResult(String charset, String mimeType, boolean unsafeContentType) {

  /**
   * Builds a result describing content that completed filtering without an unsafe-content
   * rejection.
   *
   * <p>Callers typically use this factory in bridge code after the concrete runtime filter returns
   * successfully. The method preserves whatever MIME or charset metadata the runtime exposed,
   * including {@code null} values when the runtime leaves one of those fields unspecified. The
   * returned record always reports {@code unsafeContentType()} as {@code false}.
   *
   * @param charset charset reported by the filter, or {@code null} when the runtime did not provide
   *     a specific charset
   * @param mimeType MIME type reported by the filter, or {@code null} when the runtime did not
   *     provide a specific MIME type
   * @return detached safe result carrying the protocol-visible metadata needed for an FCP filter
   *     reply
   */
  public static FcpFilterResult safe(String charset, String mimeType) {
    return new FcpFilterResult(charset, mimeType, false);
  }

  /**
   * Builds a result describing content rejected by the runtime as unsafe.
   *
   * <p>This factory intentionally drops MIME and charset details so adapter callers do not
   * accidentally mix partial metadata with an unsafe outcome. Use it when the runtime-side filter
   * reports an unsafe-content failure that should become the existing FCP unsafe flag behavior. The
   * returned record always has {@code null} metadata and {@code unsafeContentType()} set to {@code
   * true}.
   *
   * @return detached unsafe result with no exposed MIME or charset payload, suitable for building a
   *     stable {@code FilterResultMessage}
   */
  public static FcpFilterResult unsafe() {
    return new FcpFilterResult(null, null, true);
  }
}
