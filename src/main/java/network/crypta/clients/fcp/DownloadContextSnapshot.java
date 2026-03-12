package network.crypta.clients.fcp;

import network.crypta.client.FetchContext;
import network.crypta.client.InsertContext.CompatibilityMode;
import network.crypta.keys.FreenetURI;

/**
 * Represents fetch-context and compatibility metadata captured for a download request.
 *
 * <p>This value object aggregates the subset of download status data that is derived from the
 * request's execution context rather than its progress counters or outcome. Callers typically build
 * it alongside other snapshot bundles and pass it into a status formatter or encoder that produces
 * an FCP reply. The snapshot stores object references as provided and does not perform validation
 * or normalization; mutable array inputs are defensively copied.
 *
 * <p>The instance is immutable. Referenced objects such as {@link FetchContext} may still be
 * mutable and shared, while array fields are defensively copied at construction and access time.
 * The snapshot intentionally does not interpret compatibility mode ordering or URI normalization,
 * leaving those concerns to downstream consumers.
 *
 * <ul>
 *   <li>Preserves fetch-context settings that influence status output and filtering.
 *   <li>Captures compatibility modes and splitfile key overrides, if any.
 *   <li>Holds request URI and compression policy for reporting purposes.
 * </ul>
 *
 * @see FetchContext
 * @see DownloadRequestStatusDetails
 */
@SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
public final class DownloadContextSnapshot {
  private final FetchContext fetchContext;
  private final CompatibilityMode[] compatModes;
  private final byte[] splitfileKey;
  private final FreenetURI uri;
  private final boolean dontCompress;

  /**
   * Creates a context snapshot for download status reporting.
   *
   * <p>The constructor stores each argument verbatim so the snapshot mirrors the request state at
   * the time the status response is prepared. Reference parameters may be {@code null} when the
   * associated data is unknown or not applicable, and those {@code null} values are forwarded
   * unmodified to downstream encoders. The snapshot does not validate array lengths, URI schemes,
   * or compatibility semantics; callers are responsible for ensuring the inputs are appropriate for
   * their status reporting use case.
   *
   * <pre>{@code
   * DownloadContextSnapshot context =
   *     new DownloadContextSnapshot(fetchContext, compatModes, splitfileKey, uri, dontCompress);
   * }</pre>
   *
   * @param fetchContext fetch context providing filter and MIME overrides, or {@code null}
   * @param compatModes compatibility modes observed for the request, possibly empty or {@code null}
   * @param splitfileKey splitfile crypto key override bytes, or {@code null} if not applicable
   * @param uri request URI to report, or {@code null} when not yet resolved
   * @param dontCompress whether reinsertion should skip compression when producing output
   */
  public DownloadContextSnapshot(
      FetchContext fetchContext,
      CompatibilityMode[] compatModes,
      byte[] splitfileKey,
      FreenetURI uri,
      boolean dontCompress) {
    this.fetchContext = fetchContext;
    this.compatModes = copyCompatModes(compatModes);
    this.splitfileKey = copySplitfileKey(splitfileKey);
    this.uri = uri;
    this.dontCompress = dontCompress;
  }

  /**
   * Returns the fetch context captured in this snapshot.
   *
   * <p>The context can include filtering settings, MIME overrides, and other request-scoped
   * options. The returned reference is the original object supplied at construction time and is not
   * copied. It may be {@code null} when no context was available, and callers should handle that
   * case by applying their own defaults or by omitting context-derived fields in status output.
   *
   * @return the fetch context reference, or {@code null} when not available
   */
  public FetchContext fetchContext() {
    return fetchContext;
  }

  /**
   * Returns the compatibility modes observed for the request.
   *
   * <p>The returned array is a defensive copy. It may be {@code null} or empty.
   *
   * @return the compatibility mode array, or {@code null} if no modes were recorded
   */
  public CompatibilityMode[] compatModes() {
    return copyCompatModes(compatModes);
  }

  /**
   * Returns the splitfile crypto key override, if any.
   *
   * <p>The returned byte array is a defensive copy. It may be {@code null} when no override is
   * configured or when the request does not involve splitfiles.
   *
   * @return the splitfile key bytes, or {@code null} when no override is set
   */
  public byte[] splitfileKey() {
    return copySplitfileKey(splitfileKey);
  }

  /**
   * Returns the request URI associated with this snapshot.
   *
   * <p>The URI may be {@code null} when the request has not yet resolved a definitive URI or when
   * the caller chooses not to expose it. The snapshot does not validate or normalize the URI; it
   * simply returns the stored reference for status reporting.
   *
   * @return the request URI, or {@code null} when no URI is available
   */
  public FreenetURI uri() {
    return uri;
  }

  /**
   * Returns whether reinsertion should skip compression.
   *
   * <p>This flag is captured for status reporting and is not derived from other fields. It reflects
   * the request's reinsertion policy at snapshot creation time and does not change after
   * construction.
   *
   * @return {@code true} when reinsertion should skip compression, {@code false} otherwise
   */
  public boolean dontCompress() {
    return dontCompress;
  }

  private static CompatibilityMode[] copyCompatModes(CompatibilityMode[] input) {
    return input == null ? null : input.clone();
  }

  private static byte[] copySplitfileKey(byte[] input) {
    return input == null ? null : input.clone();
  }
}
