package network.crypta.platform.api.content;

import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.contentformats.ContentFormatProfileRegistry;

/**
 * Shared app-facing policy for bounded content fetch sources.
 *
 * <p>The Platform API accepts only Crypta/Freenet content-key forms for foreground app fetches and
 * durable subscription polling. This helper intentionally does not parse full content keys; it
 * rejects inputs that can be confused with local paths, generic URL schemes, protocol-relative
 * hosts, query strings, fragments, or multiline diagnostics before the runtime fetch port sees
 * them.
 *
 * <p>Callers use this class at the API boundary, before constructing runtime fetch requests or
 * storing subscription metadata. It keeps the app-visible value and the runtime value separate so
 * routes can report the URI the app supplied while lower layers receive the raw {@code CHK@},
 * {@code SSK@}, {@code USK@}, or {@code KSK@} form. Runtime code still validates the full key
 * syntax and performs the actual fetch; this class provides the narrower public-beta guardrail that
 * prevents the app platform from becoming a generic URL fetcher, local path probe, or log-injection
 * path. All methods are stateless and safe to call concurrently.
 */
public final class ContentFetchPolicy {
  /**
   * Default app-facing foreground fetch byte bound.
   *
   * <p>The value is deliberately small enough for reference-app import flows and preview reads. App
   * callers may ask for a lower value per request, but this is the bound used when the request
   * omits {@code maxBytes}.
   */
  public static final long DEFAULT_APP_FETCH_MAX_BYTES =
      ContentFormatProfileRegistry.FETCHED_DOCUMENT_MAX_BYTES;

  /**
   * Hard app-facing foreground fetch byte bound.
   *
   * <p>The API rejects larger requested limits before invoking the runtime fetch port. This cap is
   * a public API safety bound, not a statement about daemon-wide storage or network limits.
   */
  public static final long HARD_APP_FETCH_MAX_BYTES = 1_048_576L;

  /**
   * Default app-facing foreground fetch timeout in milliseconds.
   *
   * <p>Foreground fetches run on behalf of an interactive app request, so the default favors a
   * bounded response over long background retry behavior. Subscription polling uses its own
   * scheduler policy.
   */
  public static final long DEFAULT_APP_FETCH_TIMEOUT_MILLIS = 30_000L;

  /**
   * Hard app-facing foreground fetch timeout in milliseconds.
   *
   * <p>The content route refuses larger timeout requests to keep app-facing calls finite and
   * release-certification evidence deterministic. The value is expressed in milliseconds because
   * Platform API parameters are form fields.
   */
  public static final long HARD_APP_FETCH_TIMEOUT_MILLIS = 60_000L;

  private static final String CRYPTA_SCHEME_PREFIX = "crypta:";
  private static final Set<ContentKeyKind> FOREGROUND_KINDS = EnumSet.allOf(ContentKeyKind.class);
  private static final Set<ContentKeyKind> SUBSCRIPTION_KINDS = EnumSet.of(ContentKeyKind.USK);

  private ContentFetchPolicy() {}

  /**
   * Normalizes a foreground app fetch URI.
   *
   * <p>Foreground fetches may use any supported public content-key family because they return a
   * single bounded response to the calling app. The method accepts an optional {@code crypta:}
   * wrapper, preserves that app-facing value in the result, and derives the runtime URI by removing
   * the wrapper. It rejects blank text, control characters, whitespace, query strings, fragments,
   * backslashes, protocol-relative hosts, local paths, and unrelated schemes before lower layers
   * can produce diagnostics that echo unsafe input.
   *
   * @param rawUri app-supplied URI value taken from request parameters or equivalent app input
   * @return normalized source metadata containing both app-facing and runtime URI forms
   * @throws PlatformApiException when the URI is missing, unsafe, or unsupported by foreground
   *     fetch
   */
  public static NormalizedContentSource normalizeForegroundSource(String rawUri) {
    return normalize(rawUri, FOREGROUND_KINDS, invalidForegroundSource());
  }

  /**
   * Normalizes a durable subscription source URI.
   *
   * <p>Background subscription polling intentionally has a narrower source model than ad hoc
   * foreground fetches. Subscriptions must track an updatable public source, so this method accepts
   * only {@code USK@...} values and {@code crypta:USK@...} wrappers. It applies the same
   * path-confusion and diagnostic-safety checks as foreground normalization, then returns the
   * stable pair that durable records and scheduler jobs can store without preserving raw rejected
   * input.
   *
   * @param rawUri app-supplied subscription source from form parameters, import data, or storage
   * @return normalized source metadata for the accepted public USK source
   * @throws PlatformApiException when the source is missing, unsafe, or not a USK
   */
  public static NormalizedContentSource normalizeSubscriptionSource(String rawUri) {
    return normalize(rawUri, SUBSCRIPTION_KINDS, invalidSubscriptionSource());
  }

  /**
   * Sanitizes a runtime-reported resolved URI for foreground fetch responses.
   *
   * <p>Runtime fetch implementations may return resolved URI metadata alongside fetched bytes. That
   * metadata is treated as untrusted because it can cross into JSON responses, audit summaries, and
   * release evidence. This method reuses foreground source validation and converts unsafe values to
   * {@code null} instead of throwing so response construction can omit suspicious metadata without
   * echoing it.
   *
   * @param value resolved URI candidate reported by the runtime fetch implementation
   * @return safe resolved URI text, or {@code null} when the candidate is absent or unsafe
   */
  public static String sanitizeForegroundResolvedUri(String value) {
    return sanitizeResolvedUri(value, FOREGROUND_KINDS);
  }

  /**
   * Sanitizes a runtime-reported resolved URI for durable subscription metadata.
   *
   * <p>Subscription metadata must remain suitable for app summaries and scheduler recovery. The
   * sanitizer therefore accepts only the same public USK forms that subscription creation accepts.
   * Unsafe, non-USK, malformed, or absent runtime values are represented as {@code null}, leaving
   * digest-based deduplication and source metadata as the remaining stable signals.
   *
   * @param value resolved URI candidate reported by the runtime fetch implementation
   * @return safe resolved USK text, or {@code null} when the candidate is absent or unsafe
   */
  public static String sanitizeSubscriptionResolvedUri(String value) {
    return sanitizeResolvedUri(value, SUBSCRIPTION_KINDS);
  }

  /**
   * Extracts a USK edition from a safe resolved URI candidate.
   *
   * <p>The returned edition is advisory metadata for subscription summaries and deduplication. The
   * method first runs the subscription resolved-URI sanitizer, then parses the third
   * slash-delimited segment of the runtime {@code USK@} form. Missing segments, non-numeric
   * editions, non-USK keys, path-confusion input, and unsupported schemes return {@code null};
   * callers should not treat that result as a fetch failure.
   *
   * @param value resolved URI candidate reported by the runtime fetch implementation
   * @return parsed edition number, or {@code null} when no safe numeric edition is present
   */
  public static Long resolvedUskEdition(String value) {
    String sanitized = sanitizeSubscriptionResolvedUri(value);
    if (sanitized == null) {
      return null;
    }
    String runtimeUri = runtimeFetchUri(sanitized);
    String[] segments = runtimeUri.split("/", -1);
    if (segments.length < 3) {
      return null;
    }
    try {
      return Long.parseLong(segments[2]);
    } catch (NumberFormatException _) {
      return null;
    }
  }

  private static NormalizedContentSource normalize(
      String rawUri, Set<ContentKeyKind> allowedKinds, PlatformApiException failure) {
    if (rawUri == null || hasUnsafeControl(rawUri)) {
      throw failure;
    }
    String requestedUri = rawUri.trim();
    if (hasUnsafeUriText(requestedUri)) {
      throw failure;
    }
    String runtimeUri = runtimeFetchUri(requestedUri);
    if (runtimeUri.startsWith("/") || hasDisallowedScheme(runtimeUri)) {
      throw failure;
    }
    ContentKeyKind kind = contentKeyKind(runtimeUri);
    if (kind == null
        || !allowedKinds.contains(kind)
        || runtimeUri.length() <= kind.prefix.length()) {
      throw failure;
    }
    return new NormalizedContentSource(requestedUri, runtimeUri, kind);
  }

  private static String sanitizeResolvedUri(String value, Set<ContentKeyKind> allowedKinds) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return normalize(value, allowedKinds, invalidForegroundSource()).requestedUri();
    } catch (PlatformApiException _) {
      return null;
    }
  }

  private static String runtimeFetchUri(String requestedUri) {
    if (requestedUri.regionMatches(
        true, 0, CRYPTA_SCHEME_PREFIX, 0, CRYPTA_SCHEME_PREFIX.length())) {
      return requestedUri.substring(CRYPTA_SCHEME_PREFIX.length()).trim();
    }
    return requestedUri;
  }

  private static boolean hasUnsafeControl(String value) {
    for (int index = 0; index < value.length(); index++) {
      if (Character.isISOControl(value.charAt(index))) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasUnsafeUriText(String value) {
    return value.isEmpty()
        || containsWhitespace(value)
        || value.indexOf('?') >= 0
        || value.indexOf('#') >= 0
        || value.indexOf('\\') >= 0;
  }

  private static boolean hasDisallowedScheme(String uri) {
    int colon = uri.indexOf(':');
    int at = uri.indexOf('@');
    return colon >= 0 && (at < 0 || colon < at);
  }

  private static ContentKeyKind contentKeyKind(String uri) {
    for (ContentKeyKind kind : ContentKeyKind.values()) {
      if (uri.regionMatches(true, 0, kind.prefix, 0, kind.prefix.length())) {
        return kind;
      }
    }
    return null;
  }

  private static boolean containsWhitespace(String value) {
    for (int index = 0; index < value.length(); index++) {
      if (Character.isWhitespace(value.charAt(index))) {
        return true;
      }
    }
    return false;
  }

  private static PlatformApiException invalidForegroundSource() {
    return new PlatformApiException(
        400,
        "unsupported_content_source",
        "Content fetch URI must be a CHK@, SSK@, USK@, KSK@, or crypta: content key.");
  }

  private static PlatformApiException invalidSubscriptionSource() {
    return new PlatformApiException(
        400,
        "unsupported_content_subscription_source",
        "Content subscriptions require a USK@ or crypta:USK@ source URI.");
  }

  /**
   * Normalized URI components accepted by the app-facing content fetch policy.
   *
   * <p>The record carries both the app-facing URI and the runtime fetch URI so routes can preserve
   * the caller's accepted {@code crypta:} wrapper in responses while passing the unwrapped content
   * key to runtime fetch machinery. Instances are immutable and are created only after the source
   * text has passed the policy checks in this class.
   *
   * @param requestedUri trimmed URI text that remains safe to report to the app
   * @param runtimeUri unwrapped content-key URI passed to runtime fetch code
   * @param kind recognized content-key family for routing and policy decisions
   */
  public record NormalizedContentSource(
      String requestedUri, String runtimeUri, ContentKeyKind kind) {
    /**
     * Creates normalized source metadata after policy validation has accepted the URI.
     *
     * @param requestedUri trimmed URI text that remains safe to report to the app
     * @param runtimeUri unwrapped content-key URI passed to runtime fetch code
     * @param kind recognized content-key family for routing and policy decisions
     * @throws NullPointerException when any component is {@code null}
     */
    public NormalizedContentSource {
      Objects.requireNonNull(requestedUri, "requestedUri");
      Objects.requireNonNull(runtimeUri, "runtimeUri");
      Objects.requireNonNull(kind, "kind");
    }
  }

  /**
   * Supported Crypta/Freenet content-key families for app-facing content reads.
   *
   * <p>The enum is intentionally limited to the public content-key prefixes recognized by the
   * Platform API. It records the prefix used for coarse policy classification; it does not validate
   * the cryptographic structure, routing fields, or edition semantics of a complete key.
   */
  public enum ContentKeyKind {
    /**
     * Content hash key.
     *
     * <p>{@code CHK@} values identify immutable content and are accepted for foreground bounded
     * fetches, but they are not valid durable subscription sources.
     */
    CHK("CHK@"),

    /**
     * Signed subspace key.
     *
     * <p>{@code SSK@} values are accepted for foreground reads. Subscription creation rejects them
     * because subscriptions need an updatable editioned source.
     */
    SSK("SSK@"),

    /**
     * Updatable signed key.
     *
     * <p>{@code USK@} values are accepted for foreground reads and are the only key family accepted
     * for durable content subscriptions.
     */
    USK("USK@"),

    /**
     * Keyword signed key.
     *
     * <p>{@code KSK@} values are accepted for foreground bounded reads where the app explicitly
     * requests one key, but they are not accepted as subscription sources.
     */
    KSK("KSK@");

    private final String prefix;

    ContentKeyKind(String prefix) {
      this.prefix = prefix;
    }
  }
}
