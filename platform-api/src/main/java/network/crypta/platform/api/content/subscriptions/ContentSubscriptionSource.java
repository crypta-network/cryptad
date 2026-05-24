package network.crypta.platform.api.content.subscriptions;

import network.crypta.platform.api.PlatformApiException;

/**
 * Normalized source metadata for a background content subscription.
 *
 * <p>Background subscriptions intentionally accept a narrower source set than foreground content
 * fetches. The parser accepts only public {@code USK@...} values and {@code crypta:USK@...} values,
 * rejects query strings, fragments, whitespace, multiline text, local paths, and unrelated schemes,
 * and produces the runtime fetch URI that the scheduler passes to the detached content fetch port.
 * The original app-facing source string is preserved only after it has passed those checks.
 *
 * <p>This record is not a general URI parser. It encodes the PR-239 subscription rules so the API
 * handler, durable record constructor, and scheduler recovery path all apply the same validation
 * and redaction behavior.
 *
 * @param sourceUri normalized app-facing public source URI
 * @param runtimeFetchUri normalized USK URI used for detached runtime fetches
 */
public record ContentSubscriptionSource(String sourceUri, String runtimeFetchUri) {
  private static final String CRYPTA_SCHEME_PREFIX = "crypta:";
  private static final String USK_PREFIX = "USK@";

  /**
   * Normalizes an app-supplied source URI for durable subscription state.
   *
   * <p>The returned record keeps the app-visible source URI and the runtime fetch URI separate.
   * This lets summaries show the app-owned public source while scheduler code avoids passing the
   * {@code crypta:} wrapper to lower-level fetch machinery. Invalid input fails with the stable API
   * error code used by subscription creation.
   *
   * @param rawUri app-supplied candidate source URI from form parameters or storage
   * @return normalized source metadata accepted for background polling
   * @throws PlatformApiException if the URI is blank, unsafe, or not a USK source
   */
  static ContentSubscriptionSource normalizeSourceUri(String rawUri) {
    if (rawUri == null) {
      throw invalidSource();
    }
    if (rawUri.indexOf('\n') >= 0 || rawUri.indexOf('\r') >= 0 || rawUri.indexOf('\u0000') >= 0) {
      throw invalidSource();
    }
    String sourceUri = rawUri.trim();
    if (sourceUri.isEmpty()
        || containsWhitespace(sourceUri)
        || sourceUri.indexOf('?') >= 0
        || sourceUri.indexOf('#') >= 0) {
      throw invalidSource();
    }
    String runtimeUri = runtimeFetchUri(sourceUri);
    if (runtimeUri.startsWith("/")
        || runtimeUri.startsWith("\\")
        || hasDisallowedScheme(runtimeUri)
        || !startsWithUsk(runtimeUri)) {
      throw invalidSource();
    }
    return new ContentSubscriptionSource(sourceUri, runtimeUri);
  }

  /**
   * Sanitizes a resolved URI before storing or returning it.
   *
   * <p>Detached fetches may report resolved URIs that were not originally supplied by the app. This
   * method reuses subscription source validation and returns {@code null} instead of propagating
   * unsafe or unsupported values into durable metadata, logs, release evidence, or API summaries.
   *
   * @param value resolved URI candidate reported by the runtime
   * @return normalized public source URI, or {@code null} when the value is absent or unsafe
   */
  static String sanitizeResolvedUri(String value) {
    if (value == null || value.isBlank()) {
      return null;
    }
    try {
      return normalizeSourceUri(value).sourceUri();
    } catch (PlatformApiException _) {
      return null;
    }
  }

  /**
   * Extracts the resolved edition number from a sanitized USK URI.
   *
   * <p>The scheduler uses this value as safe metadata for app summaries and deduplication. If the
   * runtime omits a resolved URI, reports a non-USK value, or returns an edition segment that is
   * not numeric, the method returns {@code null} and leaves digest-based dedupe as the remaining
   * signal.
   *
   * @param value resolved URI candidate reported by the runtime
   * @return parsed USK edition number, or {@code null} when no safe edition is available
   */
  static Long resolvedUskEdition(String value) {
    String sanitized = sanitizeResolvedUri(value);
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

  private static String runtimeFetchUri(String requestedUri) {
    if (requestedUri.regionMatches(
        true, 0, CRYPTA_SCHEME_PREFIX, 0, CRYPTA_SCHEME_PREFIX.length())) {
      return requestedUri.substring(CRYPTA_SCHEME_PREFIX.length()).trim();
    }
    return requestedUri;
  }

  private static boolean hasDisallowedScheme(String uri) {
    int colon = uri.indexOf(':');
    int at = uri.indexOf('@');
    return colon >= 0 && (at < 0 || colon < at);
  }

  private static boolean startsWithUsk(String uri) {
    return uri.regionMatches(true, 0, USK_PREFIX, 0, USK_PREFIX.length());
  }

  private static boolean containsWhitespace(String value) {
    for (int index = 0; index < value.length(); index++) {
      if (Character.isWhitespace(value.charAt(index))) {
        return true;
      }
    }
    return false;
  }

  private static PlatformApiException invalidSource() {
    return new PlatformApiException(
        400,
        "unsupported_content_subscription_source",
        "Content subscriptions require a USK@ or crypta:USK@ source URI.");
  }
}
