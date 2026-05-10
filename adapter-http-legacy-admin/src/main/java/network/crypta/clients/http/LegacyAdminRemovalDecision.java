package network.crypta.clients.http;

import java.util.Objects;

/**
 * One request-level removal decision for a known legacy admin surface.
 *
 * <p>The dispatcher creates this value after {@link LegacyAdminRemovalPolicy} has matched a
 * canonical removed-by-default legacy route and verified that the replacement is usable for the
 * current request. The record is intentionally small: it contains the stable registry surface, the
 * HTTP status line to send, the same-origin replacement URL, and the bounded diagnostic event to
 * count. It never keeps caller-specific request data.
 *
 * <p>Instances are immutable and safe to pass between the dispatch gate, response writer, and
 * diagnostics recorder. The compact constructor validates the response shape rather than
 * re-evaluating route policy, so callers should construct decisions through the static factories
 * below. Those factories encode the current wave semantics:
 *
 * <ul>
 *   <li>safe reads either redirect to or describe the replacement;
 *   <li>mutating requests are blocked before the legacy handler can run;
 *   <li>all replacement URLs remain local same-origin paths.
 * </ul>
 *
 * @param surface registry surface that matched the request path
 * @param mode execution mode that caused this decision
 * @param statusCode HTTP status to return
 * @param reason HTTP reason phrase paired with {@code statusCode}
 * @param replacementUrl same-origin replacement route
 * @param redirect whether the response should include a {@code Location} header
 * @param usageEvent diagnostic event to record for the decision
 */
record LegacyAdminRemovalDecision(
    LegacyAdminSurface surface,
    LegacyAdminRemovalMode mode,
    int statusCode,
    String reason,
    String replacementUrl,
    boolean redirect,
    LegacyAdminUsageEvent usageEvent) {
  /**
   * Creates and validates one immutable removal decision.
   *
   * <p>The compact constructor enforces the small safety boundary that every caller depends on:
   * status codes must be valid HTTP status values, text fields must be nonblank, replacement URLs
   * must stay same-origin, and diagnostic events must be explicit. It does not inspect request
   * state or re-run route matching.
   */
  LegacyAdminRemovalDecision {
    Objects.requireNonNull(surface, "surface");
    Objects.requireNonNull(mode, "mode");
    requireStatus(statusCode);
    requireText(reason, "reason");
    requireReplacementUrl(replacementUrl);
    Objects.requireNonNull(usageEvent, "usageEvent");
  }

  /**
   * Builds a safe-read decision that redirects to the replacement route.
   *
   * <p>The method is used for surfaces in {@link LegacyAdminRemovalMode#REDIRECT_TO_REPLACEMENT}.
   * It emits a {@code 303 See Other} decision so old bookmarks and slashless canonical aliases move
   * to the app or Web Shell URL without replaying request bodies. Diagnostics record the event as a
   * replacement response, not as a rendered legacy fallback.
   *
   * @param surface removed-by-default surface with a same-origin replacement URL
   * @return immutable decision describing the redirect response to emit
   */
  static LegacyAdminRemovalDecision redirect(LegacyAdminSurface surface) {
    return new LegacyAdminRemovalDecision(
        surface,
        LegacyAdminRemovalMode.REDIRECT_TO_REPLACEMENT,
        303,
        "See Other",
        surface.replacementUrl(),
        true,
        LegacyAdminUsageEvent.REPLACEMENT_RESPONSE);
  }

  /**
   * Builds a safe-read decision that returns a gone-with-replacement page.
   *
   * <p>This shape is reserved for routes where a redirect is not the right operator experience but
   * the old page should still stop rendering by default. The response writer will send a compact
   * {@code 410 Gone} HTML page that contains only the registry title and replacement link.
   *
   * @param surface removed-by-default surface with a same-origin replacement URL
   * @return immutable decision describing the gone-with-replacement response to emit
   */
  static LegacyAdminRemovalDecision gone(LegacyAdminSurface surface) {
    return new LegacyAdminRemovalDecision(
        surface,
        LegacyAdminRemovalMode.GONE_WITH_REPLACEMENT,
        410,
        "Gone",
        surface.replacementUrl(),
        false,
        LegacyAdminUsageEvent.REPLACEMENT_RESPONSE);
  }

  /**
   * Builds a mutating-request decision that blocks legacy handler execution.
   *
   * <p>When the current removal wave applies, non-read methods must not fall through to old queue,
   * insert, peer, or connectivity mutations. This decision preserves the surface's configured
   * removal mode for diagnostics while using a {@code 410 Gone} response and a distinct event
   * counter for blocked mutations.
   *
   * @param surface removed-by-default surface whose legacy action must not execute
   * @return immutable decision describing the blocked mutating request response
   */
  static LegacyAdminRemovalDecision blockedMutation(LegacyAdminSurface surface) {
    return new LegacyAdminRemovalDecision(
        surface,
        surface.removalMode(),
        410,
        "Gone",
        surface.replacementUrl(),
        false,
        LegacyAdminUsageEvent.BLOCKED_MUTATING_REQUEST);
  }

  /**
   * Validates that the supplied integer fits the HTTP status-code range.
   *
   * @param statusCode numeric response status that will be written to the HTTP response line
   */
  private static void requireStatus(int statusCode) {
    if (statusCode < 100 || statusCode > 599) {
      throw new IllegalArgumentException("statusCode must be an HTTP status");
    }
  }

  /**
   * Validates required text used in the status line or diagnostic metadata.
   *
   * @param value candidate text value that must be present and nonblank
   * @param label field label used in exception messages for invalid input
   */
  private static void requireText(String value, String label) {
    Objects.requireNonNull(value, label);
    if (value.isBlank()) {
      throw new IllegalArgumentException(label + " must not be blank");
    }
  }

  /**
   * Validates a replacement URL before it reaches a response header or HTML body.
   *
   * <p>Removal decisions only carry registry-provided replacement routes, and those routes must
   * remain same-origin absolute paths. Keeping the field name local to this helper makes the
   * invariant clear without forcing callers to repeat a label that cannot vary for this record.
   *
   * @param value candidate local replacement route that must start with one slash and not two
   */
  private static void requireReplacementUrl(String value) {
    requireText(value, "replacementUrl");
    if (!value.startsWith("/") || value.startsWith("//")) {
      throw new IllegalArgumentException("replacementUrl must be a same-origin absolute path");
    }
  }
}
