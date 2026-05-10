package network.crypta.clients.http;

/**
 * Bounded diagnostic event classes for legacy admin route observations.
 *
 * <p>The values describe how a known legacy surface was handled without storing request-specific
 * data. They intentionally avoid method names, query strings, form values, peer references, URIs,
 * file paths, remote addresses, and request bodies.
 *
 * <p>{@link LegacyAdminUsageRecorder} converts these events into aggregate counters exposed through
 * Platform API diagnostics. The enum is not an audit log and is not intended to reconstruct
 * individual requests. Its purpose is to let operators and release certification distinguish
 * between four broad outcomes: an old page still rendered, a primary-replaced fallback rendered, a
 * replacement response was sent, or a mutating legacy request was blocked before old behavior could
 * run.
 *
 * <p>All values are process-local observations. Counts reset when the node restarts, and the
 * recorder keeps only stable surface ids plus the latest observation timestamp.
 */
enum LegacyAdminUsageEvent {
  /**
   * A legacy toadlet rendered a response for the mapped route.
   *
   * <p>This generic event is used for mapped legacy surfaces that are neither primary-replaced
   * fallback pages nor retained/pending pages with their own aggregate bucket.
   */
  RENDERED_LEGACY,

  /**
   * A primary-replaced route still rendered as direct legacy fallback.
   *
   * <p>Replacement-unavailable wave-1 requests and later-wave primary-replaced pages use this event
   * when the old handler legitimately renders. The counter helps decide whether a fallback is still
   * in active use before a later removal wave tightens behavior.
   */
  FALLBACK_RENDERED,

  /**
   * A retained or pending route rendered unchanged.
   *
   * <p>This event separates intentional legacy usage from fallback usage. Browse-adjacent retained
   * routes and pending setup or message flows can remain visible in diagnostics without looking
   * like removal-wave regressions.
   */
  RETAINED_OR_PENDING_RENDERED,

  /**
   * The removal gate returned a redirect or gone-with-replacement response.
   *
   * <p>The old toadlet did not render. The request reached a removed-by-default canonical page and
   * received a replacement response because the target replacement was available for that request.
   */
  REPLACEMENT_RESPONSE,

  /**
   * The removal gate blocked a mutating legacy request before invoking old behavior.
   *
   * <p>This event is intentionally distinct from replacement read responses so diagnostics can show
   * whether old POST, PUT, DELETE, PATCH, or similar entry points are still being exercised after a
   * surface enters a removal wave.
   */
  BLOCKED_MUTATING_REQUEST
}
