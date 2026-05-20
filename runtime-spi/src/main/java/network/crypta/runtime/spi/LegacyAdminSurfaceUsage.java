package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Detached usage counter for one legacy admin HTTP surface.
 *
 * <p>The record intentionally carries only route-level metadata. It does not include query strings,
 * form fields, request bodies, Freenet/Crypta URIs, peer references, filesystem paths, or remote
 * addresses. Platform API diagnostics can therefore expose this value without leaking sensitive
 * request details from the legacy HTTP adapter.
 *
 * <p>The type lives in {@code runtime-spi} so transport-neutral diagnostics code can receive legacy
 * admin usage data without importing HTTP toadlets or adapter classes. The {@code state} value is a
 * string rather than an adapter enum for the same reason: higher layers display or serialize the
 * current state, but they do not own the retirement policy.
 *
 * <p>Counts are process-local and monotonic for one node process. A {@code lastSeenEpochMillis}
 * value of {@code 0} means the surface is known but has not been observed in the current process
 * window. Consumers should treat the values as deletion-planning telemetry, not a durable audit
 * trail.
 *
 * @param surfaceId stable identifier assigned by the legacy-admin retirement registry
 * @param title user-facing page or surface title suitable for diagnostics output
 * @param legacyPath canonical same-origin legacy route prefix without request parameters
 * @param state retirement state name assigned to the surface by the HTTP adapter
 * @param replacementUrl same-origin replacement Web Shell or app URL, or {@code null} when none is
 *     declared
 * @param removalMode current execution/removal mode assigned by the HTTP adapter
 * @param removalWave first removal wave number, or {@code 0} when the surface is not removed by
 *     default
 * @param removedByDefaultSince stable release/phase marker, or {@code null} when not removed by
 *     default
 * @param fallbackPolicy path-free description of temporary fallback behavior
 * @param removalScope bounded route-scope enum name used by the removal gate
 * @param scopeExpandedInWave removal wave that expanded matching beyond canonical aliases, or
 *     {@code 0} when no later wave expanded the scope
 * @param count number of observed visits since process start
 * @param replacementResponseCount number of redirect or gone-with-replacement responses since
 *     process start
 * @param blockedMutatingRequestCount number of removed legacy mutating requests blocked before old
 *     behavior could execute
 * @param fallbackRenderCount number of temporary legacy fallback renderings since process start
 * @param retainedOrPendingRenderCount number of retained or pending legacy responses since process
 *     start
 * @param lastSeenEpochMillis last observed visit timestamp in epoch milliseconds, or {@code 0} when
 *     no visit has been recorded
 */
public record LegacyAdminSurfaceUsage(
    String surfaceId,
    String title,
    String legacyPath,
    String state,
    String replacementUrl,
    String removalMode,
    int removalWave,
    String removedByDefaultSince,
    String fallbackPolicy,
    String removalScope,
    int scopeExpandedInWave,
    long count,
    long replacementResponseCount,
    long blockedMutatingRequestCount,
    long fallbackRenderCount,
    long retainedOrPendingRenderCount,
    long lastSeenEpochMillis) {
  /**
   * Creates an immutable legacy-admin usage entry.
   *
   * <p>The constructor validates only structural invariants that are meaningful outside the legacy
   * HTTP adapter. Required text fields must be present, while {@code replacementUrl} may be {@code
   * null} for retained, pending, or infrastructure-like entries. Counts and timestamps cannot be
   * negative because diagnostics clients treat them as unsigned process counters.
   *
   * @throws NullPointerException if any required text field is {@code null}
   * @throws IllegalArgumentException if a count or timestamp is negative
   */
  public LegacyAdminSurfaceUsage {
    Objects.requireNonNull(surfaceId, "surfaceId");
    Objects.requireNonNull(title, "title");
    Objects.requireNonNull(legacyPath, "legacyPath");
    Objects.requireNonNull(state, "state");
    Objects.requireNonNull(removalMode, "removalMode");
    Objects.requireNonNull(fallbackPolicy, "fallbackPolicy");
    Objects.requireNonNull(removalScope, "removalScope");
    if (removedByDefaultSince != null && removedByDefaultSince.isBlank()) {
      throw new IllegalArgumentException("removedByDefaultSince must not be blank");
    }
    if (fallbackPolicy.isBlank()) {
      throw new IllegalArgumentException("fallbackPolicy must not be blank");
    }
    if (removalWave < 0) {
      throw new IllegalArgumentException("removalWave must not be negative");
    }
    if (removalScope.isBlank()) {
      throw new IllegalArgumentException("removalScope must not be blank");
    }
    if (scopeExpandedInWave < 0) {
      throw new IllegalArgumentException("scopeExpandedInWave must not be negative");
    }
    if (count < 0) {
      throw new IllegalArgumentException("count must not be negative");
    }
    if (replacementResponseCount < 0) {
      throw new IllegalArgumentException("replacementResponseCount must not be negative");
    }
    if (blockedMutatingRequestCount < 0) {
      throw new IllegalArgumentException("blockedMutatingRequestCount must not be negative");
    }
    if (fallbackRenderCount < 0) {
      throw new IllegalArgumentException("fallbackRenderCount must not be negative");
    }
    if (retainedOrPendingRenderCount < 0) {
      throw new IllegalArgumentException("retainedOrPendingRenderCount must not be negative");
    }
    if (lastSeenEpochMillis < 0) {
      throw new IllegalArgumentException("lastSeenEpochMillis must not be negative");
    }
  }
}
