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
 * @param count number of observed visits since process start
 * @param lastSeenEpochMillis last observed visit timestamp in epoch milliseconds, or {@code 0} when
 *     no visit has been recorded
 */
public record LegacyAdminSurfaceUsage(
    String surfaceId,
    String title,
    String legacyPath,
    String state,
    String replacementUrl,
    long count,
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
    if (count < 0) {
      throw new IllegalArgumentException("count must not be negative");
    }
    if (lastSeenEpochMillis < 0) {
      throw new IllegalArgumentException("lastSeenEpochMillis must not be negative");
    }
  }
}
