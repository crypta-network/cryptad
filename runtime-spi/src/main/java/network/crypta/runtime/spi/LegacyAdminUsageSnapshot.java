package network.crypta.runtime.spi;

import java.util.List;
import java.util.Objects;

/**
 * Detached process-local usage snapshot for legacy admin HTTP surfaces.
 *
 * <p>The snapshot is bounded by the legacy-admin retirement registry. It is not a request log and
 * does not persist across process restarts. Consumers should use it to identify which fallback
 * surfaces are still being exercised before planning later deletion work.
 *
 * <p>The ordered list is already detached from the recorder that produced it. Callers can serialize
 * the snapshot or compare it in tests without coordinating with request threads that may continue
 * to record new observations. Entries usually include zero-count surfaces so diagnostics can show
 * the complete retirement map, not only the surfaces that have been used since startup.
 *
 * <p>This record does not define the registry or recording policy. It is a transport-neutral value
 * object for Platform API handlers and other diagnostics consumers that need a stable, immutable
 * view of the current process window.
 *
 * @param surfaces ordered usage entries for known legacy admin surfaces, copied on construction
 */
public record LegacyAdminUsageSnapshot(List<LegacyAdminSurfaceUsage> surfaces) {
  /**
   * Creates an immutable usage snapshot.
   *
   * <p>The constructor defensively copies the supplied list. Mutating the source list after
   * construction does not affect the snapshot, and the accessor returns an unmodifiable list.
   *
   * @throws NullPointerException if {@code surfaces} is {@code null}
   */
  public LegacyAdminUsageSnapshot {
    Objects.requireNonNull(surfaces, "surfaces");
    surfaces = List.copyOf(surfaces);
  }
}
