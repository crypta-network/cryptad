package network.crypta.runtime.spi;

import java.util.List;
import java.util.Objects;

/**
 * Detached snapshot containing the current alert list.
 *
 * <p>This record packages the full ordered alert feed for one read operation. The structure stays
 * intentionally small because callers can derive counts, empty-state decisions, and display order
 * directly from the list itself. No additional metadata is required to preserve the current alert
 * semantics across the detached boundary.
 *
 * <p>The list order is significant. Implementations should preserve the runtime-defined encounter
 * order so consumers can render alerts consistently with other operator-facing surfaces. The record
 * also makes a defensive copy of the incoming list, which means callers can safely hold the
 * snapshot after the originating collection is mutated or discarded.
 *
 * @param alerts ordered detached alert snapshots
 */
public record AlertListSnapshot(List<AlertSnapshot> alerts) {
  /**
   * Creates one detached alert-list snapshot.
   *
   * <p>The compact constructor copies the supplied list into an unmodifiable list so later
   * mutations to the source collection do not affect the snapshot.
   *
   * @throws NullPointerException if {@code alerts} is {@code null}
   */
  public AlertListSnapshot {
    alerts = List.copyOf(Objects.requireNonNull(alerts, "alerts"));
  }
}
