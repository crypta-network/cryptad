package network.crypta.runtime.spi;

/**
 * Exposes the narrow connectivity-read capabilities needed by the HTTP admin page.
 *
 * <p>This port is intentionally scoped to the connectivity toadlet and nothing more. It returns a
 * detached snapshot containing listener-port configuration, UDP socket summary status, the current
 * connection-type notice when active, and optional advanced per-peer or per-IP tracker details. The
 * contract keeps daemon internals such as {@code Node}, {@code AddressTracker}, UDP socket
 * handlers, and alert-framework classes on the daemon side of the boundary.
 *
 * <p>Implementations should remain read-only. Callers are expected to request one snapshot per HTTP
 * response and render from that immutable view instead of reaching back into live daemon objects.
 */
public interface ConnectivityPort {
  /**
   * Returns a point-in-time snapshot of the node's connectivity state.
   *
   * <p>The {@code includeAdvancedDetails} flag preserves the current cost boundary used by the HTTP
   * page: callers that only need the summary view can skip the tracker-table export, while callers
   * in advanced mode can request the additional per-peer and per-IP rows.
   *
   * @param includeAdvancedDetails whether advanced tracker-table details should be included in the
   *     returned snapshot
   * @return detached connectivity snapshot describing the current runtime state at call time
   */
  ConnectivitySnapshot snapshot(boolean includeAdvancedDetails);
}
