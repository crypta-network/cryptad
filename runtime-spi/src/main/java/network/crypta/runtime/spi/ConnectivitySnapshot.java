package network.crypta.runtime.spi;

import java.util.List;
import java.util.Objects;

/**
 * Detached snapshot of the data needed to render the connectivity admin page.
 *
 * <p>This record is the main payload returned by {@link ConnectivityPort}. It combines the small
 * set of listener-port details shown near the top of the page with per-socket UDP reachability
 * information and, when available, the current connection-type notice. Advanced tracker-table
 * details are nested under each socket snapshot, so the caller can request summary-only or
 * full-detail views without changing the overall shape of the response.
 *
 * <p>The record is immutable. Collection components are defensively copied, so callers can keep the
 * snapshot for the lifetime of a request without worrying about concurrent daemon mutations.
 *
 * @param darknetFnpPort configured darknet FNP port exposed by the node
 * @param opennetFnpPort configured opennet FNP port, or a non-positive value when opennet is
 *     disabled
 * @param fproxyListener detached snapshot of the current FProxy listener configuration
 * @param fcpListener detached snapshot of the current FCP listener configuration
 * @param consoleListener detached snapshot of the current TMCI listener configuration
 * @param connectionTypeNotice optional detached connection-type notice, or {@code null} when no
 *     notice is active
 * @param sockets detached UDP socket snapshots in encounter order for page rendering
 */
public record ConnectivitySnapshot(
    int darknetFnpPort,
    int opennetFnpPort,
    ConnectivityListenerPortSnapshot fproxyListener,
    ConnectivityListenerPortSnapshot fcpListener,
    ConnectivityListenerPortSnapshot consoleListener,
    ConnectivityNoticeSnapshot connectionTypeNotice,
    List<ConnectivitySocketSnapshot> sockets) {
  /**
   * Creates an immutable connectivity snapshot.
   *
   * <p>The constructor copies the socket list defensively. The optional connection-type notice may
   * be absent, but every other component must be present.
   *
   * @throws NullPointerException if any required component except {@code connectionTypeNotice} is
   *     {@code null}
   */
  public ConnectivitySnapshot {
    Objects.requireNonNull(fproxyListener, "fproxyListener");
    Objects.requireNonNull(fcpListener, "fcpListener");
    Objects.requireNonNull(consoleListener, "consoleListener");
    Objects.requireNonNull(sockets, "sockets");
    sockets = List.copyOf(sockets);
  }
}
