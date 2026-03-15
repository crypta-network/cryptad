package network.crypta.runtime.spi;

/**
 * Identifies which legacy connections page the runtime adapter should render.
 *
 * <p>The current legacy admin UI still exposes two distinct peer-list pages with different table
 * columns and action capabilities: the darknet friends page and the opennet strangers page. This
 * enum keeps that choice explicit while remaining detached from daemon-only peer or HTTP classes.
 */
public enum ConnectionsPageKind {
  /** Renders the legacy darknet friends page. */
  DARKNET,

  /** Renders the legacy opennet strangers page. */
  OPENNET
}
