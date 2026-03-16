package network.crypta.runtime.spi;

import java.util.List;
import java.util.Optional;

/**
 * Exposes the narrow legacy darknet friends-page companion capability.
 *
 * <p>This port exists specifically to support the remaining legacy friends-page POST actions and
 * per-peer noderef download path while keeping the current hash-based selection-token scheme out of
 * the generic {@link PeerPort}. It provides detached peer identity, display-name, and private-note
 * data for the current page selection model plus one optional full noderef export for a selected
 * peer.
 *
 * <p>The port is intentionally conservative and page-oriented. It does not attempt to model all
 * darknet peer behavior, and it does not expose live daemon peer objects or field-set transport
 * types to the HTTP layer. Typical callers render the friends page, map submitted checkbox names
 * back to the selected peers, and then route any non-destructive updates through {@link PeerPort}
 * using the exact identity carried by each detached snapshot. That keeps the legacy selection-token
 * behavior local to this bridge instead of turning it into a generic peer-management concern.
 */
public interface DarknetConnectionsPort {
  /**
   * Lists the current darknet peers in encounter order for the legacy friends page.
   *
   * <p>The returned snapshots preserve the existing selection-token semantics used by the legacy
   * HTML form field names while also carrying the detached runtime peer identifier needed for later
   * mutation through {@link PeerPort}. Implementations should return a fresh detached view for each
   * call so the HTTP layer can compare form values against the page state it just rendered.
   *
   * @return detached friends-page peer snapshots in encounter order
   */
  List<DarknetConnectionPeerSnapshot> listPeers();

  /**
   * Exports one full noderef for the peer identified by the supplied legacy selection token.
   *
   * <p>The selection token follows the current hash-based friends-page scheme. Implementations
   * should preserve the existing encounter-order resolution behavior and return {@link
   * Optional#empty()} when no matching peer exists or when the peer has no full noderef export.
   * Callers should treat an empty result as a normal miss rather than as an exceptional condition,
   * because the legacy page already tolerates peers disappearing between render and download.
   *
   * @param selectionToken legacy hash-based friends-page peer token
   * @return optional detached noderef export for the selected peer
   */
  Optional<NodeReferenceSnapshot> exportPeerReference(int selectionToken);
}
