package network.crypta.runtime.spi;

import java.util.List;

/**
 * Exposes the narrow peer-management capabilities needed by management-facing protocols.
 *
 * <p>This port is intentionally limited to the current FCP peer-management family. It provides
 * detached peer snapshots, add/remove operations, darknet-only peer mutations, and access to the
 * existing private darknet comment note without exposing daemon internals such as peer classes,
 * network subsystem types, or legacy field-set transport objects to higher layers.
 *
 * <p>The port does not perform access control and does not know about request identifiers or wire
 * framing. Those concerns remain with the higher layer, which requests a snapshot or mutation
 * result here and then decides whether and how it should be serialized.
 *
 * <p>Implementations are expected to preserve the daemon's current peer-management semantics for
 * this narrow slice, including the existing distinction between unknown peers, darknet-only
 * operations, and legacy add-peer rejection reasons. The API is intentionally small, so later PRs
 * can migrate adjacent message families independently instead of collapsing everything into one
 * coarse management surface.
 */
public interface PeerPort {
  /**
   * Lists the currently known peers using the requested export flags.
   *
   * <p>The returned values are detached snapshots. Callers can serialize them immediately or pass
   * them through other protocol-specific mapping without holding references to live peer objects.
   *
   * @param includeMetadata whether peer metadata should be attached to each snapshot
   * @param includeVolatile whether volatile peer status should be attached to each snapshot
   * @return detached peer snapshots in encounter order
   */
  List<PeerSnapshot> list(boolean includeMetadata, boolean includeVolatile);

  /**
   * Resolves one peer and exports it using the requested flags.
   *
   * <p>The lookup semantics remain implementation-defined, but callers should expect the same peer
   * identifier handling that the legacy daemon path already used for management requests.
   *
   * @param nodeIdentifier peer identifier used for lookup
   * @param includeMetadata whether peer metadata should be attached to the snapshot
   * @param includeVolatile whether volatile peer status should be attached to the snapshot
   * @return detached snapshot of the resolved peer
   * @throws UnknownPeerException if the peer cannot be resolved
   */
  PeerSnapshot get(String nodeIdentifier, boolean includeMetadata, boolean includeVolatile)
      throws UnknownPeerException;

  /**
   * Adds one peer reference to the runtime using the supplied darknet defaults when applicable.
   *
   * <p>The supplied reference is already resolved and parsed at the protocol boundary. The runtime
   * adapter performs the daemon-side peer creation, self-peer detection, duplicate checks, and
   * legacy failure mapping that previously lived in the FCP message handler.
   *
   * @param reference detached peer-reference tree to add
   * @param trust darknet trust level to apply when the reference is a darknet peer
   * @param visibility darknet visibility to apply when the reference is a darknet peer
   * @return detached snapshot of the newly added peer, including metadata and volatile state
   * @throws PeerAddRejectedException if the runtime rejects the reference with a preserved legacy
   *     reason
   */
  PeerSnapshot add(PeerFieldSet reference, PeerTrust trust, PeerVisibility visibility)
      throws PeerAddRejectedException;

  /**
   * Applies one optional settings update to an existing darknet peer.
   *
   * <p>Each nullable field in {@code update} follows the legacy management rule that absent values
   * mean "leave the current setting unchanged." Implementations may therefore apply only a subset
   * of the available flags before exporting the updated peer.
   *
   * @param nodeIdentifier peer identifier used for lookup
   * @param update optional darknet settings update
   * @return detached snapshot of the updated peer, including metadata and volatile state
   * @throws UnknownPeerException if the peer cannot be resolved
   * @throws DarknetPeerRequiredException if the resolved peer is not a darknet peer
   */
  PeerSnapshot updateDarknetPeer(String nodeIdentifier, DarknetPeerSettingsUpdate update)
      throws UnknownPeerException, DarknetPeerRequiredException;

  /**
   * Applies one optional settings update to a darknet peer resolved by exact peer identity.
   *
   * <p>This method exists for detached callers that already know the selected peer's unique
   * identity string and must avoid the legacy nickname or address fallback used by {@link
   * #updateDarknetPeer(String, DarknetPeerSettingsUpdate)}.
   *
   * @param peerIdentity exact peer identity string used for lookup
   * @param update optional darknet settings update
   * @return detached snapshot of the updated peer, including metadata and volatile state
   * @throws UnknownPeerException if the peer cannot be resolved
   * @throws DarknetPeerRequiredException if the resolved peer is not a darknet peer
   */
  PeerSnapshot updateDarknetPeerByIdentity(String peerIdentity, DarknetPeerSettingsUpdate update)
      throws UnknownPeerException, DarknetPeerRequiredException;

  /**
   * Removes one peer from the runtime.
   *
   * <p>The returned snapshot contains only the removal details needed by the current peer-removal
   * response path. Callers should not expect it to preserve the full exported peer tree.
   *
   * @param nodeIdentifier peer identifier used for lookup
   * @return detached removal result describing the removed peer
   * @throws UnknownPeerException if the peer cannot be resolved
   */
  RemovedPeerSnapshot remove(String nodeIdentifier) throws UnknownPeerException;

  /**
   * Removes one peer from the runtime using an exact peer identity match.
   *
   * <p>This method exists for detached callers that already know the selected peer's unique
   * identity string and must avoid the legacy nickname or address fallback used by {@link
   * #remove(String)}.
   *
   * @param peerIdentity exact peer identity string used for lookup
   * @return detached removal result describing the removed peer
   * @throws UnknownPeerException if the peer cannot be resolved
   */
  RemovedPeerSnapshot removeByIdentity(String peerIdentity) throws UnknownPeerException;

  /**
   * Reads the existing private darknet comment note for one peer.
   *
   * <p>This method intentionally exposes only the currently supported private darknet comment note.
   * It does not attempt to model a general peer-note registry.
   *
   * @param nodeIdentifier peer identifier used for lookup
   * @return current private darknet comment note text
   * @throws UnknownPeerException if the peer cannot be resolved
   * @throws DarknetPeerRequiredException if the resolved peer is not a darknet peer
   */
  String readPrivateDarknetComment(String nodeIdentifier)
      throws UnknownPeerException, DarknetPeerRequiredException;

  /**
   * Writes the private darknet comment note for one peer and returns the stored text.
   *
   * <p>Implementations should return the stored note text after applying the update so callers can
   * emit a detached response without re-reading daemon state through other APIs.
   *
   * @param nodeIdentifier peer identifier used for lookup
   * @param noteText note text to store
   * @return stored private darknet comment note text
   * @throws UnknownPeerException if the peer cannot be resolved
   * @throws DarknetPeerRequiredException if the resolved peer is not a darknet peer
   */
  String writePrivateDarknetComment(String nodeIdentifier, String noteText)
      throws UnknownPeerException, DarknetPeerRequiredException;

  /**
   * Writes the private darknet comment note for one peer resolved by exact peer identity.
   *
   * <p>This method exists for detached callers that already know the selected peer's unique
   * identity string and must avoid the legacy nickname or address fallback used by {@link
   * #writePrivateDarknetComment(String, String)}.
   *
   * @param peerIdentity exact peer identity string used for lookup
   * @param noteText note text to store
   * @return stored private darknet comment note text
   * @throws UnknownPeerException if the peer cannot be resolved
   * @throws DarknetPeerRequiredException if the resolved peer is not a darknet peer
   */
  String writePrivateDarknetCommentByIdentity(String peerIdentity, String noteText)
      throws UnknownPeerException, DarknetPeerRequiredException;
}
