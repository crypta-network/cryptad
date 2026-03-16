package network.crypta.runtime.spi;

import java.util.Objects;

/**
 * Represents one detached peer entry used by the legacy darknet friends-page actions.
 *
 * <p>This snapshot intentionally preserves the current hash-based selection token used by the
 * legacy HTML form fields, but it keeps that token-specific concern isolated to the friends-page
 * companion SPI rather than widening the generic peer-management API. Callers receive the detached
 * identity and display data needed to map the submitted checkbox and note field names back to the
 * selected peer.
 *
 * <p>Instances are immutable and detached from the live daemon state. The HTTP layer can therefore
 * keep them only for the duration of one render or form submission without holding a reference to a
 * live {@code DarknetPeerNode}. The snapshot carries only the data the legacy friends page still
 * needs in this migration stage: the current selection token, the peer identity used for exact
 * updates, the display name shown in the UI, the private note text needed to preserve the old
 * "write only when changed" behavior, and the detached remove-policy decision used by the legacy
 * confirmation flow.
 *
 * @param selectionToken legacy hash-based token used in friends-page form field names
 * @param nodeIdentifier detached peer identity string suitable for exact-identity friends-page
 *     updates and removal through {@link PeerPort}
 * @param displayName detached friend display name used in the legacy UI and downloads
 * @param privateNoteText detached private darknet comment note currently shown on the page
 * @param removableWithoutForce whether the legacy friends page may remove this peer immediately
 *     without rendering the force-remove confirmation form
 * @see DarknetConnectionsPort
 */
public record DarknetConnectionPeerSnapshot(
    int selectionToken,
    String nodeIdentifier,
    String displayName,
    String privateNoteText,
    boolean removableWithoutForce) {
  /**
   * Creates an immutable friends-page peer snapshot.
   *
   * <p>The constructor rejects {@code null} string fields so callers can treat each component as a
   * ready-to-render value without repeating null checks in the HTTP layer.
   *
   * @throws NullPointerException if any detached string field is {@code null}
   */
  public DarknetConnectionPeerSnapshot {
    Objects.requireNonNull(nodeIdentifier, "nodeIdentifier");
    Objects.requireNonNull(displayName, "displayName");
    Objects.requireNonNull(privateNoteText, "privateNoteText");
  }
}
