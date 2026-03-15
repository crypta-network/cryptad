package network.crypta.runtime.spi;

/**
 * Categorizes the legacy add-peer failure reasons preserved by the peer-management SPI.
 *
 * <p>The values in this enum let the daemon-side adapter keep the current peer-add behavior while
 * returning a JDK-only error surface to higher layers. Management code can map these reasons back
 * to existing protocol errors without inspecting daemon exceptions or peer internals.
 */
public enum PeerAddFailureReason {
  /** The supplied peer reference could not be parsed into a usable legacy peer definition. */
  REF_PARSE_ERROR,

  /** The reference targets opennet peering, but opennet support is disabled in the runtime. */
  OPENNET_DISABLED,

  /** The reference failed signature verification during legacy peer creation. */
  REF_SIGNATURE_INVALID,

  /** The supplied reference resolved to the local node and cannot be added as a remote peer. */
  CANNOT_PEER_WITH_SELF,

  /** A peer with the same identity is already present, so the new reference is rejected. */
  DUPLICATE_PEER_REF
}
