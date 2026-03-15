package network.crypta.runtime.spi;

/**
 * Selects the trust level assigned to a newly added darknet peer.
 *
 * <p>This enum mirrors the current legacy darknet trust choices while keeping the runtime SPI free
 * of daemon-only enums. Callers are expected to map protocol or UI inputs onto these values before
 * invoking {@link PeerPort#add(PeerFieldSet, PeerTrust, PeerVisibility)}.
 */
public enum PeerTrust {
  /** Assigns the most restrictive trust level supported by the current legacy darknet logic. */
  LOW,

  /** Assigns the default trust level used for ordinary darknet peer relationships. */
  NORMAL,

  /** Assigns the least restrictive trust level supported by the current legacy darknet logic. */
  HIGH
}
