package network.crypta.runtime.spi;

/**
 * Selects the visibility assigned to a newly added darknet peer.
 *
 * <p>This enum mirrors the current legacy darknet visibility choices while keeping the runtime SPI
 * free of daemon-only enums. The values intentionally match the existing wire-level semantics used
 * by the daemon.
 */
public enum PeerVisibility {
  /** Exposes both the peer relationship and the peer name where the legacy daemon allows it. */
  YES,

  /** Exposes only the peer name while withholding fuller visibility in legacy exports. */
  NAME_ONLY,

  /** Applies the most private visibility mode supported by the current legacy daemon behavior. */
  NO
}
