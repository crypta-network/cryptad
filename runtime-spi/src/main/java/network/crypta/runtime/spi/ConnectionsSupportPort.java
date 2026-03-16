package network.crypta.runtime.spi;

import java.io.IOException;

/**
 * Exposes the narrow legacy connections-page support capability still needed by the HTTP layer.
 *
 * <p>This port is intentionally transitional and page-oriented. The legacy friends and strangers
 * pages still need one feature-flag check and one file-backed noderef import source, but those
 * concerns do not justify widening broader runtime SPI surfaces such as {@link ConnectionsPagePort}
 * or {@link NodeInfoPort}. Implementations may delegate to live daemon state internally while
 * exposing only JDK-only types here.
 *
 * <p>The port is not a general node API. It exists only to finish removing direct daemon-root
 * dependencies from the legacy connections-family HTTP toadlets.
 */
public interface ConnectionsSupportPort {
  /**
   * Returns whether opennet support is currently enabled.
   *
   * <p>Callers use this to decide whether to expose or route the legacy strangers page without
   * depending on daemon-local network objects.
   *
   * @return {@code true} when opennet is enabled in the live runtime
   */
  boolean isOpennetEnabled();

  /**
   * Reads and concatenates peer-offer reference text for legacy add-peer import.
   *
   * <p>The returned text should preserve the current legacy behavior of scanning the node's
   * peer-offer directory, reading matching reference files as UTF-8 text, and concatenating their
   * contents in encountered iteration order.
   *
   * @return concatenated peer-offer noderef text, or an empty string when no matching files exist
   * @throws IOException on I/O failure while reading the peer-offer reference files
   */
  String readPeerOfferReferencesText() throws IOException;
}
