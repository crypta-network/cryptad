package network.crypta.runtime.spi;

import java.io.IOException;

/**
 * Exposes the narrow legacy connections-page support capability still needed by the HTTP layer.
 *
 * <p>This port is intentionally transitional and page-oriented. The legacy friends and strangers
 * pages still need a small set of support helpers that do not justify widening broader runtime SPI
 * surfaces such as {@link ConnectionsPagePort} or {@link NodeInfoPort}: installer download metadata
 * for the add-friend page, one feature-flag check, one file-backed noderef import source, and one
 * URL/Freenet-URI noderef loading helper. Implementations may delegate to live daemon state
 * internally while exposing only JDK-only types here.
 *
 * <p>The port is not a general node API. It exists only to finish removing direct daemon-root
 * dependencies from the legacy connections-family HTTP toadlets.
 */
public interface ConnectionsSupportPort {
  /**
   * Returns the detached metadata for the Windows installer offered by the add-friend page.
   *
   * <p>The returned snapshot must preserve the current legacy semantics: when the local file is
   * present, callers can stream it directly from the add-friend endpoint; otherwise they can build
   * the fallback link from {@code "/" + sourceUriText}.
   *
   * @return current Windows installer snapshot for add-friend download handling
   */
  ConnectionsInstallerSnapshot windowsInstaller();

  /**
   * Returns the detached metadata for the non-Windows installer offered by the add-friend page.
   *
   * <p>The returned snapshot must preserve the current legacy semantics: when the local file is
   * present, callers can stream it directly from the add-friend endpoint; otherwise they can build
   * the fallback link from {@code "/" + sourceUriText}.
   *
   * @return current non-Windows installer snapshot for add-friend download handling
   */
  ConnectionsInstallerSnapshot nonWindowsInstaller();

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

  /**
   * Reads peer-reference text from a URL or Freenet URI source for legacy add-peer import.
   *
   * <p>The supplied location text may be a Freenet URI or a regular URL. Implementations should
   * preserve the historical URI-first then URL-fallback loading behavior while keeping the exposed
   * API JDK-only.
   *
   * @param locationText source text naming the peer-reference document to load
   * @return fetched peer-reference text with the legacy newline-preserving shape
   * @throws IOException if the text cannot be parsed as a usable location or if loading fails
   */
  StringBuilder readPeerReferenceText(String locationText) throws IOException;
}
