package network.crypta.clients.http;

import java.net.URI;

/**
 * Interface for {@link Toadlet}s that want to asked when a link to it is being filtered.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public interface LinkFilterExceptedToadlet {

  /**
   * Returns whether the given should be excepted from being filtered.
   *
   * @param link The link to check
   * @return {@code true} if the link should not be filtered, {@code false} if it should be filtered
   */
  boolean isLinkExcepted(URI link);
}
