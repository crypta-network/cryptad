package network.crypta.client.filter;

import java.net.URI;
import network.crypta.clients.http.LinkFilterExceptedToadlet;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.clients.http.Toadlet;

/**
 * Provides link filter exceptions to the content filter.
 *
 * <p>At the moment the only implementation is {@link SimpleToadletServer} which forwards the
 * request to a {@link Toadlet} if it implements {@link LinkFilterExceptedToadlet}.
 *
 * @author <a href="mailto:bombe@pterodactylus.net">David ‘Bombe’ Roden</a>
 */
public interface LinkFilterExceptionProvider {

  /**
   * Returns whether the given should be excepted from being filtered.
   *
   * @param link The link to check
   * @return {@code true} if the link should not be filtered, {@code false} if it should be filtered
   */
  boolean isLinkExcepted(URI link);
}
