package network.crypta.clients.http;

import java.io.Serial;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * If thrown, the ToadletContainer re-runs the request with the new URI. Note that it DOES NOT
 * change the method to "GET"! So you can redirect to another toadlet and expect the other toadlet
 * to deal with a POST. However if you want to dump the contents of the POST, you need to actually
 * write a redirect.
 *
 * @author Matthew Toseland <toad@amphibian.dyndns.org> (0xE43DA450)
 * @author xor <xor@freenetproject.org>
 */
public class RedirectException extends Exception {
  @Serial private static final long serialVersionUID = -1;
  final URI newuri;

  public RedirectException(String newURI) throws URISyntaxException {
    this.newuri = new URI(newURI);
  }

  public RedirectException(URI newURI) {
    this.newuri = newURI;
  }

  /**
   * @return The URI to which this Exception shall redirect.
   */
  public URI getTarget() {
    return newuri;
  }
}
