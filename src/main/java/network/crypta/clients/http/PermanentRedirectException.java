package network.crypta.clients.http;

import java.io.Serial;
import java.net.URI;

public class PermanentRedirectException extends Exception {

  @Serial private static final long serialVersionUID = -166786248237623796L;
  URI newuri;

  public PermanentRedirectException() {
    super();
  }

  public PermanentRedirectException(URI newURI) {
    this.newuri = newURI;
  }
}
