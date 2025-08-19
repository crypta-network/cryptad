package network.crypta.io.comm;

import java.io.Serial;

/**
 * Thown when we can't parse a string to a Peer.
 *
 * @author amphibian
 */
public class ReferenceSignatureVerificationException extends Exception {
  @Serial private static final long serialVersionUID = -1;

  public ReferenceSignatureVerificationException(Exception e) {
    super(e);
  }

  public ReferenceSignatureVerificationException() {
    super();
  }

  public ReferenceSignatureVerificationException(String string) {
    super(string);
  }
}
