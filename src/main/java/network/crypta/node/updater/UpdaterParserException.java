package network.crypta.node.updater;

import java.io.Serial;

public class UpdaterParserException extends Exception {

  @Serial private static final long serialVersionUID = 1L;

  public UpdaterParserException(String msg) {
    super(msg);
  }
}
