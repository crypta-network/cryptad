package network.crypta.support.compress;

import java.io.IOException;
import java.io.Serial;

/** The input exceeded the allowed maximum read length. */
public class CompressionInputSizeException extends IOException {

  @Serial private static final long serialVersionUID = -1L;

  public final long maxAllowed;

  public CompressionInputSizeException(long maxAllowed) {
    super("The input exceeded the maximum allowed size: " + maxAllowed);
    this.maxAllowed = maxAllowed;
  }
}
