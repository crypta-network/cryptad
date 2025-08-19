package network.crypta.support.compress;

import java.io.IOException;
import java.io.Serial;

/** The output was too big for the buffer. */
public class CompressionOutputSizeException extends IOException {

  @Serial private static final long serialVersionUID = -1;
  public final long estimatedSize;

  CompressionOutputSizeException() {
    this(-1);
  }

  CompressionOutputSizeException(long sz) {
    super("The output was too big for the buffer; estimated size: " + sz);
    estimatedSize = sz;
  }
}
