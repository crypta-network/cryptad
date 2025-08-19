package network.crypta.support.io;

import java.io.InputStream;

public class NullInputStream extends InputStream {
  public NullInputStream() {}

  @Override
  public int read() {
    return -1;
  }
}
