package network.crypta.support.io;

import java.io.OutputStream;

public class NullOutputStream extends OutputStream {
  public NullOutputStream() {}

  @Override
  public void write(int b) {}

  @Override
  public void write(byte[] buf, int off, int len) {}
}
