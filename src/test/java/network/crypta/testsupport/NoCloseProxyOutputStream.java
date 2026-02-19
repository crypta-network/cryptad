package network.crypta.testsupport;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/** OutputStream wrapper that flushes on close but does not close the delegate stream. */
public class NoCloseProxyOutputStream extends FilterOutputStream {
  public NoCloseProxyOutputStream(OutputStream out) {
    super(out);
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
    out.write(b, off, len);
  }

  @Override
  public void close() throws IOException {
    flush();
  }
}
