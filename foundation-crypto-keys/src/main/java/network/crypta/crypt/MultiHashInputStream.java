package network.crypta.crypt;

import java.io.IOException;
import java.io.InputStream;
import network.crypta.support.io.SkipShieldingInputStream;
import org.jetbrains.annotations.NotNull;

public class MultiHashInputStream extends SkipShieldingInputStream {

  private final MultiHashDigester digester;
  private long readBytes;

  public MultiHashInputStream(InputStream proxy, long generateHashes) {
    super(proxy);
    this.digester = MultiHashDigester.fromBitmask(generateHashes);
  }

  @Override
  public int read(byte @NotNull [] buf, int off, int len) throws IOException {
    int ret = in.read(buf, off, len);
    if (ret <= 0) return ret;
    digester.update(buf, off, ret);
    readBytes += ret;
    return ret;
  }

  /** Slow, you should buffer the stream to avoid this! */
  @Override
  public int read() throws IOException {
    int ret = in.read();
    if (ret < 0) return ret;
    byte[] b = new byte[] {(byte) ret};
    digester.update(b, 0, 1);
    readBytes++;
    return ret;
  }

  @Override
  public boolean markSupported() {
    return false;
  }

  @Override
  public void reset() throws IOException {
    throw new IOException("mark/reset not supported");
  }

  @Override
  public void mark(int readlimit) {
    // Intentionally a no-op: mark/reset are not supported because this stream
    // updates multiple digests incrementally and cannot rewind that state.
    // See: markSupported() returns false and reset() throws IOException.
  }

  public HashResult[] getResults() {
    return digester.getResults().toArray(new HashResult[0]);
  }

  public long getReadBytes() {
    return readBytes;
  }
}
