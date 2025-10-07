package network.crypta.support;

import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

public class OutputStreamLogger extends OutputStream {
  private static final Logger LOG = LoggerFactory.getLogger(OutputStreamLogger.class);

  final Level prio;
  final String prefix;
  final String charset;

  public OutputStreamLogger(Level prio, String prefix, String charset) {
    this.prio = prio;
    this.prefix = prefix;
    this.charset = charset;
  }

  private void logByPriority(String msg) {
    switch (prio) {
      case ERROR:
        LOG.error(msg);
        break;
      case WARN:
        LOG.warn(msg);
        break;
      case INFO:
        LOG.info(msg);
        break;
      case DEBUG:
      case TRACE:
      default:
        if (LOG.isDebugEnabled()) LOG.debug(msg);
        else LOG.info(msg);
        break;
    }
  }

  @Override
  public void write(int b) {
    logByPriority(prefix + (char) b);
  }

  @Override
  public void write(byte[] buf, int offset, int length) {
    try {
      // FIXME use Charset/CharsetDecoder
      logByPriority(prefix + new String(buf, offset, length, charset));
    } catch (UnsupportedEncodingException e) {
      // Impossible. Nothing we can do safely here. :(
    }
  }

  @Override
  public void write(byte[] buf) {
    write(buf, 0, buf.length);
  }
}
