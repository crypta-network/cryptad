package network.crypta.support;

import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import network.crypta.support.Logger.LogLevel;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class OutputStreamLogger extends OutputStream {
  private static final Logger LOG = LoggerFactory.getLogger(OutputStreamLogger.class);

  final LogLevel prio;
  final String prefix;
  final String charset;

  public OutputStreamLogger(LogLevel prio, String prefix, String charset) {
    this.prio = prio;
    this.prefix = prefix;
    this.charset = charset;
  }

  private void logByPriority(String msg) {
    switch (prio) {
      case ERROR:
        LOG.error(msg);
        break;
      case WARNING:
        LOG.warn(msg);
        break;
      case NORMAL:
        LOG.info(msg);
        break;
      case DEBUG:
      case MINOR:
      case MINIMAL:
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
