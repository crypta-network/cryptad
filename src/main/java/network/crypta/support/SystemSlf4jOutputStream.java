package network.crypta.support;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import org.slf4j.Logger;

/**
 * OutputStream that forwards bytes to SLF4J while preserving the original console stream.
 *
 * <p>Design goals: - Avoid feedback loops when Logback writes to System.out/err by using a
 * thread-local guard. - Mirror low-severity stdout writes back to the original stream so the
 * terminal still shows the line even if the ConsoleAppender is filtering WARN+.
 *
 * <p>Writes performed while the guard is active are considered to originate from the logging
 * backend and are forwarded directly to the original stream to avoid recursion and duplicates.
 */
public final class SystemSlf4jOutputStream extends OutputStream {

  private static final ThreadLocal<Boolean> IN_LOGGING =
      ThreadLocal.withInitial(() -> Boolean.FALSE);

  private final PrintStream original;
  private final Logger logger;
  private final String prefix;
  private final String charset;
  private final boolean mirrorToOriginalForBelowWarn;

  public SystemSlf4jOutputStream(
      PrintStream original,
      Logger logger,
      String prefix,
      String charset,
      boolean mirrorToOriginalForBelowWarn) {
    this.original = original;
    this.logger = logger;
    this.prefix = prefix == null ? "" : prefix;
    this.charset = charset;
    this.mirrorToOriginalForBelowWarn = mirrorToOriginalForBelowWarn;
  }

  @Override
  public void write(int b) throws IOException {
    if (Boolean.TRUE.equals(IN_LOGGING.get())) {
      original.write(b);
      return;
    }
    try {
      IN_LOGGING.set(Boolean.TRUE);
      logger.info(prefix + (char) b);
    } finally {
      IN_LOGGING.set(Boolean.FALSE);
    }
    if (mirrorToOriginalForBelowWarn) {
      original.write(b);
    }
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
    if (Boolean.TRUE.equals(IN_LOGGING.get())) {
      original.write(b, off, len);
      return;
    }
    try {
      IN_LOGGING.set(Boolean.TRUE);
      try {
        logger.info(prefix + new String(b, off, len, charset));
      } catch (UnsupportedEncodingException e) {
        logger.info(prefix + new String(b, off, len));
      }
    } finally {
      IN_LOGGING.set(Boolean.FALSE);
    }
    if (mirrorToOriginalForBelowWarn) {
      original.write(b, off, len);
    }
  }

  @Override
  public void write(byte[] b) throws IOException {
    write(b, 0, b.length);
  }

  @Override
  public void flush() throws IOException {
    original.flush();
  }
}
