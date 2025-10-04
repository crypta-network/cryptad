package network.crypta.support;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import network.crypta.support.Logger.LogLevel;

/**
 * OutputStream that mirrors bytes into Crypta's Logger while preserving the original console.
 *
 * <p>Key goals: - Preserve real console output (forward writes to the original {@link
 * PrintStream}). - Avoid feedback loops and duplicate file entries when Logback's ConsoleAppender
 * writes back to System.out/System.err by using a thread-local recursion guard.
 *
 * <p>Behavior: - When a write originates from application code (guard == false), log the text via
 * {@link Logger#logStatic(Object, String, LogLevel)} and do not write directly to the original
 * stream (to avoid double-printing). The subsequent ConsoleAppender write will be forwarded to the
 * original stream while the guard is set, so the console still shows the line once. - When a write
 * originates from the logging backend (guard == true), bypass logging and just forward to the
 * original stream so ConsoleAppender output reaches the terminal.
 */
public class TeeOutputStreamLogger extends OutputStream {

  private static final ThreadLocal<Boolean> IN_LOGGING =
      ThreadLocal.withInitial(() -> Boolean.FALSE);

  private final PrintStream original;
  private final LogLevel priority;
  private final String prefix;
  private final String charset;

  public TeeOutputStreamLogger(
      PrintStream original, LogLevel priority, String prefix, String charset) {
    this.original = original;
    this.priority = priority;
    this.prefix = prefix;
    this.charset = charset;
  }

  @Override
  public void write(int b) throws IOException {
    if (Boolean.TRUE.equals(IN_LOGGING.get())) {
      // This write originates from the logging system (e.g., ConsoleAppender). Preserve console.
      original.write(b);
      return;
    }
    try {
      IN_LOGGING.set(Boolean.TRUE);
      Logger.logStatic(this, prefix + (char) b, priority);
    } finally {
      IN_LOGGING.set(Boolean.FALSE);
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
        // Use charset to avoid platform-default ambiguity
        Logger.logStatic(this, prefix + new String(b, off, len, charset), priority);
      } catch (UnsupportedEncodingException e) {
        // Fallback to platform default if an unexpected charset issue occurs
        Logger.logStatic(this, prefix + new String(b, off, len), priority);
      }
    } finally {
      IN_LOGGING.set(Boolean.FALSE);
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
