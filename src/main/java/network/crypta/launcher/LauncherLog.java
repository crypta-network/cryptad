package network.crypta.launcher;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

/**
 * Minimal logging helpers for the launcher package.
 *
 * <p>- `logDebug()` prints only when `CRYPTA_LAUNCHER_DEBUG` is truthy.
 *
 * <p>- `logWarn()` and `logError()` always print to stderr with a timestamped prefix.
 */
public final class LauncherLog {
  private enum Lvl {
    DEBUG,
    INFO,
    WARN,
    ERROR
  }

  private static volatile Boolean debugEnabled;

  private LauncherLog() {}

  public static void logDebug(String msg) {
    emit(Lvl.DEBUG, msg, null);
  }

  public static void logDebug(String msg, Throwable t) {
    emit(Lvl.DEBUG, msg, t);
  }

  public static void logWarn(String msg) {
    emit(Lvl.WARN, msg, null);
  }

  public static void logWarn(String msg, Throwable t) {
    emit(Lvl.WARN, msg, t);
  }

  public static void logError(String msg) {
    emit(Lvl.ERROR, msg, null);
  }

  public static void logError(String msg, Throwable t) {
    emit(Lvl.ERROR, msg, t);
  }

  private static boolean isDebugEnabled() {
    Boolean cached = debugEnabled;
    if (cached != null) {
      return cached;
    }
    synchronized (LauncherLog.class) {
      if (debugEnabled == null) {
        String v = System.getenv("CRYPTA_LAUNCHER_DEBUG");
        if (v != null) {
          v = v.toLowerCase(Locale.ROOT).trim();
        }
        debugEnabled =
            "1".equals(v) || "true".equals(v) || "yes".equals(v) || "y".equals(v) || "on".equals(v);
      }
      return debugEnabled;
    }
  }

  private static String tsNow() {
    return LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_TIME);
  }

  private static void emit(Lvl level, String msg, Throwable t) {
    if (level == Lvl.DEBUG && !isDebugEnabled()) {
      return;
    }
    String base = tsNow() + " [Launcher/" + level.name() + "] " + msg;
    if (t == null) {
      System.err.println(base);
      return;
    }
    StringWriter sw = new StringWriter();
    t.printStackTrace(new PrintWriter(sw));
    System.err.println(base + "\n" + sw);
  }
}
