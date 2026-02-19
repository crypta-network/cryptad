package network.crypta.support;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import java.util.HashSet;
import java.util.Set;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * SLF4J logging bootstrap utilities used by tests and tooling.
 *
 * <p>Replaces the deprecated network.crypta.support.Logger facade.
 */
public final class Logging {
  private static final Set<String> APPLIED_LOGGER_NAMES = new HashSet<>();

  private Logging() {}

  /** Sets the root logger level and applies optional per-package overrides. */
  public static void bootstrap(Level level, String details) {
    setRootLevel(level);
    applyDetails(details);
  }

  /** Sets the level for the named logger when running with Logback. */
  public static void setLevel(String loggerName, Level level) {
    LoggerPair pair = resolveLogbackLogger(loggerName);
    if (pair == null) {
      return;
    }
    pair.logger.setLevel(toLogback(level));
    pair.context.resetTurboFilterList();
  }

  /** Sets the root logger level when running with Logback. */
  public static void setRootLevel(Level level) {
    LoggerPair pair = resolveLogbackLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    if (pair == null) {
      return;
    }
    pair.logger.setLevel(toLogback(level));
    pair.context.resetTurboFilterList();
  }

  /** Sets a named logger to OFF when using Logback. */
  public static void setOff(String loggerName) {
    LoggerPair pair = resolveLogbackLogger(loggerName);
    if (pair == null) {
      return;
    }
    pair.logger.setLevel(ch.qos.logback.classic.Level.OFF);
    pair.context.resetTurboFilterList();
  }

  private static synchronized void applyDetails(String details) {
    LoggerPair root = resolveLogbackLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    if (root == null) {
      return;
    }
    clearOverrides(root.context);
    if (details == null || details.isBlank()) {
      return;
    }
    for (String rawToken : details.split(",")) {
      String token = rawToken.trim();
      if (token.isEmpty() || !token.contains(":")) {
        continue;
      }
      int idx = token.indexOf(':');
      String section = token.substring(0, idx);
      String lvl = token.substring(idx + 1).trim().toUpperCase();
      if ("NONE".equals(lvl) || "OFF".equals(lvl)) {
        setOff(section);
        APPLIED_LOGGER_NAMES.add(section);
        continue;
      }
      Level level = toSlf4jLevelOrNull(lvl);
      if (level == null) {
        continue;
      }
      setLevel(section, level);
      APPLIED_LOGGER_NAMES.add(section);
    }
  }

  private static synchronized void clearOverrides(LoggerContext context) {
    for (String name : APPLIED_LOGGER_NAMES) {
      Logger logger = context.getLogger(name);
      logger.setLevel(null); // inherit root level
    }
    APPLIED_LOGGER_NAMES.clear();
  }

  private static Level toSlf4jLevelOrNull(String value) {
    return switch (value) {
      case "ERROR" -> Level.ERROR;
      case "WARN" -> Level.WARN;
      case "INFO" -> Level.INFO;
      case "DEBUG" -> Level.DEBUG;
      case "TRACE" -> Level.TRACE;
      default -> null;
    };
  }

  private static ch.qos.logback.classic.Level toLogback(Level level) {
    return switch (level) {
      case ERROR -> ch.qos.logback.classic.Level.ERROR;
      case WARN -> ch.qos.logback.classic.Level.WARN;
      case INFO -> ch.qos.logback.classic.Level.INFO;
      case DEBUG -> ch.qos.logback.classic.Level.DEBUG;
      case TRACE -> ch.qos.logback.classic.Level.TRACE;
    };
  }

  private static LoggerPair resolveLogbackLogger(String name) {
    Object factory = LoggerFactory.getILoggerFactory();
    if (!(factory instanceof LoggerContext context)) {
      return null;
    }
    return new LoggerPair(context, context.getLogger(name));
  }

  private record LoggerPair(LoggerContext context, Logger logger) {}
}
