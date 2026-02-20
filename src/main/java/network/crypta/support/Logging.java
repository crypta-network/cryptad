package network.crypta.support;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;
import org.slf4j.LoggerFactory;
import org.slf4j.event.Level;

/**
 * SLF4J logging bootstrap utilities used by tests and tooling.
 *
 * <p>This utility centralizes runtime log-level configuration for environments that use Logback as
 * the SLF4J backend. Callers can set a root threshold, apply targeted logger overrides, and clear
 * previously applied overrides when re-bootstraping logging. The API is intentionally static, so it
 * can be invoked early during startup, from tests, or from integration tooling without requiring a
 * dependency-injected logging component.
 *
 * <p>Overrides are tracked by logger name in process memory and are reset before new detail rules
 * are applied, which keeps repeated bootstrap calls deterministic. If the active SLF4J
 * implementation is not Logback, methods become no-ops instead of failing, allowing code paths that
 * call this helper to remain backend-agnostic.
 */
public final class Logging {
  private static final Set<String> APPLIED_LOGGER_NAMES = new HashSet<>();

  private Logging() {}

  /**
   * Configures baseline logging and optional per-logger overrides.
   *
   * <p>This method first applies the root level, then parses, and applies detail rules such as
   * {@code "network.crypta:DEBUG,org.example:WARN"}.
   *
   * @param level baseline root logging level to apply
   * @param details optional comma-separated override rules in {@code loggerName:LEVEL} form
   */
  public static void bootstrap(Level level, String details) {
    setRootLevel(level);
    applyDetails(details);
  }

  /**
   * Sets the effective level for a specific logger.
   *
   * <p>If Logback is not the active backend, this method returns without applying changes.
   *
   * @param loggerName fully qualified logger name to configure
   * @param level level to apply to the specified logger
   */
  public static void setLevel(String loggerName, Level level) {
    LoggerPair pair = resolveLogbackLogger(loggerName);
    if (pair == null) {
      return;
    }
    pair.logger.setLevel(toLogback(level));
    pair.context.resetTurboFilterList();
  }

  /**
   * Sets the root logger level.
   *
   * <p>If Logback is not the active backend, this method returns without applying changes.
   *
   * @param level root logging threshold to configure
   */
  public static void setRootLevel(Level level) {
    LoggerPair pair = resolveLogbackLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    if (pair == null) {
      return;
    }
    pair.logger.setLevel(toLogback(level));
    pair.context.resetTurboFilterList();
  }

  /**
   * Disables a specific logger by setting its level to {@code OFF}.
   *
   * <p>If Logback is not the active backend, this method returns without applying changes.
   *
   * @param loggerName fully qualified logger name to disable
   */
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
    for (String rawToken : details.split(",", -1)) {
      String token = rawToken.trim();
      int idx = token.indexOf(':');
      if (idx >= 0) {
        String section = token.substring(0, idx);
        String lvl = token.substring(idx + 1).trim().toUpperCase(Locale.ROOT);
        if ("NONE".equals(lvl) || "OFF".equals(lvl)) {
          setOff(section);
          APPLIED_LOGGER_NAMES.add(section);
        } else {
          Level level = toSlf4jLevelOrNull(lvl);
          if (level != null) {
            setLevel(section, level);
            APPLIED_LOGGER_NAMES.add(section);
          }
        }
      }
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
