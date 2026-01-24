package network.crypta.node;

import ch.qos.logback.classic.AsyncAppender;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.Appender;
import ch.qos.logback.core.rolling.DefaultTimeBasedFileNamingAndTriggeringPolicy;
import ch.qos.logback.core.rolling.RollingFileAppender;
import ch.qos.logback.core.rolling.RollingPolicy;
import ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy;
import ch.qos.logback.core.rolling.TimeBasedFileNamingAndTriggeringPolicy;
import ch.qos.logback.core.util.FileSize;
import java.io.File;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import network.crypta.config.Dimension;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.config.OptionFormatException;
import network.crypta.config.SubConfig;
import network.crypta.support.ModuloTimeTriggeringPolicy;
import network.crypta.support.ModuloTimeTriggeringPolicy.Unit;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.StringCallback;
import org.slf4j.ILoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configures runtime logging for the node using Logback.
 *
 * <p>This handler wires the node's {@link SubConfig} options to Logback at runtime. It supports
 * enabling/disabling emission, switching the log directory, applying a size-and-time based rolling
 * policy (including a total on-disk size cap), and per-logger priority overrides. The class
 * interacts with the Logback root logger and expects an {@code ASYNC_FILE} appender with a {@link
 * RollingFileAppender} child to be present in the active configuration. When that structure is
 * missing, methods return without side effects.
 *
 * <p>Thread-safety: mutations that toggle overall emission synchronize on an internal lock. Other
 * reconfiguration methods perform best-effort updates and are designed to be safe to call from
 * configuration callbacks.
 *
 * <p>Side effects: updates the system property {@code crypta.log.dir}, manipulates Logback policies
 * and the root logger level, and writes to {@code System.err} for early/guarded errors. No
 * application logger is used inside this class to avoid recursion during reconfiguration.
 */
public class LoggingConfigHandler {
  // Intentionally no SLF4J logger; use System.err only for guarded errors.

  // String literals used at least 3 times (java:S1192)
  private static final String LVL_TRACE = "TRACE";
  private static final String LVL_DEBUG = "DEBUG";
  private static final String LVL_ERROR = "ERROR";
  private static final String LVL_INFO = "INFO";
  private static final String LVL_WARN = "WARN";
  private static final String LVL_OFF = "OFF";

  private class PriorityCallback extends StringCallback implements EnumerableOptionCallback {
    @Override
    public String get() {
      Level lvl = getRootLevel();
      return fromLogbackLevel(lvl);
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      try {
        Level target = toLogbackLevel(val);
        setRootLevel(target);
      } catch (IllegalArgumentException e) {
        throw new OptionFormatException(e.getMessage());
      }
    }

    private String fromLogbackLevel(Level lvl) {
      if (lvl == null) return LVL_WARN; // default
      return switch (lvl.levelInt) {
        case Level.TRACE_INT -> LVL_TRACE;
        case Level.DEBUG_INT -> LVL_DEBUG;
        case Level.INFO_INT -> LVL_INFO;
        case Level.ERROR_INT -> LVL_ERROR;
        case Level.OFF_INT -> LVL_OFF;
        default -> LVL_WARN;
      };
    }

    private void setRootLevel(Level level) {
      LoggerContext ctx = resolveLoggerContext();
      if (ctx == null) return;
      ch.qos.logback.classic.Logger root = ctx.getLogger(Logger.ROOT_LOGGER_NAME);
      root.setLevel(level);
    }

    private Level getRootLevel() {
      LoggerContext ctx = resolveLoggerContext();
      if (ctx == null) return Level.WARN;
      ch.qos.logback.classic.Logger root = ctx.getLogger(Logger.ROOT_LOGGER_NAME);
      return root.getLevel();
    }

    @Override
    public String[] getPossibleValues() {
      // Present standard SLF4J/Logback levels in UI (synonyms still accepted on input)
      return new String[] {LVL_TRACE, LVL_DEBUG, LVL_INFO, LVL_WARN, LVL_ERROR, LVL_OFF};
    }
  }

  private static final String SYS_PROP_LOG_DIR = "crypta.log.dir";
  private static final String APPENDER_ASYNC_FILE = "ASYNC_FILE";
  private static final String APPENDER_ASYNC_UID_TRACE = "ASYNC_UID_TRACE";
  private static final String LOG_FILE_PREFIX = "crypta";
  private static final String UID_TRACE_FILE_PREFIX = "crypta-uidtrace";
  private static final String LOGGER_UID_TRACE = "network.crypta.uidtrace";
  // Total on-disk usage cap for rotated/archived logs.
  private static final String CONF_LOGS_TOTAL_SIZE_CAP = "logsTotalSizeCap";
  private static final long MIN_LOGS_TOTAL_SIZE_CAP_BYTES = 50L * 1024L * 1024L; // 50 MiB
  private static final String CONF_PRIORITY = "priority";
  private static final String UNIT_MINUTE = "MINUTE";
  private static final String UNIT_HOUR = "HOUR";
  private static final String UNIT_DAY = "DAY";
  private static final String UNIT_WEEK = "WEEK";
  private static final String UNIT_MONTH = "MONTH";
  private static final String UNIT_YEAR = "YEAR";
  private static final String UNIT_WEEK_OF_YEAR = "WEEK_OF_YEAR"; // alias normalized to WEEK
  private static final String PATTERN_HOURLY = "yyyy-MM-dd_HH";
  private final SubConfig config;
  // Controls Logback directly; no legacy LoggerHook path.
  private boolean loggerEnabled;
  private File logDir;
  private long logsTotalSizeCap;
  private String logRotateInterval;
  private long maxCachedLogBytes;
  private int maxCachedLogLines;
  private long maxBacklogNotBusy;
  // No executor needed; configuration is synchronous and local.
  // Stdout/stderr capture is not used; Logback owns console handling.
  private final Set<String> appliedLoggerNames = new HashSet<>();
  private String priorityDetailRaw = "";

  /**
   * Creates a handler and registers logging-related options against the provided configuration.
   *
   * <p>Reads initial values, applies them to Logback (including the log directory and rolling
   * policy), and enables or disables emission according to the {@code enabled} flag.
   *
   * @param loggingConfig the {@link SubConfig} subsection that carries logging options; must not be
   *     {@code null}
   * @throws InvalidConfigValueException if the initial log directory is invalid or cannot be
   *     created
   */
  public LoggingConfigHandler(SubConfig loggingConfig) throws InvalidConfigValueException {
    this.config = loggingConfig;

    registerEnabled(loggingConfig);
    boolean loggingEnabled = loggingConfig.getBoolean("enabled");

    registerDirname(loggingConfig, loggingEnabled);

    registerLogsTotalSizeCap();

    // priority (node may override on testnet)
    registerPriority();

    registerPriorityDetail();

    registerInterval();

    registerMaxCachedBytes();

    registerMaxCachedLines();

    registerMaxBacklogNotBusy();

    if (loggingEnabled) {
      enableLogger();
    } else {
      // Ensure SLF4J/Logback does not emit logs when disabled at startup.
      disableLogger();
    }
    config.finishedInitialization();
  }

  private void registerEnabled(SubConfig loggingConfig) {
    loggingConfig.register(
        "enabled",
        true,
        new Option.Meta(1, true, false, "LogConfigHandler.enabled", "LogConfigHandler.enabledLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return loggerEnabled;
          }

          @Override
          public void set(Boolean val) {
            final boolean enable = Boolean.TRUE.equals(val);
            if (enable == loggerEnabled) return;
            if (!enable) {
              disableLogger();
            } else {
              enableLogger();
            }
          }
        });
  }

  private void registerDirname(SubConfig loggingConfig, boolean loggingEnabled)
      throws InvalidConfigValueException {
    loggingConfig.register(
        "dirname",
        "logs",
        new Option.Meta(2, true, false, "LogConfigHandler.dirName", "LogConfigHandler.dirNameLong"),
        new StringCallback() {
          @Override
          public String get() {
            return logDir.getPath();
          }

          @Override
          public void set(String val) throws InvalidConfigValueException {
            File f = new File(val);
            if (f.equals(logDir)) return;
            preSetLogDir(f);
            // Still here
            logDir = f;
            // Keep SLF4J rolling appender in the same directory
            System.setProperty(SYS_PROP_LOG_DIR, logDir.getAbsolutePath());
            // Reconfigure Logback file appender to the new directory immediately
            reconfigureLogbackFileDirectory(logDir);
          }
        });

    logDir = new File(config.getString("dirname"));
    // Initialize Logback rolling file location to match the configured directory.
    System.setProperty(SYS_PROP_LOG_DIR, logDir.getAbsolutePath());
    // Ensure Logback's file appender targets the initial directory.
    reconfigureLogbackFileDirectory(logDir);
    if (loggingEnabled) {
      preSetLogDir(logDir);
    }
    // Note: enabling the logger invokes preSetLogDir as well.
  }

  private void registerLogsTotalSizeCap() {
    // Total disk space used by rotated/archived logs (bytes).
    config.register(
        CONF_LOGS_TOTAL_SIZE_CAP,
        "200M",
        new Option.Meta(
            3,
            true,
            true,
            "LogConfigHandler.logsTotalSizeCap",
            "LogConfigHandler.logsTotalSizeCapLong"),
        new LongCallback() {
          @Override
          public Long get() {
            return logsTotalSizeCap;
          }

          @Override
          public void set(Long val) {
            if (val == null) val = 0L;
            // Enforce minimum of 50 MiB to keep rolling policy sane relative to maxFileSize.
            if (val < MIN_LOGS_TOTAL_SIZE_CAP_BYTES) val = MIN_LOGS_TOTAL_SIZE_CAP_BYTES;
            logsTotalSizeCap = val;
            // Apply to Logback rolling policy immediately.
            updateLogbackTotalSizeCap(logsTotalSizeCap);
          }
        },
        true);

    // Determine effective initial value with backward-compatibility.
    long initial = config.getLong(CONF_LOGS_TOTAL_SIZE_CAP);
    if (initial < MIN_LOGS_TOTAL_SIZE_CAP_BYTES) initial = MIN_LOGS_TOTAL_SIZE_CAP_BYTES;
    logsTotalSizeCap = initial;
    // Ensure Logback picks up the configured cap at startup.
    updateLogbackTotalSizeCap(logsTotalSizeCap);
  }

  private void registerPriority() {
    config.register(
        CONF_PRIORITY,
        LVL_WARN,
        new Option.Meta(
            4,
            false,
            false,
            "LogConfigHandler.minLoggingPriority",
            "LogConfigHandler.minLoggingPriorityLong"),
        new PriorityCallback());
  }

  private void registerPriorityDetail() {
    config.register(
        "priorityDetail",
        "",
        new Option.Meta(
            5,
            true,
            false,
            "LogConfigHandler.detailedPriorityThreshold",
            "LogConfigHandler.detailedPriorityThresholdLong"),
        new StringCallback() {
          @Override
          public String get() {
            return priorityDetailRaw == null ? "" : priorityDetailRaw;
          }

          @Override
          public void set(String val) throws InvalidConfigValueException {
            applyPerLoggerOverrides(val);
          }
        });
  }

  private void registerInterval() {
    // Interval (kept for compatibility; Logback handles rotation).
    config.register(
        "interval",
        "1HOUR",
        new Option.Meta(
            5,
            true,
            false,
            "LogConfigHandler.rotationInterval",
            "LogConfigHandler.rotationIntervalLong"),
        new StringCallback() {
          @Override
          public String get() {
            return logRotateInterval;
          }

          @Override
          public void set(String val) {
            logRotateInterval = val;
            // Apply new interval to Logback rolling pattern immediately.
            reconfigureLogbackFileDirectory(logDir);
          }
        });

    logRotateInterval = config.getString("interval");
    // Apply current interval to Logback pattern at startup.
    reconfigureLogbackFileDirectory(logDir);
  }

  private void registerMaxCachedBytes() {
    // Maximum cached bytes in RAM (not used by Logback path).
    config.register(
        "maxCachedBytes",
        "1M",
        new Option.Meta(
            6,
            true,
            false,
            "LogConfigHandler.maxCachedBytes",
            "LogConfigHandler.maxCachedBytesLong"),
        new LongCallback() {
          @Override
          public Long get() {
            return maxCachedLogBytes;
          }

          @Override
          public void set(Long val) {
            if (val < 0) val = 0L;
            if (val == maxCachedLogBytes) return;
            maxCachedLogBytes = val;
            // No-op under SLF4J/Logback.
          }
        },
        true);

    maxCachedLogBytes = config.getLong("maxCachedBytes");
  }

  private void registerMaxCachedLines() {
    // Maximum cached lines in RAM (legacy; requires restart to take effect).
    config.register(
        "maxCachedLines",
        "10k",
        new Option.Meta(
            7,
            true,
            false,
            "LogConfigHandler.maxCachedLines",
            "LogConfigHandler.maxCachedLinesLong"),
        new IntCallback() {
          @Override
          public Integer get() {
            return maxCachedLogLines;
          }

          @Override
          public void set(Integer val) throws NodeNeedRestartException {
            if (val < 0) val = 0;
            if (val == maxCachedLogLines) return;
            maxCachedLogLines = val;
            throw new NodeNeedRestartException("logger.maxCachedLogLines"); // documented restart
          }
        },
        Dimension.NOT);

    maxCachedLogLines = config.getInt("maxCachedLines");
  }

  private void registerMaxBacklogNotBusy() {
    config.register(
        "maxBacklogNotBusy",
        "60000",
        new Option.Meta(
            8,
            true,
            false,
            "LogConfigHandler.maxBacklogNotBusy",
            "LogConfigHandler.maxBacklogNotBusy"),
        new LongCallback() {

          @Override
          public Long get() {
            return maxBacklogNotBusy;
          }

          @Override
          public void set(Long val) throws InvalidConfigValueException {
            if (val < 0) throw new InvalidConfigValueException("Must be >= 0");
            if (val == maxBacklogNotBusy) return;
            maxBacklogNotBusy = val;
            // No-op under SLF4J/Logback
          }
        },
        false);

    maxBacklogNotBusy = config.getLong("maxBacklogNotBusy");
  }

  private final Object enableLoggerLock = new Object();

  /** Turn on log emission and apply current configuration. */
  @SuppressWarnings({"java:S106", "java:S4507", "CallToPrintStackTrace"})
  private void enableLogger() {
    try {
      preSetLogDir(logDir);
    } catch (InvalidConfigValueException e3) {
      System.err.println("Set log directory failed (path=" + logDir + "): " + e3);
      e3.printStackTrace();
    }
    synchronized (enableLoggerLock) {
      if (loggerEnabled) return;
      try {
        config.forceUpdate(CONF_PRIORITY);
        config.forceUpdate("priorityDetail");
      } catch (InvalidConfigValueException _) {
        System.err.println(
            "Invalid logger.priority in configuration: " + config.getString(CONF_PRIORITY));
      } catch (NodeNeedRestartException _) {
        // not expected for priority updates
      }

      loggerEnabled = true;
    }
  }

  /** Reconfigure the rolling file appender to use a new directory without a JVM restart. */
  @SuppressWarnings("java:S106")
  private void reconfigureLogbackFileDirectory(File newDir) {
    try {
      LoggerContext ctx = resolveLoggerContext();
      if (ctx == null) return;
      String datePat = datePatternForInterval(logRotateInterval);
      updateRollingAppenderDirectory(
          ctx,
          newDir,
          datePat,
          Logger.ROOT_LOGGER_NAME,
          APPENDER_ASYNC_FILE,
          LOG_FILE_PREFIX,
          "crypta-latest.log");
      updateRollingAppenderDirectory(
          ctx,
          newDir,
          datePat,
          LOGGER_UID_TRACE,
          APPENDER_ASYNC_UID_TRACE,
          UID_TRACE_FILE_PREFIX,
          "crypta-uidtrace-latest.log");
    } catch (Exception e) {
      System.err.println("Logback file directory reconfiguration failed: " + e);
    }
  }

  private LoggerContext resolveLoggerContext() {
    ILoggerFactory lf = LoggerFactory.getILoggerFactory();
    if (lf instanceof LoggerContext loggercontext) {
      return loggercontext;
    }
    return null;
  }

  private AsyncAppender resolveAsyncAppender(
      LoggerContext ctx, String loggerName, String appenderName) {
    ch.qos.logback.classic.Logger logger = ctx.getLogger(loggerName);
    Appender<?> async = logger.getAppender(appenderName);
    if (async instanceof AsyncAppender asyncappender) {
      return asyncappender;
    }
    return null;
  }

  private RollingFileAppender<ILoggingEvent> findRollingFileAppender(AsyncAppender aa) {
    for (Iterator<Appender<ILoggingEvent>> it = aa.iteratorForAppenders(); it.hasNext(); ) {
      Appender<ILoggingEvent> child = it.next();
      if (child instanceof RollingFileAppender) {
        return (RollingFileAppender<ILoggingEvent>) child;
      }
    }
    return null;
  }

  private void updateRollingAppenderDirectory(
      LoggerContext ctx,
      File dir,
      String datePat,
      String loggerName,
      String asyncAppenderName,
      String prefix,
      String latestName) {
    AsyncAppender aa = resolveAsyncAppender(ctx, loggerName, asyncAppenderName);
    if (aa == null) return;
    RollingFileAppender<ILoggingEvent> rfa = findRollingFileAppender(aa);
    if (rfa == null) return;
    String newPattern = new File(dir, prefix + "-%d{" + datePat + "}.%i.log.gz").getAbsolutePath();
    String newFile = new File(dir, latestName).getAbsolutePath();
    applyRollingPolicyUpdate(ctx, rfa, newFile, newPattern);
  }

  private void applyRollingPolicyUpdate(
      LoggerContext ctx,
      RollingFileAppender<ILoggingEvent> rfa,
      String newFile,
      String newPattern) {
    RollingPolicy rp = rfa.getRollingPolicy();
    if (!(rp instanceof SizeAndTimeBasedRollingPolicy<?> st)) return;

    // Compute policy parameters first to avoid leaving appender stopped on error
    int multiple = parseIntervalMultiple(logRotateInterval);
    String unit = safeParseIntervalUnit(logRotateInterval);
    assignPolicy(ctx, st, multiple, unit);

    // Stop appender and policy before applying structural changes
    st.stop();
    rfa.stop();
    st.setFileNamePattern(newPattern);
    // Keep total size cap aligned with configured logsTotalSizeCap
    st.setTotalSizeCap(new FileSize(logsTotalSizeCap));

    // Restart in order: policy then appender
    st.start();
    rfa.setFile(newFile);
    rfa.start();
  }

  private static <E> void assignPolicy(
      LoggerContext ctx, SizeAndTimeBasedRollingPolicy<E> st, int multiple, String unit) {
    TimeBasedFileNamingAndTriggeringPolicy<E> policy = buildTriggeringPolicy(ctx, multiple, unit);
    st.setTimeBasedFileNamingAndTriggeringPolicy(policy);
  }

  private static <E> TimeBasedFileNamingAndTriggeringPolicy<E> buildTriggeringPolicy(
      LoggerContext ctx, int multiple, String unit) {
    if (multiple > 1
        && (UNIT_MINUTE.equals(unit)
            || UNIT_HOUR.equals(unit)
            || UNIT_DAY.equals(unit)
            || UNIT_WEEK.equals(unit)
            || UNIT_MONTH.equals(unit)
            || UNIT_YEAR.equals(unit))) {
      ModuloTimeTriggeringPolicy<E> mod = new ModuloTimeTriggeringPolicy<>();
      switch (unit) {
        case UNIT_MINUTE -> mod.setUnit(Unit.MINUTE);
        case UNIT_HOUR -> mod.setUnit(Unit.HOUR);
        case UNIT_DAY -> mod.setUnit(Unit.DAY);
        case UNIT_WEEK -> mod.setUnit(Unit.WEEK);
        case UNIT_MONTH -> mod.setUnit(Unit.MONTH);
        default -> mod.setUnit(Unit.YEAR);
      }
      mod.setMultiple(multiple);
      mod.setContext(ctx);
      return mod;
    }

    DefaultTimeBasedFileNamingAndTriggeringPolicy<E> def =
        new DefaultTimeBasedFileNamingAndTriggeringPolicy<>();
    def.setContext(ctx);
    return def;
  }

  /** Apply the configured total size cap to Logback's rolling policy when present. */
  @SuppressWarnings("java:S106")
  private void updateLogbackTotalSizeCap(long bytes) {
    try {
      ILoggerFactory lf = LoggerFactory.getILoggerFactory();
      if (!(lf instanceof LoggerContext loggercontext)) return;
      updateRollingTotalSizeCap(
          loggercontext, bytes, Logger.ROOT_LOGGER_NAME, APPENDER_ASYNC_FILE, LOG_FILE_PREFIX);
      updateRollingTotalSizeCap(
          loggercontext, bytes, LOGGER_UID_TRACE, APPENDER_ASYNC_UID_TRACE, UID_TRACE_FILE_PREFIX);
    } catch (Exception e) {
      System.err.println("Update of Logback totalSizeCap failed: " + e);
    }
  }

  private void updateRollingTotalSizeCap(
      LoggerContext ctx, long bytes, String loggerName, String asyncAppenderName, String prefix) {
    AsyncAppender asyncappender = resolveAsyncAppender(ctx, loggerName, asyncAppenderName);
    if (asyncappender == null) return;
    for (Iterator<Appender<ILoggingEvent>> it = asyncappender.iteratorForAppenders();
        it.hasNext(); ) {
      Appender<ILoggingEvent> child = it.next();
      if (child instanceof RollingFileAppender<ILoggingEvent> rfa) {
        RollingPolicy rp = rfa.getRollingPolicy();
        if (rp instanceof SizeAndTimeBasedRollingPolicy<?> st) {
          st.stop();
          st.setTotalSizeCap(new FileSize(bytes));
          String datePat = datePatternForInterval(logRotateInterval);
          String dir = System.getProperty(SYS_PROP_LOG_DIR, new File(".").getAbsolutePath());
          String pat = new File(dir, prefix + "-%d{" + datePat + "}.%i.log.gz").getAbsolutePath();
          st.setFileNamePattern(pat);
          st.start();
        }
        break;
      }
    }
  }

  /**
   * Maps {@code logger.interval} to a Logback date pattern; multipliers round down to the base
   * unit.
   */
  private String datePatternForInterval(String configured) {
    if (configured == null || configured.isEmpty()) return PATTERN_HOURLY; // default hourly
    String s = configured.trim().toUpperCase();
    // Strip optional trailing 'S'
    if (s.endsWith("S")) s = s.substring(0, s.length() - 1);
    // Extract numeric prefix (we ignore it for Logback granularity)
    int i = 0;
    while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
    String unit = parseIntervalUnit(s);
    return switch (unit) {
      case UNIT_MINUTE -> "yyyy-MM-dd_HH-mm";
      case UNIT_DAY -> "yyyy-MM-dd";
      case UNIT_WEEK -> "YYYY-ww"; // ISO week-based year
      case UNIT_MONTH -> "yyyy-MM";
      case UNIT_YEAR -> "yyyy";
      default -> PATTERN_HOURLY;
    };
  }

  private String parseIntervalUnit(String s) {
    if (s == null || s.isEmpty()) return UNIT_HOUR; // default granularity
    String up = s.toUpperCase();
    // Accept plural units (e.g. 5MINUTES) by trimming an optional trailing 'S'
    if (up.endsWith("S")) up = up.substring(0, up.length() - 1);
    int i = 0;
    while (i < up.length() && Character.isDigit(up.charAt(i))) i++;
    String unit = (i == 0) ? up : up.substring(i);
    // Normalize aliases
    if (unit.equals(UNIT_WEEK_OF_YEAR)) return UNIT_WEEK;
    return unit;
  }

  /** Null-safe wrapper for interval unit parsing with sane default. */
  private String safeParseIntervalUnit(String s) {
    try {
      return parseIntervalUnit(s);
    } catch (Exception _) {
      return UNIT_HOUR;
    }
  }

  private int parseIntervalMultiple(String configured) {
    if (configured == null || configured.isEmpty()) return 1;
    String s = configured.trim().toUpperCase();
    if (s.endsWith("S")) s = s.substring(0, s.length() - 1);
    int i = 0;
    while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
    if (i == 0) return 1;
    try {
      return Math.max(1, Integer.parseInt(s.substring(0, i)));
    } catch (NumberFormatException _) {
      return 1;
    }
  }

  /**
   * Disables log emission by setting the root level to {@link Level#OFF} and clearing any
   * per-logger overrides so they inherit from root again.
   *
   * <p>Thread-safety: synchronizes on an internal lock to serialize disable with other state
   * transitions.
   */
  @SuppressWarnings("java:S106")
  protected void disableLogger() {
    synchronized (enableLoggerLock) {
      // Reconfigure SLF4J/Logback so no further logs are emitted.
      try {
        LoggerContext ctx = resolveLoggerContext();
        if (ctx != null) {
          // Clear any per-logger overrides so they inherit from root again
          for (String name : appliedLoggerNames) {
            ch.qos.logback.classic.Logger logger = ctx.getLogger(name);
            logger.setLevel(null);
          }
          appliedLoggerNames.clear();
          // Set root level to OFF to disable emission
          ch.qos.logback.classic.Logger root = ctx.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
          root.setLevel(Level.OFF);
        }
      } catch (Exception e) {
        System.err.println("Disable logging via Logback failed: " + e);
      }
      // Mark as disabled even if we were already disabled
      loggerEnabled = false;
    }
  }

  /**
   * Validates or creates the target log directory before any Logback reconfiguration.
   *
   * @param f directory to use for log files; must refer to a directory path
   * @throws InvalidConfigValueException when the path refers to a non-directory or cannot be
   *     created
   */
  protected void preSetLogDir(File f) throws InvalidConfigValueException {
    boolean exists = f.exists();
    if (exists && !f.isDirectory())
      throw new InvalidConfigValueException("Cannot overwrite a file with a log directory");
    if (!exists && !f.mkdir() && !f.isDirectory()) {
      // Ensure directory creation succeeds; treat failure as invalid config
      throw new InvalidConfigValueException("Cannot create log directory");
    }
  }

  // ===== SLF4J/Logback helpers =====

  private Level toLogbackLevel(String val) {
    if (val == null) throw new IllegalArgumentException("priority cannot be null");
    String s = val.trim().toUpperCase(Locale.ROOT);
    // Accept standard names and historical synonyms for backward compatibility
    return switch (s) {
      // Standard
      case LVL_TRACE -> Level.TRACE;
      case LVL_DEBUG, "MINOR" -> Level.DEBUG;
      case LVL_INFO, "NORMAL" -> Level.INFO;
      case LVL_WARN, "WARNING" -> Level.WARN;
      case LVL_ERROR -> Level.ERROR;
      case LVL_OFF, "NONE" -> Level.OFF;
      // Synonyms
      case "MINIMAL" -> Level.TRACE;
      default -> throw new IllegalArgumentException("Unknown priority: " + val);
    };
  }

  private void applyPerLoggerOverrides(String detail) throws InvalidConfigValueException {
    LoggerContext ctx = resolveLoggerContext();
    if (ctx == null) return;

    // If no update provided, keep current overrides intact (legacy behavior)
    if (detail == null) return;

    String raw = detail.trim();
    // Explicitly clearing overrides when empty
    if (raw.isEmpty()) {
      clearAllOverrides(ctx);
      priorityDetailRaw = "";
      return;
    }

    // Parse into a temporary map first; do not mutate existing overrides until validated
    Map<String, Level> newOverrides = parseOverrides(raw);

    // Apply updates
    removeObsoleteOverrides(ctx, newOverrides);
    applyOverrides(ctx, newOverrides);
    priorityDetailRaw = raw;
  }

  private void clearAllOverrides(LoggerContext ctx) {
    for (String name : appliedLoggerNames) {
      ch.qos.logback.classic.Logger logger = ctx.getLogger(name);
      logger.setLevel(null); // inherit root
    }
    appliedLoggerNames.clear();
  }

  private Map<String, Level> parseOverrides(String raw) throws InvalidConfigValueException {
    Map<String, Level> result = new HashMap<>();
    String[] tokens = raw.split(",");
    for (String token : tokens) {
      if (token != null && !token.isEmpty()) {
        int x = token.indexOf(':');
        if (x >= 0 && x != token.length() - 1) { // ignore malformed pair silently as before
          String section = token.substring(0, x);
          String val = token.substring(x + 1);
          Level lvl;
          try {
            lvl = toLogbackLevel(val);
          } catch (IllegalArgumentException e) {
            throw new InvalidConfigValueException(e.getMessage());
          }
          result.put(section, lvl);
        }
      }
    }
    return result;
  }

  private void removeObsoleteOverrides(LoggerContext ctx, Map<String, Level> newOverrides) {
    for (String name : new java.util.HashSet<>(appliedLoggerNames)) {
      if (!newOverrides.containsKey(name)) {
        ch.qos.logback.classic.Logger logger = ctx.getLogger(name);
        logger.setLevel(null);
        appliedLoggerNames.remove(name);
      }
    }
  }

  private void applyOverrides(LoggerContext ctx, Map<String, Level> newOverrides) {
    for (Map.Entry<String, Level> e : newOverrides.entrySet()) {
      ch.qos.logback.classic.Logger lgr = ctx.getLogger(e.getKey());
      lgr.setLevel(e.getValue());
      appliedLoggerNames.add(e.getKey());
    }
  }
}
