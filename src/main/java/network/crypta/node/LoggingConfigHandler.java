package network.crypta.node;

import ch.qos.logback.classic.AsyncAppender;
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
import java.io.PrintStream;
import java.lang.ref.WeakReference;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import network.crypta.config.Dimension;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.OptionFormatException;
import network.crypta.config.SubConfig;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;
import network.crypta.support.LoggerHook;
import network.crypta.support.LoggerHook.InvalidThresholdException;
import network.crypta.support.LoggerHookChain;
import network.crypta.support.ModuloTimeTriggeringPolicy;
import network.crypta.support.ModuloTimeTriggeringPolicy.Unit;
import network.crypta.support.Slf4jLoggerHook;
import network.crypta.support.TeeOutputStreamLogger;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.StringCallback;
import org.slf4j.ILoggerFactory;
import org.slf4j.LoggerFactory;

public class LoggingConfigHandler {
  private static class PriorityCallback extends StringCallback implements EnumerableOptionCallback {
    @Override
    public String get() {
      LoggerHookChain chain = Logger.getChain();
      return chain.getThresholdNew().name();
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      LoggerHookChain chain = Logger.getChain();
      try {
        chain.setThreshold(val);
        // Keep SLF4J hook aligned when present (guard against GC race)
        Slf4jLoggerHook hook = (slf4jHookRef == null) ? null : slf4jHookRef.get();
        if (hook != null) {
          hook.setThreshold(val);
        }
      } catch (LoggerHook.InvalidThresholdException e) {
        throw new OptionFormatException(e.getMessage());
      }
    }

    @Override
    public String[] getPossibleValues() {
      List<LogLevel> priorities = LogLevel.getEntries();
      ArrayList<String> values = new ArrayList<>(priorities.size() + 1);
      for (LogLevel p : priorities) values.add(p.name());

      return values.toArray(new String[0]);
    }
  }

  private static final String SYS_PROP_LOG_DIR = "crypta.log.dir";
  private static final String CONF_MAX_ZIPPED_SIZE = "maxZippedLogsSize";
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
  // FileLoggerHook removed; SLF4J/Logback handles outputs
  private Slf4jLoggerHook slf4jHook;
  // Weak reference to allow static callbacks to update the hook without leaks
  private static WeakReference<Slf4jLoggerHook> slf4jHookRef = new WeakReference<>(null);
  private File logDir;
  private long maxZippedLogsSize;
  private String logRotateInterval;
  private long maxCachedLogBytes;
  private int maxCachedLogLines;
  private long maxBacklogNotBusy;
  // No executor required; logging configuration is independent
  // When capturing stdout/err, remember the originals to restore on disable
  private PrintStream originalStdout;
  private PrintStream originalStderr;
  private boolean capturedStdStreams;

  public LoggingConfigHandler(SubConfig loggingConfig) throws InvalidConfigValueException {
    this.config = loggingConfig;

    registerEnabled(loggingConfig);
    boolean loggingEnabled = loggingConfig.getBoolean("enabled");

    registerDirname(loggingConfig, loggingEnabled);

    registerMaxZippedLogsSize();

    // priority (node may override on testnet)
    registerPriority();

    registerPriorityDetail();

    registerInterval();

    registerMaxCachedBytes();

    registerMaxCachedLines();

    registerMaxBacklogNotBusy();

    if (loggingEnabled) enableLogger();
    config.finishedInitialization();
  }

  private void registerEnabled(SubConfig loggingConfig) {
    loggingConfig.register(
        "enabled",
        true,
        1,
        true,
        false,
        "LogConfigHandler.enabled",
        "LogConfigHandler.enabledLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return slf4jHook != null;
          }

          @Override
          public void set(Boolean val) {
            final boolean enable = Boolean.TRUE.equals(val);
            if (enable == (slf4jHook != null)) return;
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
        2,
        true,
        false,
        "LogConfigHandler.dirName",
        "LogConfigHandler.dirNameLong",
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
    // Initialize SLF4J rolling file location to mirror FileLoggerHook directory
    System.setProperty(SYS_PROP_LOG_DIR, logDir.getAbsolutePath());
    // Ensure Logback's file appender targets the initial directory
    reconfigureLogbackFileDirectory(logDir);
    if (loggingEnabled) {
      preSetLogDir(logDir);
    }
    // => enableLogger must run preSetLogDir
  }

  private void registerMaxZippedLogsSize() {
    // max space used by zipped logs
    config.register(
        CONF_MAX_ZIPPED_SIZE,
        "10M",
        3,
        true,
        true,
        "LogConfigHandler.maxZippedLogsSize",
        "LogConfigHandler.maxZippedLogsSizeLong",
        new LongCallback() {
          @Override
          public Long get() {
            return maxZippedLogsSize;
          }

          @Override
          public void set(Long val) {
            if (val < 0) val = 0L;
            maxZippedLogsSize = val;
            // Apply to Logback rolling policy immediately
            updateLogbackTotalSizeCap(maxZippedLogsSize);
          }
        },
        true);

    maxZippedLogsSize = config.getLong(CONF_MAX_ZIPPED_SIZE);
    // Ensure Logback picks up the configured cap at startup
    updateLogbackTotalSizeCap(maxZippedLogsSize);
  }

  private void registerPriority() {
    config.register(
        CONF_PRIORITY,
        "warning",
        4,
        false,
        false,
        "LogConfigHandler.minLoggingPriority",
        "LogConfigHandler.minLoggingPriorityLong",
        new PriorityCallback());
  }

  private void registerPriorityDetail() {
    config.register(
        "priorityDetail",
        "",
        5,
        true,
        false,
        "LogConfigHandler.detailedPriorityThreshold",
        "LogConfigHandler.detailedPriorityThresholdLong",
        new StringCallback() {
          @Override
          public String get() {
            LoggerHookChain chain = Logger.getChain();
            return chain.getDetailedThresholds();
          }

          @Override
          public void set(String val) throws InvalidConfigValueException {
            LoggerHookChain chain = Logger.getChain();
            try {
              chain.setDetailedThresholds(val);
              Slf4jLoggerHook hook = (slf4jHookRef == null) ? null : slf4jHookRef.get();
              if (hook != null) {
                hook.setDetailedThresholds(val);
              }
            } catch (InvalidThresholdException e) {
              throw new InvalidConfigValueException(e.getMessage());
            }
          }
        });
  }

  private void registerInterval() {
    // interval (kept for compatibility; handled by Logback)
    config.register(
        "interval",
        "1HOUR",
        5,
        true,
        false,
        "LogConfigHandler.rotationInterval",
        "LogConfigHandler.rotationIntervalLong",
        new StringCallback() {
          @Override
          public String get() {
            return logRotateInterval;
          }

          @Override
          public void set(String val) {
            logRotateInterval = val;
            // Apply new interval to Logback rolling pattern immediately
            reconfigureLogbackFileDirectory(logDir);
          }
        });

    logRotateInterval = config.getString("interval");
    // Apply current interval to Logback pattern at startup
    reconfigureLogbackFileDirectory(logDir);
  }

  private void registerMaxCachedBytes() {
    // max cached bytes in RAM
    config.register(
        "maxCachedBytes",
        "1M",
        6,
        true,
        false,
        "LogConfigHandler.maxCachedBytes",
        "LogConfigHandler.maxCachedBytesLong",
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
            // No-op under SLF4J/Logback
          }
        },
        true);

    maxCachedLogBytes = config.getLong("maxCachedBytes");
  }

  private void registerMaxCachedLines() {
    // max cached lines in RAM
    config.register(
        "maxCachedLines",
        "10k",
        7,
        true,
        false,
        "LogConfigHandler.maxCachedLines",
        "LogConfigHandler.maxCachedLinesLong",
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
            throw new NodeNeedRestartException("logger.maxCachedLogLines");
          }
        },
        Dimension.NOT);

    maxCachedLogLines = config.getInt("maxCachedLines");
  }

  private void registerMaxBacklogNotBusy() {
    config.register(
        "maxBacklogNotBusy",
        "60000",
        8,
        true,
        false,
        "LogConfigHandler.maxBacklogNotBusy",
        "LogConfigHandler.maxBacklogNotBusy",
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

  /** Turn on the logger. */
  @SuppressWarnings("java:S106")
  private void enableLogger() {
    try {
      preSetLogDir(logDir);
    } catch (InvalidConfigValueException e3) {
      System.err.println("Cannot set log dir: " + logDir + ": " + e3);
      e3.printStackTrace();
    }
    synchronized (enableLoggerLock) {
      if (slf4jHook != null) return;
      // Do not reset the global chain: reuse it to preserve registered callbacks.
      // This promotes a non-chain logger to a chain only when needed and keeps existing hooks.
      Logger.getChain();
      try {
        config.forceUpdate(CONF_PRIORITY);
        config.forceUpdate("priorityDetail");
      } catch (InvalidConfigValueException e2) {
        System.err.println(
            "Invalid config value for logger.priority in config file: "
                + config.getString(CONF_PRIORITY));
        // Leave it at the default.
      } catch (NodeNeedRestartException e) {
        // impossible
        System.err.println(
            "impossible NodeNeedRestartException for logger.priority in config file: "
                + config.getString(CONF_PRIORITY));
      }
      // Add SLF4J sink first and align its thresholds with the chain / config
      slf4jHook = new Slf4jLoggerHook(LogLevel.DEBUG /* initial; will be overridden below */);
      Logger.globalAddHook(slf4jHook);
      // Align to current chain thresholds and per-section details
      try {
        LoggerHookChain chain = Logger.getChain();
        slf4jHook.setThreshold(chain.getThresholdNew());
        slf4jHook.setDetailedThresholds(chain.getDetailedThresholds());
      } catch (LoggerHook.InvalidThresholdException e) {
        System.err.println("SLF4J hook threshold sync failed: " + e.getMessage());
      }
      // Optional: capture System.out/err to SLF4J when requested
      if (Boolean.getBoolean("crypta.captureStdStreams")) {
        try {
          String enc = StandardCharsets.UTF_8.name();
          // Preserve existing console streams so ConsoleAppender can still emit to the terminal.
          PrintStream origOut = System.out;
          PrintStream origErr = System.err;
          this.originalStdout = origOut;
          this.originalStderr = origErr;
          System.setOut(
              new PrintStream(
                  new TeeOutputStreamLogger(origOut, LogLevel.NORMAL, "Stdout: ", enc),
                  false,
                  enc));
          System.setErr(
              new PrintStream(
                  new TeeOutputStreamLogger(origErr, LogLevel.ERROR, "Stderr: ", enc), false, enc));
          this.capturedStdStreams = true;
        } catch (Exception ignored) {
          // Best-effort; do not fail if we cannot capture
        }
      }

      // Publish weak ref for callbacks to update on future config changes
      slf4jHookRef = new WeakReference<>(slf4jHook);

      // No FileLoggerHook; SLF4J/Logback handles outputs
    }
  }

  /**
   * Reconfigure Logback's rolling file appender to point to a new directory without restarting the
   * JVM.
   */
  @SuppressWarnings("java:S106")
  private void reconfigureLogbackFileDirectory(File newDir) {
    try {
      LoggerContext ctx = resolveLoggerContext();
      if (ctx == null) return;
      AsyncAppender aa = resolveAsyncFileAppender(ctx);
      if (aa == null) return;

      RollingFileAppender<ILoggingEvent> rfa = findRollingFileAppender(aa);
      if (rfa == null) return;

      String datePat = datePatternForInterval(logRotateInterval);
      String newPattern =
          new File(newDir, "crypta-%d{" + datePat + "}.%i.log.gz").getAbsolutePath();
      String newFile = new File(newDir, "crypta-latest.log").getAbsolutePath();

      applyRollingPolicyUpdate(ctx, rfa, newFile, newPattern);
    } catch (Exception e) {
      System.err.println("Failed to reconfigure Logback file directory: " + e);
    }
  }

  private LoggerContext resolveLoggerContext() {
    ILoggerFactory lf = LoggerFactory.getILoggerFactory();
    if (lf instanceof LoggerContext loggercontext) {
      return loggercontext;
    }
    return null;
  }

  private AsyncAppender resolveAsyncFileAppender(LoggerContext ctx) {
    ch.qos.logback.classic.Logger root = ctx.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
    Appender<?> async = root.getAppender("ASYNC_FILE");
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
    // Keep total size cap aligned with configured maxZippedLogsSize
    st.setTotalSizeCap(new FileSize(maxZippedLogsSize));

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

  /** Apply configured total size cap to Logback rolling policy (if present). */
  @SuppressWarnings("java:S106")
  private void updateLogbackTotalSizeCap(long bytes) {
    try {
      ILoggerFactory lf = LoggerFactory.getILoggerFactory();
      if (!(lf instanceof LoggerContext loggercontext)) return;
      ch.qos.logback.classic.Logger root =
          loggercontext.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
      Appender<?> async = root.getAppender("ASYNC_FILE");
      if (!(async instanceof AsyncAppender asyncappender)) return;
      for (Iterator<Appender<ILoggingEvent>> it = asyncappender.iteratorForAppenders();
          it.hasNext(); ) {
        Appender<ILoggingEvent> child = it.next();
        if (child instanceof RollingFileAppender<ILoggingEvent> rfa) {
          RollingPolicy rp = rfa.getRollingPolicy();
          if (rp instanceof SizeAndTimeBasedRollingPolicy<?> st) {
            st.stop();
            st.setTotalSizeCap(new FileSize(bytes));
            // Ensure file pattern reflects current interval as well
            String datePat = datePatternForInterval(logRotateInterval);
            String dir = System.getProperty(SYS_PROP_LOG_DIR, new File(".").getAbsolutePath());
            String pat = new File(dir, "crypta-%d{" + datePat + "}.%i.log.gz").getAbsolutePath();
            st.setFileNamePattern(pat);
            st.start();
          }
          break;
        }
      }
    } catch (Exception e) {
      System.err.println("Failed to update Logback totalSizeCap: " + e);
    }
  }

  /**
   * Map "logger.interval" to a Logback date pattern. Multipliers (>1) are rounded down to base
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
    } catch (Exception ignored) {
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
    } catch (NumberFormatException e) {
      return 1;
    }
  }

  @SuppressWarnings("java:S106")
  protected void disableLogger() {
    synchronized (enableLoggerLock) {
      if (slf4jHook == null) return;
      Logger.globalRemoveHook(slf4jHook);
      slf4jHook = null;
      // If we captured stdout/err earlier, restore the originals so console stays functional
      if (capturedStdStreams) {
        try {
          if (originalStdout != null) System.setOut(originalStdout);
          if (originalStderr != null) System.setErr(originalStderr);
        } catch (Exception t) {
          // Non-fatal: prefer keeping the app running even if we cannot restore
          System.err.println("Failed to restore original std streams: " + t);
        } finally {
          capturedStdStreams = false;
          originalStdout = null;
          originalStderr = null;
        }
      }
      Logger.destroyChainIfEmpty();
    }
  }

  // no helper needed; the weak ref is replaced directly when enabling logger

  protected void preSetLogDir(File f) throws InvalidConfigValueException {
    boolean exists = f.exists();
    if (exists && !f.isDirectory())
      throw new InvalidConfigValueException("Cannot overwrite a file with a log directory");
    if (!exists && !f.mkdir() && !f.isDirectory()) {
      // Ensure directory creation succeeds; treat failure as invalid config
      throw new InvalidConfigValueException("Cannot create log directory");
    }
  }
}
