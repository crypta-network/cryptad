package network.crypta.node;

import java.io.File;
import java.util.ArrayList;
import network.crypta.config.Dimension;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.OptionFormatException;
import network.crypta.config.SubConfig;
import network.crypta.support.Executor;
import network.crypta.support.Logger;
import network.crypta.support.Logger.LogLevel;
import network.crypta.support.LoggerHook;
import network.crypta.support.LoggerHook.InvalidThresholdException;
import network.crypta.support.LoggerHookChain;
import network.crypta.support.Slf4jLoggerHook;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.StringCallback;

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
        // Keep SLF4J hook aligned when present
        if (slf4jHookRef != null && slf4jHookRef.get() != null) {
          try {
            slf4jHookRef.get().setThreshold(val);
          } catch (LoggerHook.InvalidThresholdException e) {
            // Fall through to consistent error handling below
            throw e;
          }
        }
      } catch (LoggerHook.InvalidThresholdException e) {
        throw new OptionFormatException(e.getMessage());
      }
    }

    @Override
    public String[] getPossibleValues() {
      LogLevel[] priorities = LogLevel.values();
      ArrayList<String> values = new ArrayList<>(priorities.length + 1);
      for (LogLevel p : priorities) values.add(p.name());

      return values.toArray(new String[0]);
    }
  }

  protected static final String LOG_PREFIX = "freenet";
  private final SubConfig config;
  // FileLoggerHook removed; SLF4J/Logback handles outputs
  private Slf4jLoggerHook slf4jHook;
  // Weak reference to allow static callbacks to update the hook without leaks
  private static java.lang.ref.WeakReference<Slf4jLoggerHook> slf4jHookRef =
      new java.lang.ref.WeakReference<>(null);
  private File logDir;
  private long maxZippedLogsSize;
  private String logRotateInterval;
  private long maxCachedLogBytes;
  private int maxCachedLogLines;
  private long maxBacklogNotBusy;
  private final Executor executor;

  public LoggingConfigHandler(SubConfig loggingConfig, Executor executor)
      throws InvalidConfigValueException {
    this.config = loggingConfig;
    this.executor = executor;

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
          public void set(Boolean val) throws InvalidConfigValueException {
            if (val == (slf4jHook != null)) return;
            if (!val) {
              disableLogger();
            } else {
              enableLogger();
            }
          }
        });

    boolean loggingEnabled = loggingConfig.getBoolean("enabled");

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
            System.setProperty("crypta.log.dir", logDir.getAbsolutePath());
            // Reconfigure Logback file appender to the new directory immediately
            reconfigureLogbackFileDirectory(logDir);
          }
        });

    logDir = new File(config.getString("dirname"));
    // Initialize SLF4J rolling file location to mirror FileLoggerHook directory
    System.setProperty("crypta.log.dir", logDir.getAbsolutePath());
    // Ensure Logback's file appender targets the initial directory
    reconfigureLogbackFileDirectory(logDir);
    if (loggingEnabled) {
      preSetLogDir(logDir);
    }
    // => enableLogger must run preSetLogDir

    // max space used by zipped logs

    config.register(
        "maxZippedLogsSize",
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
          public void set(Long val) throws InvalidConfigValueException {
            if (val < 0) val = 0L;
            maxZippedLogsSize = val;
            // Apply to Logback rolling policy immediately
            updateLogbackTotalSizeCap(maxZippedLogsSize);
          }
        },
        true);

    maxZippedLogsSize = config.getLong("maxZippedLogsSize");
    // Ensure Logback picks up the configured cap at startup
    updateLogbackTotalSizeCap(maxZippedLogsSize);

    // These two are forced below so we don't need to check them now

    // priority

    // Node must override this to minor on testnet.
    config.register(
        "priority",
        "warning",
        4,
        false,
        false,
        "LogConfigHandler.minLoggingPriority",
        "LogConfigHandler.minLoggingPriorityLong",
        new PriorityCallback());

    // detailed priority

    config.register(
        "priorityDetail",
        "",
        5,
        true,
        false,
        "LogConfigHandler.detaildPriorityThreshold",
        "LogConfigHandler.detaildPriorityThresholdLong",
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
              if (slf4jHookRef != null && slf4jHookRef.get() != null) {
                slf4jHookRef.get().setDetailedThresholds(val);
              }
            } catch (InvalidThresholdException e) {
              throw new InvalidConfigValueException(e.getMessage());
            }
          }
        });

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
          public void set(String val) throws InvalidConfigValueException {
            logRotateInterval = val;
            // Apply new interval to Logback rolling pattern immediately
            reconfigureLogbackFileDirectory(logDir);
          }
        });

    logRotateInterval = config.getString("interval");
    // Apply current interval to Logback pattern at startup
    reconfigureLogbackFileDirectory(logDir);

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
          public void set(Long val) throws InvalidConfigValueException {
            if (val < 0) val = 0L;
            if (val == maxCachedLogBytes) return;
            maxCachedLogBytes = val;
            // No-op under SLF4J/Logback
          }
        },
        true);

    maxCachedLogBytes = config.getLong("maxCachedBytes");

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
          public void set(Integer val)
              throws InvalidConfigValueException, NodeNeedRestartException {
            if (val < 0) val = 0;
            if (val == maxCachedLogLines) return;
            maxCachedLogLines = val;
            throw new NodeNeedRestartException("logger.maxCachedLogLines");
          }
        },
        Dimension.NOT);

    maxCachedLogLines = config.getInt("maxCachedLines");

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
          public void set(Long val) throws InvalidConfigValueException, NodeNeedRestartException {
            if (val < 0) throw new InvalidConfigValueException("Must be >= 0");
            if (val == maxBacklogNotBusy) return;
            maxBacklogNotBusy = val;
            // No-op under SLF4J/Logback
          }
        },
        false);

    maxBacklogNotBusy = config.getLong("maxBacklogNotBusy");

    if (loggingEnabled) enableLogger();
    config.finishedInitialization();
  }

  private final Object enableLoggerLock = new Object();

  /** Turn on the logger. */
  private void enableLogger() {
    try {
      preSetLogDir(logDir);
    } catch (InvalidConfigValueException e3) {
      System.err.println("Cannot set log dir: " + logDir + ": " + e3);
      e3.printStackTrace();
    }
    synchronized (enableLoggerLock) {
      if (slf4jHook != null) return;
      Logger.setupChain();
      try {
        config.forceUpdate("priority");
        config.forceUpdate("priorityDetail");
      } catch (InvalidConfigValueException e2) {
        System.err.println(
            "Invalid config value for logger.priority in config file: "
                + config.getString("priority"));
        // Leave it at the default.
      } catch (NodeNeedRestartException e) {
        // impossible
        System.err.println(
            "impossible NodeNeedRestartException for logger.priority in config file: "
                + config.getString("priority"));
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
          String enc = java.nio.charset.StandardCharsets.UTF_8.name();
          System.setOut(
              new java.io.PrintStream(
                  new network.crypta.support.OutputStreamLogger(LogLevel.NORMAL, "Stdout: ", enc),
                  false,
                  enc));
          System.setErr(
              new java.io.PrintStream(
                  new network.crypta.support.OutputStreamLogger(LogLevel.ERROR, "Stderr: ", enc),
                  false,
                  enc));
        } catch (Exception ignored) {
          // Best-effort; do not fail if we cannot capture
        }
      }

      // Publish weak ref for callbacks to update on future config changes
      slf4jHookRef = new java.lang.ref.WeakReference<>(slf4jHook);

      // No FileLoggerHook; SLF4J/Logback handles outputs
    }
  }

  /**
   * Reconfigure Logback's rolling file appender to point to a new directory without restarting the
   * JVM.
   */
  private void reconfigureLogbackFileDirectory(File newDir) {
    try {
      org.slf4j.ILoggerFactory lf = org.slf4j.LoggerFactory.getILoggerFactory();
      if (!(lf instanceof ch.qos.logback.classic.LoggerContext)) return;
      ch.qos.logback.classic.LoggerContext ctx = (ch.qos.logback.classic.LoggerContext) lf;
      ch.qos.logback.classic.Logger root = ctx.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
      ch.qos.logback.core.Appender<?> async = root.getAppender("ASYNC_FILE");
      if (!(async instanceof ch.qos.logback.classic.AsyncAppender)) return;
      ch.qos.logback.classic.AsyncAppender aa = (ch.qos.logback.classic.AsyncAppender) async;
      for (java.util.Iterator<
                  ch.qos.logback.core.Appender<ch.qos.logback.classic.spi.ILoggingEvent>>
              it = aa.iteratorForAppenders();
          it.hasNext(); ) {
        ch.qos.logback.core.Appender<ch.qos.logback.classic.spi.ILoggingEvent> child = it.next();
        if (child instanceof ch.qos.logback.core.rolling.RollingFileAppender) {
          ch.qos.logback.core.rolling.RollingFileAppender<ch.qos.logback.classic.spi.ILoggingEvent>
              rfa =
                  (ch.qos.logback.core.rolling.RollingFileAppender<
                          ch.qos.logback.classic.spi.ILoggingEvent>)
                      child;
          String newFile = new File(newDir, "crypta-latest.log").getAbsolutePath();
          String datePat = datePatternForInterval(logRotateInterval);
          String newPattern =
              new File(newDir, "crypta-%d{" + datePat + "}.%i.log.gz").getAbsolutePath();

          // Stop, update, and restart the rolling policy and appender
          rfa.stop();
          ch.qos.logback.core.rolling.RollingPolicy rp = rfa.getRollingPolicy();
          if (rp instanceof ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy) {
            ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy<
                    ch.qos.logback.classic.spi.ILoggingEvent>
                st =
                    (ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy<
                            ch.qos.logback.classic.spi.ILoggingEvent>)
                        rp;
            st.stop();
            st.setFileNamePattern(newPattern);
            // Keep total size cap aligned with configured maxZippedLogsSize
            st.setTotalSizeCap(new ch.qos.logback.core.util.FileSize(maxZippedLogsSize));
            st.start();
          }
          rfa.setFile(newFile);
          rfa.start();
          break; // updated first rolling file appender
        }
      }
    } catch (Throwable t) {
      System.err.println("Failed to reconfigure Logback file directory: " + t);
    }
  }

  /** Apply configured total size cap to Logback rolling policy (if present). */
  private void updateLogbackTotalSizeCap(long bytes) {
    try {
      org.slf4j.ILoggerFactory lf = org.slf4j.LoggerFactory.getILoggerFactory();
      if (!(lf instanceof ch.qos.logback.classic.LoggerContext)) return;
      ch.qos.logback.classic.LoggerContext ctx = (ch.qos.logback.classic.LoggerContext) lf;
      ch.qos.logback.classic.Logger root = ctx.getLogger(org.slf4j.Logger.ROOT_LOGGER_NAME);
      ch.qos.logback.core.Appender<?> async = root.getAppender("ASYNC_FILE");
      if (!(async instanceof ch.qos.logback.classic.AsyncAppender)) return;
      ch.qos.logback.classic.AsyncAppender aa = (ch.qos.logback.classic.AsyncAppender) async;
      for (java.util.Iterator<
                  ch.qos.logback.core.Appender<ch.qos.logback.classic.spi.ILoggingEvent>>
              it = aa.iteratorForAppenders();
          it.hasNext(); ) {
        ch.qos.logback.core.Appender<ch.qos.logback.classic.spi.ILoggingEvent> child = it.next();
        if (child instanceof ch.qos.logback.core.rolling.RollingFileAppender) {
          ch.qos.logback.core.rolling.RollingFileAppender<ch.qos.logback.classic.spi.ILoggingEvent>
              rfa =
                  (ch.qos.logback.core.rolling.RollingFileAppender<
                          ch.qos.logback.classic.spi.ILoggingEvent>)
                      child;
          ch.qos.logback.core.rolling.RollingPolicy rp = rfa.getRollingPolicy();
          if (rp instanceof ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy) {
            ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy<
                    ch.qos.logback.classic.spi.ILoggingEvent>
                st =
                    (ch.qos.logback.core.rolling.SizeAndTimeBasedRollingPolicy<
                            ch.qos.logback.classic.spi.ILoggingEvent>)
                        rp;
            st.stop();
            st.setTotalSizeCap(new ch.qos.logback.core.util.FileSize(bytes));
            // Ensure file pattern reflects current interval as well
            String datePat = datePatternForInterval(logRotateInterval);
            String dir =
                System.getProperty("crypta.log.dir", new java.io.File(".").getAbsolutePath());
            String pat =
                new java.io.File(dir, "crypta-%d{" + datePat + "}.%i.log.gz").getAbsolutePath();
            st.setFileNamePattern(pat);
            st.start();
          }
          break;
        }
      }
    } catch (Throwable t) {
      System.err.println("Failed to update Logback totalSizeCap: " + t);
    }
  }

  /**
   * Map logger.interval to a Logback date pattern. Multipliers (>1) are rounded down to base unit.
   */
  private String datePatternForInterval(String configured) {
    if (configured == null || configured.isEmpty()) return "yyyy-MM-dd_HH"; // default hourly
    String s = configured.trim().toUpperCase();
    // Strip optional trailing 'S'
    if (s.endsWith("S")) s = s.substring(0, s.length() - 1);
    // Extract numeric prefix (we ignore it for Logback granularity)
    int i = 0;
    while (i < s.length() && Character.isDigit(s.charAt(i))) i++;
    String unit = (i == 0) ? s : s.substring(i);
    switch (unit) {
      case "MINUTE":
        return "yyyy-MM-dd_HH-mm";
      case "HOUR":
        return "yyyy-MM-dd_HH";
      case "DAY":
        return "yyyy-MM-dd";
      case "WEEK_OF_YEAR":
      case "WEEK":
        return "YYYY-ww"; // ISO week-based year
      case "MONTH":
        return "yyyy-MM";
      case "YEAR":
        return "yyyy";
      default:
        return "yyyy-MM-dd_HH";
    }
  }

  protected void disableLogger() {
    synchronized (enableLoggerLock) {
      if (slf4jHook == null) return;
      if (slf4jHook != null) {
        Logger.globalRemoveHook(slf4jHook);
        slf4jHook = null;
      }
      Logger.destroyChainIfEmpty();
    }
  }

  // no helper needed; the weak ref is replaced directly when enabling logger

  protected void preSetLogDir(File f) throws InvalidConfigValueException {
    boolean exists = f.exists();
    if (exists && !f.isDirectory())
      throw new InvalidConfigValueException("Cannot overwrite a file with a log directory");
    if (!exists) {
      f.mkdir();
      exists = f.exists();
      if (!exists || !f.isDirectory())
        throw new InvalidConfigValueException("Cannot create log directory");
    }
  }

  // Deleter and getFileLoggerHook removed with FileLoggerHook

  public void forceEnableLogging() {
    enableLogger();
  }

  public long getMaxZippedLogFiles() {
    return maxZippedLogsSize;
  }

  public void setMaxZippedLogFiles(String maxSizeAsString)
      throws InvalidConfigValueException, NodeNeedRestartException {
    config.set("maxZippedLogsSize", maxSizeAsString);
  }
}
