package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientRequestScheduler;
import network.crypta.client.async.ClientRequestScheduler.SchedulerMode;
import network.crypta.config.Config;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.crypt.RandomSource;
import network.crypta.keys.Key;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.api.StringCallback;
import network.crypta.support.math.BootstrappingDecayingRunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Coordinates request starters and client schedulers for CHK/SSK fetches and inserts.
 *
 * <p>Wires four flows per key type (CHK and SSK): fetch (request) vs. insert, and bulk vs.
 * real-time. Each flow has its own {@link RequestStarter}, {@link BaseRequestThrottle} and {@link
 * ClientRequestScheduler}. The group also maintains several {@link ThrottleWindowManager} instances
 * that adapt concurrency based on observed round-trip times (RTT) and overload events.
 *
 * <p>Thread-safety: public methods are safe to call from the node's scheduling threads. The inner
 * throttle synchronizes state changes where required. Methods that only read state are not
 * synchronized.
 */
public final class RequestStarterGroup {
  private static final Logger LOG = LoggerFactory.getLogger(RequestStarterGroup.class);

  // Scheduler identifiers used in multiple places
  private static final String CHK_REQUESTER_NAME = "CHKrequester";
  private static final String CHK_INSERTER_NAME = "CHKinserter";
  private static final String SSK_REQUESTER_NAME = "SSKrequester";
  private static final String SSK_INSERTER_NAME = "SSKinserter";

  private final ThrottleWindowManager throttleWindowBulk;
  private final ThrottleWindowManager throttleWindowRT;
  // These are used for diagnostic reporting (stats panels, logs)
  private final ThrottleWindowManager throttleWindowCHK;
  private final ThrottleWindowManager throttleWindowSSK;
  private final ThrottleWindowManager throttleWindowInsert;
  private final ThrottleWindowManager throttleWindowRequest;
  final MyRequestThrottle chkRequestThrottleBulk;
  final RequestStarter chkRequestStarterBulk;
  final MyRequestThrottle chkInsertThrottleBulk;
  final RequestStarter chkInsertStarterBulk;
  final MyRequestThrottle sskRequestThrottleBulk;
  final RequestStarter sskRequestStarterBulk;
  final MyRequestThrottle sskInsertThrottleBulk;
  final RequestStarter sskInsertStarterBulk;

  final MyRequestThrottle chkRequestThrottleRT;
  final RequestStarter chkRequestStarterRT;
  final MyRequestThrottle chkInsertThrottleRT;
  final RequestStarter chkInsertStarterRT;
  final MyRequestThrottle sskRequestThrottleRT;
  final RequestStarter sskRequestStarterRT;
  final MyRequestThrottle sskInsertThrottleRT;
  final RequestStarter sskInsertStarterRT;

  /** Scheduler for CHK fetches in bulk mode. */
  public final ClientRequestScheduler chkFetchSchedulerBulk;

  /** Scheduler for CHK inserts in bulk mode. */
  public final ClientRequestScheduler chkPutSchedulerBulk;

  /** Scheduler for SSK fetches in bulk mode. */
  public final ClientRequestScheduler sskFetchSchedulerBulk;

  /** Scheduler for SSK inserts in bulk mode. */
  public final ClientRequestScheduler sskPutSchedulerBulk;

  /** Scheduler for CHK fetches in real-time mode. */
  public final ClientRequestScheduler chkFetchSchedulerRT;

  /** Scheduler for CHK inserts in real-time mode. */
  public final ClientRequestScheduler chkPutSchedulerRT;

  /** Scheduler for SSK fetches in real-time mode. */
  public final ClientRequestScheduler sskFetchSchedulerRT;

  /** Scheduler for SSK inserts in real-time mode. */
  public final ClientRequestScheduler sskPutSchedulerRT;

  private final NodeStats stats;

  RequestStarterGroup(
      Node node,
      NodeClientCore core,
      int portNumber,
      RandomSource random,
      Config config,
      SimpleFieldSet fs,
      ClientContext ctx)
      throws InvalidConfigValueException {
    SubConfig schedulerConfig = config.createSubConfig("node.scheduler");
    this.stats = node.network().stats();

    throttleWindowBulk =
        new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindow"), node);
    throttleWindowRT =
        new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowRT"), node);

    throttleWindowCHK =
        new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowCHK"), node);
    throttleWindowSSK =
        new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowSSK"), node);
    throttleWindowInsert =
        new ThrottleWindowManager(2.0, fs == null ? null : fs.subset("ThrottleWindowInsert"), node);
    throttleWindowRequest =
        new ThrottleWindowManager(
            2.0, fs == null ? null : fs.subset("ThrottleWindowRequest"), node);
    chkRequestThrottleBulk =
        new MyRequestThrottle(
            5000, fs == null ? null : fs.subset("CHKRequestThrottle"), 32768, false);
    chkRequestThrottleRT =
        new MyRequestThrottle(
            5000, fs == null ? null : fs.subset("CHKRequestThrottleRT"), 32768, true);
    chkRequestStarterBulk =
        new RequestStarter(
            core,
            chkRequestThrottleBulk,
            "CHK Request starter (" + portNumber + ')',
            stats.localChkFetchBytesSentAverage,
            stats.localChkFetchBytesReceivedAverage,
            new SchedulerMode(false, false, false));
    chkRequestStarterRT =
        new RequestStarter(
            core,
            chkRequestThrottleRT,
            "CHK Request starter (" + portNumber + ')',
            stats.localChkFetchBytesSentAverage,
            stats.localChkFetchBytesReceivedAverage,
            new SchedulerMode(false, false, true));
    chkFetchSchedulerBulk =
        new ClientRequestScheduler(
            new SchedulerMode(false, false, false),
            random,
            chkRequestStarterBulk,
            node,
            core,
            CHK_REQUESTER_NAME,
            ctx);
    chkFetchSchedulerRT =
        new ClientRequestScheduler(
            new SchedulerMode(false, false, true),
            random,
            chkRequestStarterRT,
            node,
            core,
            CHK_REQUESTER_NAME,
            ctx);
    chkRequestStarterBulk.setScheduler(chkFetchSchedulerBulk);
    chkRequestStarterRT.setScheduler(chkFetchSchedulerRT);

    registerSchedulerConfig(
        schedulerConfig,
        CHK_REQUESTER_NAME,
        chkFetchSchedulerBulk,
        chkFetchSchedulerRT,
        false,
        false);

    chkInsertThrottleBulk =
        new MyRequestThrottle(
            20000, fs == null ? null : fs.subset("CHKInsertThrottle"), 32768, false);
    chkInsertThrottleRT =
        new MyRequestThrottle(
            20000, fs == null ? null : fs.subset("CHKInsertThrottleRT"), 32768, true);
    chkInsertStarterBulk =
        new RequestStarter(
            core,
            chkInsertThrottleBulk,
            "CHK Insert starter (" + portNumber + ')',
            stats.localChkInsertBytesSentAverage,
            stats.localChkInsertBytesReceivedAverage,
            new SchedulerMode(true, false, false));
    chkInsertStarterRT =
        new RequestStarter(
            core,
            chkInsertThrottleRT,
            "CHK Insert starter (" + portNumber + ')',
            stats.localChkInsertBytesSentAverage,
            stats.localChkInsertBytesReceivedAverage,
            new SchedulerMode(true, false, true));
    chkPutSchedulerBulk =
        new ClientRequestScheduler(
            new SchedulerMode(true, false, false),
            random,
            chkInsertStarterBulk,
            node,
            core,
            CHK_INSERTER_NAME,
            ctx);
    chkPutSchedulerRT =
        new ClientRequestScheduler(
            new SchedulerMode(true, false, true),
            random,
            chkInsertStarterRT,
            node,
            core,
            CHK_INSERTER_NAME,
            ctx);
    chkInsertStarterBulk.setScheduler(chkPutSchedulerBulk);
    chkInsertStarterRT.setScheduler(chkPutSchedulerRT);

    registerSchedulerConfig(
        schedulerConfig, CHK_INSERTER_NAME, chkPutSchedulerBulk, chkPutSchedulerRT, false, true);

    sskRequestThrottleBulk =
        new MyRequestThrottle(
            5000, fs == null ? null : fs.subset("SSKRequestThrottle"), 1024, false);
    sskRequestThrottleRT =
        new MyRequestThrottle(
            5000, fs == null ? null : fs.subset("SSKRequestThrottleRT"), 1024, true);
    sskRequestStarterBulk =
        new RequestStarter(
            core,
            sskRequestThrottleBulk,
            "SSK Request starter (" + portNumber + ')',
            stats.localSskFetchBytesSentAverage,
            stats.localSskFetchBytesReceivedAverage,
            new SchedulerMode(false, true, false));
    sskRequestStarterRT =
        new RequestStarter(
            core,
            sskRequestThrottleRT,
            "SSK Request starter (" + portNumber + ')',
            stats.localSskFetchBytesSentAverage,
            stats.localSskFetchBytesReceivedAverage,
            new SchedulerMode(false, true, true));
    sskFetchSchedulerBulk =
        new ClientRequestScheduler(
            new SchedulerMode(false, true, false),
            random,
            sskRequestStarterBulk,
            node,
            core,
            SSK_REQUESTER_NAME,
            ctx);
    sskFetchSchedulerRT =
        new ClientRequestScheduler(
            new SchedulerMode(false, true, true),
            random,
            sskRequestStarterRT,
            node,
            core,
            SSK_REQUESTER_NAME,
            ctx);
    sskRequestStarterBulk.setScheduler(sskFetchSchedulerBulk);
    sskRequestStarterRT.setScheduler(sskFetchSchedulerRT);

    registerSchedulerConfig(
        schedulerConfig,
        SSK_REQUESTER_NAME,
        sskFetchSchedulerBulk,
        sskFetchSchedulerRT,
        true,
        false);

    sskInsertThrottleBulk =
        new MyRequestThrottle(
            20000, fs == null ? null : fs.subset("SSKInsertThrottle"), 1024, false);
    sskInsertThrottleRT =
        new MyRequestThrottle(
            20000, fs == null ? null : fs.subset("SSKInsertThrottleRT"), 1024, true);
    sskInsertStarterBulk =
        new RequestStarter(
            core,
            sskInsertThrottleBulk,
            "SSK Insert starter (" + portNumber + ')',
            stats.localSskInsertBytesSentAverage,
            stats.localSskFetchBytesReceivedAverage,
            new SchedulerMode(true, true, false));
    sskInsertStarterRT =
        new RequestStarter(
            core,
            sskInsertThrottleRT,
            "SSK Insert starter (" + portNumber + ')',
            stats.localSskInsertBytesSentAverage,
            stats.localSskFetchBytesReceivedAverage,
            new SchedulerMode(true, true, true));
    sskPutSchedulerBulk =
        new ClientRequestScheduler(
            new SchedulerMode(true, true, false),
            random,
            sskInsertStarterBulk,
            node,
            core,
            SSK_INSERTER_NAME,
            ctx);
    sskPutSchedulerRT =
        new ClientRequestScheduler(
            new SchedulerMode(true, true, true),
            random,
            sskInsertStarterRT,
            node,
            core,
            SSK_INSERTER_NAME,
            ctx);
    sskInsertStarterBulk.setScheduler(sskPutSchedulerBulk);
    sskInsertStarterRT.setScheduler(sskPutSchedulerRT);

    registerSchedulerConfig(
        schedulerConfig, SSK_INSERTER_NAME, sskPutSchedulerBulk, sskPutSchedulerRT, true, true);

    schedulerConfig.finishedInitialization();
  }

  private void registerSchedulerConfig(
      SubConfig schedulerConfig,
      String name,
      ClientRequestScheduler csBulk,
      ClientRequestScheduler csRT,
      boolean forSSKs,
      boolean forInserts)
      throws InvalidConfigValueException {
    PrioritySchedulerCallback callback = new PrioritySchedulerCallback();
    schedulerConfig.register(
        name + "_priority_policy",
        ClientRequestScheduler.PRIORITY_SOFT,
        new Option.Meta(
            name.hashCode(),
            true,
            false,
            "RequestStarterGroup.scheduler"
                + (forSSKs ? "SSK" : "CHK")
                + (forInserts ? "Inserts" : "Requests"),
            "RequestStarterGroup.schedulerLong"),
        callback);
    callback.init(csRT, csBulk, schedulerConfig.getString(name + "_priority_policy"));
  }

  /**
   * Starts all request starters.
   *
   * <p>After this call, schedulers may launch requests when capacity is available according to
   * their throttles and windows.
   */
  public void start() {
    chkRequestStarterRT.start();
    chkInsertStarterRT.start();
    sskRequestStarterRT.start();
    sskInsertStarterRT.start();
    chkRequestStarterBulk.start();
    chkInsertStarterBulk.start();
    sskRequestStarterBulk.start();
    sskInsertStarterBulk.start();
  }

  /**
   * Adaptive throttle used by request starters to compute per-request delays.
   *
   * <p>The delay is derived from a bootstrapping, decaying running average of the observed
   * round-trip time (RTT) and a simulated window size. This provides back-pressure when the
   * observed RTT increases and relaxes it as conditions improve.
   */
  public class MyRequestThrottle implements BaseRequestThrottle {
    private final BootstrappingDecayingRunningAverage roundTripTime;

    /** Data size, in bytes, used by {@link #getRate()}. */
    private final int size;

    private final boolean realTime;

    /**
     * Creates a new throttle.
     *
     * @param rtt initial round-trip time in milliseconds used to seed the average
     * @param fs optional persisted state; may be {@code null}
     * @param size representative transfer size in bytes for rate estimates
     * @param realTime whether this throttle is for real-time mode
     */
    public MyRequestThrottle(int rtt, SimpleFieldSet fs, int size, boolean realTime) {
      roundTripTime =
          new BootstrappingDecayingRunningAverage(
              rtt, 10, MINUTES.toMillis(5), 10, fs == null ? null : fs.subset("RoundTripTime"));
      this.size = size;
      this.realTime = realTime;
    }

    /**
     * Computes an inter-request delay from the current RTT and window size.
     *
     * <p>Result is clamped to {@code MIN_DELAY..MAX_DELAY} (milliseconds).
     *
     * @return delay in milliseconds before submitting the next request
     */
    @Override
    public synchronized long getDelay() {
      double rtt = roundTripTime.currentValue();
      double winSizeForMinPacketDelay = rtt / MIN_DELAY;
      double simulatedWindowSize = getThrottleWindow().currentValue(realTime);
      if (simulatedWindowSize > winSizeForMinPacketDelay) {
        simulatedWindowSize = winSizeForMinPacketDelay;
      }
      if (simulatedWindowSize < 1.0) {
        simulatedWindowSize = 1.0F;
      }
      return Math.clamp((long) (rtt / simulatedWindowSize), MIN_DELAY, MAX_DELAY);
    }

    private ThrottleWindowManager getThrottleWindow() {
      return RequestStarterGroup.this.getThrottleWindow(realTime);
    }

    /**
     * Reports a successful completion and updates the RTT average.
     *
     * @param rtt observed round-trip time in milliseconds; values below 10 ms are normalized to 10
     *     ms to avoid overreacting to very small samples
     */
    public synchronized void successfulCompletion(long rtt) {
      roundTripTime.report(Math.max(rtt, 10));
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Request completed: rtt={} ms, throttle={}, avg={}",
            rtt,
            this,
            roundTripTime.currentValue());
    }

    /** Returns a short diagnostic string with RTT, window, and mode. */
    @Override
    public String toString() {
      return "rtt: "
          + roundTripTime.currentValue()
          + " _s="
          + getThrottleWindow().currentValue(realTime)
          + " RT="
          + realTime;
    }

    /**
     * Serializes the throttle's internal statistics.
     *
     * @return a field set containing the round-trip time state
     */
    public SimpleFieldSet exportFieldSet() {
      SimpleFieldSet fs = new SimpleFieldSet(false);
      fs.put("RoundTripTime", roundTripTime.exportFieldSet(false));
      return fs;
    }

    /**
     * Returns the current RTT estimate.
     *
     * @return round-trip time in milliseconds
     */
    public double getRTT() {
      return roundTripTime.currentValue();
    }

    /**
     * Estimates throughput for this throttle.
     *
     * @return estimated bytes per second based on {@link #getDelay()} and {@link #size}
     */
    public long getRate() {
      return (long) ((1000.0 / getDelay()) * size);
    }
  }

  /**
   * Configuration callback that applies priority policy to paired schedulers.
   *
   * <p>Exposes two modes: {@code hard} (strict priority) and {@code soft} (priority with
   * randomization). The same value is applied to both the real-time and bulk schedulers.
   */
  public static class PrioritySchedulerCallback extends StringCallback
      implements EnumerableOptionCallback {
    ClientRequestScheduler csRT;
    ClientRequestScheduler csBulk;
    private final String[] possibleValues =
        new String[] {ClientRequestScheduler.PRIORITY_HARD, ClientRequestScheduler.PRIORITY_SOFT};

    /**
     * Initializes the callback and applies the initial configuration value.
     *
     * @param csRT the real-time scheduler
     * @param csBulk the bulk scheduler
     * @param config initial value; if {@code null}, the current setting is retained
     * @throws InvalidConfigValueException if {@code config} is not a supported value
     */
    public void init(ClientRequestScheduler csRT, ClientRequestScheduler csBulk, String config)
        throws InvalidConfigValueException {
      this.csRT = csRT;
      this.csBulk = csBulk;
      set(config);
    }

    /** Returns the currently selected priority policy. */
    @Override
    public String get() {
      if (csBulk != null) return csBulk.getChoosenPriorityScheduler();
      else return ClientRequestScheduler.PRIORITY_SOFT;
    }

    /**
     * Updates the priority policy on both schedulers.
     *
     * @param val new value; case-insensitive
     * @throws InvalidConfigValueException if the value is not recognized
     */
    @Override
    public void set(String val) throws InvalidConfigValueException {
      String value;
      if (val == null || val.equalsIgnoreCase(get())) return;
      if (val.equalsIgnoreCase(ClientRequestScheduler.PRIORITY_HARD)) {
        value = ClientRequestScheduler.PRIORITY_HARD;
      } else if (val.equalsIgnoreCase(ClientRequestScheduler.PRIORITY_SOFT)) {
        value = ClientRequestScheduler.PRIORITY_SOFT;
      } else {
        throw new InvalidConfigValueException("Invalid priority scheme");
      }
      csBulk.setPriorityScheduler(value);
      csRT.setPriorityScheduler(value);
    }

    /** Returns the supported values for tab completion and validation. */
    @Override
    public String[] getPossibleValues() {
      return possibleValues;
    }
  }

  /**
   * Returns the window manager for the requested mode.
   *
   * @param realTime {@code true} for real-time, {@code false} for bulk
   * @return the matching window manager
   */
  public ThrottleWindowManager getThrottleWindow(boolean realTime) {
    if (realTime) return throttleWindowRT;
    else return throttleWindowBulk;
  }

  /**
   * Records a successful request and updates diagnostic windows and stats.
   *
   * @param isSSK whether the request was for SSK; CHK otherwise
   * @param isInsert whether the request was an insert; fetch otherwise
   * @param key key associated with the request (used for location reporting)
   * @param realTime whether the request ran in real-time mode
   */
  public void requestCompleted(boolean isSSK, boolean isInsert, Key key, boolean realTime) {
    getThrottleWindow(realTime).requestCompleted();
    (isSSK ? throttleWindowSSK : throttleWindowCHK).requestCompleted();
    (isInsert ? throttleWindowInsert : throttleWindowRequest).requestCompleted();
    stats.reportOutgoingRequestLocation(key.toNormalizedDouble());
  }

  /**
   * Records a request rejection due to overload and reduces future concurrency.
   *
   * @param isSSK whether the request was for SSK; CHK otherwise
   * @param isInsert whether the request was an insert; fetch otherwise
   * @param realTime whether the request ran in real-time mode
   */
  public void rejectedOverload(boolean isSSK, boolean isInsert, boolean realTime) {
    getThrottleWindow(realTime).rejectedOverload();
    (isSSK ? throttleWindowSSK : throttleWindowCHK).rejectedOverload();
    (isInsert ? throttleWindowInsert : throttleWindowRequest).rejectedOverload();
  }

  /** Persist the throttle data to a SimpleFieldSet. */
  SimpleFieldSet persistToFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(false);
    fs.put("ThrottleWindow", throttleWindowBulk.exportFieldSet(false));
    fs.put("ThrottleWindowRT", throttleWindowRT.exportFieldSet(false));
    fs.put("ThrottleWindowCHK", throttleWindowCHK.exportFieldSet(false));
    // Note: This writes the CHK window under "ThrottleWindowSSK"; use
    // throttleWindowSSK.exportFieldSet(false) if SSK is intended. Confirm and correct mapping.
    fs.put("ThrottleWindowSSK", throttleWindowCHK.exportFieldSet(false));
    fs.put("CHKRequestThrottle", chkRequestThrottleBulk.exportFieldSet());
    fs.put("SSKRequestThrottle", sskRequestThrottleBulk.exportFieldSet());
    fs.put("CHKInsertThrottle", chkInsertThrottleBulk.exportFieldSet());
    fs.put("SSKInsertThrottle", sskInsertThrottleBulk.exportFieldSet());
    fs.put("CHKRequestThrottleRT", chkRequestThrottleRT.exportFieldSet());
    fs.put("SSKRequestThrottleRT", sskRequestThrottleRT.exportFieldSet());
    fs.put("CHKInsertThrottleRT", chkInsertThrottleRT.exportFieldSet());
    fs.put("SSKInsertThrottleRT", sskInsertThrottleRT.exportFieldSet());
    return fs;
  }

  /**
   * Returns the simulated window size for the given mode.
   *
   * @param realTime {@code true} for real-time, {@code false} for bulk
   * @return dimensionless window size used by throttles
   */
  public double getWindow(boolean realTime) {
    return getThrottleWindow(realTime).currentValue(realTime);
  }

  /**
   * Returns the current RTT estimate for the specified flow.
   *
   * @param isSSK whether the flow is SSK; CHK otherwise
   * @param isInsert whether the flow is an insert; fetch otherwise
   * @param realTime whether the flow is real-time vs. bulk
   * @return round-trip time in milliseconds
   */
  public double getRTT(boolean isSSK, boolean isInsert, boolean realTime) {
    return getThrottle(isSSK, isInsert, realTime).getRTT();
  }

  /**
   * Returns the current inter-request delay estimate for the specified flow.
   *
   * @param isSSK whether the flow is SSK; CHK otherwise
   * @param isInsert whether the flow is an insert; fetch otherwise
   * @param realTime whether the flow is real-time vs. bulk
   * @return delay in milliseconds
   */
  public double getDelay(boolean isSSK, boolean isInsert, boolean realTime) {
    return getThrottle(isSSK, isInsert, realTime).getDelay();
  }

  MyRequestThrottle getThrottle(boolean isSSK, boolean isInsert, boolean realTime) {
    if (realTime) {
      if (isSSK) {
        return isInsert ? sskInsertThrottleRT : sskRequestThrottleRT;
      }
      return isInsert ? chkInsertThrottleRT : chkRequestThrottleRT;
    }
    if (isSSK) {
      return isInsert ? sskInsertThrottleBulk : sskRequestThrottleBulk;
    }
    return isInsert ? chkInsertThrottleBulk : chkRequestThrottleBulk;
  }

  /**
   * Builds a single-line status string for UI/diagnostics.
   *
   * @param isSSK whether the flow is SSK; CHK otherwise
   * @param isInsert whether the flow is an insert; fetch otherwise
   * @param realTime whether the flow is real-time vs. bulk
   * @return a human-readable line containing type, mode, RTT, delay, and bandwidth
   */
  public String statsPageLine(boolean isSSK, boolean isInsert, boolean realTime) {
    StringBuilder sb = new StringBuilder(100);
    sb.append(isSSK ? "SSK" : "CHK");
    sb.append(' ');
    sb.append(isInsert ? "Insert" : "Request");
    sb.append(' ');
    sb.append(realTime ? "RealTime" : "Bulk");
    sb.append(" RTT=");
    MyRequestThrottle throttle = getThrottle(isSSK, isInsert, realTime);
    sb.append(TimeUtil.formatTime((long) throttle.getRTT(), 2, true));
    sb.append(" delay=");
    sb.append(TimeUtil.formatTime(throttle.getDelay(), 2, true));
    sb.append(" bw=");
    sb.append(throttle.getRate());
    sb.append("B/sec");
    return sb.toString();
  }

  /**
   * Builds a diagnostic string with either request/insert or CHK/SSK windows.
   *
   * @param mode when {@code true}, shows request vs. insert; when {@code false}, shows CHK vs. SSK
   * @return a human-readable diagnostic string
   */
  public String diagnosticThrottlesLine(boolean mode) {
    StringBuilder sb = new StringBuilder();
    if (mode) {
      sb.append("Request window: ");
      sb.append(throttleWindowRequest.toString());
      sb.append(", Insert window: ");
      sb.append(throttleWindowInsert.toString());
    } else {
      sb.append("CHK window: ");
      sb.append(throttleWindowCHK.toString());
      sb.append(", SSK window: ");
      sb.append(throttleWindowSSK.toString());
    }
    return sb.toString();
  }

  /**
   * Returns the non-simulated (real) window size for the given mode.
   *
   * @param realTime {@code true} for real-time, {@code false} for bulk
   * @return current window size as tracked by the manager
   */
  public double getRealWindow(boolean realTime) {
    return getThrottleWindow(realTime).realCurrentValue();
  }

  /**
   * Counts the total number of requests queued across all schedulers.
   *
   * @return total queued count (bulk + real-time, CHK + SSK, fetch + insert)
   */
  public long countQueuedRequests() {
    return chkFetchSchedulerBulk.countQueuedRequests()
        + sskFetchSchedulerBulk.countQueuedRequests()
        + chkPutSchedulerBulk.countQueuedRequests()
        + sskPutSchedulerBulk.countQueuedRequests()
        + chkFetchSchedulerRT.countQueuedRequests()
        + sskFetchSchedulerRT.countQueuedRequests()
        + chkPutSchedulerRT.countQueuedRequests()
        + sskPutSchedulerRT.countQueuedRequests();
  }

  /**
   * Returns the scheduler matching the requested dimensions.
   *
   * @param ssk {@code true} for SSK; {@code false} for CHK
   * @param insert {@code true} for inserts; {@code false} for fetches
   * @param realTime {@code true} for real-time; {@code false} for bulk
   * @return the corresponding scheduler instance
   */
  public ClientRequestScheduler getScheduler(boolean ssk, boolean insert, boolean realTime) {
    if (realTime) {
      if (insert) {
        return ssk ? sskPutSchedulerRT : chkPutSchedulerRT;
      }
      return ssk ? sskFetchSchedulerRT : chkFetchSchedulerRT;
    }
    if (insert) {
      return ssk ? sskPutSchedulerBulk : chkPutSchedulerBulk;
    }
    return ssk ? sskFetchSchedulerBulk : chkFetchSchedulerBulk;
  }

  /**
   * Passes a salt to all schedulers so they can initialize keyed behavior.
   *
   * @param salt opaque salt value shared across schedulers; not {@code null}
   */
  public void setGlobalSalt(byte[] salt) {
    chkFetchSchedulerBulk.startCore(salt);
    sskFetchSchedulerBulk.startCore(salt);
    chkPutSchedulerBulk.startCore(salt);
    sskPutSchedulerBulk.startCore(salt);
    chkFetchSchedulerRT.startCore(salt);
    sskFetchSchedulerRT.startCore(salt);
    chkPutSchedulerRT.startCore(salt);
    sskPutSchedulerRT.startCore(salt);
  }
}
