package network.crypta.support.math;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.util.function.LongSupplier;
import network.crypta.node.TimeSkewDetectorCallback;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exponentially time‑decaying running average.
 *
 * <p>This implementation applies exponential smoothing where each new observation is weighted by
 * the time elapsed since the previous accepted observation. Given a half‑life {@code H}
 * (milliseconds) and a monotonic elapsed interval {@code dt} (milliseconds), the decay factor is:
 *
 * <pre>
 *   decay = 0.5 ^ (dt / H)
 *   current = (current * decay) + (1 - decay) * reportedValue
 * </pre>
 *
 * <p>Consequences:
 *
 * <ul>
 *   <li>If {@code dt == H} then the new value contributes 50% to the updated average.
 *   <li>Short intervals yield a decay close to 1 (small influence of the new value), while long
 *       intervals yield a decay close to 0 (the new value dominates).
 *   <li>Elapsed time is computed from a monotonic time source to make the average resilient to
 *       wall‑clock adjustments. Wall‑clock time is only used for human‑readable timestamps and
 *       persistence metadata.
 * </ul>
 *
 * <p>Inputs outside the configured range {@code [min, max]} and non‑finite values are ignored (they
 * do not change the current value and do not advance time), but they are counted as invalid events
 * in logs. The first valid report sets the current value directly and marks the series as started.
 *
 * <p>Thread‑safety: All public methods are thread‑safe. The class uses internal synchronization to
 * ensure a consistent view of state and to compute decays atomically.
 *
 * <p>Copying: Use the copy constructor or {@link RunningAverage#copyOf(RunningAverage)}. The
 * snapshot produced by the copy constructor is independent of future updates to the original.
 *
 * <p>Persistence: The instance can be serialized in two ways:
 *
 * <ul>
 *   <li>Binary stream via {@link #writeDataTo(DataOutputStream)} and the corresponding constructor
 *       that reads from {@link DataInputStream}.
 *   <li>Human‑readable map via {@link #exportFieldSet(boolean)}. When restored with a non‑null
 *       {@link SimpleFieldSet} and {@code Started=true}, the first subsequent report only
 *       initializes timestamps and does not alter {@code currentValue}. This avoids a warm‑up spike
 *       from an arbitrarily long pause while persisted.
 * </ul>
 */
public final class TimeDecayingRunningAverage implements RunningAverage {
  private static final Logger LOG = LoggerFactory.getLogger(TimeDecayingRunningAverage.class);

  @Serial private static final long serialVersionUID = -1;
  static final int MAGIC = 0x5ff4ac94;

  // Reused literals
  private static final String LOG_MSG_CREATED = "Created {}";
  private static final String FS_KEY_STARTED = "Started";
  private static final String FS_KEY_CURRENT_VALUE = "CurrentValue";
  private static final String FS_KEY_TOTAL_REPORTS = "TotalReports";
  private static final String FS_KEY_UPTIME = "Uptime";
  private static final String LOG_LIT_WAS = " was ";

  // Copying is via the copy constructor.

  double curValue;
  final double halfLife;
  long lastReportTime;
  long createdTime;
  long lastMonotonicNanos;
  long totalReports;
  boolean started;
  double defaultValue;
  double minReport;
  double maxReport;

  private final transient TimeSkewDetectorCallback timeSkewCallback;
  private transient LongSupplier wallClockTimeSourceMillis;
  private transient LongSupplier monotonicTimeSourceNanos;

  @Override
  public String toString() {
    long now =
        wallClockTimeSourceMillis == null
            ? System.currentTimeMillis()
            : wallClockTimeSourceMillis.getAsLong();
    synchronized (this) {
      return super.toString()
          + ": currentValue="
          + curValue
          + ", halfLife="
          + halfLife
          + ", lastReportTime="
          + (now - lastReportTime)
          + "ms ago, createdTime="
          + (now - createdTime)
          + "ms ago, totalReports="
          + totalReports
          + ", started="
          + started
          + ", defaultValue="
          + defaultValue
          + ", min="
          + minReport
          + ", max="
          + maxReport;
    }
  }

  /**
   * Creates a new average starting at {@code defaultValue} and decaying with the given half‑life.
   *
   * @param defaultValue initial value returned by {@link #currentValue()} until the first valid
   *     {@link #report(double)} is accepted
   * @param halfLife half‑life in milliseconds; when {@code 0}, a minimum of {@code 1 ms} is used to
   *     avoid division by zero
   * @param min minimum accepted observation (inclusive); lower values are ignored
   * @param max maximum accepted observation (inclusive); higher values are ignored
   * @param callback optional callback used to signal negative wall‑clock drift; may be {@code null}
   */
  public TimeDecayingRunningAverage(
      double defaultValue,
      long halfLife,
      double min,
      double max,
      TimeSkewDetectorCallback callback) {
    curValue = defaultValue;
    this.defaultValue = defaultValue;
    started = false;
    this.halfLife = halfLife;
    this.wallClockTimeSourceMillis = System::currentTimeMillis;
    this.monotonicTimeSourceNanos = System::nanoTime;
    createdTime = lastReportTime = wallClockTimeSourceMillis.getAsLong();
    lastMonotonicNanos = monotonicTimeSourceNanos.getAsLong();
    this.minReport = min;
    this.maxReport = max;
    totalReports = 0;

    if (LOG.isTraceEnabled()) LOG.trace(LOG_MSG_CREATED, this);
    this.timeSkewCallback = callback;
  }

  /**
   * Creates a new average, optionally restoring state from a {@link SimpleFieldSet} snapshot.
   *
   * <p>When {@code fs} is non‑null and contains {@code Started=true}, the fields {@code
   * CurrentValue}, {@code TotalReports} and {@code Uptime} are validated and used. The first
   * subsequent {@link #report(double)} updates internal timestamps without changing the current
   * value, preventing a large jump after a long persisted pause.
   *
   * @param defaultValue initial value before the first valid report
   * @param halfLife half‑life in milliseconds
   * @param min minimum accepted observation (inclusive)
   * @param max maximum accepted observation (inclusive)
   * @param fs optional snapshot to restore from; may be {@code null}
   * @param callback optional callback used to signal negative wall‑clock drift; may be {@code null}
   */
  public TimeDecayingRunningAverage(
      double defaultValue,
      long halfLife,
      double min,
      double max,
      SimpleFieldSet fs,
      TimeSkewDetectorCallback callback) {
    curValue = defaultValue;
    this.defaultValue = defaultValue;
    started = false;
    this.halfLife = halfLife;
    this.wallClockTimeSourceMillis = System::currentTimeMillis;
    this.monotonicTimeSourceNanos = System::nanoTime;
    createdTime = wallClockTimeSourceMillis.getAsLong();
    this.lastReportTime = -1; // long warm-up may skew results, so lets wait for the first report
    this.lastMonotonicNanos = monotonicTimeSourceNanos.getAsLong();
    this.minReport = min;
    this.maxReport = max;
    totalReports = 0;

    if (LOG.isTraceEnabled()) LOG.trace(LOG_MSG_CREATED, this);
    if (fs != null) {
      started = fs.getBoolean(FS_KEY_STARTED, false);
      if (started) {
        curValue = fs.getDouble(FS_KEY_CURRENT_VALUE, curValue);
        if (curValue > maxReport || curValue < minReport || Double.isNaN(curValue)) {
          curValue = defaultValue;
          totalReports = 0;
          createdTime = wallClockTimeSourceMillis.getAsLong();
        } else {
          totalReports = fs.getLong(FS_KEY_TOTAL_REPORTS, 0);
          long uptime = fs.getLong(FS_KEY_UPTIME, 0);
          createdTime = wallClockTimeSourceMillis.getAsLong() - uptime;
        }
      }
    }
    this.timeSkewCallback = callback;
  }

  /**
   * Test‑friendly constructor with injectable time sources.
   *
   * <p>This overload behaves like the {@link #TimeDecayingRunningAverage(double, long, double,
   * double, SimpleFieldSet, TimeSkewDetectorCallback)} constructor but uses the given time
   * suppliers instead of the system clocks.
   *
   * @param defaultValue initial value before the first valid report
   * @param halfLife half‑life in milliseconds
   * @param min minimum accepted observation (inclusive)
   * @param max maximum accepted observation (inclusive)
   * @param fs optional snapshot to restore from; may be {@code null}
   * @param callback optional callback used to signal negative wall‑clock drift; may be {@code null}
   * @param wallClockTimeSourceMillis wall‑clock time supplier returning milliseconds since epoch
   * @param monotonicTimeSourceNanos monotonic time supplier returning nanoseconds
   */
  public TimeDecayingRunningAverage(
      double defaultValue,
      long halfLife,
      double min,
      double max,
      SimpleFieldSet fs,
      TimeSkewDetectorCallback callback,
      LongSupplier wallClockTimeSourceMillis,
      LongSupplier monotonicTimeSourceNanos) {
    curValue = defaultValue;
    this.defaultValue = defaultValue;
    started = false;
    this.halfLife = halfLife;
    this.wallClockTimeSourceMillis = wallClockTimeSourceMillis;
    this.monotonicTimeSourceNanos = monotonicTimeSourceNanos;
    createdTime = this.wallClockTimeSourceMillis.getAsLong();
    this.lastReportTime = -1; // wait for first report
    this.lastMonotonicNanos = this.monotonicTimeSourceNanos.getAsLong();
    this.minReport = min;
    this.maxReport = max;
    totalReports = 0;

    if (LOG.isTraceEnabled()) LOG.trace(LOG_MSG_CREATED, this);
    if (fs != null) {
      started = fs.getBoolean(FS_KEY_STARTED, false);
      if (started) {
        curValue = fs.getDouble(FS_KEY_CURRENT_VALUE, curValue);
        if (curValue > maxReport || curValue < minReport || Double.isNaN(curValue)) {
          curValue = defaultValue;
          totalReports = 0;
          createdTime = this.wallClockTimeSourceMillis.getAsLong();
        } else {
          totalReports = fs.getLong(FS_KEY_TOTAL_REPORTS, 0);
          long uptime = fs.getLong(FS_KEY_UPTIME, 0);
          createdTime = this.wallClockTimeSourceMillis.getAsLong() - uptime;
        }
      }
    }
    this.timeSkewCallback = callback;
  }

  /**
   * Restores an instance from a compact binary stream.
   *
   * <p>The stream format is:
   *
   * <ol>
   *   <li>int {@code MAGIC}
   *   <li>int {@code version} (currently {@code 1})
   *   <li>double {@code currentValue}
   *   <li>boolean {@code started}
   *   <li>long {@code totalReports}
   *   <li>long {@code priorExperienceTimeMillis} (uptime)
   * </ol>
   *
   * <p>Monotonic timestamps are reinitialized on load; the first subsequent report will compute
   * decay using the new monotonic baseline.
   *
   * @param defaultValue default value used if the serialized value is invalid or out of range
   * @param halfLife half‑life in milliseconds
   * @param min minimum accepted observation (inclusive)
   * @param max maximum accepted observation (inclusive)
   * @param dis input stream positioned at the beginning of the record
   * @param callback optional callback used to signal negative wall‑clock drift; may be {@code null}
   * @throws IOException if the stream is malformed or contains out‑of‑range/non‑finite values
   */
  public TimeDecayingRunningAverage(
      double defaultValue,
      double halfLife,
      double min,
      double max,
      DataInputStream dis,
      TimeSkewDetectorCallback callback)
      throws IOException {
    int m = dis.readInt();
    if (m != MAGIC) throw new IOException("Invalid magic " + m);
    int v = dis.readInt();
    if (v != 1) throw new IOException("Invalid version " + v);
    curValue = dis.readDouble();
    if (Double.isInfinite(curValue) || Double.isNaN(curValue))
      throw new IOException("Invalid weightedTotal: " + curValue);
    if ((curValue < min) || (curValue > max))
      throw new IOException("Out of range: curValue = " + curValue);
    started = dis.readBoolean();
    // Read fields in the same order they are written: totalReports first, then uptime
    totalReports = dis.readLong();
    long priorExperienceTime = dis.readLong();
    this.halfLife = halfLife;
    this.minReport = min;
    this.maxReport = max;
    this.defaultValue = defaultValue;

    this.wallClockTimeSourceMillis = System::currentTimeMillis;
    this.monotonicTimeSourceNanos = System::nanoTime;
    lastReportTime = -1;
    createdTime = wallClockTimeSourceMillis.getAsLong() - priorExperienceTime;
    lastMonotonicNanos = monotonicTimeSourceNanos.getAsLong();
    this.timeSkewCallback = callback;
  }

  /**
   * Copy constructor creating an independent snapshot of {@code a}.
   *
   * <p>The copy will not observe future updates to {@code a} and preserves the same time sources.
   *
   * @param a instance to copy; must not be {@code null}
   */
  public TimeDecayingRunningAverage(TimeDecayingRunningAverage a) {
    Snapshot s = a.snapshot();
    this.createdTime = s.createdTime;
    this.defaultValue = s.defaultValue;
    this.halfLife = s.halfLife;
    this.lastReportTime = s.lastReportTime;
    this.lastMonotonicNanos = s.lastMonotonicNanos;
    this.maxReport = s.maxReport;
    this.minReport = s.minReport;
    this.started = s.started;
    this.totalReports = s.totalReports;
    this.curValue = s.curValue;
    this.timeSkewCallback = s.timeSkewCallback;
    this.wallClockTimeSourceMillis = s.wallClockTimeSourceMillis;
    this.monotonicTimeSourceNanos = s.monotonicTimeSourceNanos;
  }

  private static final class Snapshot {
    long createdTime;
    double defaultValue;
    double halfLife;
    long lastReportTime;
    long lastMonotonicNanos;
    double maxReport;
    double minReport;
    boolean started;
    long totalReports;
    double curValue;
    TimeSkewDetectorCallback timeSkewCallback;
    LongSupplier wallClockTimeSourceMillis;
    LongSupplier monotonicTimeSourceNanos;
  }

  private synchronized Snapshot snapshot() {
    Snapshot s = new Snapshot();
    s.createdTime = this.createdTime;
    s.defaultValue = this.defaultValue;
    s.halfLife = this.halfLife;
    s.lastReportTime = this.lastReportTime;
    s.lastMonotonicNanos = this.lastMonotonicNanos;
    s.maxReport = this.maxReport;
    s.minReport = this.minReport;
    s.started = this.started;
    s.totalReports = this.totalReports;
    s.curValue = this.curValue;
    s.timeSkewCallback = this.timeSkewCallback;
    s.wallClockTimeSourceMillis = this.wallClockTimeSourceMillis;
    s.monotonicTimeSourceNanos = this.monotonicTimeSourceNanos;
    return s;
  }

  /** Returns the current estimate of the average. */
  @Override
  public synchronized double currentValue() {
    return curValue;
  }

  /**
   * Reports a single observation.
   *
   * <p>Values outside {@code [min, max]} or non‑finite values are ignored. The first valid report
   * sets the current value and establishes the time baseline; subsequent reports are combined using
   * the exponential decay formula based on monotonic elapsed time.
   *
   * @param d the observation to incorporate
   */
  @Override
  public void report(double d) {
    synchronized (this) {
      long wall = wallClockTimeSourceMillis.getAsLong();
      long monoNanos = monotonicTimeSourceNanos.getAsLong();
      if (d < minReport) {
        LOG.error("Impossible: {} on {}", d, this);
        return;
      }
      if (d > maxReport) {
        LOG.error("Impossible: {} on {}", d, this);
        return;
      }
      if (Double.isInfinite(d) || Double.isNaN(d)) {
        LOG.error("Reported infinity or NaN to {} : {}", this, d);
        return;
      }
      totalReports++;
      if (!started) {
        setStartedInitialValues(d, wall, monoNanos);
      } else if (lastReportTime != -1) { // might be just serialized in
        handleSubsequentReport(d, wall, monoNanos);
      }
      lastReportTime = wall;
      lastMonotonicNanos = monoNanos;
    }
  }

  private void setStartedInitialValues(double d, long wall, long monoNanos) {
    curValue = d;
    started = true;
    lastReportTime = wall;
    lastMonotonicNanos = monoNanos;
    if (LOG.isTraceEnabled()) LOG.trace("Reported {} on {} when just started", d, this);
  }

  private void handleSubsequentReport(double d, long wall, long monoNanos) {
    long clockDelta = wall - lastReportTime;
    if (clockDelta < 0) {
      LOG.error(
          "Clock (reporting) went back in time, ignoring report: {}"
              + LOG_LIT_WAS
              + "{} (back {}ms)",
          wall,
          lastReportTime,
          -clockDelta);
      lastReportTime = wall;
      if (timeSkewCallback != null) timeSkewCallback.setTimeSkewDetectedUserAlert();
      // Do not return; still compute decay using monotonic time so the average is not affected
      // by wall-clock drift.
    }

    long uptime = wall - createdTime;
    double thisHalfLife = halfLife;
    if (uptime < 0) {
      LOG.error(
          "Clock (uptime) went back in time, ignoring report: {}" + LOG_LIT_WAS + "{} (back {}ms)",
          wall,
          createdTime,
          -uptime);
      if (timeSkewCallback != null) timeSkewCallback.setTimeSkewDetectedUserAlert();
      // Do not return; continue to compute decay based on monotonic time.
      // Disable sensitivity hack.
      // Excessive sensitivity at start isn't necessarily a good thing.
      // In particular, it makes the average inconsistent - 20 reports of 0 at 1s intervals have
      // a *different* effect to 10 reports of 0 at 2s intervals!
      // Also, it increases the impact of startup spikes, which then take a long time to recover
      // from.
    }
    if (thisHalfLife == 0) thisHalfLife = 1;
    long monoDeltaMillis = Math.max(0L, (monoNanos - lastMonotonicNanos) / 1_000_000L);
    double changeFactor = Math.pow(0.5, (monoDeltaMillis) / thisHalfLife);
    applyUpdatedValueAndDebug(d, monoDeltaMillis, uptime, thisHalfLife, changeFactor);
  }

  private void applyUpdatedValueAndDebug(
      double d, long monoDeltaMillis, long uptime, double thisHalfLife, double changeFactor) {
    double oldCurValue = curValue;
    curValue =
        curValue * changeFactor /* close to 1.0 if short interval, close to 0.0 if long interval */
            + (1.0 - changeFactor) * d;
    // Keep bounds check to guard against sporadic invalid values.
    if (curValue < minReport || curValue > maxReport) {
      LOG.error("curValue={}" + LOG_LIT_WAS + "{} - out of range", curValue, oldCurValue);
      curValue = oldCurValue;
    }
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Reported {} on {}: monoDeltaMillis={}, halfLife={}, uptime={}, thisHalfLife={},"
              + " changeFactor={}, oldCurValue={}, currentValue={}, monoDeltaMillis={},"
              + " thisHalfLife={}, uptime={}, changeFactor={}",
          d,
          this,
          monoDeltaMillis,
          halfLife,
          uptime,
          thisHalfLife,
          changeFactor,
          oldCurValue,
          currentValue(),
          monoDeltaMillis,
          thisHalfLife,
          uptime,
          changeFactor);
  }

  /** Convenience overload forwarding to {@link #report(double)}. */
  @Override
  public void report(long d) {
    report((double) d);
  }

  @Override
  public double valueIfReported(double r) {
    // Intentionally unsupported: a correct prediction depends on the unknown time until the next
    // report, which is integral to the decay calculation. Callers should create a snapshot and
    // experiment on a copy if they need a what‑if value.
    throw new UnsupportedOperationException();
  }

  /** Writes the compact binary representation described in the constructor Javadoc. */
  public void writeDataTo(DataOutputStream out) throws IOException {
    long now = wallClockTimeSourceMillis.getAsLong();
    synchronized (this) {
      out.writeInt(MAGIC);
      out.writeInt(1);
      out.writeDouble(curValue);
      out.writeBoolean(started);
      out.writeLong(totalReports);
      out.writeLong(now - createdTime);
    }
  }

  /**
   * Returns the length, in bytes, of the binary representation produced by {@link #writeDataTo}.
   */
  public int getDataLength() {
    // int MAGIC + int version + double curValue + boolean started + long totalReports + long uptime
    return 4 + 4 + 8 + 1 + 8 + 8;
  }

  @Override
  public synchronized long countReports() {
    return totalReports;
  }

  /** Returns the wall‑clock timestamp (milliseconds since epoch) of the last accepted report. */
  public synchronized long lastReportTime() {
    return lastReportTime;
  }

  /**
   * Exports a human‑readable snapshot to a {@link SimpleFieldSet}.
   *
   * @param shortLived whether the returned field set is intended for short‑lived usage
   * @return a field set containing {@code Type}, {@code CurrentValue}, {@code Started}, {@code
   *     TotalReports} and {@code Uptime}
   */
  public synchronized SimpleFieldSet exportFieldSet(boolean shortLived) {
    SimpleFieldSet fs = new SimpleFieldSet(shortLived);
    fs.putSingle("Type", "TimeDecayingRunningAverage");
    fs.put(FS_KEY_CURRENT_VALUE, curValue);
    fs.put(FS_KEY_STARTED, started);
    fs.put(FS_KEY_TOTAL_REPORTS, totalReports);
    fs.put(FS_KEY_UPTIME, wallClockTimeSourceMillis.getAsLong() - createdTime);
    return fs;
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    if (wallClockTimeSourceMillis == null) wallClockTimeSourceMillis = System::currentTimeMillis;
    if (monotonicTimeSourceNanos == null) monotonicTimeSourceNanos = System::nanoTime;
    // timeSkewCallback intentionally remains null after Java deserialization
  }
}
