package network.crypta.support.math;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serial;
import java.util.function.LongSupplier;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exponentially time‑decaying running average for bounded observations.
 *
 * <p>This class applies exponential smoothing where each accepted observation is weighted by the
 * monotonic time elapsed since the previous accepted report. Callers typically construct an
 * instance once, then invoke {@link #report(double)} as samples arrive from timers or network
 * activity, and read {@link #currentValue()} or {@link #countReports()} for monitoring. The
 * half‑life is expressed in milliseconds and controls how quickly older values fade. A half‑life of
 * {@code H} means a report {@code H} milliseconds later contributes half of the new value.
 *
 * <p>Inputs outside the configured bounds and non‑finite values are ignored and do not advance
 * time, which keeps spikes and corrupted samples from contaminating the estimate. The first valid
 * report initializes the series and establishes the baseline timestamps. Instances are mutable but
 * thread-safe through internal synchronization, so a single average can be shared by multiple
 * reporting threads without additional locking. The class supports snapshot-style copying and two
 * persistence forms, providing a compact binary format as well as a human‑readable field set.
 *
 * <ul>
 *   <li>Uses monotonic time for decay to avoid wall‑clock regressions.
 *   <li>Ignores invalid inputs while logging diagnostics for visibility.
 *   <li>Offers binary and {@link SimpleFieldSet} persistence mechanisms.
 * </ul>
 *
 * @see RunningAverage
 * @see RunningAverageBounds
 */
public final class TimeDecayingRunningAverage implements RunningAverage {
  private static final Logger LOG = LoggerFactory.getLogger(TimeDecayingRunningAverage.class);

  @Serial private static final long serialVersionUID = -1;
  static final int MAGIC = 0x5ff4ac94;

  // Reused literals
  private static final String LOG_MSG_CREATED_SYSTEM = "Created average (system time) {}";
  private static final String LOG_MSG_CREATED_FIELD_SET = "Created average (field set) {}";
  private static final String LOG_MSG_CREATED_TEST_SOURCES =
      "Created average (test time sources) {}";
  private static final String FS_KEY_STARTED = "Started";
  private static final String FS_KEY_CURRENT_VALUE = "CurrentValue";
  private static final String FS_KEY_TOTAL_REPORTS = "TotalReports";
  private static final String FS_KEY_UPTIME = "Uptime";
  private static final String LOG_LIT_WAS = " was ";

  // Copying is via the copy constructor.

  /**
   * Current averaged value, updated only by accepted reports.
   *
   * <p>This value is bounded by {@code minReport} and {@code maxReport} and is read under
   * synchronization by {@link #currentValue()}.
   */
  double curValue;

  /**
   * Half‑life in milliseconds that controls how quickly old samples decay.
   *
   * <p>The value is treated as immutable after construction; a zero value is interpreted as one
   * millisecond when computing decay to avoid division by zero.
   */
  final double halfLife;

  /**
   * Wall‑clock timestamp (milliseconds since epoch) of the last accepted report.
   *
   * <p>The value advances only when a report is accepted and is used for uptime and drift checks.
   */
  long lastReportTime;

  /**
   * Wall‑clock timestamp (milliseconds since epoch) when the series started.
   *
   * <p>This value is used to compute uptime and remains stable across reports unless restored.
   */
  long createdTime;

  /**
   * Monotonic nanosecond timestamp of the last accepted report.
   *
   * <p>This value is used to compute elapsed time for decay and is never exposed directly.
   */
  long lastMonotonicNanos;

  /**
   * Total number of accepted reports.
   *
   * <p>Rejected reports do not increase this counter; it is persisted in snapshots.
   */
  long totalReports;

  /**
   * Whether the series has received its first accepted report.
   *
   * <p>While {@code false}, {@link #report(double)} initializes the current value and baselines.
   */
  boolean started;

  /**
   * Default value returned before the first accepted report.
   *
   * <p>This value is restored when persisted data is invalid or out of range.
   */
  double defaultValue;

  /**
   * Inclusive lower bound for accepted reports.
   *
   * <p>Samples below this value are rejected and logged as invalid.
   */
  double minReport;

  /**
   * Inclusive upper bound for accepted reports.
   *
   * <p>Samples above this value are rejected and logged as invalid.
   */
  double maxReport;

  private final transient TimeSkewAlertCallback timeSkewCallback;
  private transient LongSupplier wallClockTimeSourceMillis;
  private transient LongSupplier monotonicTimeSourceNanos;

  /**
   * Creates a reusable bounds object for instances of this average.
   *
   * <p>This helper exists to keep call sites concise when many averages share the same default
   * value and bounds. It does not validate values or enforce ordering; the consuming constructors
   * interpret {@code min} and {@code max} as inclusive limits and treat out‑of‑range reports as
   * invalid. Prefer passing the returned {@link RunningAverageBounds} to constructors to reduce
   * parameter count and to make configuration reuse explicit.
   *
   * @param defaultValue initial value returned before the first valid report is accepted
   * @param min inclusive lower bound for accepted observations, expressed in caller units
   * @param max inclusive upper bound for accepted observations, expressed in caller units
   * @return immutable bounds record capturing the supplied default and range
   */
  public static RunningAverageBounds bounds(double defaultValue, double min, double max) {
    return RunningAverageBounds.of(defaultValue, min, max);
  }

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
   * Creates a new running average using system time sources and the supplied bounds.
   *
   * <p>The instance starts with {@code bounds.defaultValue()} and marks itself as not started until
   * the first valid report arrives. Half‑life is expressed in milliseconds and governs decay
   * between accepted reports; when {@code halfLife} is {@code 0}, the implementation uses {@code 1}
   * to avoid division by zero while retaining the "very fast decay" semantic. The provided callback
   * is only invoked when wall‑clock time moves backward; monotonic time still drives the decay
   * calculation.
   *
   * @param bounds default value and accepted range for observations, reused across instances
   * @param halfLife half‑life in milliseconds; {@code 0} maps to a 1 ms minimum to avoid division
   *     by zero
   * @param callback optional callback notified when wall‑clock time regresses; may be {@code null}
   */
  public TimeDecayingRunningAverage(
      RunningAverageBounds bounds, long halfLife, TimeSkewAlertCallback callback) {

    curValue = bounds.defaultValue();
    this.defaultValue = bounds.defaultValue();
    started = false;
    this.halfLife = halfLife;
    this.wallClockTimeSourceMillis = System::currentTimeMillis;
    this.monotonicTimeSourceNanos = System::nanoTime;
    createdTime = lastReportTime = wallClockTimeSourceMillis.getAsLong();
    lastMonotonicNanos = monotonicTimeSourceNanos.getAsLong();
    this.minReport = bounds.min();
    this.maxReport = bounds.max();
    totalReports = 0;

    if (LOG.isTraceEnabled()) LOG.trace(LOG_MSG_CREATED_SYSTEM, this);
    this.timeSkewCallback = callback;
  }

  /**
   * Creates a new running average, optionally restoring state from a {@link SimpleFieldSet}.
   *
   * <p>This constructor is used when persistence data is available in the human‑readable field set.
   * When {@code fs} contains {@code Started=true}, the stored {@code CurrentValue}, {@code
   * TotalReports}, and {@code Uptime} fields are validated against the supplied bounds and
   * restored. The first subsequent {@link #report(double)} call only advances timestamps without
   * changing the current value to avoid a large jump after a long pause. If the stored value is
   * invalid or out of range, the instance resets to the default value and zero reports.
   *
   * @param bounds default value and accepted range for observations, shared with other instances
   * @param halfLife half‑life in milliseconds used to compute decay between reports
   * @param fs optional snapshot providing stored values; {@code null} starts a fresh instance
   * @param callback optional callback notified on wall‑clock regressions; may be {@code null}
   */
  public TimeDecayingRunningAverage(
      RunningAverageBounds bounds,
      long halfLife,
      SimpleFieldSet fs,
      TimeSkewAlertCallback callback) {

    curValue = bounds.defaultValue();
    this.defaultValue = bounds.defaultValue();
    started = false;
    this.halfLife = halfLife;
    this.wallClockTimeSourceMillis = System::currentTimeMillis;
    this.monotonicTimeSourceNanos = System::nanoTime;
    createdTime = wallClockTimeSourceMillis.getAsLong();
    this.lastReportTime = -1; // a long warm-up may skew results, so let's wait for the first report
    this.lastMonotonicNanos = monotonicTimeSourceNanos.getAsLong();
    this.minReport = bounds.min();
    this.maxReport = bounds.max();
    totalReports = 0;

    if (LOG.isTraceEnabled()) LOG.trace(LOG_MSG_CREATED_FIELD_SET, this);
    if (fs != null) {
      started = fs.getBoolean(FS_KEY_STARTED, false);
      if (started) {
        curValue = fs.getDouble(FS_KEY_CURRENT_VALUE, curValue);
        if (curValue > maxReport || curValue < minReport || Double.isNaN(curValue)) {
          curValue = this.defaultValue;
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
   * Creates a new running average using caller‑supplied time sources for testing.
   *
   * <p>This overload mirrors the field‑set constructor but allows deterministic wall‑clock and
   * monotonic time suppliers. It is intended for tests that need reproducible decay behavior or
   * simulations of clock regressions. The supplied time sources are used for all later reports, and
   * the instance follows the same validation rules for stored state as the standard field‑set
   * constructor. When {@code fs} is {@code null}, the instance behaves like a fresh average.
   *
   * @param bounds default value and accepted range for observations, shared with other instances
   * @param halfLife half‑life in milliseconds used to compute decay between reports
   * @param fs optional snapshot providing stored values; {@code null} creates a fresh instance
   * @param callback optional callback notified on wall‑clock regressions; may be {@code null}
   * @param wallClockTimeSourceMillis wall‑clock time supplier returning milliseconds since epoch
   * @param monotonicTimeSourceNanos monotonic time supplier returning nanoseconds for elapsed time
   */
  public TimeDecayingRunningAverage(
      RunningAverageBounds bounds,
      long halfLife,
      SimpleFieldSet fs,
      TimeSkewAlertCallback callback,
      LongSupplier wallClockTimeSourceMillis,
      LongSupplier monotonicTimeSourceNanos) {

    curValue = bounds.defaultValue();
    this.defaultValue = bounds.defaultValue();
    started = false;
    this.halfLife = halfLife;
    this.wallClockTimeSourceMillis = wallClockTimeSourceMillis;
    this.monotonicTimeSourceNanos = monotonicTimeSourceNanos;
    createdTime = this.wallClockTimeSourceMillis.getAsLong();
    this.lastReportTime = -1; // wait for the first report
    this.lastMonotonicNanos = this.monotonicTimeSourceNanos.getAsLong();
    this.minReport = bounds.min();
    this.maxReport = bounds.max();
    totalReports = 0;

    if (LOG.isTraceEnabled()) LOG.trace(LOG_MSG_CREATED_TEST_SOURCES, this);
    if (fs != null) {
      started = fs.getBoolean(FS_KEY_STARTED, false);
      if (started) {
        curValue = fs.getDouble(FS_KEY_CURRENT_VALUE, curValue);
        if (curValue > maxReport || curValue < minReport || Double.isNaN(curValue)) {
          curValue = this.defaultValue;
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
   * <p>The binary record is intentionally small and ordered so that {@link #writeDataTo} can emit
   * it in a single synchronized block. The caller must provide the same bounds used when
   * serializing; the constructor validates the stored {@code currentValue} against these bounds and
   * rejects the record if it is invalid. Monotonic timestamps are reinitialized on the load, so the
   * next report decays relative to the new baseline instead of an old persisted nanosecond value.
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
   * @param bounds default value and accepted range for observations, matching the serialized data
   * @param halfLife half‑life in milliseconds used for later decay calculations
   * @param dis input stream positioned at the beginning of the record to read
   * @param callback optional callback notified on wall‑clock regressions; may be {@code null}
   * @throws IOException if the magic/version mismatches or values are non‑finite or out of range
   */
  public TimeDecayingRunningAverage(
      RunningAverageBounds bounds,
      double halfLife,
      DataInputStream dis,
      TimeSkewAlertCallback callback)
      throws IOException {
    int m = dis.readInt();
    if (m != MAGIC) throw new IOException("Invalid magic " + m);
    int v = dis.readInt();
    if (v != 1) throw new IOException("Invalid version " + v);
    curValue = dis.readDouble();
    if (Double.isInfinite(curValue) || Double.isNaN(curValue))
      throw new IOException("Invalid weightedTotal: " + curValue);
    if ((curValue < bounds.min()) || (curValue > bounds.max()))
      throw new IOException("Out of range: curValue = " + curValue);
    started = dis.readBoolean();
    // Read fields in the same order they are written: totalReports first, then uptime
    totalReports = dis.readLong();
    long priorExperienceTime = dis.readLong();
    this.halfLife = halfLife;
    this.minReport = bounds.min();
    this.maxReport = bounds.max();
    this.defaultValue = bounds.defaultValue();

    this.wallClockTimeSourceMillis = System::currentTimeMillis;
    this.monotonicTimeSourceNanos = System::nanoTime;
    lastReportTime = -1;
    createdTime = wallClockTimeSourceMillis.getAsLong() - priorExperienceTime;
    lastMonotonicNanos = monotonicTimeSourceNanos.getAsLong();
    this.timeSkewCallback = callback;
  }

  /**
   * Creates an independent snapshot copy of another running average.
   *
   * <p>The copy preserves the current value, report counts, time sources, and timing baselines as
   * observed at construction time. Subsequent updates to either instance do not affect the other,
   * making this constructor suitable for "what‑if" experiments or for capturing a stable view while
   * continuing to report on the original. The source instance must be non‑null; this constructor
   * takes a synchronized snapshot internally to ensure consistency across mutable fields.
   *
   * @param a instance to copy; must not be {@code null} and should be fully initialized
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
    TimeSkewAlertCallback timeSkewCallback;
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

  /**
   * Returns the current estimate of the running average.
   *
   * <p>The returned value reflects the most recent accepted report and the decay applied across
   * elapsed monotonic time. It does not trigger any additional decay calculation; decay is applied
   * only when reports are accepted. The value is read under synchronization to provide a consistent
   * view when concurrent reporters are updating the state.
   *
   * @return the current averaged value, bounded by the configured minimum and maximum
   */
  @Override
  public synchronized double currentValue() {
    return curValue;
  }

  /**
   * Reports a single observation to update the running average.
   *
   * <p>The sample is validated against the configured bounds and must be finite. Invalid values are
   * ignored and do not advance time. The first valid report initializes the series and establishes
   * the timestamp baseline; later reports apply exponential decay based on monotonic elapsed time.
   * This method is thread-safe and synchronizes on the instance to update the related state
   * atomically.
   *
   * @param d observation to incorporate; must be finite and within the configured inclusive bounds
   */
  @Override
  public void report(double d) {
    synchronized (this) {
      long wall = wallClockTimeSourceMillis.getAsLong();
      long monoNanos = monotonicTimeSourceNanos.getAsLong();
      if (d < minReport) {
        LOG.error("Rejected report below min: {} on {}", d, this);
        return;
      }
      if (d > maxReport) {
        LOG.error("Rejected report above max: {} on {}", d, this);
        return;
      }
      if (Double.isInfinite(d) || Double.isNaN(d)) {
        LOG.error("Rejected non-finite report on {}: {}", this, d);
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
    if (LOG.isTraceEnabled()) LOG.trace("Started average with report {} on {}", d, this);
  }

  private void handleSubsequentReport(double d, long wall, long monoNanos) {
    long clockDelta = wall - lastReportTime;
    if (clockDelta < 0) {
      LOG.error(
          "Wall-clock regression during report: {}" + LOG_LIT_WAS + "{} (back {}ms)",
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
          "Uptime regression during report: {}" + LOG_LIT_WAS + "{} (back {}ms)",
          wall,
          createdTime,
          -uptime);
      if (timeSkewCallback != null) timeSkewCallback.setTimeSkewDetectedUserAlert();
      // Do not return; continue to compute decay based on monotonic time.
      // Disable sensitivity hack.
      // Excessive sensitivity at the start isn't necessarily a good thing.
      // In particular, it makes the average inconsistent - 20 reports of 0 at 1s intervals have
      // a *different* effect to 10 reports of 0 at 2s intervals!
      // Also, it increases the impact of startup spikes, which then take a long time to recover
      // from.
    }
    if (thisHalfLife == 0) thisHalfLife = 1;
    long monoDeltaMillis = Math.max(0L, (monoNanos - lastMonotonicNanos) / 1_000_000L);
    double changeFactor = Math.pow(0.5, monoDeltaMillis / thisHalfLife);
    applyUpdatedValueAndDebug(d, monoDeltaMillis, uptime, thisHalfLife, changeFactor);
  }

  private void applyUpdatedValueAndDebug(
      double d, long monoDeltaMillis, long uptime, double thisHalfLife, double changeFactor) {
    double oldCurValue = curValue;
    curValue =
        curValue
                * changeFactor /* close to 1.0 if a short interval, close to 0.0 if a long interval */
            + (1.0 - changeFactor) * d;
    // Keep bounds check to guard against sporadic invalid values.
    if (curValue < minReport || curValue > maxReport) {
      LOG.error(
          "Computed average out of range: curValue={}" + LOG_LIT_WAS + "{}", curValue, oldCurValue);
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

  /**
   * Reports a single observation supplied as a long integer.
   *
   * <p>This convenience overload converts the value to {@code double} and delegates to {@link
   * #report(double)}, preserving the same bounds checks, decay behavior, and logging. It is
   * primarily intended for callers that naturally measure integer values (for example, counts or
   * sizes) but want the same averaging semantics.
   *
   * @param d observation to incorporate, converted to {@code double} before validation
   */
  @Override
  public void report(long d) {
    report((double) d);
  }

  /**
   * Indicates that predictive values are unsupported for this average.
   *
   * <p>Unlike simple averages, a meaningful prediction requires knowledge of the time until the
   * next report, which is a required input to the decay computation. Callers that need "what‑if"
   * results should instead copy the instance using the copy constructor and experiment with {@link
   * #report(double)} on the copy to simulate elapsed time and sample sequences.
   *
   * @param r hypothetical value that would be reported; ignored by this implementation
   * @return nothing; this method always throws an exception
   * @throws UnsupportedOperationException always, because the prediction is not well-defined
   */
  @Override
  public double valueIfReported(double r) {
    // Intentionally unsupported: a correct prediction depends on the unknown time until the next
    // report, which is integral to the decay calculation. Callers should create a snapshot and
    // experiment on a copy if they need a what‑if value.
    throw new UnsupportedOperationException();
  }

  /**
   * Writes the compact binary representation described in the binary constructor documentation.
   *
   * <p>The output is written under synchronization to ensure the snapshot of the mutable state is
   * consistent. The caller is responsible for providing a stream positioned at the desired writing
   * location. The method writes values in a fixed order that matches the binary constructor, so the
   * output can be consumed later to restore an equivalent instance.
   *
   * @param out destination stream to receive the binary record; must be non-null and writable
   * @throws IOException if the underlying stream rejects writes or becomes unavailable
   */
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
   * Returns the number of bytes written by {@link #writeDataTo}.
   *
   * <p>This value reflects the current binary format, which includes a magic value, a version
   * number, the current value, a started flag, the report count, and the uptime. It is constant for
   * the current format and does not depend on the instance state, but the method remains an
   * instance member for API symmetry with other persistence helpers.
   *
   * <p>int MAGIC + int version + double curValue + boolean started + long totalReports + long
   * uptime
   *
   * @return byte length of the current binary record format
   */
  public int getDataLength() {
    return 4 + 4 + 8 + 1 + 8 + 8;
  }

  /**
   * Returns the number of accepted reports so far.
   *
   * <p>This counter increments only when a report is accepted (finite and within bounds). Rejected
   * samples do not increase the count. The value is synchronized to provide a consistent view when
   * concurrent reporters are updating the state.
   *
   * @return number of accepted reports since construction or restoration
   */
  @Override
  public synchronized long countReports() {
    return totalReports;
  }

  /**
   * Returns the wall‑clock timestamp of the last accepted report.
   *
   * <p>The value has been expressed in milliseconds since the epoch and reflects the last report
   * that passed validation. If no valid report has been accepted, the value is the most recent
   * baseline set during construction or restoration. The value is synchronized to avoid races with
   * reporters.
   *
   * @return wall‑clock time of the most recent accepted report, in milliseconds since epoch
   */
  public synchronized long lastReportTime() {
    return lastReportTime;
  }

  /**
   * Exports a human‑readable snapshot of the current state.
   *
   * <p>The returned {@link SimpleFieldSet} contains the type identifier and the persisted fields
   * needed by the field‑set constructor: {@code CurrentValue}, {@code Started}, {@code
   * TotalReports}, and {@code Uptime}. The snapshot is captured under synchronization to ensure
   * consistency across mutable fields. Callers typically persist the result and later pass it back
   * into the constructor to resume reporting without a warm‑up spike after downtime.
   *
   * @param shortLived whether the field set is intended for short‑lived usage or caching
   * @return field set snapshot containing the current value, report counts, and uptime metadata
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

  /**
   * Restores transient fields after Java serialization.
   *
   * <p>Java deserialization does not restore transient time suppliers or the time skew callback, so
   * this method ensures that wall‑clock and monotonic time sources fall back to system defaults.
   * The callback intentionally remains {@code null} after deserialization to avoid unexpected side
   * effects when the object is restored.
   *
   * @param in input stream used by Java serialization to restore fields
   * @throws IOException if the underlying stream cannot be read
   * @throws ClassNotFoundException if the serialized class cannot be resolved
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    in.defaultReadObject();
    if (wallClockTimeSourceMillis == null) wallClockTimeSourceMillis = System::currentTimeMillis;
    if (monotonicTimeSourceNanos == null) monotonicTimeSourceNanos = System::nanoTime;
    // timeSkewCallback intentionally remains null after Java deserialization
  }
}
