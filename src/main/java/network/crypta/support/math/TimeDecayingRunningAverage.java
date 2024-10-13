package network.crypta.support.math;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serial;
import network.crypta.node.TimeSkewDetectorCallback;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Time decaying running average.
 *
 * <p>Decay factor = 0.5 ^ (interval / halflife).
 *
 * <p>So if the interval is exactly the half-life then reporting 0 will halve the value.
 *
 * <p>Note that the older version has a half life on the influence of any given report without
 * taking into account the fact that reports persist and accumulate. :)
 */
public final class TimeDecayingRunningAverage implements RunningAverage, Cloneable {
  private static final Logger LOG = LoggerFactory.getLogger(TimeDecayingRunningAverage.class);

  @Serial private static final long serialVersionUID = -1;
  static final int MAGIC = 0x5ff4ac94;

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

  private final TimeSkewDetectorCallback timeSkewCallback;
  private final java.util.function.LongSupplier wallClockTimeSourceMillis;
  private final java.util.function.LongSupplier monotonicTimeSourceNanos;

  @Override
  public String toString() {
    long now = wallClockTimeSourceMillis == null ? System.currentTimeMillis() : wallClockTimeSourceMillis.getAsLong();
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
   * @param defaultValue
   * @param halfLife
   * @param min
   * @param max
   * @param callback
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

    if (LOG.isTraceEnabled()) LOG.trace("Created {}", this);
    this.timeSkewCallback = callback;
  }

  /**
   * @param defaultValue
   * @param halfLife
   * @param min
   * @param max
   * @param fs
   * @param callback
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

    if (LOG.isTraceEnabled()) LOG.trace("Created {}", this);
    if (fs != null) {
      started = fs.getBoolean("Started", false);
      if (started) {
        curValue = fs.getDouble("CurrentValue", curValue);
        if (curValue > maxReport || curValue < minReport || Double.isNaN(curValue)) {
          curValue = defaultValue;
          totalReports = 0;
          createdTime = wallClockTimeSourceMillis.getAsLong();
        } else {
          totalReports = fs.getLong("TotalReports", 0);
          long uptime = fs.getLong("Uptime", 0);
          createdTime = wallClockTimeSourceMillis.getAsLong() - uptime;
        }
      }
    }
    this.timeSkewCallback = callback;
  }

  /** Test-friendly constructor with injected time sources. */
  public TimeDecayingRunningAverage(
      double defaultValue,
      long halfLife,
      double min,
      double max,
      SimpleFieldSet fs,
      TimeSkewDetectorCallback callback,
      java.util.function.LongSupplier wallClockTimeSourceMillis,
      java.util.function.LongSupplier monotonicTimeSourceNanos) {
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

    if (LOG.isTraceEnabled()) LOG.trace("Created {}", this);
    if (fs != null) {
      started = fs.getBoolean("Started", false);
      if (started) {
        curValue = fs.getDouble("CurrentValue", curValue);
        if (curValue > maxReport || curValue < minReport || Double.isNaN(curValue)) {
          curValue = defaultValue;
          totalReports = 0;
          createdTime = this.wallClockTimeSourceMillis.getAsLong();
        } else {
          totalReports = fs.getLong("TotalReports", 0);
          long uptime = fs.getLong("Uptime", 0);
          createdTime = this.wallClockTimeSourceMillis.getAsLong() - uptime;
        }
      }
    }
    this.timeSkewCallback = callback;
  }

  /**
   * @param defaultValue
   * @param halfLife
   * @param min
   * @param max
   * @param dis
   * @param callback
   * @throws IOException
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
    totalReports = dis.readLong();
    this.timeSkewCallback = callback;
  }

  /**
   * @param a
   */
  public TimeDecayingRunningAverage(TimeDecayingRunningAverage a) {
    synchronized (a) {
      this.createdTime = a.createdTime;
      this.defaultValue = a.defaultValue;
      this.halfLife = a.halfLife;
      this.lastReportTime = a.lastReportTime;
      this.maxReport = a.maxReport;
      this.minReport = a.minReport;
      this.started = a.started;
      this.totalReports = a.totalReports;
      this.curValue = a.curValue;
      this.timeSkewCallback = a.timeSkewCallback;
    }
  }

  /**
   * @return
   */
  @Override
  public synchronized double currentValue() {
    return curValue;
  }

  /**
   * @param d
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
        curValue = d;
        started = true;
        lastReportTime = wall;
        lastMonotonicNanos = monoNanos;
        if (LOG.isTraceEnabled()) LOG.trace("Reported " + d + " on " + this + " when just started");
      } else if (lastReportTime != -1) { // might be just serialized in
        long clockDelta = wall - lastReportTime;
        if (clockDelta < 0) {
          LOG.error(
              "Clock (reporting) went back in time, ignoring report: "
                  + wall
                  + " was "
                  + lastReportTime
                  + " (back "
                  + (-clockDelta)
                  + "ms)");
          lastReportTime = wall;
          if (timeSkewCallback != null) timeSkewCallback.setTimeSkewDetectedUserAlert();
          return;
        }
        long uptime = wall - createdTime;
        double thisHalfLife = halfLife;
        if (uptime < 0) {
          LOG.error(
              "Clock (uptime) went back in time, ignoring report: "
                  + wall
                  + " was "
                  + createdTime
                  + " (back "
                  + (-uptime)
                  + "ms)");
          if (timeSkewCallback != null) timeSkewCallback.setTimeSkewDetectedUserAlert();
          return;
          // Disable sensitivity hack.
          // Excessive sensitivity at start isn't necessarily a good thing.
          // In particular it makes the average inconsistent - 20 reports of 0 at 1s intervals have
          // a *different* effect to 10 reports of 0 at 2s intervals!
          // Also it increases the impact of startup spikes, which then take a long time to recover
          // from.
          // } else {
          // double oneFourthOfUptime = uptime / 4D;
          // if(oneFourthOfUptime < thisHalfLife) thisHalfLife = oneFourthOfUptime;
        }
        if (thisHalfLife == 0) thisHalfLife = 1;
        long monoDeltaMillis = Math.max(0L, (monoNanos - lastMonotonicNanos) / 1_000_000L);
        double changeFactor = Math.pow(0.5, (monoDeltaMillis) / thisHalfLife);
        double oldCurValue = curValue;
        curValue =
            curValue
                    * changeFactor /* close to 1.0 if short interval, close to 0.0 if long interval */
                + (1.0 - changeFactor) * d;
        // FIXME remove when stop getting reports of wierd output values
        if (curValue < minReport || curValue > maxReport) {
          LOG.error("curValue=" + curValue + " was " + oldCurValue + " - out of range");
          curValue = oldCurValue;
        }
        if (LOG.isDebugEnabled())
          LOG.debug(
              "Reported "
                  + d
                  + " on "
                  + this
                  + ": thisInterval="
                  + thisInterval
                  + ", halfLife="
                  + halfLife
                  + ", uptime="
                  + uptime
                  + ", thisHalfLife="
                  + thisHalfLife
                  + ", changeFactor="
                  + changeFactor
                  + ", oldCurValue="
                  + oldCurValue
                  + ", currentValue="
                  + currentValue()
                  + ", monoDeltaMillis="
                  + monoDeltaMillis
                  + ", thisHalfLife="
                  + thisHalfLife
                  + ", uptime="
                  + uptime
                  + ", changeFactor="
                  + changeFactor);
      }
      lastReportTime = wall;
      lastMonotonicNanos = monoNanos;
    }
  }

  /**
   * @param d
   */
  @Override
  public void report(long d) {
    report((double) d);
  }

  @Override
  public double valueIfReported(double r) {
    throw new UnsupportedOperationException();
  }

  /**
   * @param out
   * @throws IOException
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
   * @return
   */
  public int getDataLength() {
    return 4 + 4 + 8 + 8 + 1 + 8 + 8;
  }

  @Override
  public synchronized long countReports() {
    return totalReports;
  }

  /**
   * @return
   */
  public synchronized long lastReportTime() {
    return lastReportTime;
  }

  /**
   * @param shortLived
   * @return
   */
  public synchronized SimpleFieldSet exportFieldSet(boolean shortLived) {
    SimpleFieldSet fs = new SimpleFieldSet(shortLived);
    fs.putSingle("Type", "TimeDecayingRunningAverage");
    fs.put("CurrentValue", curValue);
    fs.put("Started", started);
    fs.put("TotalReports", totalReports);
    fs.put("Uptime", wallClockTimeSourceMillis.getAsLong() - createdTime);
    return fs;
  }

  /** Returns an independent snapshot copy. */
  public TimeDecayingRunningAverage clone() {
    return new TimeDecayingRunningAverage(this);
  }
}
