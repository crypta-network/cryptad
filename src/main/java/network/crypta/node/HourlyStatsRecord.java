package network.crypta.node;

import java.text.DecimalFormat;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import network.crypta.support.HTMLNode;
import network.crypta.support.math.TrivialRunningAverage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Aggregates request statistics for a single wall-clock hour.
 *
 * <p>This class records outcomes for accepted remote requests grouped in two complementary
 * dimensions:
 *
 * <ul>
 *   <li>By HTL (hop-to-live) — the array {@code byHTL} stores per-HTL running statistics where the
 *       measured value is the logarithm base-2 of the routing distance ({@code log2(dist)}).
 *   <li>By logarithmic routing distance — the array {@code byDist} stores per-distance-bucket
 *       statistics where the measured value is the HTL observed for that request.
 * </ul>
 *
 * <p>Thread-safety: mutations and string rendering use synchronization on {@code this}. Callers may
 * invoke {@link #remoteRequest(boolean, boolean, boolean, int, double)} concurrently; the internal
 * state is protected. Call {@link #markFinal()} to indicate that no more updates should be recorded
 * for the hour.
 */
public class HourlyStatsRecord {
  private static final Logger LOG = LoggerFactory.getLogger(HourlyStatsRecord.class);

  /** Number of logarithmic distance buckets (0 is closest). */
  private static final int N_DISTANCE_GROUPS = 16;

  private final boolean completeHour;
  private boolean finishedReporting;

  /** Statistics bucketed by HTL; values are {@code log2(distance)}. */
  private final StatsLine[] byHTL;

  /** Statistics bucketed by {@code log2(distance)}; values are HTL. */
  private final StatsLine[] byDist;

  private final Date beginTime;
  private final Node node;

  /**
   * Creates a new per-hour aggregator starting at the current time (UTC).
   *
   * @param node Node that provides {@link Node#maxHTL()} and the local routing location.
   * @param completeHour whether this record starts at the hour boundary; affects only reporting.
   */
  public HourlyStatsRecord(Node node, boolean completeHour) {
    this.node = node;
    this.completeHour = completeHour;
    finishedReporting = false;
    byHTL = new StatsLine[node.maxHTL() + 1];
    for (int i = 0; i < byHTL.length; i++) byHTL[i] = new StatsLine();
    byDist = new StatsLine[N_DISTANCE_GROUPS];
    for (int i = 0; i < byDist.length; i++) byDist[i] = new StatsLine();

    beginTime = new Date();
  }

  /**
   * Marks the record as complete so no additional observations are accepted.
   *
   * <p>Thread-safety: synchronized on {@code this}.
   */
  public synchronized void markFinal() {
    finishedReporting = true;
  }

  /**
   * Records an accepted remote request and updates running statistics.
   *
   * <p>The routing distance is computed as the circular location difference in {@code [0,1]}; its
   * base-2 logarithm ({@code log2(distance)}) is recorded for HTL buckets. For distance buckets,
   * the HTL value is recorded instead. Very small distances are clamped to {@link Double#MIN_VALUE}
   * to avoid {@code -Infinity} in {@code log2}.
   *
   * @param ssk whether the request type is SSK ({@code true}) or CHK ({@code false})
   * @param success whether the request succeeded
   * @param local when {@code success} is {@code true}, whether the success was local
   * @param htl the observed HTL when the request arrived; negative values are rejected
   * @param location the request's routing location in {@code [0,1]}
   * @throws IllegalStateException if the record is marked final
   * @throws IllegalArgumentException if {@code htl < 0} or {@code location} is outside {@code
   *     [0,1]}
   */
  public synchronized void remoteRequest(
      boolean ssk, boolean success, boolean local, int htl, double location) {
    if (finishedReporting)
      throw new IllegalStateException("Attempted to modify completed stats record.");
    if (htl < 0) throw new IllegalArgumentException("Invalid HTL.");
    if (location < 0 || location > 1) throw new IllegalArgumentException("Invalid location.");
    htl = Math.min(htl, node.maxHTL());
    double rawDist = Location.distance(node.network().location(), location);
    // Avoid -Infinity when taking log2(distance) for identical locations.
    if (rawDist <= 0.0) rawDist = Double.MIN_VALUE;
    double logDist = Math.log(rawDist) / Math.log(2.0);
    // Upper bound: distance in (0, 1] → log2(distance) ≤ 0; epsilon accounts for MIN_NORMAL.
    assert logDist < (-1.0 + 0x1.0p-1022 /* Double.MIN_NORMAL */);
    int distBucket = ((int) Math.floor(-1 * logDist));
    if (distBucket >= byDist.length) distBucket = byDist.length - 1;

    // Record location difference (log2)
    if (ssk) {
      byHTL[htl].locDiffSSK.report(logDist);
    } else {
      byHTL[htl].locDiffCHK.report(logDist);
    }

    StatsLine htlLine = byHTL[htl];
    StatsLine distLine = byDist[distBucket];

    if (success) {
      reportSuccess(ssk, local, htlLine, distLine, logDist, htl);
    } else {
      reportFailure(ssk, htlLine, distLine, logDist, htl);
    }
  }

  /** Emits a multi-line summary at INFO level using {@link #toString()}. */
  public void log() {
    LOG.atInfo().log(this::toString);
  }

  private static final DateTimeFormatter UTC_DATE_TIME =
      DateTimeFormatter.ofPattern("yyyyMMdd HH:mm:ss.SSS").withZone(ZoneOffset.UTC);

  // Formatting helpers for tables and summaries.
  private static final DecimalFormat fix3p3pct = new DecimalFormat("##0.000%");
  private static final DecimalFormat fix4p = new DecimalFormat("#.0000");

  /**
   * Returns a human-readable, multi-line snapshot of the current statistics.
   *
   * <p>Layout:
   *
   * <ul>
   *   <li>Header with hour start (UTC), node uptime in milliseconds, build number, and flags
   *       indicating whether the hour is complete and whether reporting is finished.
   *   <li>One row per HTL bucket: counts and running averages of {@code log2(distance)} as returned
   *       by {@link StatsLine#toString()}.
   *   <li>One row per logarithmic distance bucket: counts and running averages of HTL as returned
   *       by {@link StatsLine#toString()}.
   * </ul>
   */
  @Override
  public synchronized String toString() {
    StringBuilder s = new StringBuilder();
    s.append("HourlyStats: hour start (UTC) ");
    s.append(UTC_DATE_TIME.format(beginTime.toInstant())).append("\n");
    s.append("HourlyStats: node uptime (ms)\t").append(node.network().uptime()).append("\n");
    s.append("HourlyStats: build number\t").append(Version.currentBuildNumber()).append("\n");
    s.append("HourlyStats: completeHour\t").append(completeHour);
    s.append("\tfinished\t").append(finishedReporting).append("\n");

    // Column guide for HTL-bucket rows: counts then averages of log2(distance).
    s.append(
        "HourlyStats: HTL columns\tCHK_local\tCHK_remote\tCHK_fail\tSSK_local\tSSK_remote\tSSK_fail"
            + "\tavg_CHK_local_log2dist\tavg_CHK_remote_log2dist\tavg_CHK_fail_log2dist"
            + "\tavg_SSK_local_log2dist\tavg_SSK_remote_log2dist\tavg_SSK_fail_log2dist\n");
    for (int i = byHTL.length - 1; i >= 0; i--) {
      s.append("HourlyStats: HTL\t").append(i).append("\t");
      s.append(byHTL[i].toString()).append("\n");
    }
    // Column guide for distance-bucket rows: counts then averages of HTL.
    s.append(
        "HourlyStats: logDist columns\tCHK_local\tCHK_remote\tCHK_fail\tSSK_local\tSSK_remote"
            + "\tSSK_fail\tavg_CHK_local_HTL\tavg_CHK_remote_HTL\tavg_CHK_fail_HTL"
            + "\tavg_SSK_local_HTL\tavg_SSK_remote_HTL\tavg_SSK_fail_HTL\n");
    for (int i = 0; i < byDist.length; i++) {
      s.append("HourlyStats: logDist\t").append(i).append("\t");
      s.append(byDist[i].toString()).append("\n");
    }
    return s.toString();
  }

  private static void reportSuccess(
      boolean ssk, boolean local, StatsLine htlLine, StatsLine distLine, double logDist, int htl) {
    TrivialRunningAverage htlAvg;
    if (ssk) {
      htlAvg = local ? htlLine.sskLocalSuccess : htlLine.sskRemoteSuccess;
    } else {
      htlAvg = local ? htlLine.chkLocalSuccess : htlLine.chkRemoteSuccess;
    }

    TrivialRunningAverage distAvg;
    if (ssk) {
      distAvg = local ? distLine.sskLocalSuccess : distLine.sskRemoteSuccess;
    } else {
      distAvg = local ? distLine.chkLocalSuccess : distLine.chkRemoteSuccess;
    }
    htlAvg.report(logDist);
    distAvg.report(htl);
  }

  private static void reportFailure(
      boolean ssk, StatsLine htlLine, StatsLine distLine, double logDist, int htl) {
    if (ssk) {
      htlLine.sskFailure.report(logDist);
      distLine.sskFailure.report(htl);
    } else {
      htlLine.chkFailure.report(logDist);
      distLine.chkFailure.report(htl);
    }
  }

  /**
   * Appends a summary table of remote request outcomes grouped by HTL into the provided HTML node.
   *
   * <p>Each data row includes, per HTL, the CHK and SSK success rates (in percent with three
   * decimals), the tuple {@code (localSuccess,remoteSuccess,total)}, and the geometric mean
   * distance multiplier {@code 2^(avg log2(distance))}. The last row aggregates totals across all
   * HTLs. Callers must provide a valid parent {@link HTMLNode} to receive the table.
   *
   * <p>Thread-safety: reads are performed under {@code synchronized(this)} to snapshot values.
   *
   * @param html parent element to which the {@code table} is added; must not be {@code null}
   */
  public void fillRemoteRequestHTLsBox(HTMLNode html) {
    HTMLNode table = html.addChild("table");
    HTMLNode row = table.addChild("tr");
    row.addChild("th", "HTL");
    row.addChild("th", "CHKs");
    row.addChild("th", "SSKs");
    char nbsp = (char) 160;
    int totalCHKLS = 0;
    int totalCHKRS = 0;
    int totalCHKT = 0;
    int totalSSKLS = 0;
    int totalSSKRS = 0;
    int totalSSKT = 0;
    synchronized (this) {
      for (int htl = byHTL.length - 1; htl > 0; htl--) {
        row = table.addChild("tr");
        row.addChild("td", Integer.toString(htl));
        StatsLine line = byHTL[htl];
        int chkLS = (int) line.chkLocalSuccess.countReports();
        int chkRS = (int) line.chkRemoteSuccess.countReports();
        int chkF = (int) line.chkFailure.countReports();
        int chkT = chkLS + chkRS + chkF;
        int sskLS = (int) line.sskLocalSuccess.countReports();
        int sskRS = (int) line.sskRemoteSuccess.countReports();
        int sskF = (int) line.sskFailure.countReports();
        int sskT = sskLS + sskRS + sskF;

        // Convert avg log2(distance) back to multiplicative distance for display.
        double locdiffCHK = line.locDiffCHK.currentValue();
        locdiffCHK = Math.pow(2.0, locdiffCHK);
        double locdiffSSK = line.locDiffSSK.currentValue();
        locdiffSSK = Math.pow(2.0, locdiffSSK);

        double chkRate = 0.;
        double sskRate = 0.;
        if (chkT > 0) chkRate = ((double) (chkLS + chkRS)) / (chkT);
        if (sskT > 0) sskRate = ((double) (sskLS + sskRS)) / (sskT);

        row.addChild(
            "td",
            fix3p3pct.format(chkRate)
                + nbsp
                + "("
                + chkLS
                + ","
                + chkRS
                + ","
                + chkT
                + ")"
                + nbsp
                + "("
                + fix4p.format(locdiffCHK)
                + ")");
        row.addChild(
            "td",
            fix3p3pct.format(sskRate)
                + nbsp
                + "("
                + sskLS
                + ","
                + sskRS
                + ","
                + sskT
                + ")"
                + nbsp
                + "("
                + fix4p.format(locdiffSSK)
                + ")");

        totalCHKLS += chkLS;
        totalCHKRS += chkRS;
        totalCHKT += chkT;
        totalSSKLS += sskLS;
        totalSSKRS += sskRS;
        totalSSKT += sskT;
      }
      double totalCHKRate = 0.0;
      double totalSSKRate = 0.0;
      if (totalCHKT > 0) totalCHKRate = ((double) (totalCHKLS + totalCHKRS)) / totalCHKT;
      if (totalSSKT > 0) totalSSKRate = ((double) (totalSSKLS + totalSSKRS)) / totalSSKT;

      row = table.addChild("tr");
      row.addChild("td", "Total");
      row.addChild(
          "td",
          fix3p3pct.format(totalCHKRate)
              + nbsp
              + "("
              + totalCHKLS
              + ","
              + totalCHKRS
              + ","
              + totalCHKT
              + ")");
      row.addChild(
          "td",
          fix3p3pct.format(totalSSKRate)
              + nbsp
              + "("
              + totalSSKLS
              + ","
              + totalSSKRS
              + ","
              + totalSSKT
              + ")");
    }
  }

  /** Aggregates counts and running averages for one dimension/bucket. */
  private static class StatsLine {
    TrivialRunningAverage chkLocalSuccess;
    TrivialRunningAverage chkRemoteSuccess;
    TrivialRunningAverage chkFailure;
    TrivialRunningAverage sskLocalSuccess;
    TrivialRunningAverage sskRemoteSuccess;
    TrivialRunningAverage sskFailure;
    TrivialRunningAverage locDiffCHK;
    TrivialRunningAverage locDiffSSK;

    StatsLine() {
      chkLocalSuccess = new TrivialRunningAverage();
      chkRemoteSuccess = new TrivialRunningAverage();
      chkFailure = new TrivialRunningAverage();
      sskLocalSuccess = new TrivialRunningAverage();
      sskRemoteSuccess = new TrivialRunningAverage();
      sskFailure = new TrivialRunningAverage();
      locDiffCHK = new TrivialRunningAverage();
      locDiffSSK = new TrivialRunningAverage();
    }

    @Override
    public String toString() {
      // Tab-separated output: 6 counts followed by 6 running averages.
      return chkLocalSuccess.countReports()
          + "\t"
          + chkRemoteSuccess.countReports()
          + "\t"
          + chkFailure.countReports()
          + "\t"
          + sskLocalSuccess.countReports()
          + "\t"
          + sskRemoteSuccess.countReports()
          + "\t"
          + sskFailure.countReports()
          + "\t"
          + fix4p.format(fixNaN(chkLocalSuccess.currentValue()))
          + "\t"
          + fix4p.format(fixNaN(chkRemoteSuccess.currentValue()))
          + "\t"
          + fix4p.format(fixNaN(chkFailure.currentValue()))
          + "\t"
          + fix4p.format(fixNaN(sskLocalSuccess.currentValue()))
          + "\t"
          + fix4p.format(fixNaN(sskRemoteSuccess.currentValue()))
          + "\t"
          + fix4p.format(fixNaN(sskFailure.currentValue()))
          + "\t";
    }

    /** Returns {@code 0.0} for {@code NaN} to keep summaries readable. */
    private static double fixNaN(double d) {
      if (Double.isNaN(d)) return 0.0;
      return d;
    }
  }
}
