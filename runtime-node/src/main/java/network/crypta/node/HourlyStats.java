package network.crypta.node;

import java.util.Calendar;
import java.util.TimeZone;
import network.crypta.support.HTMLNode;

/**
 * Collects per-hour and aggregate statistics for accepted remote requests.
 *
 * <p>This tracker maintains three rolling records: the current UTC hour, the previous UTC hour
 * (finalized), and a cumulative total since the instance was created. On a UTC hour change, the
 * current record is finalized, logged, and moved to {@code prevRecord}; a fresh current record is
 * started.
 *
 * <p>All mutating operations are synchronized, so instances are safe for concurrent use from
 * multiple threads.
 *
 * @see HourlyStatsRecord
 */
public class HourlyStats {
  // Finalized snapshot for the previous UTC hour.
  private HourlyStatsRecord prevRecord;
  // Mutable stats for the current UTC hour.
  private HourlyStatsRecord currentRecord;
  // Cumulative stats since this tracker was created.
  private final HourlyStatsRecord totalRecord;

  // UTC clocks used exclusively to detect hour boundaries (DST-safe).
  private final Calendar lastHourlyTime;
  private final Calendar currentTime;

  private final Node node;

  /**
   * Creates a new hourly statistics tracker tied to the provided node.
   *
   * <p>Timestamps are evaluated in UTC. The initial current record begins immediately and may
   * represent a partial hour if construction occurs after the top of the hour.
   *
   * @param node the local node whose configuration (e.g., max HTL and location) is used by
   *     underlying records
   */
  public HourlyStats(Node node) {
    this.node = node;
    prevRecord = null;
    currentRecord = new HourlyStatsRecord(node, false);
    totalRecord = new HourlyStatsRecord(node, false);
    lastHourlyTime = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
    currentTime = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
  }

  /**
   * Records a single incoming, accepted remote request.
   *
   * <p>If a UTC hour change is detected at call time, the current record is finalized and logged,
   * then a new current record is started before the sample is recorded. The cumulative total is
   * always updated.
   *
   * <p>Thread-safety: this method is synchronized.
   *
   * @param ssk whether the request targeted an SSK key
   * @param success whether the request succeeded
   * @param local when {@code success} is true, whether it was satisfied locally
   * @param htl hop-to-live (HTL) value observed on arrival; values above the node's maximum are
   *     clamped
   * @param location routing location in the closed interval {@code [0, 1]}
   * @throws IllegalArgumentException if {@code htl < 0} or {@code location} lies outside {@code [0,
   *     1]}
   */
  public synchronized void remoteRequest(
      boolean ssk, boolean success, boolean local, int htl, double location) {
    long now = System.currentTimeMillis();
    currentTime.setTimeInMillis(now);
    if (lastHourlyTime.get(Calendar.HOUR_OF_DAY) != currentTime.get(Calendar.HOUR_OF_DAY)) {
      // Hour boundary crossed (UTC): finalize and log the previous hour,
      // then start a fresh current record.
      lastHourlyTime.setTimeInMillis(now);
      prevRecord = currentRecord;
      currentRecord = new HourlyStatsRecord(node, true);
      prevRecord.markFinal();
      prevRecord.log();
    }

    currentRecord.remoteRequest(ssk, success, local, htl, location);
    totalRecord.remoteRequest(ssk, success, local, htl, location);
  }

  /**
   * Appends an HTML table summarizing remote-request outcomes by HTL.
   *
   * <p>The table contains one row per HTL (descending) and a final total row. For CHK and SSK
   * separately, it shows the success rate and the counts used to compute it. Values are derived
   * from the cumulative record maintained by this tracker (not only the current hour).
   *
   * @param html parent node to which the table is appended; must not be null
   */
  public void fillRemoteRequestHTLsBox(HTMLNode html) {
    totalRecord.fillRemoteRequestHTLsBox(html);
  }
}
