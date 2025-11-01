package network.crypta.node;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.text.DecimalFormat;
import network.crypta.support.Fields;
import network.crypta.support.Ticker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Estimates the node's average uptime over fixed 5-minute intervals.
 *
 * <p>The estimator samples once every five minutes (aligned by a per-node offset) and appends the
 * current {@code 5-minute-since-epoch} integer to an on-disk log. The last 48 hours and the last 7
 * days are tracked in circular buffers to compute recent uptime fractions. When the active log gets
 * large, it is rotated to a previous file and a new log is created.
 *
 * <p>Units: the sampling period is {@code PERIOD = 5 minutes}. The derived {@code timeOffset} is in
 * milliseconds and lies in {@code [0, PERIOD)}.
 *
 * <p>Threading: sampling is scheduled via {@link Ticker}. Public query methods are synchronized.
 * This class writes to {@code uptime.dat} and may rotate to {@code uptime.old.dat}.
 *
 * @author toad
 */
public class UptimeEstimator implements Runnable {
  private static final Logger LOG = LoggerFactory.getLogger(UptimeEstimator.class);

  /** Five minutes in milliseconds. */
  static final long PERIOD = MINUTES.toMillis(5);

  Ticker ticker;

  /** For each 5-minute slot in the last 48 hours, whether the node was online. */
  private final boolean[] wasOnline = new boolean[48 * 12]; // 48 hours * 12 5-minute slots/hour

  /** Whether the node was online for each 5-minute slot in the last week. */
  private final boolean[] wasOnlineWeek =
      new boolean[7 * 24 * 12]; // 7 days/week * 24 hours/day * 12 5-minute slots/hour

  /**
   * Circular index of the next slot to mark. The arrays wrap around; elements after {@code slot}
   * refer to earlier times in the window.
   */
  private int slot;

  /** Active log file to which new samples are appended. */
  private final File logFile;

  /**
   * The previous file. We have read this. When logFile reaches 48 hours, we dump the prevFile, move
   * the logFile over it, and write to a new logFile.
   */
  private final File prevFile;

  /** Sampling offset within the 5-minute period; derived from the node identity. */
  private final long timeOffset;

  /**
   * Create a new uptime estimator.
   *
   * @param runDir program directory; used to store {@code uptime.dat} and {@code uptime.old.dat}
   * @param ticker scheduler that queues time-based sampling callbacks
   * @param bs node identity bytes used to deterministically derive the sampling offset
   */
  public UptimeEstimator(ProgramDirectory runDir, Ticker ticker, byte[] bs) {
    this.ticker = ticker;
    logFile = runDir.file("uptime.dat");
    prevFile = runDir.file("uptime.old.dat");
    timeOffset =
        (int)
            ((((double) (Math.abs(Fields.hashCode(bs, bs.length / 2, bs.length - bs.length / 2))))
                    / Integer.MAX_VALUE)
                * PERIOD);
  }

  /**
   * Initialize in-memory windows and schedule the first sample.
   *
   * <p>This reads any existing log files into the 48-hour and 7-day windows, computes the initial
   * uptime, and schedules the recurring task aligned to {@code timeOffset}.
   */
  public void start() {
    long now = System.currentTimeMillis();
    int fiveMinutesSinceEpoch = (int) (now / PERIOD);
    int base = fiveMinutesSinceEpoch - wasOnlineWeek.length;
    // Read both files.
    readData(prevFile, base);
    readData(logFile, base);
    schedule(System.currentTimeMillis());
    LOG.atInfo()
        .setMessage("Created uptime estimator: timeOffset={} ms, uptime at startup={}")
        .addArgument(timeOffset)
        .addArgument(() -> new DecimalFormat("0.00").format(getUptime()))
        .log();
  }

  private void readData(File file, int base) {
    try (FileInputStream fis = new FileInputStream(file);
        DataInputStream dis = new DataInputStream(fis)) {
      while (true) {
        int offset = dis.readInt();
        if (offset >= base) {
          int slotNo = offset - base;
          if (slotNo >= wasOnlineWeek.length) {
            if (slotNo > wasOnlineWeek.length) {
              LOG.error(
                  "Corrupt uptime data in {}: window upper bound={}, read slot={}",
                  file,
                  (base + wasOnlineWeek.length),
                  slotNo);
            }
            break; // Reached the end or corrupt data beyond the window.
          }
          // slotNo is non-negative because offset >= base.
          wasOnline[slotNo % wasOnline.length] = wasOnlineWeek[slotNo] = true;
        }
      }
    } catch (EOFException e) {
      // Reached end of file; no more samples to load.
    } catch (IOException e) {
      LOG.error("Read old uptime file failed: {}; treating slots as offline", file);
    }
  }

  /**
   * Perform one sampling tick.
   *
   * <p>Marks the current slot as online, rotates the on-disk log if it exceeds the window size,
   * appends the current 5-minute counter, and schedules the next tick.
   */
  @Override
  public void run() {
    synchronized (this) {
      wasOnlineWeek[slot] = true;
      wasOnline[slot % wasOnline.length] = true;
      slot = (slot + 1) % wasOnlineWeek.length;
    }
    long now = System.currentTimeMillis();
    if (logFile.length() > wasOnlineWeek.length * 4L) {
      try {
        Files.deleteIfExists(prevFile.toPath());
      } catch (IOException e) {
        LOG.warn("Delete previous uptime file failed for {}: {}", prevFile, e.toString());
      }
      try {
        Files.move(logFile.toPath(), prevFile.toPath());
      } catch (IOException e) {
        LOG.warn("Uptime file rotation failed {} -> {}: {}", logFile, prevFile, e.toString());
      }
    }
    int fiveMinutesSinceEpoch = (int) (now / PERIOD);
    try (FileOutputStream fos = new FileOutputStream(logFile, true);
        DataOutputStream dos = new DataOutputStream(fos)) {
      dos.writeInt(fiveMinutesSinceEpoch);
    } catch (FileNotFoundException e) {
      LOG.error("Create or open uptime file failed for {}: {}", logFile, e, e);
    } catch (IOException e) {
      LOG.error("Write to uptime log failed: {}", logFile);
    } finally {
      // Schedule the next sample.
      schedule(now);
    }
  }

  private void schedule(long now) {
    long nextTime = (now / PERIOD) * PERIOD + timeOffset;
    if (nextTime < now) nextTime += PERIOD;
    ticker.queueTimedJob(this, nextTime - System.currentTimeMillis());
  }

  /**
   * Compute the uptime fraction for the provided window.
   *
   * @param uptime circular window of 5-minute samples where {@code true} means online
   * @return fraction between 0.0 and 1.0
   */
  private synchronized double getUptime(boolean[] uptime) {
    int upCount = 0;
    for (boolean sample : uptime) if (sample) upCount++;
    return ((double) upCount) / ((double) uptime.length);
  }

  /**
   * Get the node's uptime fraction over the past 48 hours (576 slots).
   *
   * @return fraction between 0.0 and 1.0
   */
  public synchronized double getUptime() {
    return getUptime(wasOnline);
  }

  /**
   * Get the node's uptime fraction over the past 7 days (2016 slots).
   *
   * @return fraction between 0.0 and 1.0
   */
  public synchronized double getUptimeWeek() {
    return getUptime(wasOnlineWeek);
  }
}
