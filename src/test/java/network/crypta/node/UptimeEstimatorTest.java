package network.crypta.node;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Path;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class UptimeEstimatorTest {

  @TempDir Path tempDir;

  @Mock Ticker ticker;

  private static byte[] zeroBytes(int n) {
    return new byte[n];
  }

  private ProgramDirectory programDirectory() throws Exception {
    ProgramDirectory pd = new ProgramDirectory();
    pd.move(tempDir.toString());
    return pd;
  }

  @Test
  void start_whenNoExistingData_expectZeroUptimeAndSchedules() throws Exception {
    // Arrange
    ProgramDirectory pd = programDirectory();
    UptimeEstimator est = new UptimeEstimator(pd, ticker, zeroBytes(32));

    // Act
    est.start();

    // Assert
    // Uptime arrays are empty until run() marks the first slot
    assertEquals(0.0, est.getUptime(), 0.0);
    assertEquals(0.0, est.getUptimeWeek(), 0.0);

    // One scheduling call is made
    verify(ticker, times(1)).queueTimedJob(eq(est), any(Long.class));
  }

  @Test
  void run_whenCalledOnce_marksCurrentSlotAndWrites() throws Exception {
    // Arrange
    ProgramDirectory pd = programDirectory();
    UptimeEstimator est = new UptimeEstimator(pd, ticker, zeroBytes(16));
    est.start();

    // Act
    est.run();

    // Assert
    // One slot out of the arrays becomes true
    double expected48h = 1.0 / (48.0 * 12.0); // 576
    double expectedWeek = 1.0 / (7.0 * 24.0 * 12.0); // 2016
    assertEquals(expected48h, est.getUptime(), 1e-12);
    assertEquals(expectedWeek, est.getUptimeWeek(), 1e-12);

    // Two scheduling calls in total: from start() and from run()
    verify(ticker, times(2)).queueTimedJob(eq(est), any(Long.class));

    // And a log file exists with a single 4-byte integer written
    File log = pd.file("uptime.dat");
    assertTrue(log.exists());
    assertEquals(4L, log.length());
  }

  @Test
  void start_whenPreexistingFilesWithOffsets_setsExpectedFractions() throws Exception {
    // Arrange
    ProgramDirectory pd = programDirectory();
    File prev = pd.file("uptime.old.dat");
    File log = pd.file("uptime.dat");

    // Base in five-minute slots as used by UptimeEstimator.start()
    final long periodMillis = 5L * 60L * 1000L;
    int nowSlots = (int) (System.currentTimeMillis() / periodMillis);
    int base = nowSlots - (7 * 24 * 12); // one week window length

    // Choose four valid slot numbers within [0, 2015], none at edges to avoid boundary races
    int[] slotNos = new int[] {1, 1440, 2013, 2014};

    try (DataOutputStream d1 = new DataOutputStream(new FileOutputStream(prev));
        DataOutputStream d2 = new DataOutputStream(new FileOutputStream(log))) {
      // Two in prev, two in current
      d1.writeInt(base + slotNos[0]);
      d1.writeInt(base + slotNos[1]);
      d2.writeInt(base + slotNos[2]);
      d2.writeInt(base + slotNos[3]);
    }

    UptimeEstimator est = new UptimeEstimator(pd, ticker, zeroBytes(8));

    // Act
    est.start();

    // Assert
    double expectedWeek = 4.0 / (7.0 * 24.0 * 12.0); // 4 out of 2016
    double expected48h = 4.0 / (48.0 * 12.0); // chosen slots occupy 4 distinct 48h indices
    assertEquals(expectedWeek, est.getUptimeWeek(), 1e-9);
    assertEquals(expected48h, est.getUptime(), 1e-9);
  }

  @Test
  void run_whenLogExceedsThreshold_rotatesToPrevAndAppendsFresh() throws Exception {
    // Arrange
    ProgramDirectory pd = programDirectory();
    UptimeEstimator est = new UptimeEstimator(pd, ticker, zeroBytes(4));
    est.start();

    // Threshold bytes == 2016 * 4
    final int writesToExceed = 2016 + 1; // +1 to make length > threshold

    // Perform enough runs to exceed threshold
    for (int i = 0; i < writesToExceed; i++) {
      est.run();
    }

    // This next run will observe length > threshold and rotate
    est.run();

    // Assert
    File prev = pd.file("uptime.old.dat");
    File log = pd.file("uptime.dat");
    assertTrue(prev.exists());
    assertTrue(prev.length() > 0L);
    assertTrue(log.exists());
    assertEquals(4L, log.length(), "new log should start fresh after rotation");
  }

  @Test
  void start_whenCorruptSlotBeyondWindow_ignoresAndLeavesZero() throws Exception {
    // Arrange
    ProgramDirectory pd = programDirectory();
    File log = pd.file("uptime.dat");

    final long periodMillis = 5L * 60L * 1000L;
    int nowSlots = (int) (System.currentTimeMillis() / periodMillis);
    int base = nowSlots - (7 * 24 * 12);

    // Write a single bogus entry strictly beyond the week window
    try (DataOutputStream d = new DataOutputStream(new FileOutputStream(log))) {
      d.writeInt(base + (7 * 24 * 12) + 123);
    }

    UptimeEstimator est = new UptimeEstimator(pd, ticker, zeroBytes(12));

    // Act
    est.start();

    // Assert
    assertEquals(0.0, est.getUptimeWeek(), 0.0);
    assertEquals(0.0, est.getUptime(), 0.0);
  }
}
