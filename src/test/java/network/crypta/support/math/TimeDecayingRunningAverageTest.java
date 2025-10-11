package network.crypta.support.math;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.Arrays;
import java.util.function.LongSupplier;
import network.crypta.node.TimeSkewDetectorCallback;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class TimeDecayingRunningAverageTest {

  private static final double EPS = 1e-12;

  // Helpers to build deterministic Mockito stubs
  private static LongSupplier wallTimes(long... millis) {
    LongSupplier s = mock(LongSupplier.class);
    final long[] seq = Arrays.copyOf(millis, millis.length);
    final int[] i = {0};
    when(s.getAsLong()).thenAnswer(inv -> seq[Math.min(i[0]++, seq.length - 1)]);
    return s;
  }

  private static LongSupplier monoTimesFromMillis(long... millis) {
    LongSupplier s = mock(LongSupplier.class);
    final long[] seq = Arrays.stream(millis).map(m -> m * 1_000_000L).toArray();
    final int[] i = {0};
    when(s.getAsLong()).thenAnswer(inv -> seq[Math.min(i[0]++, seq.length - 1)]);
    return s;
  }

  @Test
  @DisplayName("currentValue_whenNoReports_returnsDefaultValue")
  void currentValue_whenNoReports_returnsDefaultValue() {
    // Arrange
    LongSupplier wall = wallTimes(1_000);
    LongSupplier mono = monoTimesFromMillis(0);

    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.5, 1000, 0, 1, null, null, wall, mono);

    // Act
    double v = avg.currentValue();

    // Assert
    assertEquals(0.5, v, EPS);
  }

  @Test
  @DisplayName("report_whenFirstValidValue_setsStartedAndCurrentToValue")
  void report_whenFirstValidValue_setsStartedAndCurrentToValue() {
    // Arrange
    LongSupplier wall = wallTimes(1_000, 1_500);
    LongSupplier mono = monoTimesFromMillis(0, 500);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1000, 0, 1, null, null, wall, mono);

    // Act
    avg.report(1.0);

    // Assert
    assertEquals(1.0, avg.currentValue(), EPS);
    assertEquals(1L, avg.countReports());
  }

  @Test
  @DisplayName("report_whenElapsedEqualsHalfLife_updatesBy50Percent")
  void report_whenElapsedEqualsHalfLife_updatesBy50Percent() {
    // Arrange
    LongSupplier wall = wallTimes(1_000, 1_000, 2_000);
    LongSupplier mono = monoTimesFromMillis(0, 0, 1_000);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, null, null, wall, mono);
    avg.report(0.0); // first report sets baseline

    // Act
    avg.report(1.0);

    // Assert
    assertEquals(0.5, avg.currentValue(), EPS);
  }

  @Test
  @DisplayName("report_whenTwoHalfLives_elapsedBlends75PercentNew")
  void report_whenTwoHalfLives_elapsedBlends75PercentNew() {
    // Arrange
    LongSupplier wall = wallTimes(1_000, 1_000, 2_000, 4_000);
    LongSupplier mono = monoTimesFromMillis(0, 0, 1_000, 3_000); // second delta = 2_000ms
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, null, null, wall, mono);
    avg.report(0.0);
    avg.report(1.0); // after 1 HL -> 0.5

    // Act: after additional 2 HL (changeFactor = 0.25)
    avg.report(1.0);

    // Assert: old=0.5 -> 0.5*0.25 + 1*0.75 = 0.875
    assertEquals(0.875, avg.currentValue(), EPS);
  }

  @Test
  @DisplayName("report_whenHalfLifeZero_usesMinimumOneMillisecondForDecay")
  void report_whenHalfLifeZero_usesMinimumOneMillisecondForDecay() {
    // Arrange: half-life = 0 -> treated as 1ms
    LongSupplier wall = wallTimes(1_000, 1_000, 2_000);
    LongSupplier mono = monoTimesFromMillis(0, 0, 1_000);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 0, 0, 1, null, null, wall, mono);
    avg.report(0.0);

    // Act: 1,000 ms elapsed with effective HL=1 -> changeFactor = 0.5^(1000/1) ~ 0.0
    // Numerically this under-flows to ~0.0, so value should move to the new sample (1.0)
    avg.report(1.0);

    // Assert
    assertEquals(1.0, avg.currentValue(), EPS);
  }

  @ParameterizedTest(name = "report_whenValueBelowMin_isIgnored[{index}]({0})")
  @ValueSource(doubles = {-1.0, -1000.0})
  @DisplayName("report_whenValueBelowMin_isIgnored")
  void report_whenValueBelowMin_isIgnored(double bad) {
    // Arrange
    LongSupplier wall = wallTimes(1_000, 1_000);
    LongSupplier mono = monoTimesFromMillis(0, 0);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.25, 1_000, 0, 1, null, null, wall, mono);
    avg.report(0.25);
    long before = avg.countReports();

    // Act
    avg.report(bad);

    // Assert
    assertEquals(0.25, avg.currentValue(), EPS);
    assertEquals(before, avg.countReports());
  }

  @ParameterizedTest(name = "report_whenValueAboveMax_isIgnored[{index}]({0})")
  @ValueSource(doubles = {1.01, 1000.0})
  @DisplayName("report_whenValueAboveMax_isIgnored")
  void report_whenValueAboveMax_isIgnored(double bad) {
    // Arrange
    LongSupplier wall = wallTimes(1_000, 1_000);
    LongSupplier mono = monoTimesFromMillis(0, 0);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.75, 1_000, 0, 1, null, null, wall, mono);
    avg.report(0.75);
    long before = avg.countReports();

    // Act
    avg.report(bad);

    // Assert
    assertEquals(0.75, avg.currentValue(), EPS);
    assertEquals(before, avg.countReports());
  }

  @ParameterizedTest(name = "report_whenNaNOrInfinity_isIgnored[{index}]({0})")
  @ValueSource(doubles = {Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY})
  @DisplayName("report_whenNaNOrInfinity_isIgnored")
  void report_whenNaNOrInfinity_isIgnored(double bad) {
    // Arrange
    LongSupplier wall = wallTimes(1_000, 1_000);
    LongSupplier mono = monoTimesFromMillis(0, 0);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.4, 1_000, 0, 1, null, null, wall, mono);
    avg.report(0.4);
    long before = avg.countReports();

    // Act
    avg.report(bad);

    // Assert
    assertEquals(0.4, avg.currentValue(), EPS);
    assertEquals(before, avg.countReports());
  }

  @Test
  @DisplayName("report_whenWallClockGoesBackward_usesMonotonic")
  void report_whenWallClockGoesBackward_usesMonotonic() {
    // Arrange
    TimeSkewDetectorCallback cb = mock(TimeSkewDetectorCallback.class);
    LongSupplier wall = wallTimes(10_000, 12_000, 11_500);
    LongSupplier mono = monoTimesFromMillis(0, 1_000, 2_000); // delta 1000ms used
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, null, cb, wall, mono);
    avg.report(0.0);

    // Act
    avg.report(1.0);

    // Assert: 1 half-life -> current moves halfway, proving monotonic use
    assertEquals(0.5, avg.currentValue(), EPS);
  }

  @Test
  @DisplayName("report_whenUptimeNegative_appliesDecay")
  void report_whenUptimeNegative_appliesDecay() {
    // Arrange
    TimeSkewDetectorCallback cb = mock(TimeSkewDetectorCallback.class);
    LongSupplier wall = wallTimes(10_000, 11_000, 9_000);
    LongSupplier mono = monoTimesFromMillis(0, 1_000, 2_000);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, null, cb, wall, mono);
    avg.report(0.0);

    // Act
    avg.report(1.0);

    // Assert: still decays using monotonic delta despite negative uptime
    assertTrue(avg.currentValue() >= 0.5 - 1e-9);
  }

  @Test
  @DisplayName("report_whenMonotonicRegresses_clampsElapsedToZero")
  void report_whenMonotonicRegresses_clampsElapsedToZero() {
    // Arrange
    LongSupplier wall = wallTimes(1_000, 1_100, 1_200); // strictly increasing wall clock
    LongSupplier mono = monoTimesFromMillis(500, 1_000, 800); // regress at third call
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, null, null, wall, mono);
    avg.report(1.0); // start at 1.0

    // Act: second report with mono delta negative -> treated as 0ms elapsed
    avg.report(0.123);

    // Assert: no change due to 0ms elapsed
    assertEquals(1.0, avg.currentValue(), EPS);
    assertEquals(2L, avg.countReports());
  }

  @Test
  @DisplayName("exportFieldSet_whenShortLivedTrue_containsExpectedValues")
  void exportFieldSet_whenShortLivedTrue_containsExpectedValues() {
    // Arrange
    LongSupplier wall = wallTimes(1_000, 2_000, 2_000); // ctor, report, export
    LongSupplier mono = monoTimesFromMillis(0, 0);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, null, null, wall, mono);
    avg.report(0.5);

    // Act
    SimpleFieldSet fs = avg.exportFieldSet(true);

    // Assert
    assertEquals("TimeDecayingRunningAverage", fs.get("Type"));
    assertEquals("true", fs.get("Started"));
    assertEquals("1", fs.get("TotalReports"));
    assertEquals("0.5", fs.get("CurrentValue"));
    assertEquals("1000", fs.get("Uptime"));
  }

  @Test
  @DisplayName("restoreFromFieldSet_whenStartedTrue_ignoresFirstReportThenDecays")
  void restoreFromFieldSet_whenStartedTrue_ignoresFirstReportThenDecays() {
    // Arrange: snapshot says value=0.5, started=true, uptime=1000, totalReports=1
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Type", "TimeDecayingRunningAverage");
    sfs.putSingle("Started", "true");
    sfs.putSingle("Uptime", "1000");
    sfs.putSingle("TotalReports", "1");
    sfs.putSingle("CurrentValue", "0.5");

    LongSupplier wall = wallTimes(2_000, 3_000, 4_000);
    LongSupplier mono = monoTimesFromMillis(0, 0, 1_000);

    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, sfs, null, wall, mono);

    // Assert initial restored state
    assertEquals(0.5, avg.currentValue(), EPS);
    assertEquals(1L, avg.countReports());

    // Act 1: first report is ignored for value, only timestamps/count advance
    avg.report(0.0);
    assertEquals(0.5, avg.currentValue(), EPS);
    assertEquals(2L, avg.countReports());

    // Act 2: subsequent report decays normally (1 half-life -> 0.25)
    avg.report(0.0);
    assertEquals(0.25, avg.currentValue(), EPS);
    assertEquals(3L, avg.countReports());
  }

  @Test
  @DisplayName("restoreFromFieldSet_whenValueInvalid_resetsToDefaultAndZeroCount")
  void restoreFromFieldSet_whenValueInvalid_resetsToDefaultAndZeroCount() {
    // Arrange: set CurrentValue out of [min,max]
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Type", "TimeDecayingRunningAverage");
    sfs.putSingle("Started", "true");
    sfs.putSingle("Uptime", "1000");
    sfs.putSingle("TotalReports", "7");
    sfs.putSingle("CurrentValue", "2.0"); // out of range for [0,1]

    LongSupplier wall = wallTimes(5_000);
    LongSupplier mono = monoTimesFromMillis(0);

    // Act
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.42, 1_000, 0, 1, sfs, null, wall, mono);

    // Assert: defaults restored
    assertEquals(0.42, avg.currentValue(), EPS);
    assertEquals(0L, avg.countReports());
  }

  @Test
  @DisplayName("valueIfReported_whenCalled_throwsUnsupportedOperationException")
  void valueIfReported_whenCalled_throwsUnsupportedOperationException() {
    // Arrange
    LongSupplier wall = wallTimes(1_000);
    LongSupplier mono = monoTimesFromMillis(0);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, null, null, wall, mono);

    // Act + Assert
    assertThrows(UnsupportedOperationException.class, () -> avg.valueIfReported(123.0));
  }

  @Test
  @DisplayName("getDataLength_whenCalled_returns33Bytes")
  void getDataLength_whenCalled_returns33Bytes() {
    // Arrange
    LongSupplier wall = wallTimes(1_000);
    LongSupplier mono = monoTimesFromMillis(0);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, null, null, wall, mono);

    // Act + Assert
    assertEquals(33, avg.getDataLength());
  }

  @Test
  @DisplayName("constructor_whenFieldSetNull_behavesAsFreshInstance")
  void constructor_whenFieldSetNull_behavesAsFreshInstance() {
    // Arrange
    LongSupplier wall = wallTimes(1_000);
    LongSupplier mono = monoTimesFromMillis(0);

    // Act
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.33, 1_000, 0, 1, null, null, wall, mono);

    // Assert
    assertEquals(0.33, avg.currentValue(), EPS);
    assertEquals(0L, avg.countReports());
  }

  @Test
  @DisplayName("binaryConstructor_whenMagicInvalid_throwsIOException")
  void binaryConstructor_whenMagicInvalid_throwsIOException() throws Exception {
    // Arrange: wrong magic, otherwise valid record
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(0xdeadbeef); // wrong magic
      dos.writeInt(1); // version
      dos.writeDouble(0.5);
      dos.writeBoolean(true);
      dos.writeLong(3L);
      dos.writeLong(100L);
    }
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));

    // Act + Assert
    assertThrows(
        java.io.IOException.class,
        () -> new TimeDecayingRunningAverage(0.0, 1_000.0, 0.0, 1.0, dis, null));
  }

  @Test
  @DisplayName("binaryConstructor_whenCurValueOutOfRange_throwsIOException")
  void binaryConstructor_whenCurValueOutOfRange_throwsIOException() throws Exception {
    // Arrange: correct magic+version but curValue = 2.0 out of [0,1]
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeInt(0x5ff4ac94); // magic used by implementation
      dos.writeInt(1); // version
      dos.writeDouble(2.0); // out of range
      dos.writeBoolean(true);
      dos.writeLong(1L);
      dos.writeLong(0L);
    }
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));

    // Act + Assert
    assertThrows(
        java.io.IOException.class,
        () -> new TimeDecayingRunningAverage(0.0, 1_000.0, 0.0, 1.0, dis, null));
  }

  @Test
  @DisplayName("binaryRoundTrip_whenSerializedAndRestored_preservesValueAndCount")
  void binaryRoundTrip_whenSerializedAndRestored_preservesValueAndCount() throws Exception {
    // Arrange
    LongSupplier wall = wallTimes(1_000, 1_500, 2_500, 2_500); // ctor, r1, r2, write
    LongSupplier mono = monoTimesFromMillis(0, 500, 1_500);
    TimeDecayingRunningAverage avg =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, null, null, wall, mono);
    avg.report(1.0);
    avg.report(1.0);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      avg.writeDataTo(dos);
    }

    // Act: restore using binary constructor
    ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
    try (DataInputStream dis = new DataInputStream(bais)) {
      TimeDecayingRunningAverage restored =
          new TimeDecayingRunningAverage(0.0, 1_000.0, 0.0, 1.0, dis, null);

      // Assert
      assertEquals(avg.currentValue(), restored.currentValue(), EPS);
      assertEquals(avg.countReports(), restored.countReports());
      assertEquals(-1L, restored.lastReportTime()); // constructor semantics
    }
  }

  @Test
  @DisplayName("copyConstructor_whenUsed_createsIndependentSnapshot")
  void copyConstructor_whenUsed_createsIndependentSnapshot() {
    // Arrange
    LongSupplier wall1 = wallTimes(1_000, 1_000, 2_000);
    LongSupplier mono1 = monoTimesFromMillis(0, 0, 1_000);
    TimeDecayingRunningAverage original =
        new TimeDecayingRunningAverage(0.0, 1_000, 0, 1, null, null, wall1, mono1);
    TimeDecayingRunningAverage copy = new TimeDecayingRunningAverage(original);

    // Act: update only the copy
    copy.report(0.0);
    copy.report(1.0);

    // Assert: original remains untouched; copy updated
    assertEquals(0.0, original.currentValue(), EPS);
    assertEquals(0L, original.countReports());
    // After one HL from 0.0 to 1.0 -> 0.5
    assertEquals(0.5, copy.currentValue(), EPS);
    assertEquals(2L, copy.countReports());
  }
}
