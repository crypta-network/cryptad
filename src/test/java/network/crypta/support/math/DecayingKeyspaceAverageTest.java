package network.crypta.support.math;

import java.util.Objects;
import java.util.stream.Stream;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.closeTo;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DecayingKeyspaceAverage} in AAA style.
 *
 * <p>Deterministic, no time/I-O dependencies. We use Mockito to mock {@link SimpleFieldSet} when
 * exercising persistence-based construction paths.
 */
class DecayingKeyspaceAverageTest {

  private static final double EPS = 1e-12;

  // -------- Helpers / sources --------

  static Stream<Double> invalidDoubles() {
    return Stream.of(-0.1, 1.1, Double.NaN, Double.POSITIVE_INFINITY, Double.NEGATIVE_INFINITY);
  }

  static Stream<Double> boundaryDoubles() {
    return Stream.of(0.0, 1.0);
  }

  // -------- Tests --------

  @Test
  void currentValue_whenConstructedWithDefault_expectDefault() {
    // Arrange
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(0.5, 2, null);

    // Act
    double value = avg.currentValue();

    // Assert
    assertThat(value, equalTo(0.5));
  }

  @ParameterizedTest
  @MethodSource("invalidDoubles")
  void report_whenInvalid_expectIllegalArgumentException(Double invalid) {
    // Arrange
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(0.5, 2, null);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> avg.report(invalid));
  }

  @ParameterizedTest
  @MethodSource("invalidDoubles")
  void valueIfReported_whenInvalid_expectIllegalArgumentException(Double invalid) {
    // Arrange
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(0.5, 2, null);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> avg.valueIfReported(invalid));
  }

  @ParameterizedTest
  @MethodSource("boundaryDoubles")
  void report_whenBoundaryValues_expectAccepted(Double boundary) {
    // Arrange
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(0.5, 2, null);
    assertEquals(0, avg.countReports());

    // Act
    assertDoesNotThrow(() -> avg.report(boundary));

    // Assert
    assertEquals(1, avg.countReports());
    // For boundary=1.0, the stored value normalizes to 0.0; for 0.0, it's 0.0 directly.
    assertThat(avg.currentValue(), closeTo(0.0, EPS));
  }

  @Test
  void valueIfReported_whenCalled_doesNotMutateState() {
    // Arrange
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(0.25, 2, null);
    avg.report(0.25); // anchor first sample; decay=1.0
    double beforeValue = avg.currentValue();
    long beforeCount = avg.countReports();

    // Act
    double predicted = avg.valueIfReported(0.75);

    // Assert
    // Expect normalize(s + 0.5 * change(s, d)) with s=0.25, d=0.75, change=0.5
    double expected =
        KeyspaceMath.normalize(beforeValue + 0.5 * KeyspaceMath.change(beforeValue, 0.75));
    assertThat(predicted, closeTo(expected, EPS));
    assertThat(avg.currentValue(), closeTo(beforeValue, EPS));
    assertEquals(beforeCount, avg.countReports());
  }

  @Test
  void report_whenWrapsAcrossBoundary_expectShortestPath() {
    // Arrange
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(0.5, 2, null);

    // Act + Assert (anchor at 0.5)
    avg.report(0.5);
    assertThat(avg.currentValue(), equalTo(0.5));

    // Act + Assert (0.5 -> 1.0 wraps at boundary; expected 0.75 due to 0.5 decay)
    avg.report(1.0);
    assertThat(avg.currentValue(), equalTo(0.75));

    // Act + Assert (0.75 -> 0.25 across wrap, expected 0.0)
    avg.report(0.25);
    assertThat(avg.currentValue(), equalTo(0.0));

    // Act + Assert (continue sequence as regression coverage)
    avg.report(0.25);
    assertThat(avg.currentValue(), equalTo(0.125));
    avg.report(0.875);
    assertThat(avg.currentValue(), equalTo(0.0));
    avg.report(0.75);
    assertThat(avg.currentValue(), equalTo(0.875));
  }

  @Test
  void reportLong_whenCalled_expectIllegalArgumentException() {
    // Arrange
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(0.5, 2, null);

    // Act + Assert
    assertThrows(IllegalArgumentException.class, () -> avg.report(1L));
  }

  @Test
  void changeMaxReports_whenSetToOne_nextReportReplacesCurrent() {
    // Arrange
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(0.0, 2, null);
    avg.report(0.9); // anchor: s=0.9

    // Act: with maxReports=2, reporting 0.1 moves halfway across the shortest path
    avg.report(0.1);
    double expectedHalf = KeyspaceMath.normalize(0.9 + 0.5 * KeyspaceMath.change(0.9, 0.1));
    assertThat(avg.currentValue(), closeTo(expectedHalf, EPS));

    // Act: increase decay by setting maxReports=1 so the next report fully replaces the current
    avg.changeMaxReports(1);
    avg.report(0.2);

    // Assert: the new value equals the unwrapped target (normalized)
    double expectedFull =
        KeyspaceMath.normalize(expectedHalf + KeyspaceMath.change(expectedHalf, 0.2));
    assertThat(avg.currentValue(), closeTo(expectedFull, EPS));
  }

  @Test
  void copyConstructor_whenCopied_modifyingCopyDoesNotAffectOriginal() {
    // Arrange
    DecayingKeyspaceAverage original = new DecayingKeyspaceAverage(0.5, 2, null);
    original.report(0.5);
    original.report(0.75);
    DecayingKeyspaceAverage copy = new DecayingKeyspaceAverage(original);
    double originalBefore = original.currentValue();
    long reportsBefore = original.countReports();

    // Act
    copy.report(0.875); // mutate copy only

    // Assert
    assertThat(original.currentValue(), closeTo(originalBefore, EPS));
    assertEquals(reportsBefore, original.countReports());
  }

  @Test
  void copyOf_whenCalled_returnsDeepCopy() {
    // Arrange
    DecayingKeyspaceAverage original = new DecayingKeyspaceAverage(0.5, 2, null);
    original.report(0.5);
    original.report(1.0);
    double snapValue = original.currentValue();
    long snapReports = original.countReports();

    // Act: take a snapshot using the interface helper and then mutate the original
    RunningAverage snapshot = RunningAverage.copyOf(original);
    original.report(0.25);

    // Assert: snapshot is independent
    assertThat(snapshot.currentValue(), closeTo(snapValue, EPS));
    assertEquals(snapReports, snapshot.countReports());
  }

  @Test
  void constructorWithBaseAverage_whenBaseMutatedAfterConstruction_doesNotAffectInstance() {
    // Arrange (prepare a base underlying average with some state)
    BootstrappingDecayingRunningAverage base =
        new BootstrappingDecayingRunningAverage(0.25, -2.0, 2.0, 4, null);
    base.report(0.75);
    double snapshot = base.currentValue();
    long snapReports = base.countReports();

    // Act: construct instance from base (takes snapshot) and then mutate base
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(base);
    base.report(0.0); // mutate base after construction

    // Assert: the new instance reflects the snapshot, not later mutations
    assertThat(avg.currentValue(), closeTo(snapshot, EPS));
    assertEquals(snapReports, avg.countReports());
  }

  @Test
  void exportFieldSet_whenCalled_containsTypeAndCurrentValueAndReports() {
    // Arrange
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(0.5, 2, null);
    avg.report(0.5);
    avg.report(1.0); // normalizes to 0.75 internally, then to [0,1)
    double current = avg.currentValue();
    long reports = avg.countReports();

    // Act
    SimpleFieldSet sfs = avg.exportFieldSet(false);

    // Assert
    assertThat(sfs.get("Type"), equalTo("BootstrappingDecayingRunningAverage"));
    String currentValue = Objects.requireNonNull(sfs.get("CurrentValue"));
    String reportCount = Objects.requireNonNull(sfs.get("Reports"));
    assertThat(Double.parseDouble(currentValue), closeTo(current, EPS));
    assertEquals(reports, Long.parseLong(reportCount));
  }

  @Test
  void constructor_whenFsProvided_usesPersistedValues() {
    // Arrange: mock SimpleFieldSet to simulate persisted state
    SimpleFieldSet fs = mock(SimpleFieldSet.class);
    when(fs.getDouble(eq("CurrentValue"), anyDouble())).thenReturn(1.75);
    when(fs.getLong(eq("Reports"), anyLong())).thenReturn(13L);

    // Act
    DecayingKeyspaceAverage avg = new DecayingKeyspaceAverage(0.5, 4, fs);

    // Assert: the underlying snapshot is picked up from fs
    assertThat(avg.currentValue(), equalTo(1.75));
    assertEquals(13L, avg.countReports());
  }
}
