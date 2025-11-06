package network.crypta.client.events;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Date;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

@SuppressWarnings("java:S100")
class SplitfileProgressEventTest {

  @Test
  void api_whenQueried_expectImplementsClientEventAndStableCode() {
    SplitfileProgressEvent event = new SplitfileProgressEvent(10, 3, null, 1, 0, null, 5, 2, false);

    assertInstanceOf(ClientEvent.class, event, "Event must implement ClientEvent");
    assertEquals(SplitfileProgressEvent.CODE, event.getCode(), "getCode must return CODE");
    assertEquals(0x07, event.getCode(), "CODE must be the expected numeric value");
  }

  @Test
  void constructor_whenDatesProvided_makesDefensiveCopies() {
    Date success = new Date(1_000_000L);
    Date failure = new Date(2_000_000L);

    SplitfileProgressEvent event =
        new SplitfileProgressEvent(1, 0, success, 0, 0, failure, 1, 0, false);

    // Mutate the original inputs after construction
    success.setTime(9_999_999L);
    failure.setTime(8_888_888L);

    assertNotNull(event.latestSuccess);
    assertNotNull(event.latestFailure);
    assertEquals(1_000_000L, event.latestSuccess.getTime(), "latestSuccess must be copied");
    assertEquals(2_000_000L, event.latestFailure.getTime(), "latestFailure must be copied");
  }

  @Test
  void constructor_whenNullDatesProvided_storesNulls() {
    SplitfileProgressEvent event = new SplitfileProgressEvent(0, 0, null, 0, 0, null, 1, 0, false);

    assertNull(event.latestSuccess, "Null latestSuccess input must store null");
    assertNull(event.latestFailure, "Null latestFailure input must store null");
  }

  @Test
  void defaultConstructor_whenUsed_setsExpectedDefaults() {
    SplitfileProgressEvent event = new SplitfileProgressEvent();

    assertEquals(0, event.totalBlocks);
    assertEquals(0, event.succeedBlocks);
    assertNotNull(event.latestSuccess, "Default latestSuccess should be non-null current time");
    assertEquals(0, event.failedBlocks);
    assertEquals(0, event.fatallyFailedBlocks);
    assertNull(event.latestFailure);
    assertEquals(0, event.minSuccessFetchBlocks);
    assertFalse(event.finalizedTotal);

    // Calling getDescription should normalize minSuccessfulBlocks from 0 to 1 when succeed==0
    String desc = event.getDescription();
    assertEquals(1, event.getMinSuccessfulBlocks(), "minSuccessfulBlocks must be normalized to 1");
    assertTrue(
        desc.startsWith("Completed 0% 0/1 (failed 0, fatally 0, total 0, minSuccessFetch 0) "),
        "Description should reflect normalized denominator and 0% progress");
  }

  @Test
  @DisplayName("getDescription_whenNormalValues_formatsPercentAndFields")
  void getDescription_whenNormalValues_formatsPercentAndFields() {
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(
            100, // total
            25, // succeed
            null, 2, // failed
            1, // fatally failed
            null, 50, // minSuccessfulBlocks
            5, // minSuccessFetchBlocks
            false);

    String desc = event.getDescription();

    assertEquals(
        "Completed 50% 25/50 (failed 2, fatally 1, total 100, minSuccessFetch 5) ",
        desc, "Description should include integer percent and all counters");
  }

  @Test
  @DisplayName("getDescription_whenFinalizedTrue_appendsFinalizedLabel")
  void getDescription_whenFinalizedTrue_appendsFinalizedLabel() {
    SplitfileProgressEvent event = new SplitfileProgressEvent(10, 5, null, 0, 0, null, 10, 0, true);

    String desc = event.getDescription();

    assertTrue(desc.contains("(finalized total)"), "Should include finalized label");
    assertTrue(desc.endsWith("(finalized total)"), "Finalized label should be at the end");
  }

  @Test
  @DisplayName(
      "getDescription_whenMinSuccessfulZeroAndSucceedZero_normalizesDenominatorAndShowsZeroPercent")
  void
      getDescription_whenMinSuccessfulZeroAndSucceedZero_normalizesDenominatorAndShowsZeroPercent() {
    SplitfileProgressEvent event = new SplitfileProgressEvent(0, 0, null, 0, 0, null, 0, 0, false);

    String desc = event.getDescription();

    assertEquals(
        1, event.getMinSuccessfulBlocks(), "Denominator must normalize to 1 when zero/zero");
    assertEquals(
        "Completed 0% 0/1 (failed 0, fatally 0, total 0, minSuccessFetch 0) ",
        desc, "Description should render 0% and 0/1 after normalization");
  }

  @Test
  @DisplayName(
      "getDescription_whenMinSuccessfulZeroAndSucceedPositive_omitsPercentAndKeepsDenominatorZero")
  void
      getDescription_whenMinSuccessfulZeroAndSucceedPositive_omitsPercentAndKeepsDenominatorZero() {
    SplitfileProgressEvent event = new SplitfileProgressEvent(0, 3, null, 0, 0, null, 0, 0, false);

    String desc = event.getDescription();

    // No percent is appended in this branch; we expect a double space after "Completed"
    assertTrue(desc.startsWith("Completed  "), "Percent should be omitted when denominator is 0");
    assertTrue(desc.contains("/0"), "Denominator should remain 0 in the textual counters");
    assertFalse(desc.contains("%"), "Percent sign must not appear in this branch");
  }

  @ParameterizedTest(name = "{0}/{1} -> {2}%")
  @CsvSource({
    // succeed, minSuccessful, expectedPercent
    "0,1,0",
    "1,1,100",
    "1,2,50",
    "1,3,33",
    "2,3,66",
    "49,100,49"
  })
  void getDescription_whenVariousRatios_formatsIntegerPercent(
      int succeed, int minSuccessful, int expectedPercent) {
    SplitfileProgressEvent event =
        new SplitfileProgressEvent(0, succeed, null, 0, 0, null, minSuccessful, 0, false);

    String desc = event.getDescription();

    String expectedPrefix = "Completed " + expectedPercent + "% " + succeed + "/" + minSuccessful;
    assertTrue(
        desc.startsWith(expectedPrefix),
        () -> "Expected prefix: '" + expectedPrefix + "' but was '" + desc + "'");
  }
}
