package network.crypta.client;

import static org.junit.jupiter.api.Assertions.*;

import java.util.stream.Stream;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.keys.FreenetURI;
import network.crypta.node.LowLevelPutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
class InsertExceptionTest {

  @Test
  void constructor_withModeMessageAndUri_expectFieldsAndMessage() {
    InsertExceptionMode mode = InsertExceptionMode.CANCELLED;
    String msg = "details";
    FreenetURI uri = FreenetURI.EMPTY_CHK_URI;

    InsertException ex = new InsertException(mode, msg, uri);

    assertEquals(mode, ex.mode);
    assertEquals(uri, ex.getUri());
    assertNull(ex.getErrorCodes());
    assertEquals(msg, ex.extra);
    assertEquals(InsertException.getMessage(mode) + ": " + msg, ex.getMessage());
  }

  @Test
  void constructor_withModeAndUri_expectFields() {
    InsertExceptionMode mode = InsertExceptionMode.ROUTE_NOT_FOUND;
    FreenetURI uri = FreenetURI.EMPTY_CHK_URI;

    InsertException ex = new InsertException(mode, uri);

    assertEquals(mode, ex.mode);
    assertEquals(uri, ex.getUri());
    assertNull(ex.getErrorCodes());
    assertNull(ex.extra);
    assertEquals(InsertException.getMessage(mode), ex.getMessage());
  }

  @Test
  void constructor_withModeAndThrowable_expectCauseExtraAndMessage() {
    InsertExceptionMode mode = InsertExceptionMode.INTERNAL_ERROR;
    RuntimeException cause = new RuntimeException("boom");
    FreenetURI uri = FreenetURI.EMPTY_CHK_URI;

    InsertException ex = new InsertException(mode, cause, uri);

    assertSame(cause, ex.getCause());
    assertEquals("boom", ex.extra);
    assertEquals(uri, ex.getUri());
    assertEquals(mode, ex.mode);
    assertEquals(InsertException.getMessage(mode) + ": boom", ex.getMessage());
  }

  @Test
  void constructor_withModeMessageAndThrowable_expectConcatenatedMessageAndCause() {
    InsertExceptionMode mode = InsertExceptionMode.BUCKET_ERROR;
    IllegalStateException cause = new IllegalStateException("oops");
    String message = "wrap";
    FreenetURI uri = FreenetURI.EMPTY_CHK_URI;

    InsertException ex = new InsertException(mode, message, cause, uri);

    assertSame(cause, ex.getCause());
    assertEquals("oops", ex.extra);
    assertEquals(InsertException.getMessage(mode) + ": " + message + ": oops", ex.getMessage());
  }

  @Test
  void constructor_withModeAndTracker_expectTrackerAndUriSet() {
    FailureCodeTracker tracker = new FailureCodeTracker(true);
    tracker.inc(InsertExceptionMode.CANCELLED);

    FreenetURI uri = FreenetURI.EMPTY_CHK_URI;
    InsertException ex =
        new InsertException(InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS, tracker, uri);

    assertSame(tracker, ex.getErrorCodes());
    assertEquals(uri, ex.getUri());
    assertNull(ex.extra);
    assertEquals(
        InsertException.getMessage(InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS), ex.getMessage());
  }

  @Test
  void constructor_withModeMessageAndTracker_whenMessageNotNull_expectMessageIncludedAndExtraSet() {
    FailureCodeTracker tracker = new FailureCodeTracker(true);
    tracker.inc(InsertExceptionMode.CANCELLED);

    String message = "detail";
    InsertExceptionMode mode = InsertExceptionMode.TOO_MANY_FILES;
    InsertException ex = new InsertException(mode, message, tracker, FreenetURI.EMPTY_CHK_URI);

    assertSame(tracker, ex.getErrorCodes());
    assertEquals(message, ex.extra);
    assertEquals(InsertException.getMessage(mode) + ": " + message, ex.getMessage());
  }

  @Test
  void constructor_withModeMessageAndTracker_whenMessageNull_expectOnlyBaseMessage() {
    FailureCodeTracker tracker = new FailureCodeTracker(true);
    InsertExceptionMode mode = InsertExceptionMode.TOO_BIG;

    InsertException ex = new InsertException(mode, null, tracker, FreenetURI.EMPTY_CHK_URI);

    assertSame(tracker, ex.getErrorCodes());
    assertNull(ex.extra);
    assertEquals(InsertException.getMessage(mode), ex.getMessage());
  }

  @Test
  void constructor_withModeOnly_expectDefaults() {
    InsertExceptionMode mode = InsertExceptionMode.META_STRINGS_NOT_SUPPORTED;
    InsertException ex = new InsertException(mode);

    assertEquals(mode, ex.mode);
    assertNull(ex.getUri());
    assertNull(ex.getErrorCodes());
    assertNull(ex.extra);
    assertEquals(InsertException.getMessage(mode), ex.getMessage());
  }

  @Test
  void copyConstructor_whenSourceHasTracker_expectDeepCopyOfTrackerAndSameOtherFields() {
    FailureCodeTracker tracker = new FailureCodeTracker(true);
    tracker.inc(InsertExceptionMode.CANCELLED);
    FreenetURI uri = FreenetURI.EMPTY_CHK_URI;
    InsertException original =
        new InsertException(InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS, tracker, uri);

    InsertException copy = new InsertException(original);

    assertEquals(original.mode, copy.mode);
    assertEquals(original.extra, copy.extra);
    assertEquals(original.getUri(), copy.getUri());

    FailureCodeTracker originalTracker = original.getErrorCodes();
    FailureCodeTracker copyTracker = copy.getErrorCodes();
    assertNotNull(originalTracker);
    assertNotNull(copyTracker);
    assertNotSame(originalTracker, copyTracker, "errorCodes should be deep-copied");
    assertEquals(originalTracker.totalCount(), copyTracker.totalCount());

    // Mutate the original tracker and verify the copy is unchanged
    originalTracker.inc(InsertExceptionMode.BINARY_BLOB_FORMAT_ERROR);
    assertEquals(2, originalTracker.totalCount());
    assertEquals(1, copyTracker.totalCount());
  }

  @Test
  void constructFrom_whenKnownCodes_expectMappedModes() {
    assertEquals(
        InsertExceptionMode.COLLISION,
        InsertException.constructFrom(new LowLevelPutException(LowLevelPutException.COLLISION))
            .mode);
    assertEquals(
        InsertExceptionMode.INTERNAL_ERROR,
        InsertException.constructFrom(new LowLevelPutException(LowLevelPutException.INTERNAL_ERROR))
            .mode);
    assertEquals(
        InsertExceptionMode.REJECTED_OVERLOAD,
        InsertException.constructFrom(
                new LowLevelPutException(LowLevelPutException.REJECTED_OVERLOAD))
            .mode);
    assertEquals(
        InsertExceptionMode.ROUTE_NOT_FOUND,
        InsertException.constructFrom(
                new LowLevelPutException(LowLevelPutException.ROUTE_NOT_FOUND))
            .mode);
    assertEquals(
        InsertExceptionMode.ROUTE_REALLY_NOT_FOUND,
        InsertException.constructFrom(
                new LowLevelPutException(LowLevelPutException.ROUTE_REALLY_NOT_FOUND))
            .mode);
  }

  @Test
  void constructFrom_whenUnknownCode_expectInternalErrorWithDetail() {
    LowLevelPutException llpe = new LowLevelPutException(999);
    InsertException ex = InsertException.constructFrom(llpe);
    assertEquals(InsertExceptionMode.INTERNAL_ERROR, ex.mode);
    assertTrue(ex.getMessage().contains("Unknown error 999"));
  }

  @Test
  void getMessage_and_getShortMessage_returnNonEmptyStrings() {
    for (InsertExceptionMode mode : InsertExceptionMode.values()) {
      String longMsg = InsertException.getMessage(mode);
      String shortMsg = InsertException.getShortMessage(mode);
      assertNotNull(longMsg);
      assertFalse(longMsg.isEmpty());
      assertNotNull(shortMsg);
      assertFalse(shortMsg.isEmpty());
    }
  }

  static Stream<InsertExceptionMode> fatalModes() {
    return Stream.of(
        InsertExceptionMode.INVALID_URI,
        InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS,
        InsertExceptionMode.COLLISION,
        InsertExceptionMode.CANCELLED,
        InsertExceptionMode.META_STRINGS_NOT_SUPPORTED,
        InsertExceptionMode.BINARY_BLOB_FORMAT_ERROR,
        InsertExceptionMode.TOO_BIG,
        InsertExceptionMode.BUCKET_ERROR,
        InsertExceptionMode.INTERNAL_ERROR);
  }

  static Stream<InsertExceptionMode> nonFatalModes() {
    return Stream.of(
        InsertExceptionMode.REJECTED_OVERLOAD,
        InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS,
        InsertExceptionMode.ROUTE_NOT_FOUND,
        InsertExceptionMode.ROUTE_REALLY_NOT_FOUND);
  }

  @ParameterizedTest
  @MethodSource("fatalModes")
  void isFatal_static_whenFatalModes_expectTrue(InsertExceptionMode mode) {
    assertTrue(InsertException.isFatal(mode));
  }

  @ParameterizedTest
  @MethodSource("nonFatalModes")
  void isFatal_static_whenNonFatalModes_expectFalse(InsertExceptionMode mode) {
    assertFalse(InsertException.isFatal(mode));
  }

  @Test
  void isFatal_instanceMethod_delegatesToStatic() {
    assertTrue(new InsertException(InsertExceptionMode.CANCELLED).isFatal());
    assertFalse(new InsertException(InsertExceptionMode.REJECTED_OVERLOAD).isFatal());
  }

  @Test
  void construct_whenNullOrEmptyTracker_expectNull() {
    assertNull(InsertException.construct(null));

    FailureCodeTracker empty = new FailureCodeTracker(true);
    assertTrue(empty.isEmpty());
    assertNull(InsertException.construct(empty));
  }

  @Test
  void construct_whenSingleCode_expectModeFromTrackerAndNoErrorCodes() {
    FailureCodeTracker tracker = new FailureCodeTracker(true);
    tracker.inc(InsertExceptionMode.CANCELLED);

    InsertException ex = InsertException.construct(tracker);
    assertNotNull(ex);
    assertEquals(InsertExceptionMode.CANCELLED, ex.mode);
    assertNull(ex.getErrorCodes());
  }

  @Test
  void construct_whenMultipleCodesAndFatal_expectFatalErrorsInBlocks() {
    FailureCodeTracker tracker = new FailureCodeTracker(true);
    tracker.inc(InsertExceptionMode.CANCELLED);
    tracker.inc(InsertExceptionMode.ROUTE_NOT_FOUND);

    InsertException ex = InsertException.construct(tracker);
    assertNotNull(ex);
    assertEquals(InsertExceptionMode.FATAL_ERRORS_IN_BLOCKS, ex.mode);
    assertSame(tracker, ex.getErrorCodes());
    assertNull(ex.getUri());
  }

  @Test
  void construct_whenMultipleCodesAndNotFatal_expectTooManyRetriesInBlocks() {
    FailureCodeTracker tracker = new FailureCodeTracker(true);
    tracker.inc(InsertExceptionMode.ROUTE_NOT_FOUND);
    tracker.inc(InsertExceptionMode.REJECTED_OVERLOAD);

    InsertException ex = InsertException.construct(tracker);
    assertNotNull(ex);
    assertEquals(InsertExceptionMode.TOO_MANY_RETRIES_IN_BLOCKS, ex.mode);
    assertSame(tracker, ex.getErrorCodes());
  }

  @Test
  void getByCode_whenValidAndInvalid_expectMappingAndException() {
    assertEquals(
        InsertExceptionMode.CANCELLED,
        InsertExceptionMode.getByCode(InsertExceptionMode.CANCELLED.code));
    assertThrows(IllegalArgumentException.class, () -> InsertExceptionMode.getByCode(0));
  }
}
