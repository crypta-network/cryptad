package network.crypta.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.filter.DataFilterException;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FetchExceptionTest {

  // Helper to read l10n messages deterministically
  private static String longMsg(FetchExceptionMode mode) {
    return NodeL10n.getBase().getString("FetchException.longError." + mode.code);
  }

  private static String shortMsg(FetchExceptionMode mode) {
    return NodeL10n.getBase().getString("FetchException.shortError." + mode.code);
  }

  @Test
  void constructor_modeOnly_setsFieldsAndMessages() {
    FetchExceptionMode mode = FetchExceptionMode.DATA_NOT_FOUND;
    FetchException ex = new FetchException(mode);

    assertEquals(mode, ex.getMode());
    assertEquals(longMsg(mode), ex.getMessage());
    assertEquals(shortMsg(mode), ex.getShortMessage());
    assertEquals(-1, ex.getExpectedSize());
    assertNull(ex.newURI);
    assertNull(ex.errorCodes);
  }

  @Test
  void constructor_withSizeFinalizedAndMime_setsAllFields() {
    FetchExceptionMode mode = FetchExceptionMode.TOO_BIG;
    long size = 42L;
    String mime = "application/json";
    FetchException ex = new FetchException(mode, size, true, mime);

    assertEquals(mode, ex.getMode());
    assertEquals(size, ex.getExpectedSize());
    assertEquals(mime, ex.getExpectedMimeType());
    assertTrue(ex.finalizedSize());

    ex = ex.notFinalized();
    assertFalse(ex.finalizedSize());
  }

  @Test
  void constructor_withUri_setsUriAndFields() {
    FreenetURI uri = new FreenetURI("KSK", "doc");
    FetchException ex =
        new FetchException(FetchExceptionMode.PERMANENT_REDIRECT, 123L, true, "text/plain", uri);

    assertEquals(FetchExceptionMode.PERMANENT_REDIRECT, ex.getMode());
    assertEquals(123L, ex.getExpectedSize());
    assertEquals("text/plain", ex.getExpectedMimeType());
    assertTrue(ex.finalizedSize());
    assertEquals(uri, ex.newURI);
  }

  @Test
  void getMessage_whenNull_throwsNpe() {
    assertThrows(NullPointerException.class, () -> FetchException.getMessage(null));
  }

  @Test
  void isFatal_variousModes_matchContract() {
    assertTrue(FetchException.isFatal(FetchExceptionMode.INTERNAL_ERROR));
    assertFalse(FetchException.isFatal(FetchExceptionMode.SPLITFILE_ERROR));
    assertTrue(FetchException.isFatal(FetchExceptionMode.WRONG_MIME_TYPE));
    assertTrue(FetchException.isFatal(FetchExceptionMode.NOT_ENOUGH_DISK_SPACE));
    assertFalse(FetchException.isFatal(FetchExceptionMode.TRANSFER_FAILED));
  }

  @Test
  void isDefinitelyFatal_variousModes_matchContract() {
    assertFalse(FetchException.isDefinitelyFatal(FetchExceptionMode.INTERNAL_ERROR));
    assertTrue(FetchException.isDefinitelyFatal(FetchExceptionMode.ARCHIVE_FAILURE));
    assertTrue(
        FetchException.isDefinitelyFatal(FetchExceptionMode.CONTENT_VALIDATION_UNKNOWN_MIME));
    assertFalse(FetchException.isDefinitelyFatal(FetchExceptionMode.CANCELLED));
  }

  @Test
  void isDataFound_static_handlesSplitfileViaTracker() {
    FailureCodeTracker tracker = new FailureCodeTracker(true);
    // Mark a mode that implies data was found (e.g., TOO_BIG)
    tracker.inc(FetchExceptionMode.TOO_BIG.code, 1);

    assertTrue(FetchException.isDataFound(FetchExceptionMode.SPLITFILE_ERROR, tracker));
  }

  @Test
  void isDataFound_instance_falseForDnfModes() {
    FetchException ex = new FetchException(FetchExceptionMode.DATA_NOT_FOUND);
    assertFalse(ex.isDataFound());
  }

  @Test
  void isDNF_identifiesDnfModes() {
    assertTrue(new FetchException(FetchExceptionMode.DATA_NOT_FOUND).isDNF());
    assertTrue(new FetchException(FetchExceptionMode.ALL_DATA_NOT_FOUND).isDNF());
    assertTrue(new FetchException(FetchExceptionMode.RECENTLY_FAILED).isDNF());
    assertFalse(new FetchException(FetchExceptionMode.ARCHIVE_FAILURE).isDNF());
  }

  @Test
  void isErrorCode_boundaries_work() {
    // Compute max code from the enum to avoid hard-coding
    int max = 0;
    for (FetchExceptionMode m : FetchExceptionMode.values()) {
      max = Math.max(max, m.code);
    }
    assertFalse(FetchException.isErrorCode(-1));
    assertTrue(FetchException.isErrorCode(max));
    assertFalse(FetchException.isErrorCode(max + 1));
  }

  @Test
  void constructor_fromMetadataParseException_setsModeAndMessage() {
    MetadataParseException mpe = new MetadataParseException("bad meta");
    FetchException ex = new FetchException(mpe);

    assertEquals(FetchExceptionMode.INVALID_METADATA, ex.getMode());
    assertEquals(
        longMsg(FetchExceptionMode.INVALID_METADATA) + ": " + mpe.getMessage(), ex.getMessage());
    assertEquals(mpe.getMessage(), ex.extraMessage);
    assertEquals(mpe, ex.getCause());
  }

  @Test
  void constructor_fromArchiveFailureException_setsModeAndMessage() {
    ArchiveFailureException afe = new ArchiveFailureException("boom");
    FetchException ex = new FetchException(afe);

    assertEquals(FetchExceptionMode.ARCHIVE_FAILURE, ex.getMode());
    assertEquals(
        longMsg(FetchExceptionMode.ARCHIVE_FAILURE) + ": " + afe.getMessage(), ex.getMessage());
    assertEquals(afe.getMessage(), ex.extraMessage);
    assertEquals(afe, ex.getCause());
  }

  @Test
  void constructor_fromArchiveRestartException_usesRestartMessageButFailureMode() {
    ArchiveRestartException are = new ArchiveRestartException("please retry");
    FetchException ex = new FetchException(are);

    // Message uses ARCHIVE_RESTART text, but mode is ARCHIVE_FAILURE (as implemented)
    assertEquals(
        longMsg(FetchExceptionMode.ARCHIVE_RESTART) + ": " + are.getMessage(), ex.getMessage());
    assertEquals(FetchExceptionMode.ARCHIVE_FAILURE, ex.getMode());
    assertEquals(are, ex.getCause());
  }

  @Test
  void constructor_modeThrowable_wrapsCauseAndSetsExtra() {
    Exception cause = new Exception("Eee");
    FetchException ex = new FetchException(FetchExceptionMode.BUCKET_ERROR, cause);

    assertEquals(FetchExceptionMode.BUCKET_ERROR, ex.getMode());
    assertEquals(
        longMsg(FetchExceptionMode.BUCKET_ERROR) + ": " + cause.getMessage(), ex.getMessage());
    assertEquals(cause.getMessage(), ex.extraMessage);
    assertEquals(cause, ex.getCause());
    assertEquals(-1, ex.getExpectedSize());
    assertNull(ex.newURI);
  }

  @Test
  void constructor_reasonModeThrowable_includesReasonInMessage() {
    Exception cause = new Exception("Oops");
    FetchExceptionMode mode = FetchExceptionMode.BLOCK_DECODE_ERROR;
    FetchException ex = new FetchException(mode, "Because", cause);

    assertEquals("Because : " + longMsg(mode) + ": " + cause.getMessage(), ex.getMessage());
    assertEquals(cause.getMessage(), ex.extraMessage);
    assertEquals(mode, ex.getMode());
  }

  @Test
  void constructor_modeSizeReasonThrowableMime_setsFields() {
    Exception cause = new Exception("bad");
    FetchException ex =
        new FetchException(FetchExceptionMode.WRONG_MIME_TYPE, 100L, "why", cause, "text/html");

    assertEquals(FetchExceptionMode.WRONG_MIME_TYPE, ex.getMode());
    assertEquals(100L, ex.getExpectedSize());
    assertEquals("text/html", ex.getExpectedMimeType());
    assertEquals(cause.getMessage(), ex.extraMessage);
    assertEquals(cause, ex.getCause());
  }

  @Test
  void constructor_fromDataFilterException_formatsMessageAndFields() {
    DataFilterException dfe = org.mockito.Mockito.mock(DataFilterException.class);
    org.mockito.Mockito.when(dfe.getMessage()).thenReturn("why unsafe");
    FetchException ex = new FetchException(12L, dfe, "image/gif");

    String unsafeDetails = NodeL10n.getBase().getString("FetchException.unsafeContentDetails");
    assertEquals(
        longMsg(FetchExceptionMode.CONTENT_VALIDATION_FAILED)
            + " "
            + unsafeDetails
            + " "
            + dfe.getMessage(),
        ex.getMessage());
    assertEquals(FetchExceptionMode.CONTENT_VALIDATION_FAILED, ex.getMode());
    assertEquals(12L, ex.getExpectedSize());
    assertEquals("image/gif", ex.getExpectedMimeType());
    assertEquals(dfe, ex.getCause());
  }

  @Test
  void constructor_modeSizeThrowableMime_setsFields() {
    Exception cause = new Exception("fail");
    FetchException ex =
        new FetchException(
            FetchExceptionMode.TRANSFER_FAILED, 55L, cause, "application/octet-stream");

    assertEquals(FetchExceptionMode.TRANSFER_FAILED, ex.getMode());
    assertEquals(55L, ex.getExpectedSize());
    assertEquals("application/octet-stream", ex.getExpectedMimeType());
    assertEquals(cause.getMessage(), ex.extraMessage);
    assertEquals(cause, ex.getCause());
  }

  @Test
  void constructor_modeAndErrorCodes_setsTracker() {
    FailureCodeTracker tracker = new FailureCodeTracker(false);
    tracker.inc(FetchExceptionMode.DATA_NOT_FOUND.code, 2);
    FetchException ex = new FetchException(FetchExceptionMode.SPLITFILE_ERROR, tracker);

    assertEquals(FetchExceptionMode.SPLITFILE_ERROR, ex.getMode());
    assertEquals(tracker, ex.errorCodes);
    assertEquals(longMsg(FetchExceptionMode.SPLITFILE_ERROR), ex.getMessage());
  }

  @Test
  void constructor_modeErrorCodesAndMsg_setsTrackerAndMessage() {
    FailureCodeTracker tracker = new FailureCodeTracker(false);
    tracker.inc(FetchExceptionMode.DATA_NOT_FOUND.code, 1);
    FetchException ex = new FetchException(FetchExceptionMode.SPLITFILE_ERROR, tracker, "details");

    assertEquals(longMsg(FetchExceptionMode.SPLITFILE_ERROR) + ": details", ex.getMessage());
    assertEquals("details", ex.extraMessage);
    assertEquals(tracker, ex.errorCodes);
  }

  @Test
  void constructor_modeMsg_setsExtraMessage() {
    FetchException ex = new FetchException(FetchExceptionMode.INVALID_URI, "bad");
    assertEquals(longMsg(FetchExceptionMode.INVALID_URI) + ": bad", ex.getMessage());
    assertEquals("bad", ex.extraMessage);
  }

  @Test
  void constructor_modeUri_setsUri() {
    FreenetURI uri = new FreenetURI("KSK", "name");
    FetchException ex = new FetchException(FetchExceptionMode.PERMANENT_REDIRECT, uri);
    assertEquals(uri, ex.newURI);
    assertEquals(longMsg(FetchExceptionMode.PERMANENT_REDIRECT), ex.getMessage());
  }

  @Test
  void constructor_modeMsgUri_setsFieldsAndMessage() {
    FreenetURI uri = new FreenetURI("KSK", "n");
    FetchException ex =
        new FetchException(FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS, "info", uri);
    assertEquals(uri, ex.newURI);
    assertEquals(
        longMsg(FetchExceptionMode.NOT_ENOUGH_PATH_COMPONENTS) + ": info", ex.getMessage());
    assertEquals("info", ex.extraMessage);
  }

  @Test
  void copyConstructor_newMode_changesModeAndKeepsMetadata() {
    FailureCodeTracker tracker = new FailureCodeTracker(false);
    tracker.inc(FetchExceptionMode.DATA_NOT_FOUND.code, 1);
    FetchException original = new FetchException(FetchExceptionMode.DATA_NOT_FOUND, "x");
    // attach some metadata to original
    original = original.withExpectedSize(7L);

    FetchException updated = new FetchException(original, FetchExceptionMode.PERMANENT_REDIRECT);
    assertEquals(FetchExceptionMode.PERMANENT_REDIRECT, updated.getMode());
    assertEquals(original.getExpectedSize(), updated.getExpectedSize());
    assertEquals(original.getExpectedMimeType(), updated.getExpectedMimeType());
    assertEquals(original.newURI, updated.newURI);
    assertEquals(original.extraMessage, updated.extraMessage);
    assertEquals(
        longMsg(FetchExceptionMode.PERMANENT_REDIRECT) + ": " + original.extraMessage,
        updated.getMessage());
  }

  @Test
  void copyConstructor_newUri_preservesMessageAndCause() {
    Exception cause = new Exception("root");
    FetchException original = new FetchException(FetchExceptionMode.BUCKET_ERROR, cause);
    FreenetURI newUri = new FreenetURI("KSK", "updated");

    FetchException withUri = new FetchException(original, newUri);
    assertEquals(original.getMessage(), withUri.getMessage());
    assertEquals(original.getCause(), withUri.getCause());
    assertEquals(newUri, withUri.newURI);
    assertEquals(original.getMode(), withUri.getMode());
  }

  @Test
  void copyConstructor_returnsDeepCopyOfTracker() {
    FailureCodeTracker tracker = new FailureCodeTracker(false);
    tracker.inc(FetchExceptionMode.ROUTE_NOT_FOUND.code, 3);
    FetchException ex = new FetchException(FetchExceptionMode.SPLITFILE_ERROR, tracker);

    FetchException cloned = new FetchException(ex);
    assertNotNull(cloned);
    assertEquals(ex.getMode(), cloned.getMode());

    // Capture cloned count, then mutate the original tracker and ensure cloned one doesn't change
    FailureCodeTracker clonedTracker = cloned.errorCodes;
    assertNotNull(clonedTracker);
    int clonedCount = clonedTracker.getErrorCount(FetchExceptionMode.ROUTE_NOT_FOUND);
    assertTrue(clonedCount > 0);
    tracker.inc(FetchExceptionMode.ROUTE_NOT_FOUND.code, 2);
    assertEquals(clonedCount, clonedTracker.getErrorCount(FetchExceptionMode.ROUTE_NOT_FOUND));
  }

  @Test
  void toString_containsKeyFields() {
    FetchException ex = new FetchException(FetchExceptionMode.TOO_BIG, 999L, true, "text/plain");
    String s = ex.toString();
    assertTrue(s.startsWith("FetchException:"));
    assertTrue(s.contains(longMsg(FetchExceptionMode.TOO_BIG)));
    assertTrue(s.contains("999"));
    assertTrue(s.contains("text/plain"));
  }

  @Test
  void toUserFriendlyString_includesExtraMessageWhenPresent() {
    FetchException ex = new FetchException(FetchExceptionMode.INVALID_URI, "oops");
    assertEquals(shortMsg(FetchExceptionMode.INVALID_URI) + " : oops", ex.toUserFriendlyString());
  }

  @Test
  void getShortMessage_whenCausePresent_usesCauseToString() {
    Exception cause = new Exception("cause");
    FetchException ex = new FetchException(FetchExceptionMode.BUCKET_ERROR, cause);
    assertEquals(cause.toString(), ex.getShortMessage());
  }
}
