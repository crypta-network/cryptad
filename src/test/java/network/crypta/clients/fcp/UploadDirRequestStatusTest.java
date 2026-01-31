package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;

import java.time.Instant;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class UploadDirRequestStatusTest {

  private static final Instant SUCCESS_DATE = Instant.ofEpochMilli(5_000L);
  private static final Instant FAILURE_DATE = Instant.ofEpochMilli(10_000L);

  @Test
  void constructor_whenInitialized_preservesDirectoryMetadata() {
    FreenetURI finalUri = new FreenetURI("KSK", "final-index.html");
    FreenetURI targetUri = new FreenetURI("KSK", "target-index.html");

    UploadDirRequestStatus status =
        createStatus(
            finalUri,
            targetUri,
            InsertExceptionMode.COLLISION,
            "initial short",
            "initial long",
            4_096L,
            8);

    assertEquals(4_096L, status.getTotalDataSize());
    assertEquals(8, status.getNumberOfFiles());
    assertEquals(4_096L, status.getDataSize());
    assertEquals(finalUri, status.getFinalURI());
    assertEquals(targetUri, status.getTargetURI());
  }

  @Test
  void constructor_whenDirectoryEmpty_allowsZeroValues() {
    UploadDirRequestStatus status =
        createStatus(null, null, InsertExceptionMode.TOO_BIG, "zero short", "zero long", 0L, 0);

    assertEquals(0L, status.getTotalDataSize());
    assertEquals(0, status.getNumberOfFiles());
    assertEquals(0L, status.getDataSize());
  }

  @Test
  void copy_whenSourceMutates_copyRetainsSnapshot() {
    FreenetURI initialFinalUri = new FreenetURI("KSK", "initial.html");
    FreenetURI initialTargetUri = new FreenetURI("KSK", "target.html");
    UploadDirRequestStatus status =
        createStatus(
            initialFinalUri,
            initialTargetUri,
            InsertExceptionMode.INTERNAL_ERROR,
            "short",
            "long",
            1_024L,
            3);

    UploadDirRequestStatus copy = status.copy();

    assertNotSame(status, copy);
    assertEquals(status.getTotalDataSize(), copy.getTotalDataSize());
    assertEquals(status.getNumberOfFiles(), copy.getNumberOfFiles());
    assertEquals(status.getFinalURI(), copy.getFinalURI());
    assertEquals(status.getFailureReason(false), copy.getFailureReason(false));
    assertEquals(status.getFailureReason(true), copy.getFailureReason(true));

    FreenetURI updatedFinalUri = new FreenetURI("KSK", "updated.html");
    status.setFinished(
        true,
        updatedFinalUri,
        InsertExceptionMode.BINARY_BLOB_FORMAT_ERROR,
        "updated short",
        "updated long");

    assertEquals(initialFinalUri, copy.getFinalURI());
    assertEquals("short", copy.getFailureReason(false));
    assertEquals("long", copy.getFailureReason(true));
    assertEquals(updatedFinalUri, status.getFinalURI());
    assertEquals("updated short", status.getFailureReason(false));
  }

  private static UploadDirRequestStatus createStatus(
      FreenetURI finalUri,
      FreenetURI targetUri,
      InsertExceptionMode failureCode,
      String failureReasonShort,
      String failureReasonLong,
      long totalSize,
      int files) {
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            "identifier",
            Persistence.REBOOT,
            true,
            false,
            false,
            20,
            10,
            5,
            SUCCESS_DATE,
            1,
            2,
            FAILURE_DATE,
            true,
            (short) 5);
    UploadRequestStatusDetails details =
        new UploadRequestStatusDetails(
            finalUri, targetUri, failureCode, failureReasonShort, failureReasonLong);
    return new UploadDirRequestStatus(statusSnapshot, details, totalSize, files);
  }
}
