package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.io.File;
import java.util.Date;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.clients.fcp.ClientPut.COMPRESS_STATE;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import org.junit.jupiter.api.Test;

@SuppressWarnings({"java:S100", "JavaUtilDate"})
class UploadFileRequestStatusTest {

  private static final Date SUCCESS_DATE = new Date(1_000L);
  private static final Date FAILURE_DATE = new Date(2_000L);

  @Test
  void constructor_whenInitialized_preservesProvidedMetadata() {
    File orig = new File("/tmp/out.dat");

    UploadFileRequestStatus status =
        createStatus(null, null, orig, 42L, "application/octet-stream", COMPRESS_STATE.WAITING);

    assertEquals(42L, status.getDataSize());
    assertEquals("application/octet-stream", status.getMIMEType());
    assertSame(orig, status.getOrigFilename());
    assertEquals(COMPRESS_STATE.WAITING, status.isCompressing());
  }

  @Test
  void getPreferredFilename_whenSuperProvidesName_returnsUriName() {
    FreenetURI finalUri = new FreenetURI("KSK", "final-name.txt");
    File orig = new File("/tmp/local.bin");
    UploadFileRequestStatus status =
        createStatus(finalUri, null, orig, 100L, "text/plain", COMPRESS_STATE.COMPRESSING);

    String preferred = status.getPreferredFilename();

    assertEquals("final-name.txt", preferred);
  }

  @Test
  void getPreferredFilename_whenSuperReturnsNull_usesOriginalFilename() {
    File orig = new File("/tmp/report.bin");
    UploadFileRequestStatus status =
        createStatus(null, null, orig, 10L, "text/plain", COMPRESS_STATE.COMPRESSING);

    String preferred = status.getPreferredFilename();

    assertEquals("report.bin", preferred);
  }

  @Test
  void getPreferredFilename_whenTargetHasName_prefersTargetUri() {
    FreenetURI targetUri = new FreenetURI("KSK", "target-name.txt");
    UploadFileRequestStatus status =
        createStatus(null, targetUri, null, 10L, "text/plain", COMPRESS_STATE.WORKING);

    String preferred = status.getPreferredFilename();

    assertEquals("target-name.txt", preferred);
  }

  @Test
  void getPreferredFilename_whenNoUriOrFile_returnsNull() {
    UploadFileRequestStatus status =
        createStatus(null, null, null, 0L, "text/plain", COMPRESS_STATE.WORKING);

    assertNull(status.getPreferredFilename());
  }

  @Test
  void updateCompressionStatus_whenStateChanges_reflectsLatestValue() {
    UploadFileRequestStatus status =
        createStatus(null, null, null, 10L, "text/plain", COMPRESS_STATE.WAITING);

    status.updateCompressionStatus(COMPRESS_STATE.COMPRESSING);
    assertEquals(COMPRESS_STATE.COMPRESSING, status.isCompressing());

    status.updateCompressionStatus(COMPRESS_STATE.WORKING);
    assertEquals(COMPRESS_STATE.WORKING, status.isCompressing());
  }

  @Test
  void copy_whenSourceMutates_copyRemainsIndependent() {
    UploadFileRequestStatus status =
        createStatus(
            null,
            null,
            new File("source.txt"),
            256L,
            "application/json",
            COMPRESS_STATE.COMPRESSING);

    UploadFileRequestStatus copy = status.copy();

    assertNotSame(status, copy);
    assertEquals(status.getDataSize(), copy.getDataSize());
    assertEquals(status.getMIMEType(), copy.getMIMEType());
    assertEquals(status.getOrigFilename(), copy.getOrigFilename());
    assertEquals(status.isCompressing(), copy.isCompressing());

    status.updateCompressionStatus(COMPRESS_STATE.WORKING);

    assertEquals(COMPRESS_STATE.COMPRESSING, copy.isCompressing());
    assertEquals(COMPRESS_STATE.WORKING, status.isCompressing());
  }

  private static UploadFileRequestStatus createStatus(
      FreenetURI finalUri,
      FreenetURI targetUri,
      File origFile,
      long dataSize,
      String mimeType,
      COMPRESS_STATE compressState) {
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            "identifier",
            Persistence.CONNECTION,
            true,
            false,
            false,
            10,
            5,
            3,
            SUCCESS_DATE,
            1,
            2,
            FAILURE_DATE,
            true,
            (short) 3);
    UploadRequestStatusDetails details =
        new UploadRequestStatusDetails(
            finalUri, targetUri, InsertExceptionMode.INTERNAL_ERROR, "short", "long");
    return new UploadFileRequestStatus(
        statusSnapshot, details, dataSize, mimeType, origFile, compressState);
  }
}
