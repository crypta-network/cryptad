package network.crypta.clients.fcp;

import java.io.File;
import java.time.Instant;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.support.api.Bucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class DownloadRequestStatusTest {

  @Mock private Bucket initialShadow;

  private static final String IDENTIFIER = "req-1";
  private static final short PRIORITY = 3;
  private static final FcpCompatibilityMode[] COMPAT_SAMPLE =
      new FcpCompatibilityMode[] {FcpCompatibilityMode.COMPAT_1250};
  private static final byte[] SPLITFILE_KEY = new byte[] {1, 2, 3};

  @Test
  void toTempSpace_whenDestFilenameMissing_returnsTrue() {
    DownloadRequestStatus status =
        buildStatus(null, new FreenetURI("KSK", "index.html"), false, initialShadow);

    assertTrue(status.toTempSpace());
  }

  @Test
  void toTempSpace_whenDestFilenamePresent_returnsFalse() {
    File destination = new File("/tmp/result.dat");
    DownloadRequestStatus status =
        buildStatus(destination, new FreenetURI("KSK", "index.html"), false, initialShadow);

    assertFalse(status.toTempSpace());
    assertSame(destination, status.getDestFilename());
  }

  @Test
  void getPreferredFilename_whenDestFileExists_returnsBasename() {
    File destination = new File("/var/tmp/archive.tar");
    DownloadRequestStatus status =
        buildStatus(destination, new FreenetURI("KSK", "main.html"), false, initialShadow);

    assertEquals("archive.tar", status.getPreferredFilename());
  }

  @Test
  void getPreferredFilename_whenUriProvidesNames_usesUriPreferredName() {
    DownloadRequestStatus status =
        buildStatus(null, new FreenetURI("KSK", "main-page.html"), false, initialShadow);

    assertEquals("main-page.html", status.getPreferredFilename());
  }

  @Test
  void getPreferredFilename_whenUriLacksMetadata_returnsNull() {
    DownloadRequestStatus status =
        buildStatus(null, new FreenetURI("CHK", null), false, initialShadow);

    assertNull(status.getPreferredFilename());
  }

  @Test
  void detectedDontCompress_whenConstructedWithFlag_propagatesValue() {
    DownloadRequestStatus status =
        buildStatus(
            new File("/tmp/file.bin"), new FreenetURI("KSK", "file.bin"), true, initialShadow);

    assertTrue(status.detectedDontCompress());
  }

  @Test
  void getFailureReason_whenShortRequested_returnsShortText() {
    DownloadRequestStatus status =
        buildStatus(
            new File("/tmp/file.bin"), new FreenetURI("KSK", "file.bin"), false, initialShadow);

    assertEquals("Short reason", status.getFailureReason(false));
  }

  @Test
  void getFailureReason_whenLongRequested_returnsLongText() {
    DownloadRequestStatus status =
        buildStatus(
            new File("/tmp/file.bin"), new FreenetURI("KSK", "file.bin"), false, initialShadow);

    assertEquals("Detailed long reason", status.getFailureReason(true));
  }

  @Test
  void setFinished_whenCalled_updatesTerminalFieldsAndFlags() {
    DownloadRequestStatus status =
        buildStatus(
            new File("/tmp/file.bin"), new FreenetURI("KSK", "file.bin"), false, initialShadow);
    Bucket completedBucket = org.mockito.Mockito.mock(Bucket.class);

    status.setFinished(
        true,
        new DownloadOutcomeInfo(
            2048L,
            "image/png",
            FetchExceptionMode.CONTENT_HASH_FAILED,
            "new short",
            "new long",
            completedBucket,
            true));

    assertTrue(status.hasFinished());
    assertTrue(status.hasSucceeded());
    assertEquals(2048L, status.getDataSize());
    assertEquals("image/png", status.getMIMEType());
    assertEquals(FetchExceptionMode.CONTENT_HASH_FAILED, status.getFailureCode());
    assertEquals("new short", status.getFailureReason(false));
    assertEquals("new long", status.getFailureReason(true));
    assertSame(completedBucket, status.getDataShadow());
    assertTrue(status.filterData);
  }

  @Test
  void updateDetectedCompatModes_whenCalled_replacesModesAndDontCompressFlag() {
    DownloadRequestStatus status =
        buildStatus(
            new File("/tmp/file.bin"), new FreenetURI("KSK", "file.bin"), false, initialShadow);
    FcpCompatibilityMode[] newModes =
        new FcpCompatibilityMode[] {
          FcpCompatibilityMode.COMPAT_1255, FcpCompatibilityMode.COMPAT_1468
        };

    status.updateDetectedCompatModes(newModes, true);

    assertSame(newModes, status.getCompatibilityMode());
    assertTrue(status.detectedDontCompress());
  }

  @Test
  void updateDetectedSplitfileKey_whenCalled_replacesKeyReference() {
    DownloadRequestStatus status =
        buildStatus(
            new File("/tmp/file.bin"), new FreenetURI("KSK", "file.bin"), false, initialShadow);
    byte[] newKey = new byte[] {9, 8, 7};

    status.updateDetectedSplitfileKey(newKey);

    assertSame(newKey, status.getOverriddenSplitfileCryptoKey());
  }

  @Test
  void updateExpectedFields_whenCalled_updatesMimeAndLength() {
    DownloadRequestStatus status =
        buildStatus(
            new File("/tmp/file.bin"), new FreenetURI("KSK", "file.bin"), false, initialShadow);

    status.updateExpectedMIME("application/json");
    status.updateExpectedDataLength(8192L);

    assertEquals("application/json", status.getMIMEType());
    assertEquals(8192L, status.getDataSize());
  }

  @Test
  void redirect_whenCalled_updatesUri() {
    DownloadRequestStatus status =
        buildStatus(
            new File("/tmp/file.bin"), new FreenetURI("KSK", "file.bin"), false, initialShadow);
    FreenetURI redirected = new FreenetURI("KSK", "new-doc.txt");

    status.redirect(redirected);

    assertSame(redirected, status.getURI());
  }

  @Test
  void copy_whenInvoked_returnsDeepCopyOfMutableArrays() {
    DownloadRequestStatus status =
        buildStatus(
            new File("/tmp/file.bin"), new FreenetURI("KSK", "file.bin"), false, initialShadow);

    DownloadRequestStatus copy = status.copy();

    assertNotSame(status, copy);
    assertEquals(status.getDataSize(), copy.getDataSize());
    assertArrayEquals(
        status.getOverriddenSplitfileCryptoKey(), copy.getOverriddenSplitfileCryptoKey());
    assertNotSame(status.getOverriddenSplitfileCryptoKey(), copy.getOverriddenSplitfileCryptoKey());
    assertArrayEquals(status.getCompatibilityMode(), copy.getCompatibilityMode());
    if (status.getCompatibilityMode() != null) {
      assertNotSame(status.getCompatibilityMode(), copy.getCompatibilityMode());
    }
    assertEquals(status.getFailureCode(), copy.getFailureCode());
    assertEquals(status.getFailureReason(true), copy.getFailureReason(true));
    assertEquals(status.getFailureReason(false), copy.getFailureReason(false));
  }

  private static DownloadRequestStatus buildStatus(
      File destination, FreenetURI uri, boolean dontCompress, Bucket dataShadow) {
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            IDENTIFIER,
            Persistence.CONNECTION,
            true,
            false,
            false,
            10,
            5,
            3,
            Instant.EPOCH,
            0,
            0,
            null,
            true,
            PRIORITY);
    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(
            1024L,
            "text/plain",
            FetchExceptionMode.DATA_NOT_FOUND,
            "Short reason",
            "Detailed long reason",
            dataShadow,
            false);
    DownloadRequestStatusDetails details =
        new DownloadRequestStatusDetails(
            outcome,
            destination,
            COMPAT_SAMPLE.clone(),
            SPLITFILE_KEY.clone(),
            uri,
            false,
            dontCompress);
    return new DownloadRequestStatus(statusSnapshot, details);
  }
}
