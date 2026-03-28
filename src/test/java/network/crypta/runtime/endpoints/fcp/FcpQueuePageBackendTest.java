package network.crypta.runtime.endpoints.fcp;

import java.io.File;
import java.net.MalformedURLException;
import java.time.Instant;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertContext;
import network.crypta.client.async.PersistenceDisabledException;
import network.crypta.clients.fcp.ClientPut.COMPRESS_STATE;
import network.crypta.clients.fcp.DownloadRequestStatus;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.fcp.RequestStatus;
import network.crypta.clients.fcp.UploadDirRequestStatus;
import network.crypta.clients.fcp.UploadFileRequestStatus;
import network.crypta.keys.FreenetURI;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.admin.queue.page.QueueCompressionState;
import network.crypta.runtime.admin.queue.page.QueuePageBackend;
import network.crypta.runtime.admin.queue.page.QueuePageDownloadView;
import network.crypta.runtime.admin.queue.page.QueuePageRequestView;
import network.crypta.runtime.admin.queue.page.QueuePageUploadDirView;
import network.crypta.runtime.admin.queue.page.QueuePageUploadFileView;
import network.crypta.runtime.endpoints.ClientEndpoints;
import network.crypta.runtime.spi.RequestQueueUnavailableException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class FcpQueuePageBackendTest {

  @Mock private NodeClientCore core;
  @Mock private ClientEndpoints endpoints;
  @Mock private FCPServer fcpServer;

  private QueuePageBackend backend;

  @BeforeEach
  void setUp() {
    when(core.getEndpoints()).thenReturn(endpoints);
    backend = new FcpQueuePageBackend(core);
  }

  @Test
  void getGlobalRequests_whenConstructed_defersFcpLookupUntilMethodCall() throws Exception {
    verifyNoInteractions(endpoints, fcpServer);
    when(endpoints.getFCPServer()).thenReturn(fcpServer);
    when(fcpServer.getGlobalRequests()).thenReturn(new RequestStatus[0]);

    backend.getGlobalRequests();

    verify(endpoints).getFCPServer();
    verify(fcpServer).getGlobalRequests();
  }

  @Test
  void getGlobalRequests_whenFcpServerMissing_returnsEmptyArray() throws Exception {
    when(endpoints.getFCPServer()).thenReturn(null);

    QueuePageRequestView[] views = backend.getGlobalRequests();

    assertEquals(0, views.length);
  }

  @Test
  void getGlobalRequests_whenEndpointsMissing_returnsEmptyArray() throws Exception {
    when(core.getEndpoints()).thenReturn(null);

    QueuePageRequestView[] views = backend.getGlobalRequests();

    assertEquals(0, views.length);
    verifyNoInteractions(fcpServer);
  }

  @Test
  void getGlobalRequests_whenPersistenceDisabled_translatesToRequestQueueUnavailableException()
      throws Exception {
    PersistenceDisabledException cause = new PersistenceDisabledException();
    when(endpoints.getFCPServer()).thenReturn(fcpServer);
    when(fcpServer.getGlobalRequests()).thenThrow(cause);

    RequestQueueUnavailableException thrown =
        assertThrows(RequestQueueUnavailableException.class, backend::getGlobalRequests);

    assertSame(cause, thrown.getCause());
  }

  @Test
  void getGlobalRequests_whenStatusesPresent_adaptsDownloadAndUploadViews() throws Exception {
    DownloadRequestStatus download = org.mockito.Mockito.mock(DownloadRequestStatus.class);
    UploadFileRequestStatus uploadFile = org.mockito.Mockito.mock(UploadFileRequestStatus.class);
    UploadDirRequestStatus uploadDir = org.mockito.Mockito.mock(UploadDirRequestStatus.class);
    Instant lastSuccess = Instant.parse("2026-03-28T12:34:56Z");
    Instant lastFailure = Instant.parse("2026-03-28T12:35:56Z");
    InsertContext.CompatibilityMode[] compatModes = {
      InsertContext.CompatibilityMode.COMPAT_1468, InsertContext.CompatibilityMode.COMPAT_1468
    };
    byte[] overrideKey = new byte[] {0x01, 0x23};
    FreenetURI downloadUri = sampleUri("index_d51.xml");
    FreenetURI uploadUri = sampleUri("upload.txt");
    when(endpoints.getFCPServer()).thenReturn(fcpServer);
    when(fcpServer.getGlobalRequests())
        .thenReturn(new RequestStatus[] {download, uploadFile, uploadDir});

    when(download.getIdentifier()).thenReturn("download-1");
    when(download.hasSucceeded()).thenReturn(false);
    when(download.hasFinished()).thenReturn(true);
    when(download.getPriority()).thenReturn((short) 3);
    when(download.getTotalBlocks()).thenReturn(20);
    when(download.isTotalFinalized()).thenReturn(true);
    when(download.getMinBlocks()).thenReturn(10);
    when(download.getFetchedBlocks()).thenReturn(7);
    when(download.getLastSuccess()).thenReturn(lastSuccess);
    when(download.getLastFailure()).thenReturn(lastFailure);
    when(download.getURI()).thenReturn(downloadUri);
    when(download.getDataSize()).thenReturn(4096L);
    when(download.isPersistent()).thenReturn(true);
    when(download.isPersistentForever()).thenReturn(false);
    when(download.getFatalyFailedBlocks()).thenReturn(2);
    when(download.getFailedBlocks()).thenReturn(1);
    when(download.isStarted()).thenReturn(true);
    when(download.getFailureReason(false)).thenReturn("Bad MIME");
    when(download.getPreferredFilenameSafe()).thenReturn("index_d51.xml");
    when(download.toTempSpace()).thenReturn(false);
    when(download.getFailureCode()).thenReturn(FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME);
    when(download.getMIMEType()).thenReturn("text/plain");
    when(download.getDestFilename()).thenReturn(new File("downloads/index_d51.xml"));
    when(download.getCompatibilityMode()).thenReturn(compatModes);
    when(download.getOverriddenSplitfileCryptoKey()).thenReturn(overrideKey);
    when(download.detectedDontCompress()).thenReturn(true);

    when(uploadFile.getIdentifier()).thenReturn("upload-file-1");
    when(uploadFile.hasSucceeded()).thenReturn(true);
    when(uploadFile.hasFinished()).thenReturn(true);
    when(uploadFile.getPriority()).thenReturn((short) 2);
    when(uploadFile.getTotalBlocks()).thenReturn(12);
    when(uploadFile.isTotalFinalized()).thenReturn(false);
    when(uploadFile.getMinBlocks()).thenReturn(8);
    when(uploadFile.getFetchedBlocks()).thenReturn(8);
    when(uploadFile.getLastSuccess()).thenReturn(lastSuccess);
    when(uploadFile.getLastFailure()).thenReturn(null);
    when(uploadFile.getURI()).thenReturn(uploadUri);
    when(uploadFile.getDataSize()).thenReturn(512L);
    when(uploadFile.isPersistent()).thenReturn(true);
    when(uploadFile.isPersistentForever()).thenReturn(true);
    when(uploadFile.getFatalyFailedBlocks()).thenReturn(0);
    when(uploadFile.getFailedBlocks()).thenReturn(0);
    when(uploadFile.isStarted()).thenReturn(true);
    when(uploadFile.getFailureReason(false)).thenReturn(null);
    when(uploadFile.getPreferredFilenameSafe()).thenReturn("upload.txt");
    when(uploadFile.getFinalURI()).thenReturn(uploadUri);
    when(uploadFile.getMIMEType()).thenReturn("text/plain");
    when(uploadFile.getOrigFilename()).thenReturn(new File("uploads/upload.txt"));
    when(uploadFile.isCompressing()).thenReturn(COMPRESS_STATE.COMPRESSING);

    when(uploadDir.getIdentifier()).thenReturn("upload-dir-1");
    when(uploadDir.hasSucceeded()).thenReturn(false);
    when(uploadDir.hasFinished()).thenReturn(false);
    when(uploadDir.getPriority()).thenReturn((short) 4);
    when(uploadDir.getTotalBlocks()).thenReturn(30);
    when(uploadDir.isTotalFinalized()).thenReturn(true);
    when(uploadDir.getMinBlocks()).thenReturn(20);
    when(uploadDir.getFetchedBlocks()).thenReturn(15);
    when(uploadDir.getLastSuccess()).thenReturn(lastSuccess);
    when(uploadDir.getLastFailure()).thenReturn(lastFailure);
    when(uploadDir.getURI()).thenReturn(uploadUri);
    when(uploadDir.getDataSize()).thenReturn(2048L);
    when(uploadDir.isPersistent()).thenReturn(false);
    when(uploadDir.isPersistentForever()).thenReturn(false);
    when(uploadDir.getFatalyFailedBlocks()).thenReturn(1);
    when(uploadDir.getFailedBlocks()).thenReturn(2);
    when(uploadDir.isStarted()).thenReturn(false);
    when(uploadDir.getFailureReason(false)).thenReturn("Pending");
    when(uploadDir.getPreferredFilenameSafe()).thenReturn("site");
    when(uploadDir.getFinalURI()).thenReturn(uploadUri);
    when(uploadDir.getTotalDataSize()).thenReturn(2048L);
    when(uploadDir.getNumberOfFiles()).thenReturn(7);

    QueuePageRequestView[] views = backend.getGlobalRequests();

    assertEquals(3, views.length);
    assertDownloadView(views[0], lastSuccess, lastFailure, downloadUri, compatModes, overrideKey);
    assertUploadFileView(views[1], lastSuccess, uploadUri);
    assertUploadDirView(views[2], lastSuccess, lastFailure, uploadUri);
  }

  @Test
  void getGlobalRequests_whenGenericStatusPresent_adaptsBaseRequestView() throws Exception {
    RequestStatus genericStatus = org.mockito.Mockito.mock(RequestStatus.class);
    Instant lastSuccess = Instant.parse("2026-03-28T12:34:56Z");
    Instant lastFailure = Instant.parse("2026-03-28T12:35:56Z");
    FreenetURI uri = sampleUri("generic.txt");
    when(endpoints.getFCPServer()).thenReturn(fcpServer);
    when(fcpServer.getGlobalRequests()).thenReturn(new RequestStatus[] {genericStatus});
    when(genericStatus.getIdentifier()).thenReturn("generic-1");
    when(genericStatus.hasSucceeded()).thenReturn(true);
    when(genericStatus.hasFinished()).thenReturn(false);
    when(genericStatus.getPriority()).thenReturn((short) 5);
    when(genericStatus.getTotalBlocks()).thenReturn(11);
    when(genericStatus.isTotalFinalized()).thenReturn(true);
    when(genericStatus.getMinBlocks()).thenReturn(7);
    when(genericStatus.getFetchedBlocks()).thenReturn(4);
    when(genericStatus.getLastSuccess()).thenReturn(lastSuccess);
    when(genericStatus.getLastFailure()).thenReturn(lastFailure);
    when(genericStatus.getURI()).thenReturn(uri);
    when(genericStatus.getDataSize()).thenReturn(204L);
    when(genericStatus.isPersistent()).thenReturn(true);
    when(genericStatus.isPersistentForever()).thenReturn(false);
    when(genericStatus.getFatalyFailedBlocks()).thenReturn(1);
    when(genericStatus.getFailedBlocks()).thenReturn(2);
    when(genericStatus.isStarted()).thenReturn(true);
    when(genericStatus.getFailureReason(false)).thenReturn("generic failure");
    when(genericStatus.getPreferredFilenameSafe()).thenReturn("generic.txt");

    QueuePageRequestView[] views = backend.getGlobalRequests();

    assertEquals(1, views.length);
    assertCommonRequestView(
        views[0],
        "generic-1",
        true,
        false,
        (short) 5,
        11,
        true,
        7,
        4,
        lastSuccess,
        lastFailure,
        uri,
        204L,
        true,
        false,
        1,
        2,
        true,
        "generic failure",
        "generic.txt");
    assertFalse(views[0] instanceof QueuePageDownloadView);
    assertFalse(views[0] instanceof QueuePageUploadFileView);
    assertFalse(views[0] instanceof QueuePageUploadDirView);
  }

  @Test
  void getGlobalRequests_whenUploadCompressionStatesPresent_mapsAllCompressionStates()
      throws Exception {
    UploadFileRequestStatus waiting = org.mockito.Mockito.mock(UploadFileRequestStatus.class);
    UploadFileRequestStatus compressing = org.mockito.Mockito.mock(UploadFileRequestStatus.class);
    UploadFileRequestStatus working = org.mockito.Mockito.mock(UploadFileRequestStatus.class);
    when(endpoints.getFCPServer()).thenReturn(fcpServer);
    when(fcpServer.getGlobalRequests())
        .thenReturn(new RequestStatus[] {waiting, compressing, working});
    when(waiting.isCompressing()).thenReturn(COMPRESS_STATE.WAITING);
    when(compressing.isCompressing()).thenReturn(COMPRESS_STATE.COMPRESSING);
    when(working.isCompressing()).thenReturn(COMPRESS_STATE.WORKING);

    QueuePageRequestView[] views = backend.getGlobalRequests();

    assertSame(
        QueueCompressionState.WAITING,
        assertInstanceOf(QueuePageUploadFileView.class, views[0]).getCompressionState());
    assertSame(
        QueueCompressionState.COMPRESSING,
        assertInstanceOf(QueuePageUploadFileView.class, views[1]).getCompressionState());
    assertSame(
        QueueCompressionState.WORKING,
        assertInstanceOf(QueuePageUploadFileView.class, views[2]).getCompressionState());
  }

  private FreenetURI sampleUri(String suffix) {
    try {
      return new FreenetURI(
          "CHK@DTCDUmnkKFlrJi9UlDDVqXlktsIXvAJ~ZTseyx5cAZs,PmA2rLgWZKVyMXxSn-ZihSskPYDTY19uhrMwqDV-~Sk,AAICAAI/"
              + suffix);
    } catch (MalformedURLException e) {
      throw new AssertionError(e);
    }
  }

  private void assertDownloadView(
      QueuePageRequestView actual,
      Instant lastSuccess,
      Instant lastFailure,
      FreenetURI downloadUri,
      InsertContext.CompatibilityMode[] compatModes,
      byte[] overrideKey) {
    QueuePageDownloadView downloadView = assertInstanceOf(QueuePageDownloadView.class, actual);
    assertCommonRequestView(
        downloadView,
        "download-1",
        false,
        true,
        (short) 3,
        20,
        true,
        10,
        7,
        lastSuccess,
        lastFailure,
        downloadUri,
        4096L,
        true,
        false,
        2,
        1,
        true,
        "Bad MIME",
        "index_d51.xml");
    assertFalse(downloadView.toTempSpace());
    assertSame(FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME, downloadView.getFailureCode());
    assertEquals("text/plain", downloadView.getMimeType());
    assertEquals(new File("downloads/index_d51.xml"), downloadView.getDestFilename());
    assertArrayEquals(compatModes, downloadView.getCompatibilityMode());
    assertArrayEquals(overrideKey, downloadView.getOverriddenSplitfileCryptoKey());
    assertTrue(downloadView.detectedDontCompress());
  }

  private void assertUploadFileView(
      QueuePageRequestView actual, Instant lastSuccess, FreenetURI uploadUri) {
    QueuePageUploadFileView uploadFileView =
        assertInstanceOf(QueuePageUploadFileView.class, actual);
    assertCommonRequestView(
        uploadFileView,
        "upload-file-1",
        true,
        true,
        (short) 2,
        12,
        false,
        8,
        8,
        lastSuccess,
        null,
        uploadUri,
        512L,
        true,
        true,
        0,
        0,
        true,
        null,
        "upload.txt");
    assertSame(uploadUri, uploadFileView.getFinalUri());
    assertEquals("text/plain", uploadFileView.getMimeType());
    assertEquals(new File("uploads/upload.txt"), uploadFileView.getOrigFilename());
    assertSame(QueueCompressionState.COMPRESSING, uploadFileView.getCompressionState());
  }

  private void assertUploadDirView(
      QueuePageRequestView actual, Instant lastSuccess, Instant lastFailure, FreenetURI uploadUri) {
    QueuePageUploadDirView uploadDirView = assertInstanceOf(QueuePageUploadDirView.class, actual);
    assertCommonRequestView(
        uploadDirView,
        "upload-dir-1",
        false,
        false,
        (short) 4,
        30,
        true,
        20,
        15,
        lastSuccess,
        lastFailure,
        uploadUri,
        2048L,
        false,
        false,
        1,
        2,
        false,
        "Pending",
        "site");
    assertSame(uploadUri, uploadDirView.getFinalUri());
    assertEquals(2048L, uploadDirView.getTotalDataSize());
    assertEquals(7, uploadDirView.getNumberOfFiles());
  }

  private void assertCommonRequestView(
      QueuePageRequestView actual,
      String identifier,
      boolean succeeded,
      boolean finished,
      short priority,
      int totalBlocks,
      boolean totalFinalized,
      int minBlocks,
      int fetchedBlocks,
      Instant lastSuccess,
      Instant lastFailure,
      FreenetURI uri,
      long dataSize,
      boolean persistent,
      boolean persistentForever,
      int fatalFailedBlocks,
      int failedBlocks,
      boolean started,
      String failureReason,
      String preferredFilename) {
    assertEquals(identifier, actual.getIdentifier());
    assertEquals(succeeded, actual.hasSucceeded());
    assertEquals(finished, actual.hasFinished());
    assertEquals(priority, actual.getPriority());
    assertEquals(totalBlocks, actual.getTotalBlocks());
    assertEquals(totalFinalized, actual.isTotalFinalized());
    assertEquals(minBlocks, actual.getMinBlocks());
    assertEquals(fetchedBlocks, actual.getFetchedBlocks());
    assertSame(lastSuccess, actual.getLastSuccess());
    assertSame(lastFailure, actual.getLastFailure());
    assertSame(uri, actual.getUri());
    assertEquals(dataSize, actual.getDataSize());
    assertEquals(persistent, actual.isPersistent());
    assertEquals(persistentForever, actual.isPersistentForever());
    assertEquals(fatalFailedBlocks, actual.getFatalyFailedBlocks());
    assertEquals(failedBlocks, actual.getFailedBlocks());
    assertEquals(started, actual.isStarted());
    if (failureReason == null) {
      assertNull(actual.getFailureReason(false));
    } else {
      assertEquals(failureReason, actual.getFailureReason(false));
    }
    assertEquals(preferredFilename, actual.getPreferredFilenameSafe());
  }
}
