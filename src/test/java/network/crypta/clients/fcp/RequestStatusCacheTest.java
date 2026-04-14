package network.crypta.clients.fcp;

import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.client.InsertException.InsertExceptionMode;
import network.crypta.client.async.CacheFetchResult;
import network.crypta.client.events.SplitfileProgressEvent;
import network.crypta.clients.fcp.ClientPut.COMPRESS_STATE;
import network.crypta.clients.fcp.ClientRequest.Persistence;
import network.crypta.keys.FreenetURI;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.ResumeContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class RequestStatusCacheTest {

  @Mock private SplitfileProgressEvent progressEvent;

  @Test
  void addDownload_whenIdentifierReused_expectOnlyLatestInSnapshot() {
    RequestStatusCache cache = new RequestStatusCache();

    FreenetURI uri1 = mock(FreenetURI.class);
    FreenetURI uri2 = mock(FreenetURI.class);

    DownloadRequestStatus first = mock(DownloadRequestStatus.class);
    when(first.getIdentifier()).thenReturn("id");
    when(first.getURI()).thenReturn(uri1);

    DownloadRequestStatus second = mock(DownloadRequestStatus.class);
    when(second.getIdentifier()).thenReturn("id");
    when(second.getURI()).thenReturn(uri2);
    DownloadRequestStatus secondCopy = mock(DownloadRequestStatus.class);
    when(second.copy()).thenReturn(secondCopy);

    cache.addDownload(first);
    cache.addDownload(second);

    List<RequestStatus> snapshot = new ArrayList<>();
    cache.addTo(snapshot);

    assertEquals(1, snapshot.size());
    assertSame(secondCopy, snapshot.getFirst());
  }

  @Test
  void finishedDownload_whenPresent_delegatesToStatus() {
    RequestStatusCache cache = new RequestStatusCache();

    DownloadRequestStatus status = mock(DownloadRequestStatus.class);
    when(status.getIdentifier()).thenReturn("download-1");
    when(status.getURI()).thenReturn(mock(FreenetURI.class));
    cache.addDownload(status);

    Bucket bucket = mock(Bucket.class);
    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(
            42L, "text/plain", FetchExceptionMode.BUCKET_ERROR, "short", "long", bucket, false);
    cache.finishedDownload("download-1", true, outcome);

    verify(status).setFinished(true, outcome);
  }

  @Test
  void updateStarted_withFalseThenTrue_invokesRestartAndSetStarted() {
    RequestStatusCache cache = new RequestStatusCache();

    UploadRequestStatus status = mock(UploadRequestStatus.class);
    when(status.getIdentifier()).thenReturn("upload-1");
    when(status.getURI()).thenReturn(null);
    cache.addUpload(status);

    cache.updateStarted("upload-1", false);
    cache.updateStarted("upload-1", true);

    verify(status).restart(false);
    verify(status).setStarted(true);
  }

  @Test
  void updateStarted_withRedirect_updatesUriIndex() throws Exception {
    RequestStatusCache cache = new RequestStatusCache();

    FreenetURI originalUri = mock(FreenetURI.class);
    FreenetURI redirectUri = mock(FreenetURI.class);

    DownloadRequestStatus status =
        newDownloadStatus("dl", originalUri, false, 1L, "text/plain", null, false);

    cache.addDownload(status);

    cache.updateStarted("dl", redirectUri);

    @SuppressWarnings("unchecked")
    MultiValueTable<FreenetURI, DownloadRequestStatus> downloadsByUri =
        (MultiValueTable<FreenetURI, DownloadRequestStatus>) getField(cache, "downloadsByURI");

    assertFalse(downloadsByUri.containsKey(originalUri));
    assertTrue(downloadsByUri.containsKey(redirectUri));
  }

  @Test
  void getShadowBucket_whenDataAvailable_returnsWrappedResult() {
    RequestStatusCache cache = new RequestStatusCache();

    FreenetURI uri = mock(FreenetURI.class);
    Bucket bucket = new FixedBucket(8);

    DownloadRequestStatus status =
        newDownloadStatus("shadow", uri, true, 8L, "image/png", bucket, false);

    cache.addDownload(status);

    CacheFetchResult result = cache.getShadowBucket(uri, false);

    assertNotNull(result);
    assertEquals("image/png", result.getMetadata().getMIMEType());
    assertEquals(8L, result.size());
    assertFalse(result.alreadyFiltered);
  }

  @Test
  void getShadowBucket_whenFilteredAndNoFilterRequested_returnsNull() {
    RequestStatusCache cache = new RequestStatusCache();

    FreenetURI uri = mock(FreenetURI.class);
    Bucket bucket = new FixedBucket(2);

    DownloadRequestStatus status =
        newDownloadStatus("shadow-filter", uri, true, 2L, "text/plain", bucket, true);

    cache.addDownload(status);

    assertNull(cache.getShadowBucket(uri, true));
  }

  @Test
  void removeByIdentifier_whenDownload_presentEntriesAreRemoved() throws Exception {
    RequestStatusCache cache = new RequestStatusCache();

    FreenetURI uri = mock(FreenetURI.class);
    DownloadRequestStatus status =
        newDownloadStatus("remove-dl", uri, true, 1L, "text/plain", new FixedBucket(1), false);

    cache.addDownload(status);

    cache.removeByIdentifier("remove-dl");

    @SuppressWarnings("unchecked")
    MultiValueTable<FreenetURI, DownloadRequestStatus> downloadsByUri =
        (MultiValueTable<FreenetURI, DownloadRequestStatus>) getField(cache, "downloadsByURI");
    assertFalse(downloadsByUri.containsKey(uri));
    assertNull(cache.getShadowBucket(uri, false));
  }

  @Test
  void finishedUpload_whenFinalUriMissing_addsIndexAndDelegates() throws Exception {
    RequestStatusCache cache = new RequestStatusCache();

    UploadRequestStatus status = mock(UploadRequestStatus.class);
    when(status.getIdentifier()).thenReturn("up1");
    when(status.getURI()).thenReturn(null);
    when(status.getFinalURI()).thenReturn(null);
    cache.addUpload(status);

    FreenetURI finalUri = mock(FreenetURI.class);

    cache.finishedUpload("up1", true, finalUri, InsertExceptionMode.INTERNAL_ERROR, "s", "l");

    verify(status).setFinished(true, finalUri, InsertExceptionMode.INTERNAL_ERROR, "s", "l");

    @SuppressWarnings("unchecked")
    MultiValueTable<FreenetURI, RequestStatus> uploadsByFinalUri =
        (MultiValueTable<FreenetURI, RequestStatus>) getField(cache, "uploadsByFinalURI");
    assertTrue(uploadsByFinalUri.containsKey(finalUri));
  }

  @Test
  void gotFinalURI_whenMissing_setsFinalUriAndIndexes() throws Exception {
    RequestStatusCache cache = new RequestStatusCache();

    UploadRequestStatus status = mock(UploadRequestStatus.class);
    when(status.getIdentifier()).thenReturn("up2");
    when(status.getURI()).thenReturn(null);
    when(status.getFinalURI()).thenReturn(null);
    cache.addUpload(status);

    FreenetURI finalUri = mock(FreenetURI.class);

    cache.gotFinalURI("up2", finalUri);

    verify(status).setFinalURI(finalUri);

    @SuppressWarnings("unchecked")
    MultiValueTable<FreenetURI, RequestStatus> uploadsByFinalUri =
        (MultiValueTable<FreenetURI, RequestStatus>) getField(cache, "uploadsByFinalURI");
    assertTrue(uploadsByFinalUri.containsKey(finalUri));
  }

  @Test
  void updateDetectedCompatModes_whenPresent_updatesModesAndSplitfileKey() {
    RequestStatusCache cache = new RequestStatusCache();

    DownloadRequestStatus status = mock(DownloadRequestStatus.class);
    when(status.getIdentifier()).thenReturn("dl-compat");
    when(status.getURI()).thenReturn(mock(FreenetURI.class));
    cache.addDownload(status);

    FcpCompatibilityMode[] compat =
        new FcpCompatibilityMode[] {FcpCompatibilityMode.COMPAT_UNKNOWN};
    byte[] key = new byte[] {1, 2, 3};

    cache.updateDetectedCompatModes("dl-compat", compat, key, true);

    verify(status).updateDetectedCompatModes(compat, true);
    verify(status).updateDetectedSplitfileKey(key);
  }

  @Test
  void updateCompressionStatus_whenUploadFilePresent_updatesState() {
    RequestStatusCache cache = new RequestStatusCache();

    UploadFileRequestStatus status = mock(UploadFileRequestStatus.class);
    when(status.getIdentifier()).thenReturn("file-up");
    when(status.getURI()).thenReturn(null);
    cache.addUpload(status);

    cache.updateCompressionStatus("file-up", COMPRESS_STATE.COMPRESSING);

    verify(status).updateCompressionStatus(COMPRESS_STATE.COMPRESSING);
  }

  @Test
  void updateExpectedMetadata_whenDownloadPresent_propagatesToStatus() {
    RequestStatusCache cache = new RequestStatusCache();

    DownloadRequestStatus status = mock(DownloadRequestStatus.class);
    when(status.getIdentifier()).thenReturn("dl-meta");
    when(status.getURI()).thenReturn(mock(FreenetURI.class));
    cache.addDownload(status);

    cache.updateExpectedMIME("dl-meta", "application/json");
    cache.updateExpectedDataLength("dl-meta", 123L);

    verify(status).updateExpectedMIME("application/json");
    verify(status).updateExpectedDataLength(123L);
  }

  @Test
  void setPriority_whenPresent_delegatesToStatus() {
    RequestStatusCache cache = new RequestStatusCache();

    UploadRequestStatus status = mock(UploadRequestStatus.class);
    when(status.getIdentifier()).thenReturn("prio");
    when(status.getURI()).thenReturn(null);
    cache.addUpload(status);

    cache.setPriority("prio", (short) 5);

    verify(status).setPriority((short) 5);
  }

  @Test
  void updateStatus_whenPresent_delegatesEvent() {
    RequestStatusCache cache = new RequestStatusCache();

    DownloadRequestStatus status = mock(DownloadRequestStatus.class);
    when(status.getIdentifier()).thenReturn("dl-status");
    when(status.getURI()).thenReturn(mock(FreenetURI.class));
    cache.addDownload(status);

    cache.updateStatus("dl-status", progressEvent);

    verify(status).updateStatus(progressEvent);
  }

  @Test
  void clear_afterEntries_removesAllState() throws Exception {
    RequestStatusCache cache = new RequestStatusCache();

    DownloadRequestStatus download = mock(DownloadRequestStatus.class);
    when(download.getIdentifier()).thenReturn("dl-clear");
    when(download.getURI()).thenReturn(mock(FreenetURI.class));
    cache.addDownload(download);

    UploadRequestStatus upload = mock(UploadRequestStatus.class);
    when(upload.getIdentifier()).thenReturn("up-clear");
    when(upload.getURI()).thenReturn(mock(FreenetURI.class));
    cache.addUpload(upload);

    cache.clear();

    List<RequestStatus> snapshot = new ArrayList<>();
    cache.addTo(snapshot);
    assertTrue(snapshot.isEmpty());

    MultiValueTable<?, ?> downloadsByUri =
        (MultiValueTable<?, ?>) getField(cache, "downloadsByURI");
    MultiValueTable<?, ?> uploadsByFinalUri =
        (MultiValueTable<?, ?>) getField(cache, "uploadsByFinalURI");
    assertTrue(downloadsByUri.isEmpty());
    assertTrue(uploadsByFinalUri.isEmpty());
  }

  private static Object getField(Object target, String name) throws Exception {
    var field = RequestStatusCache.class.getDeclaredField(name);
    field.setAccessible(true);
    return field.get(target);
  }

  private static DownloadRequestStatus newDownloadStatus(
      String identifier,
      FreenetURI uri,
      boolean started,
      long dataSize,
      String mimeType,
      Bucket bucket,
      boolean alreadyFiltered) {
    RequestStatusSnapshot statusSnapshot =
        new RequestStatusSnapshot(
            identifier,
            Persistence.CONNECTION,
            started,
            false,
            false,
            0,
            0,
            0,
            null,
            0,
            0,
            null,
            false,
            (short) 1);
    DownloadOutcomeInfo outcome =
        new DownloadOutcomeInfo(dataSize, mimeType, null, null, null, bucket, alreadyFiltered);
    DownloadRequestStatusDetails details =
        new DownloadRequestStatusDetails(outcome, null, null, null, uri, false, false);
    return new DownloadRequestStatus(statusSnapshot, details);
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class FixedBucket implements Bucket {
    private final long size;

    FixedBucket(long size) {
      this.size = size;
    }

    @Override
    public OutputStream getOutputStream() {
      throw new UnsupportedOperationException();
    }

    @Override
    public OutputStream getOutputStreamUnbuffered() {
      throw new UnsupportedOperationException();
    }

    @Override
    public InputStream getInputStream() {
      throw new UnsupportedOperationException();
    }

    @Override
    public InputStream getInputStreamUnbuffered() {
      throw new UnsupportedOperationException();
    }

    @Override
    public String getName() {
      return "fixed";
    }

    @Override
    public long size() {
      return size;
    }

    @Override
    public boolean isReadOnly() {
      return false;
    }

    @Override
    public void setReadOnly() {
      // no-op
    }

    @Override
    public void free() {
      // no-op
    }

    @Override
    public Bucket createShadow() {
      return this;
    }

    @Override
    public void onResume(ResumeContext context) {
      throw new UnsupportedOperationException();
    }

    @Override
    public void storeTo(java.io.DataOutputStream dos) {
      throw new UnsupportedOperationException();
    }
  }
}
