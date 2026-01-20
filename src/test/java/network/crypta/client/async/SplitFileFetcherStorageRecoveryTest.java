package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import network.crypta.client.FailureCodeTracker;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.Key;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SplitFileFetcherStorageRecoveryTest {

  @Test
  void postInitReadSegmentState_whenSegmentNeedsDecode_queuesDecodeAndChecksCrossSegments()
      throws Exception {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    SplitFileFetcherSegmentStorage segment = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage otherSegment = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage[] segments =
        new SplitFileFetcherSegmentStorage[] {segment, otherSegment};
    SplitFileFetcherCrossSegmentStorage crossSegment =
        mock(SplitFileFetcherCrossSegmentStorage.class);

    setField(storage, "segments", segments);
    setField(storage, "crossSegments", new SplitFileFetcherCrossSegmentStorage[] {crossSegment});
    setField(storage, "segmentsToTryDecode", null);

    when(segment.hasFailed()).thenReturn(false);
    when(segment.needsDecode()).thenReturn(true);
    when(otherSegment.hasFailed()).thenReturn(false);
    when(otherSegment.needsDecode()).thenReturn(false);

    when(segment.readSegmentKeys()).thenReturn(mock(SplitFileSegmentKeys.class));
    when(otherSegment.readSegmentKeys()).thenReturn(mock(SplitFileSegmentKeys.class));

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(storage);

    recovery.postInitReadSegmentState();

    @SuppressWarnings("unchecked")
    List<SplitFileFetcherSegmentStorage> queued =
        (List<SplitFileFetcherSegmentStorage>) getField(storage, "segmentsToTryDecode");
    assertNotNull(queued);
    assertEquals(1, queued.size());
    assertSame(segment, queued.getFirst());
    verify(segment).readMetadata();
    verify(otherSegment).readMetadata();
    verify(segment).readSegmentKeys();
    verify(otherSegment).readSegmentKeys();
    verify(crossSegment).checkBlocks();
  }

  @Test
  void postInitReadSegmentState_whenSegmentFailed_throwsFetchExceptionAndFreesRaf()
      throws Exception {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    SplitFileFetcherSegmentStorage segment = mock(SplitFileFetcherSegmentStorage.class);
    LockableRandomAccessBuffer raf = mock(LockableRandomAccessBuffer.class);
    setField(storage, "segments", new SplitFileFetcherSegmentStorage[] {segment});
    setField(storage, "errors", new FailureCodeTracker(false));
    when(storage.getRAF()).thenReturn(raf);
    when(segment.hasFailed()).thenReturn(true);

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(storage);

    FetchException exception =
        assertThrows(FetchException.class, recovery::postInitReadSegmentState);

    assertEquals(FetchExceptionMode.SPLITFILE_ERROR, exception.mode);
    verify(raf).close();
    verify(raf).free();
    verify(segment, never()).readSegmentKeys();
  }

  @Test
  void postInitReadSegmentState_whenKeysCorrupted_throwsStorageFormatException() throws Exception {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    SplitFileFetcherSegmentStorage segment = mock(SplitFileFetcherSegmentStorage.class);
    setField(storage, "segments", new SplitFileFetcherSegmentStorage[] {segment});
    when(segment.hasFailed()).thenReturn(false);
    when(segment.needsDecode()).thenReturn(false);
    when(segment.readSegmentKeys()).thenThrow(new ChecksumFailedException());

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(storage);

    assertThrows(StorageFormatException.class, recovery::postInitReadSegmentState);

    assertNull(getField(storage, "segmentsToTryDecode"));
  }

  @Test
  void readGeneralProgress_whenValidData_setsFlagsAndErrors() throws Exception {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    FailureCodeTracker tracker = new FailureCodeTracker(false);
    tracker.inc(FetchExceptionMode.TOO_BIG);
    byte[] progress =
        buildProgressPayload(SplitFileFetcherStorage.HAS_CHECKED_DATASTORE_FLAG, tracker);

    setField(storage, "offsetGeneralProgress", 128L);
    setField(storage, "hasCheckedDatastore", false);
    setField(storage, "errors", new FailureCodeTracker(false));
    when(storage.preadChecksummedWithLength(128L)).thenReturn(progress);

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(storage);

    recovery.readGeneralProgress();

    assertTrue((boolean) getField(storage, "hasCheckedDatastore"));
    FailureCodeTracker result = (FailureCodeTracker) getField(storage, "errors");
    assertEquals(1, result.getErrorCount(FetchExceptionMode.TOO_BIG));
    verify(storage).preadChecksummedWithLength(128L);
  }

  @Test
  void readGeneralProgress_whenFlagNotSet_keepsCheckedFalse() throws Exception {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    FailureCodeTracker tracker = new FailureCodeTracker(false);
    byte[] progress = buildProgressPayload(0L, tracker);

    setField(storage, "offsetGeneralProgress", 96L);
    setField(storage, "hasCheckedDatastore", false);
    setField(storage, "errors", new FailureCodeTracker(false));
    when(storage.preadChecksummedWithLength(96L)).thenReturn(progress);

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(storage);

    recovery.readGeneralProgress();

    assertFalse((boolean) getField(storage, "hasCheckedDatastore"));
    FailureCodeTracker result = (FailureCodeTracker) getField(storage, "errors");
    assertEquals(0, result.getErrorCount(FetchExceptionMode.TOO_BIG));
  }

  @Test
  void readGeneralProgress_whenChecksumFails_resetsProgress() throws Exception {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    FailureCodeTracker originalErrors = new FailureCodeTracker(false);
    originalErrors.inc(FetchExceptionMode.TOO_BIG);
    setField(storage, "offsetGeneralProgress", 64L);
    setField(storage, "hasCheckedDatastore", true);
    setField(storage, "errors", originalErrors);
    when(storage.preadChecksummedWithLength(64L)).thenThrow(new ChecksumFailedException());

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(storage);

    recovery.readGeneralProgress();

    assertFalse((boolean) getField(storage, "hasCheckedDatastore"));
    FailureCodeTracker result = (FailureCodeTracker) getField(storage, "errors");
    assertNotSame(originalErrors, result);
    assertEquals(0, result.getErrorCount(FetchExceptionMode.TOO_BIG));
  }

  @Test
  void regenerateKeysAsync_whenPersistenceDisabled_returnsFalse() throws Exception {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    PersistentJobRunner jobRunner = mock(PersistentJobRunner.class);
    setField(storage, "jobRunner", jobRunner);
    doThrow(new PersistenceDisabledException()).when(jobRunner).queue(any(), anyInt());

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(storage);

    assertFalse(recovery.regenerateKeysAsync());

    verify(jobRunner).queue(any(), anyInt());
  }

  @Test
  void regenerateKeysAsync_whenJobRuns_rebuildsBloomFiltersAndNotifies() throws Exception {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    PersistentJobRunner jobRunner = mock(PersistentJobRunner.class);
    SplitFileFetcherKeyListener keyListener = mock(SplitFileFetcherKeyListener.class);
    SplitFileFetcherStorageCallback fetcher = mock(SplitFileFetcherStorageCallback.class);
    SplitFileFetcherSegmentStorage segment = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileSegmentKeys keys = mock(SplitFileSegmentKeys.class);
    ClientCHK clientKey = mock(ClientCHK.class);
    Key nodeKey = mock(Key.class);
    KeySalter salter = _ -> new byte[] {1, 2, 3};

    setField(storage, "jobRunner", jobRunner);
    setField(storage, "segments", new SplitFileFetcherSegmentStorage[] {segment});
    setField(storage, "keyListener", keyListener);
    setField(storage, "fetcher", fetcher);
    setField(storage, "persistent", true);
    setField(storage, "offsetSegmentBloomFilters", 20L);
    setField(storage, "offsetMainBloomFilter", 40L);

    when(fetcher.getSalter()).thenReturn(salter);
    when(segment.readSegmentKeys()).thenReturn(keys);
    when(keys.totalKeys()).thenReturn(2);
    when(keys.getKey(anyInt(), isNull(), eq(false))).thenReturn(clientKey);
    when(clientKey.getNodeKey(false)).thenReturn(nodeKey);

    ArgumentCaptor<PersistentJob> jobCaptor = ArgumentCaptor.forClass(PersistentJob.class);
    doNothing().when(jobRunner).queue(jobCaptor.capture(), anyInt());

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(storage);

    assertFalse(recovery.regenerateKeysAsync());

    PersistentJob job = jobCaptor.getValue();
    assertNotNull(job);
    assertFalse(job.run(mock(ClientContext.class)));

    verify(keyListener, times(2)).addKey(any(Key.class), eq(0), eq(salter));
    verify(keyListener).addedAllKeys();
    verify(keyListener).initialWriteSegmentBloomFilters(20L);
    verify(keyListener).innerWriteMainBloomFilter(40L);
    verify(fetcher).restartedAfterDataCorruption();
    verify(storage, never()).failOnDiskError(any(IOException.class));
  }

  @Test
  void restartCrossSegments_whenPresent_invokesRestart() {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    SplitFileFetcherCrossSegmentStorage first = mock(SplitFileFetcherCrossSegmentStorage.class);
    SplitFileFetcherCrossSegmentStorage second = mock(SplitFileFetcherCrossSegmentStorage.class);
    setField(storage, "crossSegments", new SplitFileFetcherCrossSegmentStorage[] {first, second});

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(storage);

    recovery.restartCrossSegments();

    verify(first).restart();
    verify(second).restart();
  }

  @Test
  void scheduleTryDecodeForBrokenSegments_whenListPresent_startsAndClears() {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    SplitFileFetcherSegmentStorage first = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage second = mock(SplitFileFetcherSegmentStorage.class);
    List<SplitFileFetcherSegmentStorage> broken = new ArrayList<>();
    broken.add(first);
    broken.add(second);
    setField(storage, "segmentsToTryDecode", broken);

    SplitFileFetcherStorageRecovery recovery = new SplitFileFetcherStorageRecovery(storage);

    recovery.scheduleTryDecodeForBrokenSegments();

    verify(first).tryStartDecode();
    verify(second).tryStartDecode();
    assertNull(getField(storage, "segmentsToTryDecode"));
  }

  private static byte[] buildProgressPayload(long flags, FailureCodeTracker tracker)
      throws IOException {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.writeLong(flags);
      tracker.writeFixedLengthTo(dos);
    }
    return baos.toByteArray();
  }

  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (NoSuchFieldException _) {
      try {
        Field field = target.getClass().getSuperclass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(target, value);
      } catch (ReflectiveOperationException ex) {
        throw new AssertionError(ex);
      }
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }

  private static Object getField(Object target, String fieldName) {
    try {
      Field field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true);
      return field.get(target);
    } catch (NoSuchFieldException _) {
      try {
        Field field = target.getClass().getSuperclass().getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(target);
      } catch (ReflectiveOperationException ex) {
        throw new AssertionError(ex);
      }
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }
}
