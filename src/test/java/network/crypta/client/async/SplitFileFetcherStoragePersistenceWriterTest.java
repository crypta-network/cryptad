package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import network.crypta.crypt.ChecksumChecker;
import network.crypta.support.api.LockableRandomAccessBuffer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SplitFileFetcherStoragePersistenceWriterTest {

  @Test
  void writeToRaf_whenPersistentFalse_writesKeysOnly() throws Exception {
    SplitFileFetcherSegmentStorage first = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage second = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage[] segments =
        new SplitFileFetcherSegmentStorage[] {first, second};
    SplitFileFetcherKeyListener keyListener = mock(SplitFileFetcherKeyListener.class);
    LockableRandomAccessBuffer raf = mock(LockableRandomAccessBuffer.class);
    SplitFileFetcherStorage storage = mockStorage(false, segments, keyListener);
    SplitFileFetcherStorage.AutoCloseableRafLock lock =
        mock(SplitFileFetcherStorage.AutoCloseableRafLock.class);
    when(storage.autoLockOpen()).thenReturn(lock);

    SplitFileSegmentKeys[] keys =
        new SplitFileSegmentKeys[] {
          mock(SplitFileSegmentKeys.class), mock(SplitFileSegmentKeys.class)
        };

    SplitFileFetcherStoragePersistenceWriter.writeToRaf(
        storage, keys, null, null, new byte[] {1}, 0L);

    verify(first).writeKeysWithChecksum(keys[0]);
    verify(second).writeKeysWithChecksum(keys[1]);
    verify(first, never()).writeMetadata();
    verify(second, never()).writeMetadata();
    verifyNoInteractions(keyListener);
    verifyNoInteractions(raf);
    verify(lock).close();
  }

  @Test
  void writeToRaf_whenPersistentTrue_writesMetadataAndFooter() throws Exception {
    SplitFileFetcherSegmentStorage first = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage second = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage[] segments =
        new SplitFileFetcherSegmentStorage[] {first, second};
    SplitFileFetcherKeyListener keyListener = mock(SplitFileFetcherKeyListener.class);
    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);
    LockableRandomAccessBuffer raf = mock(LockableRandomAccessBuffer.class);
    SplitFileFetcherStorage storage =
        mockStorage(true, segments, keyListener, checksumChecker, 40L, 60L, 80L, 100L);
    SplitFileFetcherStorage.AutoCloseableRafLock lock =
        mock(SplitFileFetcherStorage.AutoCloseableRafLock.class);
    when(storage.autoLockOpen()).thenReturn(lock);
    when(storage.getRAF()).thenReturn(raf);

    SplitFileFetcherStoragePersistence.PreparedMetadata prepared =
        mock(SplitFileFetcherStoragePersistence.PreparedMetadata.class);
    byte[] encodedBasicSettings = new byte[] {4, 5, 6};
    byte[] generalProgress = new byte[] {7, 8};
    long totalLength = 256L;
    SplitFileSegmentKeys[] keys =
        new SplitFileSegmentKeys[] {
          mock(SplitFileSegmentKeys.class), mock(SplitFileSegmentKeys.class)
        };

    try (MockedStatic<SplitFileFetcherStoragePersistence> mocked =
        mockStatic(SplitFileFetcherStoragePersistence.class)) {
      SplitFileFetcherStoragePersistenceWriter.writeToRaf(
          storage, keys, prepared, encodedBasicSettings, generalProgress, totalLength);

      verify(first).writeKeysWithChecksum(keys[0]);
      verify(second).writeKeysWithChecksum(keys[1]);
      verify(first).writeMetadata();
      verify(second).writeMetadata();
      verify(raf).pwrite(40L, generalProgress, 0, generalProgress.length);
      verify(keyListener).innerWriteMainBloomFilter(60L);
      verify(keyListener).initialWriteSegmentBloomFilters(80L);
      mocked.verify(
          () ->
              SplitFileFetcherStoragePersistence.writePersistentMetadata(
                  raf, 100L, prepared, encodedBasicSettings, checksumChecker, totalLength));
      verify(lock).close();
    }
  }

  @Test
  void writeToRaf_whenKeyWriteFails_propagatesIOException() throws Exception {
    SplitFileFetcherSegmentStorage first = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage second = mock(SplitFileFetcherSegmentStorage.class);
    SplitFileFetcherSegmentStorage[] segments =
        new SplitFileFetcherSegmentStorage[] {first, second};
    SplitFileFetcherKeyListener keyListener = mock(SplitFileFetcherKeyListener.class);
    SplitFileFetcherStorage storage = mockStorage(true, segments, keyListener);
    SplitFileFetcherStorage.AutoCloseableRafLock lock =
        mock(SplitFileFetcherStorage.AutoCloseableRafLock.class);
    when(storage.autoLockOpen()).thenReturn(lock);

    SplitFileSegmentKeys[] keys =
        new SplitFileSegmentKeys[] {
          mock(SplitFileSegmentKeys.class), mock(SplitFileSegmentKeys.class)
        };
    IOException failure = new IOException("boom");
    org.mockito.Mockito.doThrow(failure).when(first).writeKeysWithChecksum(keys[0]);

    assertThrows(
        IOException.class,
        () ->
            SplitFileFetcherStoragePersistenceWriter.writeToRaf(
                storage, keys, null, null, new byte[] {1}, 0L));

    verify(lock).close();
    verifyNoInteractions(keyListener);
  }

  private static SplitFileFetcherStorage mockStorage(
      boolean persistent,
      SplitFileFetcherSegmentStorage[] segments,
      SplitFileFetcherKeyListener keyListener) {
    ChecksumChecker checksumChecker = mock(ChecksumChecker.class);
    return mockStorage(persistent, segments, keyListener, checksumChecker, 0L, 0L, 0L, 0L);
  }

  private static SplitFileFetcherStorage mockStorage(
      boolean persistent,
      SplitFileFetcherSegmentStorage[] segments,
      SplitFileFetcherKeyListener keyListener,
      ChecksumChecker checksumChecker,
      long offsetGeneralProgress,
      long offsetMainBloomFilter,
      long offsetSegmentBloomFilters,
      long offsetOriginalMetadata) {
    SplitFileFetcherStorage storage = mock(SplitFileFetcherStorage.class);
    setField(storage, "segments", segments);
    setField(storage, "persistent", persistent);
    setField(storage, "offsetGeneralProgress", offsetGeneralProgress);
    setField(storage, "offsetMainBloomFilter", offsetMainBloomFilter);
    setField(storage, "offsetSegmentBloomFilters", offsetSegmentBloomFilters);
    setField(storage, "offsetOriginalMetadata", offsetOriginalMetadata);
    setField(storage, "checksumChecker", checksumChecker);
    setField(storage, "keyListener", keyListener);
    return storage;
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
}
