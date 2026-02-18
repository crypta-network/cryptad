package network.crypta.client.async;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import network.crypta.client.FetchException;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.crypt.ChecksumFailedException;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.NodeCHK;
import network.crypta.support.io.StorageFormatException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100") // Method naming per project test style
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SplitFileFetcherKeyListenerTest {

  private SplitFileFetcherStorageCallback fetcher;
  private SplitFileFetcherStorage storageMock;

  @BeforeEach
  void setUp() {
    fetcher = mock(SplitFileFetcherStorageCallback.class);
    storageMock = Mockito.mock(SplitFileFetcherStorage.class, Answers.RETURNS_DEEP_STUBS);

    Mockito.lenient()
        .when(storageMock.writeChecksummedTo(anyLong(), anyInt()))
        .thenAnswer(inv -> new ByteArrayOutputStream());
    Mockito.lenient().when(storageMock.hasFinished()).thenReturn(false);

    when(fetcher.getPriorityClass()).thenReturn((short) 7);
    when(fetcher.getHasKeyListener()).thenReturn(mock(HasKeyListener.class));
  }

  @Test
  @DisplayName("constructor_whenInvalidCounts_throwFetchException")
  void constructor_whenInvalidCounts_throwFetchException() {
    byte[] salt = new byte[32];
    FetchException ex1 =
        assertThrows(
            FetchException.class,
            () -> new SplitFileFetcherKeyListener(fetcher, storageMock, true, salt, 0, 1, 1));
    assertEquals(FetchExceptionMode.INTERNAL_ERROR, ex1.mode);

    FetchException ex2 =
        assertThrows(
            FetchException.class,
            () -> new SplitFileFetcherKeyListener(fetcher, storageMock, true, salt, 1, 0, 1));
    assertEquals(FetchExceptionMode.INTERNAL_ERROR, ex2.mode);

    FetchException ex3 =
        assertThrows(
            FetchException.class,
            () -> new SplitFileFetcherKeyListener(fetcher, storageMock, true, salt, 1, 1, 0));
    assertEquals(FetchExceptionMode.INTERNAL_ERROR, ex3.mode);
  }

  @Test
  @DisplayName("constructor_whenTooManyKeys_throwTooBig")
  void constructor_whenTooManyKeys_throwTooBig() {
    byte[] salt = new byte[32];
    int perKey = SplitFileFetcherKeyListener.DEFAULT_MAIN_BLOOM_ELEMENTS_PER_KEY;
    long threshold = (Integer.MAX_VALUE / perKey) + 1L;
    FetchException ex =
        assertThrows(
            FetchException.class,
            () ->
                new SplitFileFetcherKeyListener(
                    fetcher, storageMock, true, salt, (int) threshold, 1, 1));
    assertEquals(FetchExceptionMode.TOO_BIG, ex.mode);
  }

  @Test
  @DisplayName("addKey_afterFinishedSetupWithoutRegeneration_throws")
  void addKey_afterFinishedSetupWithoutRegeneration_throws() throws Exception {
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, false, salt, 4, 2, 2);
    listener.finishedSetup();
    assertThrows(
        IllegalStateException.class,
        () -> listener.addKey(mock(NodeCHK.class), 0, key -> new byte[] {1, 2, 3}));
  }

  @Test
  @DisplayName("probablyWantKey_whenBloomMatches_returnsTrue")
  void probablyWantKey_whenBloomMatches_returnsTrue() throws Exception {
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, true, salt, 4, 2, 2);

    NodeCHK key = mock(NodeCHK.class);
    when(key.getRoutingKey()).thenReturn("rk".getBytes(StandardCharsets.UTF_8));

    byte[] saltedKey = new byte[] {9, 8, 7, 6};
    KeySalter salter = k -> saltedKey;

    listener.addKey(key, 0, salter);
    listener.finishedSetup();

    assertTrue(listener.probablyWantKey(key, saltedKey));
  }

  @Test
  @DisplayName("probablyWantKey_whenMainBloomMiss_returnsFalse")
  void probablyWantKey_whenMainBloomMiss_returnsFalse() throws Exception {
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, false, salt, 4, 2, 2);

    NodeCHK key = mock(NodeCHK.class);
    when(key.getRoutingKey()).thenReturn("rk".getBytes(StandardCharsets.UTF_8));

    listener.finishedSetup();
    assertFalse(listener.probablyWantKey(key, new byte[] {1, 2, 3, 4}));
  }

  @Test
  @DisplayName("definitelyWantKey_whenSegmentWants_returnsPriority")
  void definitelyWantKey_whenSegmentWants_returnsPriority() throws Exception {
    int segments = 2;
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, true, salt, 4, 2, segments);

    NodeCHK key = mock(NodeCHK.class);
    when(key.getRoutingKey()).thenReturn("rk".getBytes(StandardCharsets.UTF_8));
    byte[] saltedKey = new byte[] {4, 5, 6, 7};
    listener.addKey(key, 0, k -> saltedKey);
    listener.finishedSetup();

    SplitFileFetcherSegmentStorage[] segs = new SplitFileFetcherSegmentStorage[segments];
    segs[0] = mock(SplitFileFetcherSegmentStorage.class);
    segs[1] = mock(SplitFileFetcherSegmentStorage.class);
    setSegmentsField(storageMock, segs);

    when(segs[0].definitelyWantKey(key)).thenReturn(true);
    when(segs[1].definitelyWantKey(key)).thenReturn(false);
    short expectedPrio = 5;
    when(fetcher.getPriorityClass()).thenReturn(expectedPrio);

    short prio = listener.definitelyWantKey(key, saltedKey, mock(ClientContext.class));
    assertEquals(expectedPrio, prio);
  }

  @Test
  @DisplayName("definitelyWantKey_whenNoSegmentWants_returnsMinusOne")
  void definitelyWantKey_whenNoSegmentWants_returnsMinusOne() throws Exception {
    int segments = 1;
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, true, salt, 4, 2, segments);

    NodeCHK key = mock(NodeCHK.class);
    when(key.getRoutingKey()).thenReturn("rk".getBytes(StandardCharsets.UTF_8));
    byte[] saltedKey = new byte[] {7, 7, 7, 7};
    listener.addKey(key, 0, k -> saltedKey);
    listener.finishedSetup();

    SplitFileFetcherSegmentStorage[] segs = new SplitFileFetcherSegmentStorage[segments];
    segs[0] = mock(SplitFileFetcherSegmentStorage.class);
    when(segs[0].definitelyWantKey(key)).thenReturn(false);
    setSegmentsField(storageMock, segs);

    short prio = listener.definitelyWantKey(key, saltedKey, mock(ClientContext.class));
    assertEquals(-1, prio);
  }

  @Test
  @DisplayName("handleBlock_whenSegmentAccepts_updatesBloomAndPersists")
  void handleBlock_whenSegmentAccepts_updatesBloomAndPersists() throws Exception {
    int segments = 1;
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, true, salt, 4, 2, segments);

    NodeCHK key = mock(NodeCHK.class);
    when(key.getRoutingKey()).thenReturn("rk".getBytes(StandardCharsets.UTF_8));
    byte[] saltedKey = new byte[] {1, 2, 3, 4};
    listener.addKey(key, 0, k -> saltedKey);
    listener.finishedSetup();

    SplitFileFetcherSegmentStorage[] segs = new SplitFileFetcherSegmentStorage[segments];
    segs[0] = mock(SplitFileFetcherSegmentStorage.class);
    when(segs[0].onGotKey(any(NodeCHK.class), any(CHKBlock.class))).thenReturn(true);
    setSegmentsField(storageMock, segs);

    boolean found =
        listener.handleBlock(
            key,
            saltedKey,
            mock(CHKBlock.class, Answers.RETURNS_DEEP_STUBS),
            mock(ClientContext.class));
    assertTrue(found);
    assertFalse(listener.probablyWantKey(key, saltedKey));
    verify(storageMock, times(1)).lazyWriteMetadata();
  }

  @Test
  @DisplayName("handleBlock_whenSegmentRejects_returnsFalseAndDoesNotPersist")
  void handleBlock_whenSegmentRejects_returnsFalseAndDoesNotPersist() throws Exception {
    int segments = 1;
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, false, salt, 4, 2, segments);

    NodeCHK key = mock(NodeCHK.class);
    when(key.getRoutingKey()).thenReturn("rk".getBytes(StandardCharsets.UTF_8));
    byte[] saltedKey = new byte[] {1, 2, 3, 4};
    listener.addKey(key, 0, k -> saltedKey);
    listener.finishedSetup();

    SplitFileFetcherSegmentStorage[] segs = new SplitFileFetcherSegmentStorage[segments];
    segs[0] = mock(SplitFileFetcherSegmentStorage.class);
    when(segs[0].onGotKey(any(NodeCHK.class), any(CHKBlock.class))).thenReturn(false);
    setSegmentsField(storageMock, segs);

    boolean found =
        listener.handleBlock(key, saltedKey, mock(CHKBlock.class), mock(ClientContext.class));
    assertFalse(found);
    verify(storageMock, times(0)).lazyWriteMetadata();
    assertTrue(listener.probablyWantKey(key, saltedKey));
  }

  @Test
  @DisplayName("handleBlock_whenDiskError_callsFailAndReturnsFalse")
  void handleBlock_whenDiskError_callsFailAndReturnsFalse() throws Exception {
    int segments = 1;
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, true, salt, 4, 2, segments);

    NodeCHK key = mock(NodeCHK.class);
    when(key.getRoutingKey()).thenReturn("rk".getBytes(StandardCharsets.UTF_8));
    byte[] saltedKey = new byte[] {1, 2, 3, 4};
    listener.addKey(key, 0, k -> saltedKey);
    listener.finishedSetup();

    SplitFileFetcherSegmentStorage[] segs = new SplitFileFetcherSegmentStorage[segments];
    segs[0] = mock(SplitFileFetcherSegmentStorage.class);
    doThrow(new IOException("disk"))
        .when(segs[0])
        .onGotKey(any(NodeCHK.class), any(CHKBlock.class));
    setSegmentsField(storageMock, segs);

    boolean found =
        listener.handleBlock(key, saltedKey, mock(CHKBlock.class), mock(ClientContext.class));
    assertFalse(found);
    verify(fetcher, times(1)).failOnDiskError(any(IOException.class));
    assertTrue(listener.probablyWantKey(key, saltedKey));
  }

  @Test
  @DisplayName("maybeWriteMainBloomFilter_whenDirty_writesOnce")
  void maybeWriteMainBloomFilter_whenDirty_writesOnce() throws Exception {
    int segments = 1;
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, true, salt, 4, 2, segments);

    NodeCHK key = mock(NodeCHK.class);
    when(key.getRoutingKey()).thenReturn("rk".getBytes(StandardCharsets.UTF_8));
    byte[] saltedKey = new byte[] {9, 9, 9, 9};
    listener.addKey(key, 0, k -> saltedKey);
    listener.finishedSetup();

    SplitFileFetcherSegmentStorage[] segs = new SplitFileFetcherSegmentStorage[segments];
    segs[0] = mock(SplitFileFetcherSegmentStorage.class);
    when(segs[0].onGotKey(any(NodeCHK.class), any(CHKBlock.class))).thenReturn(true);
    setSegmentsField(storageMock, segs);

    assertTrue(
        listener.handleBlock(key, saltedKey, mock(CHKBlock.class), mock(ClientContext.class)));

    AtomicInteger capturedLen = new AtomicInteger();
    AtomicLong capturedOffset = new AtomicLong();
    AtomicInteger calls = new AtomicInteger();
    // Override stub to capture values; still returns a fresh BAOS
    Mockito.lenient()
        .when(storageMock.writeChecksummedTo(anyLong(), anyInt()))
        .thenAnswer(
            inv -> {
              capturedOffset.set(inv.getArgument(0));
              capturedLen.set(inv.getArgument(1));
              calls.incrementAndGet();
              return new ByteArrayOutputStream();
            });

    listener.maybeWriteMainBloomFilter(1234L);
    listener.maybeWriteMainBloomFilter(1234L);

    assertEquals(1, calls.get());
    assertEquals(1234L, capturedOffset.get());
    assertEquals(listener.paddedMainBloomFilterSize(), capturedLen.get());
  }

  @Test
  @DisplayName("initialWriteSegmentBloomFilters_writesUsingStorage")
  void initialWriteSegmentBloomFilters_writesUsingStorage() throws Exception {
    int segments = 2;
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, false, salt, 4, 2, segments);

    long offset = 42L;
    int expectedLen = listener.totalSegmentBloomFiltersSize();
    AtomicInteger calls2 = new AtomicInteger();
    AtomicLong off = new AtomicLong();
    AtomicInteger len = new AtomicInteger();
    Mockito.lenient()
        .when(storageMock.writeChecksummedTo(anyLong(), anyInt()))
        .thenAnswer(
            inv -> {
              off.set(inv.getArgument(0));
              len.set(inv.getArgument(1));
              calls2.incrementAndGet();
              return new ByteArrayOutputStream();
            });

    listener.initialWriteSegmentBloomFilters(offset);

    assertEquals(1, calls2.get());
    assertEquals(offset, off.get());
    assertEquals(expectedLen, len.get());
  }

  @Test
  @DisplayName("persistenceAndAccessors_behaveAsExpected")
  void persistenceAndAccessors_behaveAsExpected() throws Exception {
    byte[] salt = new byte[32];
    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(fetcher, storageMock, true, salt, 4, 2, 1);

    short expectedPrio = 9;
    HasKeyListener expectedHasKeyListener = mock(HasKeyListener.class);
    when(fetcher.getPriorityClass()).thenReturn(expectedPrio);
    when(fetcher.getHasKeyListener()).thenReturn(expectedHasKeyListener);

    assertTrue(listener.persistent());
    assertEquals(expectedPrio, listener.getPriorityClass());

    assertThrows(UnsupportedOperationException.class, listener::countKeys);
    assertEquals(expectedHasKeyListener, listener.getHasKeyListener());

    when(storageMock.hasFinished()).thenReturn(true);
    assertTrue(listener.isEmpty());
    assertFalse(listener.isSSK());
    assertNull(listener.getWantedKey());
    assertNull(
        listener.getRequestsForKey(mock(NodeCHK.class), new byte[] {1}, mock(ClientContext.class)));
  }

  @Test
  @DisplayName("streamConstructor_whenChecksumFailures_flagsRegeneration")
  void streamConstructor_whenChecksumFailures_flagsRegeneration() throws Exception {
    SplitFileFetcherSegmentStorage[] segs = new SplitFileFetcherSegmentStorage[2];
    segs[0] = mock(SplitFileFetcherSegmentStorage.class);
    segs[1] = mock(SplitFileFetcherSegmentStorage.class);
    setSegmentsField(storageMock, segs);

    byte[] localSalt = new byte[32];
    for (int i = 0; i < localSalt.length; i++) localSalt[i] = (byte) (i + 1);
    int mainSizeBytes = 16;
    int mainK = 2;
    int segSizeBytes = 8;
    int perSegK = 1;

    byte[] header = new byte[32 + 4 * 4];
    System.arraycopy(localSalt, 0, header, 0, 32);
    int p = 32;
    putInt(header, p, mainSizeBytes);
    p += 4;
    putInt(header, p, mainK);
    p += 4;
    putInt(header, p, segSizeBytes);
    p += 4;
    putInt(header, p, perSegK);

    doThrow(new ChecksumFailedException())
        .when(storageMock)
        .preadChecksummed(anyLong(), any(byte[].class), anyInt(), anyInt());

    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(
            storageMock,
            fetcher,
            new DataInputStream(new ByteArrayInputStream(header)),
            true,
            false);
    assertTrue(listener.needsKeys());

    listener.addedAllKeys();
    assertFalse(listener.needsKeys());
  }

  @Test
  @DisplayName("streamConstructor_whenNewSalt_skipsMainReadAndNeedsKeys")
  void streamConstructor_whenNewSalt_skipsMainReadAndNeedsKeys() throws Exception {
    SplitFileFetcherSegmentStorage[] segs = new SplitFileFetcherSegmentStorage[1];
    segs[0] = mock(SplitFileFetcherSegmentStorage.class);
    setSegmentsField(storageMock, segs);

    byte[] localSalt = new byte[32];
    for (int i = 0; i < localSalt.length; i++) localSalt[i] = (byte) (i + 1);
    byte[] header = new byte[32 + 4 * 4];
    System.arraycopy(localSalt, 0, header, 0, 32);
    int p = 32;
    putInt(header, p, 8);
    p += 4;
    putInt(header, p, 2);
    p += 4;
    putInt(header, p, 4);
    p += 4;
    putInt(header, p, 1);

    SplitFileFetcherKeyListener listener =
        new SplitFileFetcherKeyListener(
            storageMock,
            fetcher,
            new DataInputStream(new ByteArrayInputStream(header)),
            true,
            true);
    assertTrue(listener.needsKeys());
  }

  @Test
  @DisplayName("streamConstructor_whenNegativeSizes_throwsStorageFormatException")
  void streamConstructor_whenNegativeSizes_throwsStorageFormatException() {
    byte[] localSalt = new byte[32];
    for (int i = 0; i < localSalt.length; i++) localSalt[i] = (byte) (i + 1);
    byte[] header = new byte[32 + 4 * 4];
    System.arraycopy(localSalt, 0, header, 0, 32);
    int p = 32;
    putInt(header, p, -1); // invalid main bloom size
    p += 4;
    putInt(header, p, 1);
    p += 4;
    putInt(header, p, 0);
    p += 4;
    putInt(header, p, 0);

    assertThrows(
        StorageFormatException.class,
        () ->
            new SplitFileFetcherKeyListener(
                storageMock,
                fetcher,
                new DataInputStream(new ByteArrayInputStream(header)),
                true,
                false));
  }

  // --- Helpers ---

  private static void setSegmentsField(
      SplitFileFetcherStorage target, SplitFileFetcherSegmentStorage[] value) throws Exception {
    Field f = findSegmentsField(target.getClass());
    f.setAccessible(true);
    f.set(target, value);
  }

  private static Field findSegmentsField(Class<?> type) throws NoSuchFieldException {
    Class<?> t = type;
    while (t != null) {
      try {
        return t.getDeclaredField("segments");
      } catch (NoSuchFieldException _) {
        t = t.getSuperclass();
      }
    }
    throw new NoSuchFieldException("segments");
  }

  private static void putInt(byte[] dst, int offset, int value) {
    dst[offset] = (byte) ((value >>> 24) & 0xFF);
    dst[offset + 1] = (byte) ((value >>> 16) & 0xFF);
    dst[offset + 2] = (byte) ((value >>> 8) & 0xFF);
    dst[offset + 3] = (byte) (value & 0xFF);
  }
}
