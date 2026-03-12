package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Security;
import java.util.Random;
import network.crypta.crypt.EncryptedRandomAccessBuffer;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SerialExecutor;
import network.crypta.support.api.LockableRandomAccessBuffer.RAFLock;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.support.io.TempBucketFactory.TempBucket;
import network.crypta.support.io.TempBucketFactory.TempRandomAccessBuffer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * AAA-style tests for TempBucketFactory.TempRandomAccessBuffer, consolidating and improving the
 * legacy TempBucketFactory RAF tests. Deterministic seeds; no flakiness.
 */
@SuppressWarnings({
  "java:S100",
  "java:S5778",
  "java:S2245",
  "java:S5443"
}) // method_whenCondition_expectOutcome; deterministic PRNG in tests; temp dir in tests
class TempBucketFactoryTempRandomAccessBufferTest {

  private static final int SEED_FACTORY = 12340;
  private static final int SEED_DATA = 21162101;
  private static final long MIN_DISK_SPACE = 2L * 1024 * 1024; // 2 MiB

  private Path tempDir;
  private FilenameGenerator fg;
  private PriorityAwareExecutor exec;
  private final MasterSecret secret = new MasterSecret();

  @BeforeAll
  static void registerBouncyCastle() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @BeforeEach
  void setUp() throws IOException {
    tempDir = Files.createTempDirectory("tbf-raf-junit-");
    fg = new FilenameGenerator(new Random(SEED_FACTORY), false, tempDir.toFile(), "junit-");
    exec = new SerialExecutor(NativeThread.PriorityLevel.NORM_PRIORITY.value);
  }

  @AfterEach
  void tearDown() throws IOException {
    // Best-effort cleanup of the temp directory files created by the tests.
    File dir = tempDir.toFile();
    File[] files = dir.listFiles();
    if (files != null) {
      for (File f : files) {
        try {
          Files.deleteIfExists(f.toPath());
        } catch (IOException _) {
          // ignore: best-effort cleanup in tests
        }
      }
    }
    Files.deleteIfExists(tempDir);
  }

  private TempBucketFactory newFactory(boolean encrypt, long maxRamBucket, long maxRamUsed) {
    TempBucketFactory f =
        new TempBucketFactory(
            exec,
            fg,
            maxRamBucket,
            maxRamUsed,
            /* reallyEncrypt */ encrypt,
            MIN_DISK_SPACE,
            secret);
    // Ensure encryption flag is honored for bucket/file paths as well.
    f.setEncryption(encrypt);
    return f;
  }

  // ------------------------ Direct RAF creation (plaintext path) ------------------------

  @Test
  void makeRAF_whenSizeFitsRam_returnsTempRAB_andSizeMatches() throws IOException {
    // Arrange
    TempBucketFactory f = newFactory(false, /*maxRamBucket*/ 4096, /*maxRamUsed*/ 64L * 1024);
    int size = 2048;

    // Act
    try (RandomAccessBuffer rab = f.makeRAF(size)) {
      // Assert
      assertInstanceOf(TempRandomAccessBuffer.class, rab);
      assertEquals(size, rab.size());

      // Write a deterministic pattern and read it back randomly
      byte[] data = new byte[size];
      new Random(SEED_DATA).nextBytes(data);
      rab.pwrite(0, data, 0, data.length);
      // spot-check three ranges
      assertSectionEquals(data, rab, 0, size);
      assertSectionEquals(data, rab, 1, size - 1);
      assertSectionEquals(data, rab, 17, 31);

      rab.free();
    }
  }

  // Note: The TempRandomAccessBuffer constructors always pass a compatible size to the
  // SwitchableProxyRandomAccessBuffer supertype, so we do not test the
  // "underlying smaller than size" branch here (not constructible via public API).

  @Test
  @SuppressWarnings({"java:S2095", "resource"})
  // constructor throws before resource is allocated; no leak possible
  void constructor_whenNullUnderlying_throwsNullPointerException() {
    // Arrange
    TempBucketFactory f = newFactory(false, 4096, 64L * 1024);

    // Act + Assert
    assertThrows(
        NullPointerException.class, () -> f.new TempRandomAccessBuffer(null, 1L, true, null));
  }

  @Test
  void pread_whenNegativeOffset_throwsIllegalArgumentException() throws IOException {
    // Arrange
    TempBucketFactory f = newFactory(false, 4096, 64L * 1024);
    try (RandomAccessBuffer rab = f.makeRAF(32)) {
      // Act + Assert
      assertThrows(IllegalArgumentException.class, () -> rab.pread(-1, new byte[1], 0, 1));
      rab.free();
    }
  }

  @Test
  void pwrite_whenPastEnd_throwsIOException() throws IOException {
    // Arrange
    TempBucketFactory f = newFactory(false, 4096, 64L * 1024);
    try (RandomAccessBuffer rab = f.makeRAF(16)) {
      // Act + Assert
      assertThrows(IOException.class, () -> rab.pwrite(16, new byte[1], 0, 1));
      assertThrows(IOException.class, () -> rab.pwrite(1024, new byte[1], 0, 1));
      rab.free();
    }
  }

  @Test
  void close_whenCalled_thenSubsequentOpsThrowIOException() throws IOException {
    // Arrange
    TempBucketFactory f = newFactory(false, 4096, 64L * 1024);
    try (RandomAccessBuffer rab = f.makeRAF(8)) {
      // Act
      rab.close();

      // Assert
      assertThrows(IOException.class, () -> rab.pread(0, new byte[1], 0, 1));
      assertThrows(IOException.class, () -> rab.pwrite(0, new byte[1], 0, 1));
      rab.free();
    }
  }

  @Test
  void migrateToDisk_whenInRam_movesToFile_andPreservesData_andResetsRamAccounting()
      throws IOException {
    // Arrange
    TempBucketFactory f = newFactory(false, 8192, 64L * 1024);
    int size = 4095;
    try (TempRandomAccessBuffer rab = (TempRandomAccessBuffer) f.makeRAF(size)) {
      byte[] data = new byte[size];
      new Random(SEED_DATA).nextBytes(data);
      rab.pwrite(0, data, 0, data.length);
      assertEquals(size, f.getRamUsed());

      // Act
      boolean migratedFirst = rab.migrateToDisk();
      boolean migratedSecond = rab.migrateToDisk();

      // Assert
      assertTrue(migratedFirst);
      assertFalse(migratedSecond);
      assertTrue(rab.hasMigrated());
      assertEquals(0, f.getRamUsed());
      assertSectionEquals(data, rab, 0, size);

      rab.free();
    }
  }

  // ------------------------ Bucket -> RAB conversion (parametrized: encrypt on/off)
  // ------------------------

  @ParameterizedTest(name = "bucketToRAB_array_encrypt={0}")
  @ValueSource(booleans = {false, true})
  void bucketToRandomAccessBuffer_whenArrayBucket_returnsTempRAB(boolean encrypt)
      throws IOException {
    // Arrange: small RAM limits so bucket stays in RAM
    TempBucketFactory f = newFactory(encrypt, 4096, 64L * 1024);
    byte[] data = new byte[1024];
    new Random(SEED_DATA).nextBytes(data);
    try (TempBucket bucket = (TempBucket) f.makeBucket(4096)) {
      try (var os = bucket.getOutputStreamUnbuffered()) {
        os.write(data);
      }

      // Act + Assert
      try (LockableRandomAccessBuffer rab = bucket.toRandomAccessBuffer()) {
        assertInstanceOf(TempRandomAccessBuffer.class, rab);
        TempRandomAccessBuffer t = (TempRandomAccessBuffer) rab;
        assertFalse(t.hasMigrated(), "Should not be migrated for in-RAM bucket");
        assertEquals(data.length, rab.size());

        byte[] read = new byte[data.length];
        rab.pread(0, read, 0, read.length);
        assertArrayEquals(data, read);
        rab.free();
      }
    }
  }

  @ParameterizedTest(name = "bucketToRAB_file_encrypt={0}")
  @ValueSource(booleans = {false, true})
  void bucketToRandomAccessBuffer_whenFileBucket_returnsTempRAB_andUnderlyingReflectsEncryption(
      boolean encrypt) throws IOException {
    // Arrange: force on-disk bucket by making requested size exceed RAM threshold
    TempBucketFactory f = newFactory(encrypt, 256, 512L);
    byte[] data = new byte[4096];
    new Random(SEED_DATA).nextBytes(data);
    try (TempBucket bucket = (TempBucket) f.makeBucket(8192)) {
      assertFalse(bucket.isRAMBucket());
      try (var os = bucket.getOutputStreamUnbuffered()) {
        os.write(data);
      }

      // Act + Assert
      try (LockableRandomAccessBuffer rab = bucket.toRandomAccessBuffer()) {
        // wrapper is TempRandomAccessBuffer, and it reports the logical size
        assertInstanceOf(TempRandomAccessBuffer.class, rab);
        TempRandomAccessBuffer t = (TempRandomAccessBuffer) rab;
        assertTrue(t.hasMigrated(), "File-backed bucket should yield migrated TempRAB");
        assertEquals(data.length, rab.size());

        // Underlying type reflects encryption setting
        LockableRandomAccessBuffer underlying = t.getUnderlying();
        if (encrypt) {
          assertInstanceOf(
              EncryptedRandomAccessBuffer.class,
              underlying,
              "Expected encrypted underlying RAB when encryption enabled");
        } else {
          assertInstanceOf(
              PooledFileRandomAccessBuffer.class,
              underlying,
              "Expected file-backed underlying RAB when encryption disabled");
        }
        rab.free();
      }
    }
  }

  @ParameterizedTest(name = "bucketFree_thenRABRead_encrypt={0}")
  @ValueSource(booleans = {false, true})
  void read_whenBucketFreedAfterConversion_throwsIOException(boolean encrypt) throws IOException {
    // Arrange
    TempBucketFactory f = newFactory(encrypt, 4096, 64L * 1024);
    byte[] data = new byte[1024];
    new Random(SEED_DATA).nextBytes(data);
    try (TempBucket bucket = (TempBucket) f.makeBucket(4096)) {
      try (var os = bucket.getOutputStreamUnbuffered()) {
        os.write(data);
      }
      try (TempRandomAccessBuffer rab = (TempRandomAccessBuffer) bucket.toRandomAccessBuffer()) {
        // Act
        bucket.free();

        // Assert
        byte[] buf = new byte[16];
        assertThrows(IOException.class, () -> rab.pread(0, buf, 0, buf.length));
        rab.free();
      }
    }
  }

  // ------------------------ Mockito-based edge/error propagation ------------------------

  @Test
  void pread_whenUnderlyingThrows_propagatesIOException() throws IOException {
    // Arrange: wrap a mocked underlying RAB so we can force errors
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    when(underlying.size()).thenReturn(64L);
    doThrow(new IOException("boom")).when(underlying).pread(anyLong(), any(), anyInt(), anyInt());
    TempRandomAccessBuffer proxy =
        newFactory(false, 4096, 64L * 1024).new TempRandomAccessBuffer(underlying, 1L, true, null);

    // Act + Assert
    assertThrows(IOException.class, () -> proxy.pread(0, new byte[8], 0, 8));
  }

  @Test
  void pwrite_whenUnderlyingThrows_propagatesIOException() throws IOException {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    when(underlying.size()).thenReturn(64L);
    doThrow(new IOException("boom")).when(underlying).pwrite(anyLong(), any(), anyInt(), anyInt());
    TempRandomAccessBuffer proxy =
        newFactory(false, 4096, 64L * 1024).new TempRandomAccessBuffer(underlying, 1L, true, null);

    // Act + Assert
    assertThrows(IOException.class, () -> proxy.pwrite(0, new byte[8], 0, 8));
  }

  @Test
  void lockOpen_whenOpenedAndUnlocked_delegatesToUnderlying() throws IOException {
    // Arrange
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    when(underlying.size()).thenReturn(64L);

    final boolean[] unlocked = {false};
    RAFLock underlyingLock =
        new RAFLock() {
          @Override
          protected void innerUnlock() {
            unlocked[0] = true;
          }
        };
    when(underlying.lockOpen()).thenReturn(underlyingLock);

    TempRandomAccessBuffer proxy =
        newFactory(false, 4096, 64L * 1024).new TempRandomAccessBuffer(underlying, 1L, true, null);

    // Act
    RAFLock lock = proxy.lockOpen();
    lock.unlock();

    // Assert
    verify(underlying, times(1)).lockOpen();
    assertTrue(unlocked[0], "Expected underlying RAFLock to be unlocked by proxy");
  }

  // ------------------------ Helpers ------------------------

  private static void assertSectionEquals(
      byte[] expected, RandomAccessBuffer rab, int start, int end) throws IOException {
    int len = end - start;
    byte[] tmp = new byte[len];
    rab.pread(start, tmp, 0, len);
    assertArrayEquals(copyOfRange(expected, start, end), tmp);
  }

  private static byte[] copyOfRange(byte[] src, int start, int end) {
    int len = end - start;
    byte[] out = new byte[len];
    System.arraycopy(src, start, out, 0, len);
    return out;
  }
}
