package network.crypta.support.io;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.MasterSecret;
import network.crypta.crypt.RandomSource;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.SerialExecutor;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.io.TempBucketFactory.TempBucket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Focused tests for {@link TempBucketFactory.TempBucket} covering stream lifecycle, error paths,
 * migration, and conversion to random-access buffers.
 */
@SuppressWarnings({
  "java:S100",
  "java:S2245"
}) // keep test method names with underscores; deterministic PRNG for tests
class TempBucketFactoryTempBucketTest {
  // Utility to aggregate AutoCloseable resources for dynamic scenarios
  static final class Closer implements AutoCloseable {
    private final List<AutoCloseable> resources = new ArrayList<>();

    <T extends AutoCloseable> T add(T resource) {
      resources.add(resource);
      return resource;
    }

    @Override
    public void close() {
      for (int i = resources.size() - 1; i >= 0; i--) {
        try {
          resources.get(i).close();
        } catch (Exception _) {
          // Intentionally ignore close failures in tests
        }
      }
    }
  }

  private static final MasterSecret SECRET = new MasterSecret();
  private FilenameGenerator fg;
  private PriorityAwareExecutor exec;

  @BeforeEach
  void setUp() throws IOException {
    // Deterministic sources for stable behavior
    fg = new FilenameGenerator(new DummyRandomSource(11111), false, null, "junit-tbf-");
    exec = new SerialExecutor(NativeThread.PriorityLevel.NORM_PRIORITY.value);
  }

  @AfterEach
  void tearDown() {
    // No global state to clean up; buckets are freed in each test
  }

  private TempBucketFactory newFactory(long maxRamBucket, long maxRamUsed) {
    return new TempBucketFactory(
        exec, fg, maxRamBucket, maxRamUsed, false, /* minDiskSpace */ 2 * 1024 * 1024, SECRET);
  }

  @Test
  @DisplayName("getInputStreamUnbuffered_whenNoOutputStreamOpened_throwsIOException")
  void getInputStreamUnbuffered_whenNoOutputStreamOpened_throwsIOException() throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(16, 128);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(16)) {
      assertTrue(bucket.isRAMBucket());

      // Act
      IOException ex = assertThrows(IOException.class, bucket::getInputStreamUnbuffered);

      // Assert: tolerate historical typo "opened" in message
      assertTrue(ex.getMessage().startsWith("No OutputStream has been open"));
    }
  }

  @Test
  @DisplayName("getOutputStreamUnbuffered_whenAlreadyOpen_throwsIOException")
  void getOutputStreamUnbuffered_whenAlreadyOpen_throwsIOException() throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(16, 128);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(16)) {
      // Act
      OutputStream os = bucket.getOutputStreamUnbuffered();
      IOException ex = assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);

      // Assert
      assertTrue(ex.getMessage().startsWith("Only one OutputStream per bucket"));
      os.close();
    }
  }

  @Test
  @DisplayName("free_whenCalledTwice_isIdempotent")
  void free_whenCalledTwice_isIdempotent() throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(16, 128);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(16)) {
      // Act + Assert
      assertDoesNotThrow(
          () -> {
            bucket.free();
            bucket.free();
          });
    }
  }

  @Test
  @DisplayName("methodsAfterFree_whenUsed_throwIOException")
  void methodsAfterFree_whenUsed_throwIOException() throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(16, 128);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(16)) {
      OutputStream os = bucket.getOutputStreamUnbuffered();
      os.write(1);
      os.close();
      bucket.free();

      // Act
      IOException ex1 = assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);
      IOException ex2 = assertThrows(IOException.class, bucket::getInputStreamUnbuffered);

      // Assert
      assertTrue(ex1.getMessage().startsWith("Already freed"));
      assertTrue(ex2.getMessage().startsWith("Already freed"));
    }
  }

  @Test
  @DisplayName("toRandomAccessBuffer_whenOutputOpen_throwsIOException")
  void toRandomAccessBuffer_whenOutputOpen_throwsIOException() throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(16, 128);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(16)) {
      OutputStream os = bucket.getOutputStreamUnbuffered();
      os.write(new byte[8]);

      // Act
      IOException ex = assertThrows(IOException.class, bucket::toRandomAccessBuffer);

      // Assert
      assertTrue(ex.getMessage().contains("open OutputStream"));
      os.close();
    }
  }

  @Test
  @DisplayName("toRandomAccessBuffer_whenInputOpen_throwsIOException")
  void toRandomAccessBuffer_whenInputOpen_throwsIOException() throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(16, 128);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(16)) {
      OutputStream os = bucket.getOutputStreamUnbuffered();
      os.write(new byte[8]);
      os.close();
      InputStream is = bucket.getInputStreamUnbuffered();

      // Act
      IOException ex = assertThrows(IOException.class, bucket::toRandomAccessBuffer);

      // Assert
      assertTrue(ex.getMessage().contains("open InputStream"));
      is.close();
    }
  }

  @Test
  @DisplayName("toRandomAccessBuffer_whenNoStreams_convertsAndReplacesUnderlying")
  void toRandomAccessBuffer_whenNoStreams_convertsAndReplacesUnderlying() throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(32, 256);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(32)) {
      assertTrue(bucket.isRAMBucket());
      byte[] data = new byte[24];
      new java.security.SecureRandom().nextBytes(data);
      try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
        os.write(data);
      }

      // Act
      LockableRandomAccessBuffer rab = bucket.toRandomAccessBuffer();

      // Assert
      assertNotNull(rab);
      assertEquals(data.length, rab.size());
      assertTrue(bucket.isReadOnly());
      network.crypta.support.api.Bucket underlying = bucket.getUnderlying();
      assertNotNull(underlying);
      assertEquals(rab.size(), underlying.size());
    }
  }

  @ParameterizedTest(name = "size_whenWriteLen={0}_reflectsExactSize")
  @ValueSource(ints = {0, 1, 7, 4096})
  void size_whenWriteVariousLengths_reflectsExactSize(int len) throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(8192, 1L << 20);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(8192)) {
      assertTrue(bucket.isRAMBucket());

      // Act
      try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
        if (len > 0) os.write(new byte[len]);
      }

      // Assert
      assertEquals(len, bucket.size());
    }
  }

  @Test
  @DisplayName("getOutputStreamUnbuffered_afterClose_canOpenAgain")
  void getOutputStreamUnbuffered_afterClose_canOpenAgain() throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(64, 256);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(32)) {
      assertTrue(bucket.isRAMBucket());

      // Act
      try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
        os.write(new byte[10]);
      }
      try (OutputStream os2 = bucket.getOutputStreamUnbuffered()) {
        os2.write(new byte[5]);
      }

      // Assert
      assertEquals(15, bucket.size());
    }
  }

  @Test
  @DisplayName("setReadOnly_whenSetBeforeOpen_outputOpenThrows")
  void setReadOnly_whenSetBeforeOpen_outputOpenThrows() throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(64, 256);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(32)) {
      bucket.setReadOnly();

      // Act
      IOException ex = assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);

      // Assert
      assertTrue(ex.getMessage().contains("Read only"));
    }
  }

  @Test
  @DisplayName("migrateToDisk_whenAlreadyOnDisk_returnsFalse")
  void migrateToDisk_whenAlreadyOnDisk_returnsFalse() throws IOException {
    // Arrange: force on-disk by making a large bucket
    TempBucketFactory tbf = newFactory(16, 32);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(1024)) {
      assertFalse(bucket.isRAMBucket());

      // Act
      boolean migrated = bucket.migrateToDisk();

      // Assert
      assertFalse(migrated);
    }
  }

  @Test
  @DisplayName("migrateToDisk_whenFreed_returnsFalse")
  void migrateToDisk_whenFreed_returnsFalse() throws IOException {
    // Arrange
    TempBucketFactory tbf = newFactory(64, 256);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(32)) {
      bucket.free();

      // Act
      boolean migrated = bucket.migrateToDisk();

      // Assert
      assertFalse(migrated);
    }
  }

  @Nested
  @SuppressWarnings("java:S100")
  class DiskSpaceChecks {
    /**
     * Helper to create a TempBucketFactory with a specific minimum free-disk threshold.
     *
     * <p>Parameters {@code maxRamBucket} and {@code maxRamUsed} are used to steer selection toward
     * a disk-backed bucket when needed for these disk-space tests.
     */
    private TempBucketFactory newFactoryWithMinDisk(
        long minDisk, long maxRamBucket, long maxRamUsed) {
      return new TempBucketFactory(exec, fg, maxRamBucket, maxRamUsed, false, minDisk, SECRET);
    }

    @Test
    @DisplayName("makeBucket_whenMinDiskSpaceExceededOnCreate_throwsInsufficientDiskSpace")
    void makeBucket_whenMinDiskSpaceExceededOnCreate_throwsInsufficientDiskSpace() {
      // Arrange
      long initialUsable = fg.getDir().getUsableSpace();
      long guard = 64L * 1024 * 1024; // 64 MiB safety margin against CI free-space fluctuations
      long currentUsable = fg.getDir().getUsableSpace();
      long baseUsable = Math.max(initialUsable, currentUsable);
      long minDisk = baseUsable + guard + 8192; // force failure on pre-check robustly
      TempBucketFactory tbf = newFactoryWithMinDisk(minDisk, /*maxRamBucket*/ 1, /*maxRamUsed*/ 1);

      // Act + Assert (ensure resource would be closed if unexpectedly created)
      assertThrows(
          InsufficientDiskSpaceException.class,
          () -> {
            try (var _ = (TempBucket) tbf.makeBucket(8192)) {
              fail("Expected InsufficientDiskSpaceException");
            }
          });
    }

    @Test
    @DisplayName("write_whenDiskBucketAndBelowUsableSpace_throwsInsufficientDiskSpace")
    void write_whenDiskBucketAndBelowUsableSpace_throwsInsufficientDiskSpace() throws IOException {
      // Arrange
      long initialUsable = fg.getDir().getUsableSpace();
      long guard = 64L * 1024 * 1024; // 64 MiB safety margin against CI free-space fluctuations
      long currentUsable = fg.getDir().getUsableSpace();
      long baseUsable = Math.max(initialUsable, currentUsable);
      long minDisk = baseUsable + guard + 4096; // fail per-write check on first 4K flush robustly
      TempBucketFactory tbf = newFactoryWithMinDisk(minDisk, /*maxRamBucket*/ 0, /*maxRamUsed*/ 0);

      try (RandomAccessBucket bucket = tbf.makeBucket(-1);
          OutputStream os = bucket.getOutputStreamUnbuffered()) {
        byte[] buf = new byte[4096];

        // Act + Assert
        assertThrows(InsufficientDiskSpaceException.class, () -> os.write(buf));
      }
    }
  }
}

// -------------------- Merged from TempBucketTest --------------------

// Migration-focused tests merged from TempBucketTest.TempBucketMigrationTest
@SuppressWarnings("java:S100")
class TempBucketMigrationTest {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  TempBucketMigrationTest() throws IOException {
    RandomSource weakPRNG = new DummyRandomSource(12340);
    fg = new FilenameGenerator(weakPRNG, false, null, "junit");
  }

  @Test
  void makeBucket_whenExceedRamPool_lastBucketOnDiskThenReuseRam() throws IOException {
    // Arrange
    TempBucketFactory tbf = new TempBucketFactory(exec, fg, 16, 128, false, MIN_DISK_SPACE, secret);
    int maxRamBucket = 128 / 16;
    try (TempBucketFactoryTempBucketTest.Closer closer =
        new TempBucketFactoryTempBucketTest.Closer()) {
      TempBucket[] b = new TempBucket[maxRamBucket + 1];
      for (int i = 0; i < maxRamBucket + 1; i++) {
        b[i] = closer.add((TempBucket) tbf.makeBucket(16));
        try (OutputStream os = b[i].getOutputStream()) {
          os.write(new byte[16]);
        }
      }

      // Act + Assert
      assertTrue(b[0].isRAMBucket());
      assertFalse(b[maxRamBucket].isRAMBucket());

      b[0].free();
      b[maxRamBucket].free();

      // Act: create smaller buckets to reuse RAM
      b[0] = closer.add((TempBucket) tbf.makeBucket(8));
      b[maxRamBucket] = closer.add((TempBucket) tbf.makeBucket(8));

      // Assert
      assertTrue(b[0].isRAMBucket());
      assertTrue(b[maxRamBucket].isRAMBucket());
    }
  }

  @Test
  void write_whenExceedConversionFactor_migratesToDisk() throws IOException {
    // Arrange
    TempBucketFactory tbf = new TempBucketFactory(exec, fg, 16, 128, false, MIN_DISK_SPACE, secret);
    try (TempBucket b = (TempBucket) tbf.makeBucket(16)) {
      assertTrue(b.isRAMBucket());
      OutputStream os = b.getOutputStreamUnbuffered();
      os.write(new byte[16]);

      // Act: exceed conversion factor
      for (int i = 0; i < TempBucketFactory.RAMBUCKET_CONVERSION_FACTOR - 1; i++) {
        os.write(new byte[16]);
      }

      // Assert
      assertFalse(b.isRAMBucket());
    }
  }

  @Test
  void write_whenExceedMaxRamUsed_migratesToDisk() throws IOException {
    // Arrange
    TempBucketFactory tbf = new TempBucketFactory(exec, fg, 16, 17, false, MIN_DISK_SPACE, secret);
    try (TempBucket b = (TempBucket) tbf.makeBucket(16)) {
      assertTrue(b.isRAMBucket());
      OutputStream os = b.getOutputStreamUnbuffered();
      os.write(new byte[16]);

      // Act: write beyond total RAM limit by 2 bytes
      os.write(new byte[2]);

      // Assert
      assertFalse(b.isRAMBucket());
    }
  }

  // This CAN happen due to memory pressure.
  @Test
  void read_whenMigratedDuringRead_preservesDataSmall() throws IOException {
    // Arrange
    TempBucketFactory tbf =
        new TempBucketFactory(exec, fg, 1024, 65536, false, MIN_DISK_SPACE, secret);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(64)) {
      try (OutputStream os = bucket.getOutputStreamUnbuffered();
          InputStream is = bucket.getInputStream()) {
        os.write(new byte[16]);

        // Act
        bucket.migrateToDisk();
        byte[] readTo = new byte[16];
        int read = is.read(readTo, 0, 16);

        // Assert
        assertEquals(16, read);
        for (byte v : readTo) assertEquals(0, v);
      }
    }
  }

  // Do a bigger read, verify contents.
  @Test
  void read_whenMigratedDuringRead_preservesDataLarge() throws IOException {
    // Arrange
    TempBucketFactory tbf =
        new TempBucketFactory(exec, fg, 4096, 65536, false, MIN_DISK_SPACE, secret);
    try (TempBucket bucket = (TempBucket) tbf.makeBucket(2048)) {
      byte[] data = new byte[2048];
      new java.security.SecureRandom().nextBytes(data);
      try (OutputStream os = bucket.getOutputStreamUnbuffered();
          InputStream is = bucket.getInputStream();
          DataInputStream dis = new DataInputStream(is)) {
        os.write(data);

        // Act
        bucket.migrateToDisk();
        byte[] readTo = new byte[2048];
        dis.readFully(readTo);

        // Assert
        assertArrayEquals(data, readTo);
      }
    }
  }

  private final PriorityAwareExecutor exec =
      new SerialExecutor(NativeThread.PriorityLevel.NORM_PRIORITY.value);
  private final FilenameGenerator fg;
  private static final long MIN_DISK_SPACE = 2L * 1024 * 1024;
  private static final MasterSecret secret = new MasterSecret();
}

// Bucket behavior tests merged from TempBucketTest.RealTempBucketTest_*
@SuppressWarnings({"java:S101", "NewClassNamingConvention"})
class RealTempBucketTest_8_16_F extends RealTempBucketTest_ {
  RealTempBucketTest_8_16_F() throws IOException {
    super(8, 16, false);
  }
}

@SuppressWarnings({"java:S101", "NewClassNamingConvention"})
class RealTempBucketTest_64_128_F extends RealTempBucketTest_ {
  RealTempBucketTest_64_128_F() throws IOException {
    super(64, 128, false);
  }
}

@SuppressWarnings({"java:S101", "NewClassNamingConvention"})
class RealTempBucketTest_64k_128k_F extends RealTempBucketTest_ {
  RealTempBucketTest_64k_128k_F() throws IOException {
    super(64 * 1024, 128 * 1024, false);
  }
}

@SuppressWarnings({"java:S101", "NewClassNamingConvention"})
class RealTempBucketTest_8_16_T extends RealTempBucketTest_ {
  RealTempBucketTest_8_16_T() throws IOException {
    super(8, 16, true);
  }
}

@SuppressWarnings({"java:S101", "NewClassNamingConvention"})
class RealTempBucketTest_64k_128k_T extends RealTempBucketTest_ {
  RealTempBucketTest_64k_128k_T() throws IOException {
    super(64 * 1024, 128 * 1024, true);
  }
}

@SuppressWarnings({"java:S2245", "java:S101", "NewClassNamingConvention"})
class RealTempBucketTest_ extends BucketTestBase {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  RealTempBucketTest_(int maxRamSize, int maxTotalRamSize, boolean encrypted) throws IOException {
    RandomSource weakPRNG = new DummyRandomSource(54321);
    FilenameGenerator fg = new FilenameGenerator(weakPRNG, false, null, "junit");
    PriorityAwareExecutor exec = new SerialExecutor(NativeThread.PriorityLevel.NORM_PRIORITY.value);
    tbf =
        new TempBucketFactory(
            exec, fg, maxRamSize, maxTotalRamSize, encrypted, MIN_DISK_SPACE, SECRET);

    canOverwrite = false;
  }

  @Override
  protected void freeBucket(Bucket bucket) {
    bucket.free();
  }

  @Override
  protected Bucket makeBucket(long size) throws IOException {
    return tbf.makeBucket(1); // TempBucket allows resize
  }

  // no-op: remove unused strongPRNG to satisfy SonarLint
  private final TempBucketFactory tbf;
  private static final MasterSecret SECRET = new MasterSecret();
  private static final long MIN_DISK_SPACE = 2L * 1024 * 1024;
}
