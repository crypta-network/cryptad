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
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.io.TempBucketFactory.TempBucket;
import network.crypta.support.io.TempBucketFactory.TempRandomAccessBuffer;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.jetbrains.annotations.NotNull;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for {@link TempBucketFactory} focused on factory-level behavior (selection of
 * RAM/file-backed implementations, thresholds, encryption toggling, and cleaner scheduling). Tests
 * intentionally avoid duplicating the nested class coverage which already exists in
 * TempBucketFactoryTempBucketTest and TempBucketFactoryTempRandomAccessBufferTest.
 */
@SuppressWarnings({"java:S100", "java:S5778", "java:S2245", "java:S5443"})
class TempBucketFactoryTest {

  private static final int SEED = 314159;
  private static final long MIN_DISK_SPACE = 2L * 1024 * 1024; // 2 MiB

  private Path tempDir;
  private FilenameGenerator fg;
  private final MasterSecret secret = new MasterSecret();

  @BeforeAll
  static void registerBC() {
    Security.addProvider(new BouncyCastleProvider());
  }

  @BeforeEach
  void setUp() throws IOException {
    tempDir = Files.createTempDirectory("tbf-factory-junit-");
    fg = new FilenameGenerator(new Random(SEED), false, tempDir.toFile(), "junit-");
  }

  @AfterEach
  void tearDown() throws IOException {
    File dir = tempDir.toFile();
    File[] files = dir.listFiles();
    if (files != null) {
      for (File f : files) {
        try {
          Files.deleteIfExists(f.toPath());
        } catch (IOException _) {
          // best-effort cleanup in tests
        }
      }
    }
    Files.deleteIfExists(tempDir);
  }

  private TempBucketFactory newFactory(
      PriorityAwareExecutor exec, long maxRamBucket, long maxRamUsed, boolean encrypt) {
    return new TempBucketFactory(
        exec, fg, maxRamBucket, maxRamUsed, encrypt, MIN_DISK_SPACE, secret);
  }

  private static PriorityAwareExecutor inlineExecutor() {
    return new PriorityAwareExecutor() {
      @Override
      public void execute(@NotNull Runnable job) {
        job.run();
      }

      @Override
      public void execute(Runnable job, String jobName) {
        job.run();
      }

      @Override
      public void execute(Runnable job, String jobName, boolean fromTicker) {
        job.run();
      }

      @Override
      public int[] waitingThreads() {
        return new int[network.crypta.support.io.NativeThread.JAVA_PRIORITY_RANGE + 1];
      }

      @Override
      public int[] runningThreads() {
        return new int[network.crypta.support.io.NativeThread.JAVA_PRIORITY_RANGE + 1];
      }

      @Override
      public int getWaitingThreadsCount() {
        return 0;
      }
    };
  }

  // ---------------- Factory selection: Bucket ----------------

  @Test
  void makeBucket_whenWithinRamThreshold_returnsTempBucketBackedByRAM() throws IOException {
    // Arrange
    TempBucketFactory f =
        newFactory(inlineExecutor(), /*maxRamBucket*/ 4096, /*maxRamUsed*/ 8192, false);

    // Act + Assert
    try (TempBucket bucket = (TempBucket) f.makeBucket(1024)) {
      assertTrue(bucket.isRAMBucket());
      assertEquals(0, f.getRamUsed(), "RAM usage only increases on write, not on bucket creation");
    }
  }

  @Test
  void makeBucket_whenMaxRamBucketSizeZero_returnsFileBackedBucket() throws IOException {
    // Arrange
    TempBucketFactory f =
        newFactory(inlineExecutor(), /*maxRamBucket*/ 0, /*maxRamUsed*/ 8192, false);

    // Act + Assert
    try (TempBucket bucket = (TempBucket) f.makeBucket(1024)) {
      assertFalse(bucket.isRAMBucket());
    }
  }

  @Test
  void makeBucket_whenMinDiskSpaceTooHigh_throwsInsufficientDiskSpaceException() {
    // Arrange: force file bucket and set minDiskSpace to an impossibly high value
    TempBucketFactory f = newFactory(inlineExecutor(), 0, 8192, false);
    f.setMinDiskSpace(Long.MAX_VALUE / 2);

    // Act + Assert (ensure resource is closed if creation ever succeeds)
    assertThrows(
        InsufficientDiskSpaceException.class,
        () -> {
          try (var _ = (TempBucket) f.makeBucket(4096)) {
            fail("Expected InsufficientDiskSpaceException");
          }
        });
  }

  @Test
  void makeBucket_whenUnknownSize_skipsCreationTimeDiskCheck() throws IOException {
    // Arrange: file bucket path but unknown size should skip the creation-time check
    TempBucketFactory f = newFactory(inlineExecutor(), 0, 8192, false);
    f.setMinDiskSpace(Long.MAX_VALUE / 2);

    // Act
    try (TempBucket bucket = (TempBucket) f.makeBucket(Long.MAX_VALUE)) {
      // Assert: bucket is created (later writes may still fail, which we don't exercise here)
      assertNotNull(bucket);
      assertFalse(bucket.isRAMBucket());
    }
  }

  // ---------------- Factory selection: RAF ----------------

  @Test
  void makeRAF_whenNegativeSize_throwsIllegalArgumentException() {
    // Arrange
    TempBucketFactory f = newFactory(inlineExecutor(), 4096, 8192, false);

    // Act + Assert: wrap in try-with-resources to satisfy static analysis if it ever succeeded
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          try (var _ = f.makeRAF(-1)) {
            fail("Expected IllegalArgumentException");
          }
        });
  }

  @Test
  void makeRAF_whenFitsInRam_returnsTempRandomAccessBuffer() throws IOException {
    // Arrange
    TempBucketFactory f = newFactory(inlineExecutor(), 4096, 8192, false);

    // Act
    try (LockableRandomAccessBuffer rab = f.makeRAF(2048)) {
      // Assert
      assertInstanceOf(TempRandomAccessBuffer.class, rab);
      assertEquals(2048, rab.size());
      rab.free();
    }
  }

  @Test
  void makeRAF_whenRamBudgetZero_returnsFileBackedBuffer() throws IOException {
    // Arrange: zero RAM budget forces file-backed RAF
    TempBucketFactory f = newFactory(inlineExecutor(), 4096, 0, false);

    // Act
    try (LockableRandomAccessBuffer rab = f.makeRAF(1024)) {
      // Assert
      assertInstanceOf(PooledFileRandomAccessBuffer.class, rab);
      rab.free();
    }
  }

  @ParameterizedTest(name = "makeRAF_encrypt={0}_returnsEncryptedWhenFileBacked")
  @ValueSource(booleans = {true, false})
  void makeRAF_whenEncryptionToggled_affectsReturnedTypeForFileBacked(boolean encrypt)
      throws IOException {
    // Arrange: force file path using zero RAM budget
    TempBucketFactory f = newFactory(inlineExecutor(), 4096, 0, encrypt);
    f.setEncryption(encrypt);

    // Act
    try (LockableRandomAccessBuffer rab = f.makeRAF(2048)) {
      // Assert
      if (encrypt) {
        assertInstanceOf(EncryptedRandomAccessBuffer.class, rab);
        assertTrue(f.isEncrypting());
      } else {
        assertInstanceOf(PooledFileRandomAccessBuffer.class, rab);
        assertFalse(f.isEncrypting());
      }
      rab.free();
    }
  }

  @Test
  void makeRAF_initialContents_whenReadOnlyTrue_wrapsReadOnly_andCopiesData() throws IOException {
    // Arrange: force file‑backed path and enable encryption to exercise that branch too
    TempBucketFactory f = newFactory(inlineExecutor(), 4096, 0, true);
    byte[] data = new byte[256];
    new Random(SEED).nextBytes(data);

    // Act
    try (LockableRandomAccessBuffer rab = f.makeRAF(data, 0, data.length, /*readOnly*/ true)) {
      // Assert
      assertInstanceOf(ReadOnlyRandomAccessBuffer.class, rab);
      byte[] out = new byte[data.length];
      rab.pread(0, out, 0, out.length);
      assertArrayEquals(data, out);
      rab.free();
    }
  }

  // ---------------- Thresholds and cleaner scheduling ----------------

  @Test
  void cleaner_whenUsageCrossesHighThreshold_migratesUntilBelowLowThreshold() throws IOException {
    // Arrange: mock Executor to run jobs inline and verify scheduling
    PriorityAwareExecutor exec = mock(PriorityAwareExecutor.class);
    doAnswer(
            inv -> {
              Runnable r = inv.getArgument(0);
              r.run();
              return null;
            })
        .when(exec)
        .execute(any(Runnable.class));

    // 2 RAM buffers of 512 bytes each, maxRamUsed=1024 => crosses 0.9*1024 and triggers cleaner,
    // which should migrate one buffer until usage <= 0.8*1024
    TempBucketFactory f = newFactory(exec, /*maxRamBucket*/ 1024, /*maxRamUsed*/ 1024, false);

    try (TempRandomAccessBuffer rab1 = (TempRandomAccessBuffer) f.makeRAF(512);
        TempRandomAccessBuffer rab2 = (TempRandomAccessBuffer) f.makeRAF(512)) {
      // Assert: exactly one migrated and RAM usage reduced to 512
      assertTrue(rab1.hasMigrated() ^ rab2.hasMigrated(), "Cleaner should migrate exactly one RAB");
      assertEquals(512, f.getRamUsed());

      rab1.free();
      rab2.free();
    }
  }

  // ---------------- Underlying RAFFactory propagation ----------------

  @Test
  void setMinDiskSpace_whenRaised_blocksUnderlyingRAFFactoryAllocations() {
    // Arrange: use file‑backed path for RAFFactory checks
    TempBucketFactory f = newFactory(inlineExecutor(), 4096, 0, false);
    f.setMinDiskSpace(Long.MAX_VALUE / 2);

    // Act + Assert: RAFFactory should respect the new threshold; wrap in try-with-resources in case
    // it erroneously succeeds in another environment.
    assertThrows(
        InsufficientDiskSpaceException.class,
        () -> {
          try (var _ = f.getUnderlyingRAFFactory().makeRAF(1)) {
            fail("Expected InsufficientDiskSpaceException");
          }
        });
  }
}
