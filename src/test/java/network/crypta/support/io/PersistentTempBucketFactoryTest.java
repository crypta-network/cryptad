package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import network.crypta.crypt.EncryptedRandomAccessBucket;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PersistentTempBucketFactoryTest {

  @TempDir Path tempDir;

  private static final String PREFIX = "ptbf-";

  private static SecureRandom seededSecureRandom(long seed) throws NoSuchAlgorithmException {
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    random.setSeed(seed);
    return random;
  }

  @Test
  void constructor_whenDirectoryMissingParent_expectIOException() {
    // Arrange
    File missingParentDir = tempDir.resolve("missing-parent").resolve("child").toFile();

    // Act & Assert
    assertThrows(
        IOException.class,
        () ->
            new PersistentTempBucketFactory(
                missingParentDir, PREFIX, seededSecureRandom(1L), false));
  }

  @Test
  void constructor_whenDirectoryIsFile_expectIOException() throws Exception {
    // Arrange
    Path filePath = Files.createFile(tempDir.resolve("not-a-dir"));

    // Act & Assert
    assertThrows(
        IOException.class,
        () ->
            new PersistentTempBucketFactory(
                filePath.toFile(), PREFIX, seededSecureRandom(2L), false));
  }

  @Test
  void registerAndCompletedInit_whenUnclaimedFilesExist_deletesOnlyUnregistered() throws Exception {
    // Arrange
    Path dir = Files.createDirectory(tempDir.resolve("ptbf"));
    Path keepFile = Files.createFile(dir.resolve(PREFIX + "keep"));
    Path deleteFile = Files.createFile(dir.resolve(PREFIX + "delete"));
    Path otherFile = Files.createFile(dir.resolve("other"));
    Files.createDirectory(dir.resolve(PREFIX + "dir"));

    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(dir.toFile(), PREFIX, seededSecureRandom(3L), false);

    // Act
    factory.register(keepFile.toFile());
    factory.completedInit();

    // Assert
    assertTrue(Files.exists(keepFile), "Registered file should be retained");
    assertFalse(Files.exists(deleteFile), "Unregistered prefixed file should be deleted");
    assertTrue(Files.exists(otherFile), "Non-prefixed file should be retained");
    assertTrue(Files.isDirectory(dir.resolve(PREFIX + "dir")), "Directories should be retained");
  }

  @Test
  void register_whenCompletedInitAlreadyCalled_throwsIllegalStateException() throws Exception {
    // Arrange
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(4L), false);
    factory.completedInit();
    Path file = Files.createFile(tempDir.resolve(PREFIX + "late"));
    File lateFile = file.toFile();

    // Act & Assert
    assertThrows(IllegalStateException.class, () -> factory.register(lateFile));
  }

  @Test
  void makeBucket_whenEncryptionDisabled_returnsDelayedFreeWithPersistentTempFileBucket()
      throws Exception {
    // Arrange
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(5L), false);

    // Act
    RandomAccessBucket bucket = factory.makeBucket(128);

    // Assert
    DelayedFreeRandomAccessBucket wrapper =
        assertInstanceOf(DelayedFreeRandomAccessBucket.class, bucket);
    PersistentTempFileBucket underlying =
        assertInstanceOf(PersistentTempFileBucket.class, wrapper.getUnderlying());
    assertTrue(underlying.getFile().exists(), "Backing file should exist");
    assertEquals(
        tempDir.toRealPath(),
        underlying.getFile().getParentFile().toPath().toRealPath(),
        "File should live in temp dir");
  }

  @Test
  void makeBucket_whenEncryptionEnabled_wrapsEncryptedAndPaddedBucket() throws Exception {
    // Arrange
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(6L), true);
    factory.setMasterSecret(new MasterSecret(new byte[64]));

    // Act
    RandomAccessBucket bucket = factory.makeBucket(256);

    // Assert
    DelayedFreeRandomAccessBucket wrapper =
        assertInstanceOf(DelayedFreeRandomAccessBucket.class, bucket);
    EncryptedRandomAccessBucket encrypted =
        assertInstanceOf(EncryptedRandomAccessBucket.class, wrapper.getUnderlying());
    PaddedRandomAccessBucket padded =
        assertInstanceOf(PaddedRandomAccessBucket.class, encrypted.getUnderlying());
    PersistentTempFileBucket base =
        assertInstanceOf(PersistentTempFileBucket.class, padded.getUnderlying());
    assertTrue(base.getFile().exists(), "Backing file should exist for encrypted bucket");
  }

  @Test
  void delayedFree_whenCommitIdMatches_callsRealFreeImmediately() throws Exception {
    // Arrange
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(7L), false);
    DelayedFree bucket = mock(DelayedFree.class);

    // Act
    factory.delayedFree(bucket, factory.commitID());

    // Assert
    verify(bucket).realFree();
    DelayedFree[] queued = factory.grabBucketsToFree();
    assertNotNull(queued, "No buckets should be queued");
    assertEquals(0, queued.length, "No buckets should be queued");
  }

  @Test
  void delayedFree_whenCommitIdDiffers_queuesAndGrabBucketsToFreeAdvancesCommitId()
      throws Exception {
    // Arrange
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(8L), false);
    DelayedFree bucket = mock(DelayedFree.class);
    long originalCommit = factory.commitID();

    // Act
    factory.delayedFree(bucket, 0L);
    DelayedFree[] queued = factory.grabBucketsToFree();

    // Assert
    verify(bucket, never()).realFree();
    assertNotNull(queued, "Queued buckets should be returned");
    assertEquals(1, queued.length, "Exactly one bucket should be queued");
    assertEquals(bucket, queued[0], "Queued bucket should be the original instance");
    assertEquals(originalCommit + 1, factory.commitID(), "Commit ID should advance after grab");
  }

  @Test
  void grabBucketsToFree_whenEmpty_returnsEmptyArray() throws Exception {
    // Arrange
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(9L), false);

    // Act
    DelayedFree[] queued = factory.grabBucketsToFree();

    // Assert
    assertNotNull(queued);
    assertEquals(0, queued.length);
  }

  @Test
  void finishDelayedFree_whenToFreeFalse_skipsRealFree() throws Exception {
    // Arrange
    DelayedFree bucket = mock(DelayedFree.class);
    when(bucket.toFree()).thenReturn(false);
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(10L), false);

    // Act
    factory.finishDelayedFree(new DelayedFree[] {bucket});

    // Assert
    verify(bucket, never()).realFree();
  }

  @Test
  void finishDelayedFree_whenRealFreeThrows_doesNotPropagate() throws Exception {
    // Arrange
    DelayedFree bucket = mock(DelayedFree.class);
    when(bucket.toFree()).thenReturn(true);
    RuntimeException failure = new RuntimeException("boom");
    doThrow(failure).when(bucket).realFree();
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(11L), false);

    // Act & Assert
    assertDoesNotThrow(() -> factory.finishDelayedFree(new DelayedFree[] {bucket}));
  }

  @Test
  void checkDiskSpace_whenCheckerSet_delegatesToChecker() throws Exception {
    // Arrange
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(13L), false);
    DiskSpaceChecker checker = mock(DiskSpaceChecker.class);
    factory.setDiskSpaceChecker(checker);
    File target = tempDir.resolve("target").toFile();
    when(checker.checkDiskSpace(target, 10, 4096)).thenReturn(true);

    // Act
    boolean allowed = factory.checkDiskSpace(target, 10, 4096);

    // Assert
    assertTrue(allowed);
    verify(checker).checkDiskSpace(target, 10, 4096);
  }

  @Test
  void setEncryption_whenToggled_updatesIsEncrypting() throws Exception {
    // Arrange
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(12L), false);

    // Act
    factory.setEncryption(true);

    // Assert
    assertTrue(factory.isEncrypting());
  }

  @Test
  void getGenerator_whenViewedThroughTracker_returnsPersistentFilenameGeneratorContract()
      throws Exception {
    // Arrange
    PersistentTempBucketFactory factory =
        new PersistentTempBucketFactory(tempDir.toFile(), PREFIX, seededSecureRandom(14L), false);
    //noinspection UnnecessaryLocalVariable
    PersistentFileTracker tracker = factory;
    long id = 0x14L;

    // Act
    PersistentFilenameGenerator generator = tracker.getGenerator();

    // Assert
    assertEquals(factory.fg.getFilename(id), generator.getFilename(id));
  }
}
