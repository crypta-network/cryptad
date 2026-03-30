package network.crypta.support.io;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Random;
import network.crypta.client.async.ClientContext;
import network.crypta.client.async.ClientContextDefaults;
import network.crypta.client.async.ClientContextRafFactories;
import network.crypta.client.async.ClientContextResources;
import network.crypta.client.async.ClientContextRuntime;
import network.crypta.client.async.ClientContextServices;
import network.crypta.client.async.ClientContextStorageFactories;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.ResumeContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class TempFileBucketTest extends BucketTestBase {

  @TempDir Path tempDir;

  private AutoCloseable mocks;

  @Mock private FilenameGenerator generatorMock;

  @BeforeEach
  void setUp() {
    mocks = MockitoAnnotations.openMocks(this);
  }

  @AfterEach
  void tearDown() throws Exception {
    if (mocks != null) mocks.close();
  }

  // ---- BucketTestBase contract ----

  @Override
  protected Bucket makeBucket(long size) throws IOException {
    FilenameGenerator filenameGenerator = new FilenameGenerator(weakPRNG, false, null, "junit");
    BaseFileBucket bfb =
        new TempFileBucket(filenameGenerator.makeRandomFilename(), filenameGenerator);

    assertTrue(bfb.deleteOnFree(), "deleteOnFree");

    return bfb;
  }

  @Override
  protected void freeBucket(Bucket bucket) {
    File file = ((BaseFileBucket) bucket).getFile();
    if (bucket.size() != 0) {
      assertTrue(file.exists(), "TempFile not exist");
    }
    bucket.free();
    assertFalse(file.exists(), "TempFile not deleted");
  }

  private final Random weakPRNG = new Random(12345);

  private static SecureRandom seededSecureRandom(long seed)
      throws java.security.NoSuchAlgorithmException {
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    sr.setSeed(seed);
    return sr;
  }

  // ---- Additional TempFileBucket-specific tests (AAA style) ----

  @Test
  void constructor_whenGeneratorNull_throwsNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> {
          try (var _ = new TempFileBucket(1L, null)) {
            fail("unreachable");
          }
        });
  }

  @Test
  void deleteOnExit_whenCalled_returnsFalse() throws Exception {
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(1), false, tempDir.toFile(), "tfb-");
    try (TempFileBucket bucket = new TempFileBucket(gen.makeRandomFilename(), gen)) {
      assertFalse(bucket.deleteOnExit());
    }
  }

  @Test
  void createFileOnly_whenCalled_returnsFalse() throws Exception {
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(2), false, tempDir.toFile(), "tfb-");
    try (TempFileBucket bucket = new TempFileBucket(gen.makeRandomFilename(), gen)) {
      assertFalse(bucket.createFileOnly());
    }
  }

  @Test
  void tempFileAlreadyExists_whenCalled_returnsTrue() throws Exception {
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(3), false, tempDir.toFile(), "tfb-");
    try (TempFileBucket bucket = new TempFileBucket(gen.makeRandomFilename(), gen)) {
      assertTrue(bucket.tempFileAlreadyExists());
    }
  }

  @Test
  void setReadOnly_whenCalled_setsFlagAndPreventsWrites() throws Exception {
    // Arrange
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(4), false, tempDir.toFile(), "tfb-");
    try (TempFileBucket bucket = new TempFileBucket(gen.makeRandomFilename(), gen)) {
      // Act
      bucket.setReadOnly();

      // Assert
      assertTrue(bucket.isReadOnly());
      assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);
    }
  }

  @Test
  void createShadow_whenFileExists_returnsReadOnlyAndDoesNotDeleteOnFree() throws Exception {
    // Arrange
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(5), false, tempDir.toFile(), "tfb-");
    long id = gen.makeRandomFilename();
    try (TempFileBucket original = new TempFileBucket(id, gen)) {
      // Create some content so the file exists and is non-empty
      try (OutputStream os = original.getOutputStream()) {
        os.write(new byte[] {1, 2, 3});
      }
      File file = gen.getFilename(id);
      assertTrue(file.exists());

      // Act
      try (RandomAccessBucket shadow = original.createShadow()) {
        // Assert
        assertInstanceOf(TempFileBucket.class, shadow, "Shadow must be a TempFileBucket");
        TempFileBucket shadowBucket = (TempFileBucket) shadow;
        assertTrue(shadowBucket.isReadOnly(), "Shadow must be read-only");
      }
      // Shadow closed; the file should still exist
      assertTrue(file.exists(), "Shadow.close() must not delete the file");
    }
    File file2 = gen.getFilename(id);
    assertFalse(file2.exists(), "Original.close() should delete the file");
  }

  @Test
  void getOutputStreamUnbuffered_whenBackingFileMissing_throwsFileDoesNotExistException()
      throws Exception {
    // Arrange
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(6), false, tempDir.toFile(), "tfb-");
    long id = gen.makeRandomFilename();
    File file = gen.getFilename(id);
    assertTrue(file.delete(), "Setup should delete the file");
    try (TempFileBucket bucket = new TempFileBucket(id, gen)) {
      // Act / Assert
      assertThrows(FileDoesNotExistException.class, bucket::getOutputStreamUnbuffered);
    }
  }

  @Test
  void onResume_whenNotPersistent_throwsUnsupportedOperationException() throws Exception {
    // Arrange
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(7), false, tempDir.toFile(), "tfb-");
    try (TempFileBucket bucket = new TempFileBucket(gen.makeRandomFilename(), gen)) {
      // Act / Assert
      assertThrows(UnsupportedOperationException.class, () -> bucket.onResume(null));
    }
  }

  @Test
  void innerResume_whenFileIsNull_setsGeneratorAndEnsuresFileExists() throws Exception {
    // Arrange: construct a bucket as if deserialized from an old format (the file is null)
    long id = 0xabcdeL;
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(8), false, tempDir.toFile(), "tfb-");

    ClientContext context =
        new ClientContext(
            0L,
            new ClientContextRuntime(null, null, null, null, null, seededSecureRandom(1), null),
            new ClientContextStorageFactories(
                null,
                null,
                null,
                new FilenameGenerator(seededSecureRandom(2), false, tempDir.toFile(), "trans-"),
                gen,
                null,
                null),
            new ClientContextRafFactories(null, null),
            new ClientContextServices(
                new ClientContextResources(null, null), null, null, null, null, null),
            new ClientContextDefaults(null, null, null));

    try (TempFileBucket bucket = new TempFileBucket()) {
      bucket.filenameID = id; // package-private field, same package
      // Act
      bucket.innerResume(context);

      // Assert
      File expected = gen.getFilename(id);
      assertEquals(expected, bucket.getFile());
      assertTrue(expected.exists(), "File should be created by innerResume");
      // Ensure cleanup even though deleteOnFree=false for default-constructed bucket
      bucket.free(true);
    }
  }

  @Test
  void innerResume_whenFilePresent_callsMaybeMoveOnGenerator() throws Exception {
    // Arrange
    FilenameGenerator realGen =
        new FilenameGenerator(seededSecureRandom(9), false, tempDir.toFile(), "tfb-");
    FilenameGenerator spyGen = spy(realGen);
    long id = spyGen.makeRandomFilename();

    try (TempFileBucket bucket = new TempFileBucket(id, spyGen)) {
      // ensure the backing file exists
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(new byte[] {42});
      }

      ClientContext context =
          new ClientContext(
              0L,
              new ClientContextRuntime(null, null, null, null, null, seededSecureRandom(10), null),
              new ClientContextStorageFactories(
                  null,
                  null,
                  null,
                  new FilenameGenerator(seededSecureRandom(11), false, tempDir.toFile(), "trans-"),
                  spyGen,
                  null,
                  null),
              new ClientContextRafFactories(null, null),
              new ClientContextServices(
                  new ClientContextResources(null, null), null, null, null, null, null),
              new ClientContextDefaults(null, null, null));

      // Act
      bucket.innerResume(context);

      // Assert: maybeMove must be invoked for a non-null file path
      verify(spyGen, times(1)).maybeMove(any(File.class), Mockito.eq(id));
    }
  }

  @Test
  void innerResume_whenResumeContextExposesPersistentFilenameGenerator_usesInterfaceContract()
      throws Exception {
    // Arrange
    long id = 0x55L;
    File original = tempDir.resolve("original.tmp").toFile();
    assertTrue(original.createNewFile(), "Setup should create the original file");

    PersistentFilenameGenerator initialGenerator = Mockito.mock(PersistentFilenameGenerator.class);
    Mockito.when(initialGenerator.getFilename(id)).thenReturn(original);

    try (TempFileBucket bucket = new TempFileBucket(id, initialGenerator)) {
      File relocated = tempDir.resolve("relocated.tmp").toFile();
      assertTrue(relocated.createNewFile(), "Setup should create the relocated file");

      PersistentFilenameGenerator resumedGenerator =
          Mockito.mock(PersistentFilenameGenerator.class);
      Mockito.when(resumedGenerator.maybeMove(original, id)).thenReturn(relocated);

      ResumeContext context = Mockito.mock(ResumeContext.class);
      Mockito.when(context.getPersistentFilenameGenerator()).thenReturn(resumedGenerator);

      // Act
      bucket.innerResume(context);

      // Assert
      assertEquals(relocated, bucket.getFile());
      Mockito.verify(resumedGenerator, times(1)).maybeMove(original, id);
    }
  }

  @Test
  void innerResume_whenCannotCreateFile_throwsResumeFailedException() throws Exception {
    // Arrange: file=null path points to non-existent parent so createNewFile fails
    try (TempFileBucket bucket = new TempFileBucket()) {
      bucket.filenameID = 123L;
      File badPath = tempDir.resolve("no-such-dir").resolve("badfile").toFile();
      Mockito.when(generatorMock.getFilename(123L)).thenReturn(badPath);

      ClientContext context =
          new ClientContext(
              0L,
              new ClientContextRuntime(null, null, null, null, null, seededSecureRandom(12), null),
              new ClientContextStorageFactories(
                  null,
                  null,
                  null,
                  new FilenameGenerator(seededSecureRandom(13), false, tempDir.toFile(), "trans-"),
                  generatorMock,
                  null,
                  null),
              new ClientContextRafFactories(null, null),
              new ClientContextServices(
                  new ClientContextResources(null, null), null, null, null, null, null),
              new ClientContextDefaults(null, null, null));

      // Act / Assert
      assertThrows(ResumeFailedException.class, () -> bucket.innerResume(context));
    }
  }

  @Test
  void storeTo_whenCalledOnBaseTempFileBucket_throwsUnsupportedOperationException()
      throws Exception {
    // Arrange
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(14), false, tempDir.toFile(), "tfb-");
    try (TempFileBucket bucket = new TempFileBucket(gen.makeRandomFilename(), gen)) {
      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      DataOutputStream dos = new DataOutputStream(bos);

      // Act / Assert
      assertThrows(UnsupportedOperationException.class, () -> bucket.storeTo(dos));
    }
  }

  @Test
  void equals_whenSameIdAndFlags_returnsTrue_andHashCodesMatch() throws Exception {
    // Arrange
    FilenameGenerator gen1 =
        new FilenameGenerator(seededSecureRandom(15), false, tempDir.toFile(), "a-");
    FilenameGenerator gen2 =
        new FilenameGenerator(seededSecureRandom(16), false, tempDir.toFile(), "b-");
    long id = gen1.makeRandomFilename();
    try (TempFileBucket b1 = new TempFileBucket(id, gen1);
        TempFileBucket b2 = new TempFileBucket(id, gen2)) {
      // Act & Assert
      assertEquals(b1, b2);
      assertEquals(b1.hashCode(), b2.hashCode());
    }
  }

  @Test
  void equals_whenDifferentIdOrFlags_returnsFalse() throws Exception {
    // Arrange
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(17), false, tempDir.toFile(), "tfb-");
    long id1 = gen.makeRandomFilename();
    long id2 = gen.makeRandomFilename();
    try (TempFileBucket b1 = new TempFileBucket(id1, gen);
        TempFileBucket b2 = new TempFileBucket(id2, gen);
        TempFileBucket b3 = new TempFileBucket(id1, gen)) {
      b3.setReadOnly();
      try (RandomAccessBucket b4 = b1.createShadow()) {
        assertNotEquals(b1, b2, "Different ids should not be equal");
        assertNotEquals(b1, b3, "Different readOnly flag should not be equal");
        assertNotEquals(b1, b4, "Different deleteOnFree flag should not be equal");
      }
    }
  }

  @Test
  void getFile_whenFileIsNull_usesGeneratorFilename() throws Exception {
    // Arrange
    long id = 0x12345L;
    FilenameGenerator gen =
        new FilenameGenerator(seededSecureRandom(18), false, tempDir.toFile(), "tfb-");
    // emulate deserialized state: generator set, but the file is null
    try (TempFileBucket bucket = new TempFileBucket()) {
      bucket.filenameID = id;
      bucket.generator = gen;
      // Act
      File f = bucket.getFile();

      // Assert
      assertEquals(gen.getFilename(id), f);
    }
  }
}
