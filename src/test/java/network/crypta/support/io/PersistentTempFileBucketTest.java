package network.crypta.support.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Path;
import java.security.SecureRandom;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class PersistentTempFileBucketTest {

  @TempDir Path tempDir;

  private FilenameGenerator generator;

  @Mock private PersistentTempBucketFactory trackerMock; // also implements PersistentFileTracker

  private AutoCloseable mocks;

  @BeforeEach
  void setUp() throws Exception {
    mocks = MockitoAnnotations.openMocks(this);
    // Deterministic generator and directory inside the JUnit-managed temp dir
    generator = new FilenameGenerator(seededSecureRandom(12345L), false, tempDir.toFile(), "ptfb-");
  }

  @AfterEach
  void tearDown() throws Exception {
    if (mocks != null) mocks.close();
  }

  private static SecureRandom seededSecureRandom(long seed)
      throws java.security.NoSuchAlgorithmException {
    SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
    sr.setSeed(seed);
    return sr;
  }

  private static AutoFree autoClose(PersistentTempFileBucket bucket) {
    return new AutoFree(bucket);
  }

  private static final class AutoFree implements AutoCloseable {
    private final PersistentTempFileBucket bucket;

    private AutoFree(PersistentTempFileBucket bucket) {
      this.bucket = bucket;
    }

    @Override
    public void close() {
      // Force deletion; tests rely on cleanup
      bucket.free(true);
    }
  }

  @Test
  void getOutputStreamUnbuffered_whenCalled_returnsDiskSpaceCheckingOutputStream()
      throws Exception {
    // Arrange
    long id = generator.makeRandomFilename();
    when(trackerMock.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(true);
    PersistentTempFileBucket bucket = new PersistentTempFileBucket(id, generator, trackerMock);
    try (var _ = autoClose(bucket)) {
      // Act
      OutputStream os = bucket.getOutputStreamUnbuffered();

      // Assert
      assertInstanceOf(
          DiskSpaceCheckingOutputStream.class,
          os,
          "Unbuffered stream must be DiskSpaceCheckingOutputStream");

      // Sanity: write exactly threshold bytes to trigger a single check
      byte[] buf = new byte[PersistentTempFileBucket.BUFFER_SIZE];
      os.write(buf);
      os.close();
      verify(trackerMock, atLeastOnce())
          .checkDiskSpace(
              generator.getFilename(id), buf.length, PersistentTempFileBucket.BUFFER_SIZE);
    }
  }

  @Test
  void getOutputStream_whenCalled_wrapsUnbufferedWithBufferedStream() throws Exception {
    // Arrange
    long id = generator.makeRandomFilename();
    when(trackerMock.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(true);
    PersistentTempFileBucket bucket = new PersistentTempFileBucket(id, generator, trackerMock);
    try (var _ = autoClose(bucket)) {
      // Act & Assert: BufferedOutputStream wraps unbuffered disk-space checking stream.
      try (OutputStream os = bucket.getOutputStream()) {
        assertInstanceOf(
            BufferedOutputStream.class, os, "getOutputStream() should return a buffered stream");
        // Trigger disk-space check once (indirectly validates inner wrapper)
        os.write(new byte[PersistentTempFileBucket.BUFFER_SIZE]);
      }
      verify(trackerMock, atLeastOnce())
          .checkDiskSpace(
              generator.getFilename(id),
              PersistentTempFileBucket.BUFFER_SIZE,
              PersistentTempFileBucket.BUFFER_SIZE);
    }
  }

  @ParameterizedTest
  @ValueSource(ints = {4096, 5000, 8192})
  void write_whenLengthAtOrAboveThreshold_callsCheckerOnce(int len) throws Exception {
    // Arrange
    long id = generator.makeRandomFilename();
    when(trackerMock.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(true);
    PersistentTempFileBucket bucket = new PersistentTempFileBucket(id, generator, trackerMock);
    try (var _ = autoClose(bucket)) {
      // Act
      try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
        os.write(new byte[len]);
      }

      // Assert
      verify(trackerMock, times(1))
          .checkDiskSpace(generator.getFilename(id), len, PersistentTempFileBucket.BUFFER_SIZE);
    }
  }

  @Test
  void write_whenLengthBelowThreshold_doesNotCallChecker() throws Exception {
    // Arrange
    long id = generator.makeRandomFilename();
    // No stubbing needed; should not be called at all
    PersistentTempFileBucket bucket = new PersistentTempFileBucket(id, generator, trackerMock);
    try (var _ = autoClose(bucket)) {
      // Act
      try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
        os.write(new byte[PersistentTempFileBucket.BUFFER_SIZE - 1]);
      }

      // Assert
      verify(trackerMock, never()).checkDiskSpace(any(), anyInt(), anyInt());
    }
  }

  @Test
  void getOutputStreamUnbuffered_whenInsufficientDiskSpace_throwsException_preservesFileLength()
      throws Exception {
    // Arrange
    long id = generator.makeRandomFilename();
    when(trackerMock.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(false);
    PersistentTempFileBucket bucket = new PersistentTempFileBucket(id, generator, trackerMock);
    File file = generator.getFilename(id);
    try (var _ = autoClose(bucket)) {
      // Act / Assert
      try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
        assertThrows(
            InsufficientDiskSpaceException.class,
            () -> os.write(new byte[PersistentTempFileBucket.BUFFER_SIZE]),
            "Should throw when disk space checker rejects write at threshold");
      }

      // File should exist but be empty (the write never reaches the underlying stream)
      assertTrue(file.exists(), "File should exist after stream creation");
      assertEquals(0L, file.length(), "File length should remain zero on failed write");
    }
  }

  @Test
  void getOutputStreamUnbuffered_whenReadOnly_throwsIOException() throws Exception {
    // Arrange
    long id = generator.makeRandomFilename();
    PersistentTempFileBucket bucket = new PersistentTempFileBucket(id, generator, trackerMock);
    try (var _ = autoClose(bucket)) {
      bucket.setReadOnly();
      // Act / Assert
      assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);
    }
  }

  @Test
  void createShadow_whenFileExists_returnsReadOnlyBucketAndNoDeleteOnFree() throws Exception {
    // Arrange
    long id = generator.makeRandomFilename();
    when(trackerMock.checkDiskSpace(any(), anyInt(), anyInt())).thenReturn(true);
    PersistentTempFileBucket original = new PersistentTempFileBucket(id, generator, trackerMock);
    try (var _ = autoClose(original)) {
      // Create the backing file with some data
      try (OutputStream os = original.getOutputStream()) {
        os.write(new byte[] {1, 2, 3});
      }
      File file = generator.getFilename(id);
      assertTrue(file.exists());

      // Act
      RandomAccessBucket shadow = original.createShadow();

      // Assert
      assertInstanceOf(PersistentTempFileBucket.class, shadow);
      PersistentTempFileBucket shadowBucket = (PersistentTempFileBucket) shadow;
      assertTrue(shadowBucket.isReadOnly(), "Shadow must be read-only");
      assertTrue(shadowBucket.persistent(), "Shadow must be persistent");

      // Freeing the shadow should NOT delete the underlying file
      shadowBucket.free();
      assertTrue(file.exists(), "Shadow.free() must not delete the file");
    }
    File file2 = generator.getFilename(id);
    assertFalse(file2.exists(), "Original.close() should delete the file");
  }

  @Test
  void innerResume_whenCalled_setsTrackerFromContext_andRegistersFile() throws Exception {
    // Arrange
    long id = generator.makeRandomFilename();
    PersistentTempFileBucket bucket = new PersistentTempFileBucket(id, generator, trackerMock);
    try (var _ = autoClose(bucket)) {
      // Build a ClientContext with our generator as persistentFG and a spy tracker
      ClientContext context;

      // Mockito cannot populate context.persistentFileTracker, because ClientContext assigns
      // ptbf to that field internally. So instead, spy a real PersistentTempBucketFactory and use
      // it.
      PersistentTempBucketFactory ptbfSpy =
          spy(
              new PersistentTempBucketFactory(
                  tempDir.toFile(), "ctx-", seededSecureRandom(3), false));

      // Rebuild context with ptbfSpy to ensure persistentFileTracker is our spy and persistentFG is
      // generator
      context =
          new ClientContext(
              0L,
              null,
              null,
              null,
              ptbfSpy,
              null,
              ptbfSpy,
              null,
              null,
              null,
              seededSecureRandom(1),
              null,
              null,
              new FilenameGenerator(seededSecureRandom(2), false, tempDir.toFile(), "trans-"),
              generator,
              null,
              null,
              null,
              null,
              null,
              null,
              null,
              null,
              null,
              null,
              null,
              null);

      // Act
      bucket.innerResume(context);

      // Assert: factory registers the file
      verify(ptbfSpy, times(1)).register(generator.getFilename(id));
    }
  }

  @Test
  void deleteOnExit_whenCalled_returnsFalse() {
    // Arrange
    PersistentTempFileBucket bucket = new PersistentTempFileBucket(55L, generator, trackerMock);
    try (var _ = autoClose(bucket)) {
      // Act & Assert
      assertFalse(bucket.deleteOnExit());
    }
  }

  @Test
  void getPersistentTempID_whenCalled_returnsFilenameID() {
    // Arrange
    long id = 101L;
    PersistentTempFileBucket bucket = new PersistentTempFileBucket(id, generator, trackerMock);
    try (var _ = autoClose(bucket)) {
      // Act & Assert
      assertEquals(id, bucket.getPersistentTempID());
    }
  }

  @Test
  void storeTo_whenWritten_writesSubclassMagic_andRestoresOnLoad() throws Exception {
    // Arrange
    long id = 0xdeadbeefL;
    PersistentTempFileBucket bucket = new PersistentTempFileBucket(id, generator, trackerMock);
    try (var _ = autoClose(bucket)) {
      bucket.setReadOnly(); // capture non-default field as well

      ByteArrayOutputStream bos = new ByteArrayOutputStream();
      try (DataOutputStream dos = new DataOutputStream(bos)) {
        bucket.storeTo(dos);
      }
      byte[] bytes = bos.toByteArray();

      // Act: read back
      try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
        int magic = dis.readInt();
        assertEquals(PersistentTempFileBucket.MAGIC, magic, "First int should be subclass MAGIC");

        PersistentTempFileBucket restored = new PersistentTempFileBucket(dis);

        // Assert: equals() compares id, readOnly, deleteOnFree
        assertEquals(bucket, restored, "Restored bucket should equal the original by value");
        assertEquals(bucket.getFile(), restored.getFile(), "Restored file path should match");

        restored.free(true);
      }
    }
  }

  // --- no helpers ---
}
