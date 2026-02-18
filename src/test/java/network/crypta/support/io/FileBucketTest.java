package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.stream.Stream;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link FileBucket} covering construction, flags, I/O behaviors, serialization format,
 * equality contracts, and error paths.
 */
class FileBucketTest {

  @TempDir File tempDir;

  // -----------------------------
  // Constructor and basic flags
  // -----------------------------

  @Test
  void constructor_whenNullFile_expectNullPointerException() {
    assertThrows(
        NullPointerException.class,
        () -> {
          //noinspection EmptyTryBlock
          try (var _ = new FileBucket(null, false, false, false, false)) {
            // no-op
          }
        });
  }

  @Test
  void getFile_whenConstructedWithRelativePath_expectAbsoluteFile() {
    File relative = new File("subdir/../" + System.nanoTime() + "-bucket.dat");
    try (FileBucket bucket = new FileBucket(relative, false, false, false, false)) {
      File returned = bucket.getFile();
      assertNotNull(returned);
      assertTrue(returned.isAbsolute(), "getFile should be absolute");
      assertEquals(relative.getAbsoluteFile(), returned.getAbsoluteFile());
      assertFalse(bucket.isReadOnly());
      assertFalse(bucket.createFileOnly());
      assertFalse(bucket.deleteOnExit());
      assertFalse(bucket.deleteOnFree());
    }
  }

  @Test
  void setReadOnly_whenCalled_thenGetOutputStreamThrowsIOException() {
    File target = new File(tempDir, "ro.dat");
    try (FileBucket bucket = new FileBucket(target, false, false, false, true)) {
      bucket.setReadOnly();
      assertTrue(bucket.isReadOnly());
      assertThrows(IOException.class, bucket::getOutputStream);
    }
  }

  // -----------------------------
  // createFileOnly behaviors
  // -----------------------------

  @Test
  void createFileOnly_whenFileAlreadyExists_expectFileExistsException() throws Exception {
    File target = new File(tempDir, "exists.dat");
    Files.write(target.toPath(), new byte[] {1}); // pre-create

    try (FileBucket bucket = new FileBucket(target, false, true, false, true)) {
      assertTrue(bucket.createFileOnly());
      assertThrows(FileExistsException.class, bucket::getOutputStreamUnbuffered);
    }
  }

  @Test
  void createFileOnly_whenFileAbsentAndWriteTwice_expectOverwriteAllowed() throws Exception {
    File target = new File(tempDir, "fresh.dat");
    try (FileBucket bucket = new FileBucket(target, false, true, false, false)) {
      // First write: file did not exist, should succeed.
      try (OutputStream os = bucket.getOutputStream()) {
        os.write("abc".getBytes(StandardCharsets.UTF_8));
      }
      assertEquals(3, bucket.size());

      // Second write: allowed despite createFileOnly()==true (see fileRestartCounter logic).
      try (OutputStream os = bucket.getOutputStream()) {
        os.write("XY".getBytes(StandardCharsets.UTF_8));
      }
      assertEquals(2, bucket.size());
    }
  }

  // -----------------------------
  // Deletion policies
  // -----------------------------

  @Test
  void free_whenDeleteOnFreeTrue_expectFileDeleted() throws Exception {
    File target = new File(tempDir, "delete-true.dat");
    try (FileBucket bucket = new FileBucket(target, false, false, false, true)) {
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(42);
      }
      assertTrue(target.exists());
    }
    assertFalse(target.exists());
  }

  @Test
  void free_whenDeleteOnFreeFalse_expectFilePreserved() throws Exception {
    File target = new File(tempDir, "delete-false.dat");
    try (FileBucket bucket = new FileBucket(target, false, false, false, false)) {
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(7);
      }
      assertTrue(target.exists());
    }
    assertTrue(target.exists());
    // cleanup
    assertTrue(target.delete());
  }

  @Test
  void free_whenForceFree_expectFileDeletedRegardlessOfFlag() throws Exception {
    File target = new File(tempDir, "force-free.dat");
    try (FileBucket bucket = new FileBucket(target, false, false, false, false)) {
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(1);
      }
      assertTrue(target.exists());
      // Force deletion regardless of deleteOnFree flag
      bucket.free(true);
    }
    assertFalse(target.exists());
  }

  // -----------------------------
  // Shadow and read-only
  // -----------------------------

  @Test
  void createShadow_whenCalled_expectReadOnlyAndSamePath() {
    File target = new File(tempDir, "shadow.dat");
    try (FileBucket bucket = new FileBucket(target, false, false, false, false);
        RandomAccessBucket shadow = bucket.createShadow()) {
      assertNotNull(shadow);
      assertTrue(shadow.isReadOnly());
      assertNotNull(bucket.getFile());
      assertEquals(
          bucket.getFile().getAbsolutePath(), ((FileBucket) shadow).getFile().getAbsolutePath());
      assertFalse(((FileBucket) shadow).createFileOnly());
      assertFalse(((FileBucket) shadow).deleteOnExit());
      assertFalse(((FileBucket) shadow).deleteOnFree());
    }
  }

  @Test
  void toRandomAccessBuffer_whenEmpty_expectIOException() {
    File target = new File(tempDir, "empty.dat");
    try (FileBucket bucket = new FileBucket(target, false, false, false, false)) {
      assertThrows(IOException.class, bucket::toRandomAccessBuffer);
    }
  }

  // -----------------------------
  // Serialization format
  // -----------------------------

  static Stream<Arguments> storeToFlagCombos() {
    return Stream.of(
        Arguments.of(false, false, false),
        Arguments.of(false, true, false),
        Arguments.of(true, false, false),
        Arguments.of(true, true, false));
  }

  @ParameterizedTest
  @MethodSource("storeToFlagCombos")
  void storeTo_whenCalled_writesExpectedHeaderAndFields(
      boolean readOnly, boolean createFileOnly, boolean deleteOnFree) throws Exception {
    File target =
        new File(
            tempDir, "persist-" + readOnly + "-" + createFileOnly + "-" + deleteOnFree + ".dat");
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    String expectedPath;
    try (FileBucket bucket =
        new FileBucket(target, readOnly, createFileOnly, false, deleteOnFree)) {
      assertNotNull(bucket.getFile());
      expectedPath = bucket.getFile().toString();
      try (DataOutputStream dos = new DataOutputStream(baos)) {
        bucket.storeTo(dos);
      }
    }

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      assertEquals(FileBucket.MAGIC, dis.readInt(), "outer magic");
      assertEquals(BaseFileBucket.MAGIC, dis.readInt(), "base magic");
      assertEquals(1, dis.readInt(), "base version");
      assertFalse(dis.readBoolean(), "freed flag");
      assertEquals(FileBucket.VERSION, dis.readInt(), "filebucket version");
      assertEquals(expectedPath, dis.readUTF(), "path");
      assertEquals(readOnly, dis.readBoolean(), "readOnly");
      assertEquals(deleteOnFree, dis.readBoolean(), "deleteOnFree");
      assertEquals(createFileOnly, dis.readBoolean(), "createFileOnly");
    }
  }

  @Test
  void storeTo_whenDeleteOnExitTrue_expectIllegalStateException() throws Exception {
    File target = new File(tempDir, "deleteOnExit.dat");
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (FileBucket bucket = new FileBucket(target, false, false, true, false);
        DataOutputStream dos = new DataOutputStream(baos)) {
      assertThrows(IllegalStateException.class, () -> bucket.storeTo(dos));
    }
  }

  @Test
  void constructor_whenDeserializing_expectFieldsRestored() throws Exception {
    File target = new File(tempDir, "restore.dat");
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (FileBucket original = new FileBucket(target, true, true, false, true)) {
      // Serialize using FileBucket.storeTo()
      try (DataOutputStream dos = new DataOutputStream(baos)) {
        original.storeTo(dos);
      }
      byte[] all = baos.toByteArray();
      // Skip the outer FileBucket.MAGIC to simulate a type-aware loader.
      try (DataInputStream dis2 =
          new DataInputStream(
              new ByteArrayInputStream(all, Integer.BYTES, all.length - Integer.BYTES))) {
        try (FileBucket restored = new FileBucket(dis2)) {
          assertNotNull(restored.getFile());
          assertNotNull(original.getFile());
          assertEquals(original.getFile().getAbsoluteFile(), restored.getFile().getAbsoluteFile());
          assertTrue(restored.isReadOnly());
          assertTrue(restored.createFileOnly());
          assertTrue(restored.deleteOnFree());
          assertFalse(restored.deleteOnExit());
        }
      }
    }
  }

  // -----------------------------
  // Equality and hashCode
  // -----------------------------

  static Stream<Arguments> equalityPairs() {
    return Stream.of(
        Arguments.of(
            new boolean[] {false, false, false}, new boolean[] {false, false, false}, true),
        Arguments.of(new boolean[] {true, false, false}, new boolean[] {true, false, false}, true),
        Arguments.of(new boolean[] {true, true, false}, new boolean[] {true, false, false}, false),
        Arguments.of(
            new boolean[] {false, false, true}, new boolean[] {false, false, false}, false));
  }

  @ParameterizedTest
  @MethodSource("equalityPairs")
  void equalsHashCode_whenCompared_expectContract(
      boolean[] aFlags, boolean[] bFlags, boolean expectedEqual) {
    File path = new File(tempDir, "eq.dat");
    try (FileBucket a = new FileBucket(path, aFlags[0], aFlags[1], aFlags[2], false);
        FileBucket b =
            new FileBucket(new File(path.getPath()), bFlags[0], bFlags[1], bFlags[2], false)) {
      assertEquals(expectedEqual, a.equals(b));
      assertEquals(expectedEqual, b.equals(a));
      if (expectedEqual) {
        assertEquals(a.hashCode(), b.hashCode());
      }
    }
  }

  @Test
  void equalsHashCode_whenDifferentPath_expectNotEqual() {
    File aPath = new File(tempDir, "a.dat");
    File bPath = new File(tempDir, "b.dat");
    try (FileBucket a = new FileBucket(aPath, false, false, false, false);
        FileBucket b = new FileBucket(bPath, false, false, false, false)) {
      assertNotEquals(a, b);
    }
  }

  // -----------------------------
  // Protected hooks and resume
  // -----------------------------

  @Test
  void tempFileAlreadyExists_whenCalled_expectFalse() {
    try (FileBucket bucket =
        new FileBucket(new File(tempDir, "probe.dat"), false, false, false, false)) {
      assertFalse(bucket.tempFileAlreadyExists());
    }
  }

  @Test
  void onResume_whenCalledWithMockContext_expectNoInteraction() throws Exception {
    try (FileBucket bucket =
        new FileBucket(new File(tempDir, "resume.dat"), false, false, false, false)) {
      ClientContext ctx = mock(ClientContext.class);
      bucket.onResume(ctx);
      verifyNoInteractions(ctx);
    }
  }
}
