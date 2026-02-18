package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyLong;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link RAFBucket}.
 *
 * <p>Tests follow AAA style, use deterministic data, and cover construction, I/O behavior,
 * delegation, and (de)serialization paths.
 */
class RAFBucketTest {

  private static final java.util.logging.Logger TEST_LOG =
      java.util.logging.Logger.getLogger(RAFBucketTest.class.getName());

  @SuppressWarnings("java:S1172")
  private static void ignoreInt(int ignored) {
    // Intentionally empty helper to consume values in assertions.
  }

  private static LockableRandomAccessBuffer stubRafWithContent(byte[] content) throws IOException {
    LockableRandomAccessBuffer raf = mock(LockableRandomAccessBuffer.class);
    when(raf.size()).thenReturn((long) content.length);
    // Delegate pread() to copy from the in-memory array
    doAnswer(
            inv -> {
              long fileOffset = inv.getArgument(0);
              byte[] buf = inv.getArgument(1);
              int bufOffset = inv.getArgument(2);
              int len = inv.getArgument(3);
              if (fileOffset < 0) throw new IllegalArgumentException("fileOffset < 0");
              if (fileOffset + len > content.length) throw new IOException("read exceeds length");
              System.arraycopy(content, (int) fileOffset, buf, bufOffset, len);
              return null;
            })
        .when(raf)
        .pread(anyLong(), any(byte[].class), anyInt(), anyInt());
    // No-op implementations for unused methods
    doNothing().when(raf).pwrite(anyLong(), any(byte[].class), anyInt(), anyInt());
    doNothing().when(raf).free();
    doNothing().when(raf).close();
    return raf;
  }

  private static File createSecureTempDir(String prefix) throws IOException {
    try {
      FileAttribute<Set<PosixFilePermission>> attr =
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"));
      Path p = Files.createTempDirectory(prefix, attr);
      return p.toFile();
    } catch (UnsupportedOperationException _) {
      // Non-POSIX (e.g., Windows). Create under user.home instead of public tmp.
      File base = new File(System.getProperty("user.home"));
      File dir = new File(base, prefix + System.nanoTime());
      if (!dir.mkdirs()) throw new IOException("Failed to create temp dir " + dir);
      boolean r = dir.setReadable(true, true);
      boolean w = dir.setWritable(true, true);
      boolean x = dir.setExecutable(true, true);
      if (!(r && w && x)) {
        // Best effort: warn but do not fail the test.
        TEST_LOG.warning("Unable to harden permissions on temp dir " + dir.getAbsolutePath());
      }
      return dir;
    }
  }

  @Test
  void constructorWhenUnderlyingCapturesSizeAndIsReadOnly() {
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    when(underlying.size())
        .thenReturn(123L, 999L); // later change should not affect the captured size

    RAFBucket bucket = new RAFBucket(underlying);

    assertEquals(123L, bucket.size());
    assertTrue(bucket.isReadOnly());
    assertNull(bucket.getName());
    assertNull(bucket.createShadow());

    // The underlying size later changes, but RAFBucket.size() remains the captured value
    assertEquals(123L, bucket.size());
  }

  @Test
  void getOutputStreamWhenCalledExpectIOException() {
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    when(underlying.size()).thenReturn(0L);
    RAFBucket bucket = new RAFBucket(underlying);
    assertThrows(IOException.class, bucket::getOutputStream);
    assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);
  }

  @Nested
  class InputStreamTests {
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 7, 8192, 12345})
    void getInputStreamUnbufferedWhenReadAllExpectExactBytesAndEof(int length) throws Exception {
      byte[] data = new byte[length];
      for (int i = 0; i < length; i++) {
        data[i] = (byte) (i * 31 + 7);
      }
      LockableRandomAccessBuffer raf = stubRafWithContent(data);
      RAFBucket bucket = new RAFBucket(raf);

      try (InputStream is = bucket.getInputStreamUnbuffered()) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        int moved = 0;
        while (moved < length) {
          int toRead = Math.min(buf.length, length - moved);
          int read = is.read(buf, 0, toRead);
          assertTrue(read > 0);
          out.write(buf, 0, read);
          moved += read;
        }
        assertArrayEquals(data, out.toByteArray());
        // The next read must throw EOFException according to RAFInputStream behavior
        assertThrows(EOFException.class, () -> ignoreInt(is.read(buf)));
      }
    }

    @Test
    void getInputStreamWhenReadChunksExpectBufferedReadMatchesContent() throws Exception {
      byte[] data = new byte[4096 + 13];
      for (int i = 0; i < data.length; i++) {
        data[i] = (byte) (i * 17 + 3);
      }
      LockableRandomAccessBuffer raf = stubRafWithContent(data);
      RAFBucket bucket = new RAFBucket(raf);

      try (InputStream is = bucket.getInputStream()) { // buffered wrapper
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[512];
        int moved = 0;
        while (moved < data.length) {
          int read = is.read(buf);
          assertTrue(read > 0);
          out.write(buf, 0, read);
          moved += read;
        }
        assertArrayEquals(data, out.toByteArray());
      }
    }
  }

  @Test
  void freeWhenCalledDelegatesToUnderlying() {
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    when(underlying.size()).thenReturn(0L);
    RAFBucket bucket = new RAFBucket(underlying);
    bucket.free();
    verify(underlying, times(1)).free();
  }

  @Test
  void onResumeWhenCalledDelegatesToUnderlying() throws Exception {
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    when(underlying.size()).thenReturn(0L);
    RAFBucket bucket = new RAFBucket(underlying);
    ClientContext ctx = mock(ClientContext.class);
    bucket.onResume(ctx);
    verify(underlying, times(1)).onResume(ctx);
  }

  @Test
  void toRandomAccessBufferWhenCalledReturnsSameUnderlying() {
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    when(underlying.size()).thenReturn(10L);
    RAFBucket bucket = new RAFBucket(underlying);
    assertSame(underlying, bucket.toRandomAccessBuffer());
  }

  @Test
  void storeToWhenCalledWritesMagicAndDelegates() throws Exception {
    LockableRandomAccessBuffer underlying = mock(LockableRandomAccessBuffer.class);
    when(underlying.size()).thenReturn(12L);
    // When delegate storeTo() is invoked, write a sentinel so we can assert ordering
    doAnswer(
            inv -> {
              DataOutputStream dos = inv.getArgument(0);
              dos.writeInt(0xDEADBEEF);
              return null;
            })
        .when(underlying)
        .storeTo(any(DataOutputStream.class));

    RAFBucket bucket = new RAFBucket(underlying);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      bucket.storeTo(dos);
    }

    byte[] bytes = baos.toByteArray();
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bytes))) {
      assertEquals(RAFBucket.MAGIC, dis.readInt());
      assertEquals(0xDEADBEEF, dis.readInt());
    }
    verify(underlying, times(1)).storeTo(any(DataOutputStream.class));
  }

  @Test
  @DisplayName("constructor(stream) restores underlying RAF via BucketTools.restoreRAFFrom")
  void constructorFromStreamRestoresUnderlyingAndSize() throws Exception {
    File secureDir = createSecureTempDir("rafbucket-restore-");
    File tmp = File.createTempFile("rafbucket-restore", ".bin", secureDir);
    long length = 2048L;
    // Write the file to the required length; content is irrelevant here
    try (RandomAccessFile raf = new RandomAccessFile(tmp, "rw")) {
      raf.setLength(length);
    }
    // Use read/write mode here since this constructor sets the length
    FileRandomAccessBuffer fileRaf = new FileRandomAccessBuffer(tmp, length, false);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      // We need the RAF serialization only (not the RAFBucket magic)
      fileRaf.storeTo(dos);
    }
    fileRaf.close(); // do not free; the file must exist for restore

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()))) {
      RAFBucket restored = new RAFBucket(dis, null, null, null);
      assertEquals(length, restored.size());
      LockableRandomAccessBuffer restoredRaf = restored.toRandomAccessBuffer();
      assertEquals(FileRandomAccessBuffer.class, restoredRaf.getClass());
      // The restored RAF should equal a fresh FileRandomAccessBuffer view on the same file
      FileRandomAccessBuffer expected = new FileRandomAccessBuffer(tmp, false);
      assertEquals(expected, restoredRaf);
      restored.free(); // deletes the file
    }
  }

  @Test
  void storeToAndRestoreViaBucketToolsYieldsEquivalentBucket() throws Exception {
    File secureDir = createSecureTempDir("rafbucket-roundtrip-");
    File tmp = File.createTempFile("rafbucket-roundtrip", ".bin", secureDir);
    long length = 1024L;
    try (RandomAccessFile raf = new RandomAccessFile(tmp, "rw")) {
      raf.setLength(length);
    }
    // Open using the existing file length in read-only mode
    FileRandomAccessBuffer fileRaf = new FileRandomAccessBuffer(tmp, true);
    RandomAccessBucket bucket = new RAFBucket(fileRaf);

    byte[] serialized;
    try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos)) {
      bucket.storeTo(dos);
      dos.flush();
      serialized = baos.toByteArray();
    }

    // Now restore using the generic BucketTools dispatcher
    RAFBucket restored;
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(serialized))) {
      Bucket restoredAny =
          BucketTools.restoreFrom(dis, /* fg= */ null, /* pft= */ null, /* masterKey= */ null);
      assertInstanceOf(RAFBucket.class, restoredAny);
      restored = (RAFBucket) restoredAny;
    }

    assertEquals(length, restored.size());
    assertEquals(fileRaf, restored.toRandomAccessBuffer());

    restored.free(); // cleans up tmp file
  }
}
