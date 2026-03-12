package network.crypta.support;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.regex.Pattern;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.io.ByteArrayRandomAccessBuffer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class SimpleReadOnlyArrayBucketTest {

  @Mock private ClientContext context;

  @Test
  @DisplayName("size() when constructed with full array returns array length")
  void size_whenConstructedWithFullArray_expectArrayLength() {
    byte[] data = "hello".getBytes(StandardCharsets.UTF_8);
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data)) {
      assertEquals(data.length, bucket.size());
      assertTrue(bucket.isReadOnly());
    }
  }

  @Test
  @DisplayName("getInputStream() returns exact slice and not beyond")
  void getInputStream_whenReadAll_expectExactSlice() throws IOException {
    byte[] data = "0123456789".getBytes(StandardCharsets.UTF_8);
    // slice "3456"
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data, 3, 4)) {
      byte[] read = readAll(bucket.getInputStream());
      assertArrayEquals("3456".getBytes(StandardCharsets.UTF_8), read);
    }
  }

  @Test
  @DisplayName("getInputStream() on zero-length bucket yields empty stream")
  void getInputStream_whenZeroLength_expectEmptyStream() throws IOException {
    byte[] data = "abc".getBytes(StandardCharsets.UTF_8);
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data, 1, 0)) {
      try (InputStream is = bucket.getInputStream()) {
        assertNotNull(is);
        assertEquals(-1, is.read());
      }
      assertEquals(0, bucket.size());
    }
  }

  @Test
  @DisplayName("getOutputStream() throws IOException for read-only bucket")
  void getOutputStream_whenCalled_expectIOException() {
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(new byte[1])) {
      assertThrows(IOException.class, bucket::getOutputStream);
    }
  }

  @Test
  @DisplayName("getOutputStreamUnbuffered() throws IOException for read-only bucket")
  void getOutputStreamUnbuffered_whenCalled_expectIOException() {
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(new byte[1])) {
      assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);
    }
  }

  @Test
  @DisplayName("getName() contains class name and length")
  void getName_whenCalled_expectContainsClassAndLength() {
    byte[] data = new byte[7];
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data)) {
      String name = bucket.getName();
      // Format: "SimpleReadOnlyArrayBucket: len=<n> <FQCN@hash>"
      assertTrue(name.startsWith("SimpleReadOnlyArrayBucket: len=7 "));
      assertTrue(Pattern.compile("SimpleReadOnlyArrayBucket.*@.*").matcher(name).find());
    }
  }

  @Test
  @DisplayName("setReadOnly() is a no-op and remains read-only")
  void setReadOnly_whenCalled_expectStillReadOnly() {
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(new byte[2])) {
      bucket.setReadOnly();
      assertTrue(bucket.isReadOnly());
    }
  }

  @Test
  @DisplayName("free() is a no-op and reading still works")
  void free_whenCalledThenRead_expectStillWorks() throws IOException {
    byte[] data = "hi".getBytes(StandardCharsets.UTF_8);
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data)) {
      bucket.free();
      assertArrayEquals(data, readAll(bucket.getInputStream()));
    }
  }

  @Test
  @DisplayName("createShadow() returns independent copy for small backing array")
  void createShadow_whenSmallBacking_expectCopiedSliceIndependent() throws IOException {
    byte[] src = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes(StandardCharsets.UTF_8);
    // pick a slice "HIJKL" (offset 7, length 5)
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(src, 7, 5)) {
      try (SimpleReadOnlyArrayBucket shadow = (SimpleReadOnlyArrayBucket) bucket.createShadow()) {
        assertNotNull(shadow);
        assertEquals(5, shadow.size());
        assertArrayEquals(
            "HIJKL".getBytes(StandardCharsets.UTF_8), readAll(shadow.getInputStream()));

        // mutate original backing array; shadow must remain unchanged
        src[7] = '!';
        assertArrayEquals(
            "HIJKL".getBytes(StandardCharsets.UTF_8), readAll(shadow.getInputStream()));
      }
    }
  }

  @Test
  @DisplayName("createShadow() returns null when backing array size >= 256KiB")
  void createShadow_whenLargeBacking_expectNull() {
    final int limit = 256 * 1024; // bytes
    byte[] big = new byte[limit];
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(big, 0, 1)) {
      assertNull(bucket.createShadow());
    }
  }

  @Test
  @DisplayName("toRandomAccessBuffer() returns read-only buffer with same content and size")
  void toRandomAccessBuffer_whenCalled_expectReadOnlyBufferWithSameContent() throws IOException {
    byte[] data = "0123456789".getBytes(StandardCharsets.UTF_8);
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(data, 2, 5)) { // "23456"
      try (LockableRandomAccessBuffer rab = bucket.toRandomAccessBuffer()) {
        assertInstanceOf(ByteArrayRandomAccessBuffer.class, rab);
        assertEquals(5, rab.size());

        byte[] read = new byte[5];
        rab.pread(0, read, 0, 5);
        assertArrayEquals("23456".getBytes(StandardCharsets.UTF_8), read);

        // Writes must be rejected because the buffer is read-only
        IOException ex = assertThrows(IOException.class, () -> rab.pwrite(0, new byte[] {1}, 0, 1));
        assertTrue(ex.getMessage().toLowerCase(Locale.ROOT).contains("read"));

        // Out-of-bounds and negative offsets propagate underlying exceptions
        assertThrows(IllegalArgumentException.class, () -> rab.pread(-1, new byte[1], 0, 1));
        assertThrows(IOException.class, () -> rab.pread(5, new byte[1], 0, 1));
      }
    }
  }

  @Test
  @DisplayName("onResume() and storeTo() are unsupported")
  void unsupportedOperations_whenCalled_expectUnsupportedOperationException() throws IOException {
    try (SimpleReadOnlyArrayBucket bucket = new SimpleReadOnlyArrayBucket(new byte[0])) {
      assertThrows(UnsupportedOperationException.class, () -> bucket.onResume(context));
      try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
          DataOutputStream dos = new DataOutputStream(baos)) {
        assertThrows(UnsupportedOperationException.class, () -> bucket.storeTo(dos));
      }
    }
  }

  private static byte[] readAll(InputStream is) throws IOException {
    try (InputStream input = is;
        ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      byte[] buf = new byte[64];
      int read;
      while ((read = input.read(buf)) != -1) {
        baos.write(buf, 0, read);
      }
      return baos.toByteArray();
    }
  }
}
