package network.crypta.support.io;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

class ArrayBucketTest {

  private static final String HELLO = "hello";
  private static final String MSG_READ_ONLY = "Read only";
  private static final String MSG_ALREADY_FREED = "Already freed";
  private static final String LABEL_PREFIX = "label=";

  // ---------- Helpers ----------
  private static byte[] bytes(String s) {
    return s.getBytes(StandardCharsets.US_ASCII);
  }

  // ---------- ArrayBucketFactory ----------

  @Test
  void factory_makeBucket_whenCalled_expectArrayBucketAndEmpty() throws Exception {
    // Arrange
    BucketFactory factory = new ArrayBucketFactory();
    // Act
    try (RandomAccessBucket b = factory.makeBucket(1024)) {
      // Assert
      assertInstanceOf(ArrayBucket.class, b);
      assertEquals(0, b.size());
      assertEquals("ArrayBucket", b.getName());
    }
  }

  @ParameterizedTest
  @MethodSource("factorySizeHints")
  void factory_makeBucket_ignoresSizeHint_allowsWrite(long sizeHint) throws Exception {
    // Arrange
    BucketFactory factory = new ArrayBucketFactory();
    // Act
    try (RandomAccessBucket b = factory.makeBucket(sizeHint)) {
      try (OutputStream os = b.getOutputStream()) {
        os.write(bytes("data"));
      }
      // Assert
      assertEquals(4, b.size());
      assertArrayEquals(bytes("data"), ((ArrayBucket) b).toByteArray());
    }
  }

  private static Stream<Arguments> factorySizeHints() {
    return Stream.of(Arguments.of(-1L), Arguments.of(Long.MAX_VALUE));
  }

  @Test
  void factory_makeBucket_eachCallReturnsFreshInstance() throws Exception {
    // Arrange
    BucketFactory factory = new ArrayBucketFactory();
    try (RandomAccessBucket a = factory.makeBucket(10);
        RandomAccessBucket b = factory.makeBucket(10)) {
      // Act
      try (OutputStream os = a.getOutputStream()) {
        os.write(bytes("x"));
      }
      // Assert
      assertNotSame(a, b);
      assertEquals(1, a.size());
      assertEquals(0, b.size());
    }
  }

  private static Stream<Arguments> asciiPayloads() {
    return Stream.of(
        Arguments.of("", bytes("")),
        Arguments.of("a", bytes("a")),
        Arguments.of(HELLO, bytes(HELLO)),
        Arguments.of("abcXYZ012", bytes("abcXYZ012")));
  }

  // ---------- Construction & Basics ----------

  @Test
  void size_whenNew_expectZero() {
    // Arrange & Act
    try (ArrayBucket bucket = new ArrayBucket()) {
      long size = bucket.size();
      // Assert
      assertEquals(0, size);
    }
  }

  @Test
  void getName_whenDefaultConstructor_expectArrayBucket() {
    // Arrange & Act
    try (ArrayBucket bucket = new ArrayBucket()) {
      String name = bucket.getName();
      // Assert
      assertEquals("ArrayBucket", name);
    }
  }

  @Test
  void getName_whenCustomName_expectCustomName() {
    // Arrange & Act
    try (ArrayBucket bucket = new ArrayBucket("Custom")) {
      String name = bucket.getName();
      // Assert
      assertEquals("Custom", name);
    }
  }

  @Test
  void isReadOnly_whenNew_expectFalse() {
    // Arrange & Act
    try (ArrayBucket bucket = new ArrayBucket()) {
      // Assert
      assertFalse(bucket.isReadOnly());
    }
  }

  // ---------- Streams (write/read) ----------

  @ParameterizedTest
  @MethodSource("asciiPayloads")
  void writeAndRead_whenUsingOutputStream_expectRoundTrip(String label, byte[] payload)
      throws Exception {
    // Arrange & Act
    try (ArrayBucket bucket = new ArrayBucket()) {
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(payload);
      }
      // Assert
      assertEquals(payload.length, bucket.size(), LABEL_PREFIX + label);
      assertArrayEquals(payload, bucket.toByteArray(), LABEL_PREFIX + label);
      try (InputStream in = bucket.getInputStream()) {
        byte[] read = in.readAllBytes();
        assertArrayEquals(payload, read, LABEL_PREFIX + label);
      }
    }
  }

  @Test
  void outputStream_closeTwice_afterSuccessfulClose_expectNoExceptionSecondTime() throws Exception {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket()) {
      OutputStream os = bucket.getOutputStream();
      os.write(bytes("abc"));
      // Act
      os.close();
      // Assert - second close is a no-op
      assertDoesNotThrow(os::close);
      assertArrayEquals(bytes("abc"), bucket.toByteArray());
    }
  }

  @Test
  void toString_whenAsciiData_expectAsciiString() throws Exception {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket()) {
      try (OutputStream os = bucket.getOutputStream()) {
        os.write(bytes(HELLO));
      }
      // Act
      String s = bucket.toString();
      // Assert
      assertEquals(HELLO, s);
    }
  }

  // ---------- Read-only behavior ----------

  @Test
  void getOutputStream_whenReadOnly_expectIOException() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket()) {
      bucket.setReadOnly();
      // Act & Assert
      IOException ex = assertThrows(IOException.class, bucket::getOutputStream);
      assertThat(ex.getMessage(), containsString(MSG_READ_ONLY));
    }
  }

  @Test
  void outputStream_close_whenReadOnlySetAfterObtaining_expectIOExceptionAndDataCommitted()
      throws Exception {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket()) {
      OutputStream os = bucket.getOutputStream();
      os.write(bytes("abc"));
      bucket.setReadOnly();
      // Act
      IOException ex1 = assertThrows(IOException.class, os::close);
      // Assert - close throws but internal data was already committed
      assertThat(ex1.getMessage(), containsString(MSG_READ_ONLY));
      assertArrayEquals(bytes("abc"), bucket.toByteArray());
      // And repeated close still throws because the stream was not marked closed
      IOException ex2 = assertThrows(IOException.class, os::close);
      assertThat(ex2.getMessage(), containsString(MSG_READ_ONLY));
    }
  }

  // ---------- Unbuffered aliases ----------

  @Test
  void getInputStreamUnbuffered_whenCalled_expectSameBytesAsBuffered() throws Exception {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket(bytes("data"))) {
      // Act
      byte[] a;
      try (InputStream inA = bucket.getInputStream()) {
        a = inA.readAllBytes();
      }
      byte[] b;
      try (InputStream inB = bucket.getInputStreamUnbuffered()) {
        b = inB.readAllBytes();
      }
      // Assert
      assertArrayEquals(a, b);
    }
  }

  @Test
  void getOutputStreamUnbuffered_whenReadOnly_expectIOException() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket()) {
      bucket.setReadOnly();
      // Act & Assert
      assertThrows(IOException.class, bucket::getOutputStreamUnbuffered);
    }
  }

  // ---------- toByteArray ----------

  @Test
  void toByteArray_whenNotFreed_expectDefensiveCopy() throws Exception {
    // Arrange
    byte[] init = bytes("abcdef");
    try (ArrayBucket bucket = new ArrayBucket(init)) {
      // Act
      byte[] first = bucket.toByteArray();
      first[0] = '!'; // modify returned copy
      byte[] second = bucket.toByteArray();
      // Assert
      assertNotSame(init, first, "Should return a new array instance");
      assertArrayEquals(bytes("abcdef"), second, "Underlying data must be unchanged");
    }
  }

  // ---------- RandomAccessBuffer conversion ----------

  @Test
  void toRandomAccessBuffer_whenCalled_expectReadOnlyBucketAndCopiedReadOnlyRaf() throws Exception {
    // Arrange
    byte[] init = bytes("xyz");
    try (ArrayBucket bucket = new ArrayBucket(init)) {
      // Act
      try (LockableRandomAccessBuffer raf = bucket.toRandomAccessBuffer()) {
        // Assert - bucket becomes read-only
        assertTrue(bucket.isReadOnly());
        assertThrows(IOException.class, bucket::getOutputStream);
        // RAF has same size and content
        assertEquals(3, raf.size());
        byte[] read = new byte[3];
        raf.pread(0, read, 0, 3);
        assertArrayEquals(init, read);
        // RAF is read-only
        assertThrows(IOException.class, () -> raf.pwrite(0, new byte[] {1}, 0, 1));
        // Underlying RAF buffer is a copy: mutate original init array and ensure RAF is unchanged
        init[0] = '!';
        byte[] reread = new byte[3];
        raf.pread(0, reread, 0, 3);
        assertArrayEquals(bytes("xyz"), reread);
      }
    }
  }

  // ---------- Free semantics ----------

  @Test
  void getInputStream_whenFreed_expectIOException() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket(bytes("hi"))) {
      bucket.free();
      // Act & Assert
      IOException ex = assertThrows(IOException.class, bucket::getInputStream);
      assertThat(ex.getMessage(), containsString(MSG_ALREADY_FREED));
    }
  }

  @Test
  void getOutputStream_whenFreed_expectIOException() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket(bytes("hi"))) {
      bucket.free();
      // Act & Assert
      IOException ex = assertThrows(IOException.class, bucket::getOutputStream);
      assertThat(ex.getMessage(), containsString(MSG_ALREADY_FREED));
    }
  }

  @Test
  void toByteArray_whenFreed_expectIOException() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket(bytes("hi"))) {
      bucket.free();
      // Act & Assert
      IOException ex = assertThrows(IOException.class, bucket::toByteArray);
      assertThat(ex.getMessage(), containsString(MSG_ALREADY_FREED));
    }
  }

  @Test
  void size_whenFreed_expectNullPointerException() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket(bytes("hi"))) {
      bucket.free();
      // Act & Assert (size() dereferences null `data`)
      assertThrows(NullPointerException.class, bucket::size);
    }
  }

  @Test
  void toString_whenFreed_expectNullPointerException() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket(bytes("hi"))) {
      bucket.free();
      // Act & Assert
      assertThrows(NullPointerException.class, bucket::toString);
    }
  }

  @Test
  void toRandomAccessBuffer_whenFreed_expectNullPointerException() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket(bytes("hi"))) {
      bucket.free();
      // Act & Assert
      assertThrows(NullPointerException.class, bucket::toRandomAccessBuffer);
    }
  }

  // ---------- Unsupported / No-op paths ----------

  @Test
  void createShadow_whenCalled_expectNull() {
    // Arrange & Act
    try (ArrayBucket bucket = new ArrayBucket()) {
      // Assert
      assertNull(bucket.createShadow());
    }
  }

  @Test
  void storeTo_whenCalled_expectUnsupportedOperationException() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket()) {
      DataOutputStream dos = new DataOutputStream(new ByteArrayOutputStream());
      // Act & Assert
      assertThrows(UnsupportedOperationException.class, () -> bucket.storeTo(dos));
    }
  }

  @Test
  void onResume_whenCalledWithMockContext_expectNoInteractions() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket()) {
      ClientContext ctx = mock(ClientContext.class);
      // Act
      bucket.onResume(ctx);
      // Assert
      verifyNoInteractions(ctx);
    }
  }

  // ---------- Null initial data edge case ----------

  @Test
  @DisplayName("Constructor with null backing array leads to NPEs on access")
  void methods_whenConstructedWithNull_expectNullPointerOnDataAccess() {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket((byte[]) null)) {
      // Act & Assert
      assertThrows(NullPointerException.class, bucket::size);
      assertThrows(NullPointerException.class, bucket::getInputStream);
      assertThrows(NullPointerException.class, bucket::toString);
    }
  }
}
