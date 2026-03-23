package network.crypta.support.io;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;
import java.util.stream.Stream;
import network.crypta.crypt.SHA256;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.RandomAccessBuffer;
import network.crypta.testsupport.FileTestUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * AAA-style unit tests for BucketTools (JUnit 6 + Mockito).
 *
 * <p>- Deterministic: seeded Random where relevant; no time dependencies. - Mockito used to
 * simulate I/O error/edge paths and to verify interactions.
 */
class BucketToolsTest {

  @TempDir File tempDir;

  // ---------- copy(Bucket, Bucket) ----------

  @Test
  void copy_whenSourceHasData_copiesAllBytes() throws Exception {
    // Arrange
    byte[] payload = "hello world".getBytes(StandardCharsets.UTF_8);
    try (ArrayBucket src = new ArrayBucket();
        ArrayBucket dst = new ArrayBucket()) {
      try (OutputStream os = src.getOutputStreamUnbuffered()) {
        os.write(payload);
      }

      // Act
      BucketTools.copy(src, dst);

      // Assert
      assertArrayEquals(payload, new ByteArrayInputStream(dst.toByteArray()).readAllBytes());
    }
  }

  @Test
  void copy_whenSourceEmpty_resultEmpty() throws Exception {
    // Arrange
    try (ArrayBucket src = new ArrayBucket();
        ArrayBucket dst = new ArrayBucket()) {
      // Act
      BucketTools.copy(src, dst);

      // Assert
      assertEquals(0, dst.size());
    }
  }

  // ---------- zeroPad ----------

  @ParameterizedTest
  @CsvSource({"0", "1", "4096"})
  void zeroPad_whenRequestedSize_writesThatManyZeros(long size) throws Exception {
    // Arrange
    try (ArrayBucket b = new ArrayBucket()) {
      // Act
      BucketTools.zeroPad(b, size);

      // Assert
      assertEquals(size, b.size());
      byte[] bytes = b.toByteArray();
      for (byte by : bytes) assertEquals(0, by);
    }
  }

  // ---------- paddedCopy ----------

  @Test
  void paddedCopy_whenNBytesGreaterThanBlock_throwsIAE() {
    // Arrange
    try (Bucket from = new ArrayBucket();
        Bucket to = new ArrayBucket()) {
      // Act
      Executable act = () -> BucketTools.paddedCopy(from, to, 10, 9);

      // Assert
      assertThrows(IllegalArgumentException.class, act);
    }
  }

  @Test
  void paddedCopy_whenExactSize_noExtraPadding() throws Exception {
    // Arrange
    byte[] data = {1, 2, 3, 4};
    try (ArrayBucket from = new ArrayBucket();
        ArrayBucket to = new ArrayBucket()) {
      try (OutputStream os = from.getOutputStreamUnbuffered()) {
        os.write(data);
      }

      // Act
      BucketTools.paddedCopy(from, to, data.length, data.length);

      // Assert
      assertArrayEquals(data, to.toByteArray());
    }
  }

  @Test
  void paddedCopy_whenShorterThanBlock_zeroPadsRemainder() throws Exception {
    // Arrange
    byte[] data = {9, 8, 7};
    try (ArrayBucket from = new ArrayBucket();
        ArrayBucket to = new ArrayBucket()) {
      try (OutputStream os = from.getOutputStreamUnbuffered()) {
        os.write(data);
      }

      // Act
      BucketTools.paddedCopy(from, to, 2, 5);

      // Assert
      byte[] out = to.toByteArray();
      assertEquals(5, out.length);
      assertEquals(9, out[0]);
      assertEquals(8, out[1]);
      assertEquals(0, out[2]);
      assertEquals(0, out[3]);
      assertEquals(0, out[4]);
    }
  }

  @Test
  void paddedCopy_whenSourceTooShort_throwsIOException() throws Exception {
    // Arrange
    try (ArrayBucket from = new ArrayBucket();
        ArrayBucket to = new ArrayBucket()) {
      try (OutputStream os = from.getOutputStreamUnbuffered()) {
        os.write(new byte[] {1});
      }

      // Act
      Executable act = () -> BucketTools.paddedCopy(from, to, 2, 4);

      // Assert
      assertThrows(IOException.class, act);
    }
  }

  // ---------- makeBuckets ----------

  @Test
  void makeBuckets_whenCountAndSize_createsRequestedNumber() throws Exception {
    // Arrange
    BucketFactory bf = mock(BucketFactory.class);
    when(bf.makeBucket(anyLong())).thenAnswer(_ -> mock(RandomAccessBucket.class));

    // Act
    Bucket[] buckets = BucketTools.makeBuckets(bf, 3, 123);

    // Assert
    assertEquals(3, buckets.length);
    try (var _ = verify(bf, times(3)).makeBucket(123)) {
      // Keep body non-empty to satisfy linters.
      assertEquals(3, buckets.length);
    }
  }

  // ---------- null/nonNull helpers ----------

  static Stream<Arguments> nullMixCases() {
    return Stream.of(
        // length, nonNullPositions, expectedNull, expectedNonNull
        Arguments.of(0, new int[] {}, new int[] {}, new int[] {}),
        Arguments.of(2, new int[] {}, new int[] {0, 1}, new int[] {}),
        Arguments.of(3, new int[] {0, 2}, new int[] {1}, new int[] {0, 2}));
  }

  @ParameterizedTest
  @MethodSource("nullMixCases")
  void nullIndices_and_nonNullIndices_returnExpected(
      int length, int[] nonNullPositions, int[] expectedNull, int[] expectedNonNull) {
    if (nonNullPositions.length == 0) {
      Bucket[] in = new Bucket[length];
      int[] nulls = BucketTools.nullIndices(in);
      int[] nonNulls = BucketTools.nonNullIndices(in);
      assertArrayEquals(expectedNull, nulls);
      assertArrayEquals(expectedNonNull, nonNulls);
    } else if (nonNullPositions.length == 1) {
      try (ArrayBucket b0 = new ArrayBucket()) {
        Bucket[] in = new Bucket[length];
        in[nonNullPositions[0]] = b0;
        int[] nulls = BucketTools.nullIndices(in);
        int[] nonNulls = BucketTools.nonNullIndices(in);
        assertArrayEquals(expectedNull, nulls);
        assertArrayEquals(expectedNonNull, nonNulls);
      }
    } else if (nonNullPositions.length == 2) {
      try (ArrayBucket b0 = new ArrayBucket();
          ArrayBucket b1 = new ArrayBucket()) {
        Bucket[] in = new Bucket[length];
        in[nonNullPositions[0]] = b0;
        in[nonNullPositions[1]] = b1;
        int[] nulls = BucketTools.nullIndices(in);
        int[] nonNulls = BucketTools.nonNullIndices(in);
        assertArrayEquals(expectedNull, nulls);
        assertArrayEquals(expectedNonNull, nonNulls);
      }
    } else {
      // Not exercised by current cases; keep simple and explicit.
      fail("Test case requests >2 non-null positions which is unsupported in this helper");
    }
  }

  @Test
  void nonNullBuckets_whenMixed_returnsOnlyNonNull() {
    // Arrange
    Bucket a = mock(Bucket.class);
    Bucket[] in = new Bucket[] {a, null, a};

    // Act
    Bucket[] out = BucketTools.nonNullBuckets(in);

    // Assert
    assertEquals(2, out.length);
    assertSame(a, out[0]);
    assertSame(a, out[1]);
  }

  // ---------- toByteArray(Bucket) and variant ----------

  @Test
  void toByteArray_whenSizeTooLarge_throwsOutOfMemoryError() throws Exception {
    // Arrange
    try (Bucket mockBucket = mock(Bucket.class)) {
      when(mockBucket.size()).thenReturn(1L + Integer.MAX_VALUE);

      // Act
      Executable act = () -> BucketTools.toByteArray(mockBucket);

      // Assert
      assertThrows(OutOfMemoryError.class, act);
      verify(mockBucket, never()).getInputStreamUnbuffered();
    }
  }

  @Test
  void toByteArray_whenExactSize_readsAllBytes() throws Exception {
    // Arrange
    byte[] data = {1, 2, 3, 4, 5};
    try (ArrayBucket bucket = new ArrayBucket()) {
      try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
        os.write(data);
      }

      // Act
      byte[] out = BucketTools.toByteArray(bucket);

      // Assert
      assertArrayEquals(data, out);
    }
  }

  @Test
  void toByteArray_withProvidedBuffer_whenInputEndsEarly_returnsBytesRead() throws Exception {
    // Arrange
    try (Bucket mockBucket = mock(Bucket.class)) {
      when(mockBucket.size()).thenReturn(10L);
      when(mockBucket.getInputStreamUnbuffered())
          .thenReturn(new ByteArrayInputStream(new byte[] {9, 8, 7}));
      byte[] buffer = new byte[10];

      // Act
      int moved = BucketTools.toByteArray(mockBucket, buffer);

      // Assert
      assertEquals(3, moved);
      assertArrayEquals(new byte[] {9, 8, 7}, new byte[] {buffer[0], buffer[1], buffer[2]});
    }
  }

  @Test
  void toByteArray_withProvidedBuffer_whenTooSmall_throwsIAE() {
    // Arrange
    try (Bucket mockBucket = mock(Bucket.class)) {
      when(mockBucket.size()).thenReturn(3L);
      byte[] buffer = new byte[2];

      // Act
      Executable act = () -> BucketTools.toByteArray(mockBucket, buffer);

      // Assert
      assertThrows(IllegalArgumentException.class, act);
    }
  }

  // ---------- makeImmutableBucket ----------

  @Test
  void makeImmutableBucket_whenDataProvided_writesAndSetsReadOnly() throws Exception {
    // Arrange
    byte[] data = "fixed".getBytes(StandardCharsets.UTF_8);
    ArrayBucketFactory bf = new ArrayBucketFactory();

    // Act
    try (RandomAccessBucket rab = BucketTools.makeImmutableBucket(bf, data)) {
      // Assert
      ArrayBucket asArray = (ArrayBucket) rab;
      assertArrayEquals(data, asArray.toByteArray());
      assertTrue(asArray.isReadOnly());
      assertThrows(IOException.class, asArray::getOutputStream); // read-only enforced
    }
  }

  // ---------- hash ----------

  @Test
  void hash_whenBytesProvided_matchesSHA256() throws Exception {
    // Arrange
    byte[] data = new byte[] {1, 2, 3, 4, 5, 6};
    try (ArrayBucket b = new ArrayBucket()) {
      try (OutputStream os = b.getOutputStreamUnbuffered()) {
        os.write(data);
      }
      MessageDigest md = SHA256.getMessageDigest();
      md.update(data);
      byte[] expected = md.digest();

      // Act
      byte[] actual = BucketTools.hash(b);

      // Assert
      assertArrayEquals(expected, actual);
    }
  }

  @Test
  void hash_whenStreamShorterThanSize_throwsEOF() throws Exception {
    // Arrange
    try (Bucket mockBucket = mock(Bucket.class)) {
      when(mockBucket.size()).thenReturn(10L);
      when(mockBucket.getInputStreamUnbuffered())
          .thenReturn(new ByteArrayInputStream(new byte[] {1, 2, 3}));

      // Act
      Executable act = () -> BucketTools.hash(mockBucket);

      // Assert
      assertThrows(EOFException.class, act);
    }
  }

  // ---------- copyTo(Bucket, OutputStream, long) ----------

  @ParameterizedTest
  @CsvSource({"-1,10", "0,0", "3,3"})
  void copyTo_whenTruncateLength_movesExpectedBytes(long truncate, long expected) throws Exception {
    // Arrange
    byte[] data = new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    try (ArrayBucket b = new ArrayBucket()) {
      try (OutputStream os = b.getOutputStreamUnbuffered()) {
        os.write(data);
      }
      ByteArrayOutputStream target = new ByteArrayOutputStream();

      // Act
      long moved = BucketTools.copyTo(b, target, truncate);

      // Assert
      assertEquals(expected, moved);
      byte[] written = target.toByteArray();
      assertEquals(expected, written.length);
      for (int i = 0; i < written.length; i++) assertEquals(data[i], written[i]);
    }
  }

  @Test
  void copyTo_whenInsufficientInputAndFixedLength_throwsIOException() throws Exception {
    // Arrange
    try (Bucket mockBucket = mock(Bucket.class)) {
      when(mockBucket.getInputStreamUnbuffered())
          .thenReturn(new ByteArrayInputStream(new byte[] {1, 2}));
      ByteArrayOutputStream os = new ByteArrayOutputStream();

      // Act
      Executable act = () -> BucketTools.copyTo(mockBucket, os, 5);

      // Assert
      assertThrows(IOException.class, act);
    }
  }

  // ---------- copyFrom(Bucket, InputStream, long) ----------

  @Test
  void copyFrom_whenNegativeTruncate_readsEntireStream() throws Exception {
    // Arrange
    try (ArrayBucket dst = new ArrayBucket()) {
      byte[] payload = new byte[] {4, 5, 6, 7};
      ByteArrayInputStream is = new ByteArrayInputStream(payload);

      // Act
      BucketTools.copyFrom(dst, is, -1);

      // Assert
      assertArrayEquals(payload, dst.toByteArray());
    }
  }

  @Test
  void copyFrom_whenFixedTruncate_readsOnlyThatMany() throws Exception {
    // Arrange
    try (ArrayBucket dst = new ArrayBucket()) {
      byte[] payload = new byte[] {4, 5, 6, 7};
      ByteArrayInputStream is = new ByteArrayInputStream(payload);

      // Act
      BucketTools.copyFrom(dst, is, 2);

      // Assert
      assertArrayEquals(new byte[] {4, 5}, dst.toByteArray());
    }
  }

  @Test
  void copyFrom_whenInsufficientAndFixed_throwsIOException() {
    // Arrange
    try (ArrayBucket dst = new ArrayBucket()) {
      ByteArrayInputStream is = new ByteArrayInputStream(new byte[] {9});

      // Act
      Executable act = () -> BucketTools.copyFrom(dst, is, 3);

      // Assert
      assertThrows(IOException.class, act);
    }
  }

  // ---------- split ----------

  @Test
  void split_whenExactMultiples_returnsEqualSizedBuckets_andFreesWhenRequested() throws Exception {
    // Arrange
    byte[] data = "abcdefghij".getBytes(StandardCharsets.UTF_8); // 10 bytes
    try (ArrayBucket src = new ArrayBucket()) {
      try (OutputStream os = src.getOutputStreamUnbuffered()) {
        os.write(data);
      }
      ArrayBucketFactory bf = new ArrayBucketFactory();

      // Act
      Bucket[] parts = BucketTools.split(src, 5, bf, true, false);

      // Assert
      assertEquals(2, parts.length);
      try (Bucket p0 = parts[0];
          Bucket p1 = parts[1]) {
        assertArrayEquals(
            "abcde".getBytes(StandardCharsets.UTF_8), ((ArrayBucket) p0).toByteArray());
        assertArrayEquals(
            "fghij".getBytes(StandardCharsets.UTF_8), ((ArrayBucket) p1).toByteArray());
      }
      assertThrows(IOException.class, src::getInputStream); // freed
    }
  }

  @Test
  void split_whenRemainder_lastBucketShorter() throws Exception {
    // Arrange
    byte[] data = "abcdef".getBytes(StandardCharsets.UTF_8); // 6 bytes
    try (ArrayBucket src = new ArrayBucket()) {
      try (OutputStream os = src.getOutputStreamUnbuffered()) {
        os.write(data);
      }

      // Act
      Bucket[] parts = BucketTools.split(src, 4, new ArrayBucketFactory(), false, false);

      // Assert
      assertEquals(2, parts.length);
      try (Bucket p0 = parts[0];
          Bucket p1 = parts[1]) {
        assertArrayEquals(
            "abcd".getBytes(StandardCharsets.UTF_8), ((ArrayBucket) p0).toByteArray());
        assertArrayEquals("ef".getBytes(StandardCharsets.UTF_8), ((ArrayBucket) p1).toByteArray());
      }
    }
  }

  @Test
  void split_whenLengthTooLarge_throwsIAEBeforeAlloc() {
    // Arrange
    try (Bucket big = mock(Bucket.class)) {
      when(big.size()).thenReturn(((long) Integer.MAX_VALUE) * 4 + 1);

      // Act
      Executable act = () -> BucketTools.split(big, 4, new ArrayBucketFactory(), false, false);

      // Assert
      assertThrows(IllegalArgumentException.class, act);
    }
  }

  @Test
  void split_whenPersistentFileBucket_returnsReadOnlyFileSliceBuckets() throws Exception {
    // Arrange
    File backingFile = new File(tempDir, "split.bin");
    byte[] data = "abcdefghij".getBytes(StandardCharsets.UTF_8);
    try (FileBucket src = new FileBucket(backingFile, false, false, false, false)) {
      try (OutputStream os = src.getOutputStreamUnbuffered()) {
        os.write(data);
      }

      // Act
      Bucket[] parts = BucketTools.split(src, 4, new ArrayBucketFactory(), false, true);

      // Assert
      assertEquals(3, parts.length);
      try (Bucket p0 = parts[0];
          Bucket p1 = parts[1];
          Bucket p2 = parts[2]) {
        assertInstanceOf(ReadOnlyFileSliceBucket.class, p0);
        assertInstanceOf(ReadOnlyFileSliceBucket.class, p1);
        assertInstanceOf(ReadOnlyFileSliceBucket.class, p2);
        assertArrayEquals("abcd".getBytes(StandardCharsets.UTF_8), BucketTools.toByteArray(p0));
        assertArrayEquals("efgh".getBytes(StandardCharsets.UTF_8), BucketTools.toByteArray(p1));
        assertArrayEquals("ij".getBytes(StandardCharsets.UTF_8), BucketTools.toByteArray(p2));
      }
    }
  }

  // ---------- pad(byte[], ...) and pad(Bucket, ...) ----------

  @Test
  void pad_whenCalledTwiceWithSameInputs_isDeterministic() throws Exception {
    // Arrange
    byte[] orig = "seeded".getBytes(StandardCharsets.UTF_8);

    // Act
    byte[] p1 = BucketTools.pad(orig, 32, orig.length);
    byte[] p2 = BucketTools.pad(orig, 32, orig.length);

    // Assert
    assertArrayEquals(p1, p2);
    assertEquals(32, p1.length);
    assertArrayEquals(orig, Arrays.copyOfRange(p1, 0, orig.length));
  }

  @Test
  void pad_whenDifferentContent_producesDifferentPadding() throws Exception {
    // Arrange
    byte[] a = "aaaa".getBytes(StandardCharsets.UTF_8);
    byte[] b = "bbbb".getBytes(StandardCharsets.UTF_8);

    // Act
    byte[] pa = BucketTools.pad(a, 16, 4);
    byte[] pb = BucketTools.pad(b, 16, 4);

    // Assert
    assertEquals(16, pa.length);
    assertEquals(16, pb.length);
    assertFalse(Arrays.equals(pa, pb));
  }

  // ---------- equalBuckets ----------

  @Test
  void equalBuckets_whenSameBytes_returnsTrue() throws Exception {
    // Arrange
    try (ArrayBucket a = new ArrayBucket();
        ArrayBucket b = new ArrayBucket()) {
      try (OutputStream os = a.getOutputStreamUnbuffered()) {
        os.write(new byte[] {1, 2, 3});
      }
      try (OutputStream os = b.getOutputStreamUnbuffered()) {
        os.write(new byte[] {1, 2, 3});
      }

      // Act
      boolean eq = BucketTools.equalBuckets(a, b);

      // Assert
      assertTrue(eq);
    }
  }

  @Test
  void equalBuckets_whenDifferentSize_returnsFalse() throws Exception {
    // Arrange
    try (ArrayBucket a = new ArrayBucket();
        ArrayBucket b = new ArrayBucket()) {
      try (OutputStream os = a.getOutputStreamUnbuffered()) {
        os.write(new byte[] {1, 2});
      }
      try (OutputStream os = b.getOutputStreamUnbuffered()) {
        os.write(new byte[] {1, 2, 3});
      }

      // Act
      boolean eq = BucketTools.equalBuckets(a, b);

      // Assert
      assertFalse(eq);
    }
  }

  // ---------- deprecated fill helpers (test-only) ----------

  @Test
  void fill_withSeededRandom_writesDeterministicBytes() throws Exception {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket()) {
      long length = 32;
      Random seeded = new Random(123456789L);

      // Act
      FileTestUtils.fill(bucket, seeded, length);

      // Assert
      byte[] expected = new byte[(int) length];
      new Random(123456789L).nextBytes(expected);
      assertArrayEquals(expected, bucket.toByteArray());
    }
  }

  @Test
  void fill_withoutRandom_writesRequestedLength() throws Exception {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket()) {
      // Act
      BucketTools.fill(bucket, 100);

      // Assert
      assertEquals(100, bucket.size());
    }
  }

  // ---------- copyTo(Bucket, RandomAccessBuffer, ...) ----------

  @Test
  void copyTo_randomAccessBuffer_whenNegativeLength_copiesAllAtOffset() throws Exception {
    // Arrange
    byte[] data = new byte[] {10, 20, 30};
    try (ArrayBucket src = new ArrayBucket()) {
      try (OutputStream os = src.getOutputStreamUnbuffered()) {
        os.write(data);
      }
      try (ByteArrayRandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(10)) {
        // Act
        long moved = BucketTools.copyTo(src, raf, 4, -1);

        // Assert
        assertEquals(3, moved);
        byte[] buf = new byte[10];
        raf.pread(0, buf, 0, 10);
        assertArrayEquals(new byte[] {0, 0, 0, 0, 10, 20, 30, 0, 0, 0}, buf);
      }
    }
  }

  @Test
  void copyTo_randomAccessBuffer_whenInsufficientInput_throwsIOException() throws Exception {
    // Arrange
    try (Bucket mockBucket = mock(Bucket.class);
        RandomAccessBuffer raf = new ByteArrayRandomAccessBuffer(4)) {
      when(mockBucket.getInputStreamUnbuffered())
          .thenReturn(new ByteArrayInputStream(new byte[] {1, 2}));
      // Act
      Executable act = () -> BucketTools.copyTo(mockBucket, raf, 0, 5);

      // Assert
      assertThrows(IOException.class, act);
    }
  }

  // ---------- toRandomAccessBucket ----------

  @Test
  void toRandomAccessBucket_whenAlreadyRAB_returnsSameInstance() throws Exception {
    // Arrange
    try (ArrayBucket bucket = new ArrayBucket()) {
      try (OutputStream os = bucket.getOutputStreamUnbuffered()) {
        os.write(new byte[] {1, 2, 3});
      }

      // Act
      RandomAccessBucket result =
          BucketTools.toRandomAccessBucket(bucket, new ArrayBucketFactory());

      // Assert
      assertSame(bucket, result);
    }
  }

  @Test
  void toRandomAccessBucket_whenNotRAB_copiesAndFreesOriginal() throws Exception {
    // Arrange
    byte[] bytes = "hello".getBytes(StandardCharsets.UTF_8);
    ArrayBucketFactory bf = new ArrayBucketFactory();

    // Act
    try (Bucket notRab = mock(Bucket.class)) {
      when(notRab.size()).thenReturn((long) bytes.length);
      when(notRab.getInputStreamUnbuffered()).thenReturn(new ByteArrayInputStream(bytes));
      try (RandomAccessBucket rab = BucketTools.toRandomAccessBucket(notRab, bf)) {
        // Assert
        ArrayBucket out = (ArrayBucket) rab;
        assertArrayEquals(bytes, out.toByteArray());
        verify(notRab, times(1)).free();
      }
    }
  }

  // ---------- restoreFrom / restoreRAFFrom (unknown magic) ----------

  @Test
  void restoreFrom_whenUnknownMagic_throwsStorageFormatException() throws Exception {
    // Arrange
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(0x12345678);
    }
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));

    // Act
    Executable act = () -> BucketTools.restoreFrom(dis, null, null, null);

    // Assert
    assertThrows(StorageFormatException.class, act);
  }

  @Test
  void restoreRAFFrom_whenUnknownMagic_throwsStorageFormatException() throws Exception {
    // Arrange
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.writeInt(0xCAFEBABE);
    }
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));

    // Act
    Executable act = () -> BucketTools.restoreRAFFrom(dis, null, null, null);

    // Assert
    assertThrows(StorageFormatException.class, act);
  }
}
