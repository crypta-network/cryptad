package network.crypta.support;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;

/** Unit tests for {@link BinaryBloomFilter} using JUnit 6 and Mockito. */
@SuppressWarnings("java:S100") // Allow descriptive test method names with underscores
class BinaryBloomFilterTest {

  private BinaryBloomFilter filter;

  @BeforeEach
  void setUp() {
    // 1024-bit filter (128 bytes) with k=4 for general tests
    filter = new BinaryBloomFilter(1024, 4);
  }

  @AfterEach
  void tearDown() {
    if (filter != null) {
      filter.close();
    }
  }

  @Test
  @DisplayName("removeKey_whenCalled_expectNoEffect")
  void removeKey_whenCalled_expectNoEffect() {
    byte[] key = new byte[] {1, 2, 3, 4};

    filter.addKey(key);
    int filledBefore = filter.getFilledCount();
    assertTrue(filter.checkFilter(key), "Key should be reported present after add");

    filter.removeKey(key); // No-op in BinaryBloomFilter

    assertTrue(
        filter.checkFilter(key), "Key should still be reported present after removeKey no-op");
    assertEquals(
        filledBefore, filter.getFilledCount(), "Filled count should be unchanged by removeKey");
  }

  @Test
  @DisplayName("unsetBit_whenCalled_expectNoEffect")
  void unsetBit_whenCalled_expectNoEffect() {
    // Small 8-bit filter to target a single byte
    try (BinaryBloomFilter small = new BinaryBloomFilter(8, 1)) {
      assertFalse(small.getBit(0));
      small.setBit(0);
      assertTrue(small.getBit(0));

      small.unsetBit(0); // no-op in binary variant
      assertTrue(small.getBit(0), "unsetBit must not clear bit in BinaryBloomFilter");
    }
  }

  @Test
  @DisplayName("setBitAndGetBit_whenPositions_expectLsbOrder")
  void setBitAndGetBit_whenPositions_expectLsbOrder() {
    try (BinaryBloomFilter small = new BinaryBloomFilter(8, 0)) {
      // Set only bit 1 → expect underlying byte 0b00000010 (LSB first)
      small.setBit(1);
      assertTrue(small.getBit(1));
      byte[] snapshot = new byte[1];
      int n = small.copyTo(snapshot, 0);
      assertEquals(1, n);
      assertArrayEquals(new byte[] {0b0000_0010}, snapshot);
    }
  }

  @Test
  @DisplayName("addKey_whenAddedTwice_expectIdempotentFilledCount")
  void addKey_whenAddedTwice_expectIdempotentFilledCount() {
    byte[] key = new byte[] {9, 8, 7, 6};
    filter.addKey(key);
    int firstFilled = filter.getFilledCount();
    filter.addKey(key);
    int secondFilled = filter.getFilledCount();
    assertEquals(
        firstFilled, secondFilled, "Adding same key twice should not increase filled bit count");
  }

  @Test
  @DisplayName("copyToAndRecreate_whenWritten_expectSameBehavior")
  void copyToAndRecreate_whenWritten_expectSameBehavior() {
    byte[] k1 = new byte[] {1, 1, 1, 1};
    byte[] k2 = new byte[] {2, 2, 2, 2};
    byte[] k3 = new byte[] {3, 3, 3, 3};
    filter.addKey(k1);
    filter.addKey(k2);
    filter.addKey(k3);

    byte[] buf = new byte[filter.getSizeBytes()];
    int written = filter.copyTo(buf, 0);
    assertEquals(filter.getSizeBytes(), written);

    try (BinaryBloomFilter restored =
        new BinaryBloomFilter(ByteBuffer.wrap(buf), filter.getLength(), filter.getK())) {
      assertTrue(restored.checkFilter(k1));
      assertTrue(restored.checkFilter(k2));
      assertTrue(restored.checkFilter(k3));
    }
  }

  @Test
  @DisplayName("writeTo_whenCalled_expectBytesWrittenToStream")
  void writeTo_whenCalled_expectBytesWrittenToStream() throws IOException {
    try (BinaryBloomFilter small = new BinaryBloomFilter(16, 1)) {
      // Set two bits to produce a stable byte pattern
      small.setBit(0);
      small.setBit(9); // second byte, bit 1

      byte[] expected = new byte[small.getSizeBytes()];
      small.copyTo(expected, 0);

      OutputStream os = mock(OutputStream.class);
      small.writeTo(os);

      ArgumentCaptor<byte[]> arrCap = ArgumentCaptor.forClass(byte[].class);
      ArgumentCaptor<Integer> offCap = ArgumentCaptor.forClass(Integer.class);
      ArgumentCaptor<Integer> lenCap = ArgumentCaptor.forClass(Integer.class);
      verify(os, times(1)).write(arrCap.capture(), offCap.capture(), lenCap.capture());

      assertEquals(0, offCap.getValue());
      assertEquals(expected.length, lenCap.getValue());
      byte[] actual =
          Arrays.copyOfRange(
              arrCap.getValue(), offCap.getValue(), offCap.getValue() + lenCap.getValue());
      assertArrayEquals(expected, actual);
    }
  }

  @Test
  @DisplayName("fork_whenAddKeyForkedThenMerge_expectMainHasForkBits")
  void fork_whenAddKeyForkedThenMerge_expectMainHasForkBits() {
    byte[] a = new byte[] {10, 20, 30, 40};
    byte[] b = new byte[] {11, 21, 31, 41};

    // Use the same k for fork to keep membership checks consistent
    filter.fork(filter.getK());

    filter.addKey(a); // added to both main and fork
    assertTrue(filter.checkFilter(a));

    filter.addKeyForked(b); // only to forked filter
    assertFalse(filter.checkFilter(b), "Before merge, main must not have fork-only key");

    filter.merge();
    assertTrue(filter.checkFilter(b), "After merge, main should contain fork's bits");
  }

  @Test
  @DisplayName("discard_whenCalled_expectForkAbandoned")
  void discard_whenCalled_expectForkAbandoned() {
    byte[] onlyFork = new byte[] {7, 7, 7, 7};
    filter.fork(2);
    filter.addKeyForked(onlyFork);
    assertFalse(filter.checkFilter(onlyFork));

    filter.discard();
    assertFalse(
        filter.checkFilter(onlyFork), "After discard, fork-only bits must not appear in main");

    // Idempotent behavior
    filter.discard();
  }

  @ParameterizedTest
  @DisplayName("constructor_whenLengthNotAligned_expectRoundedDownAndSize")
  @CsvSource({"1,0,0", "2,0,0", "7,0,0", "8,8,1", "9,8,1", "15,8,1", "16,16,2", "17,16,2"})
  void constructor_whenLengthNotAligned_expectRoundedDownAndSize(
      int requestedBits, int expectedBits, int expectedBytes) {
    try (BinaryBloomFilter bf = new BinaryBloomFilter(requestedBits, 3)) {
      assertEquals(expectedBits, bf.getLength());
      assertEquals(expectedBytes, bf.getSizeBytes());
    }
  }

  @Test
  @DisplayName("constructor_whenZeroLength_expectKZero")
  void constructor_whenZeroLength_expectKZero() {
    try (BinaryBloomFilter bf = new BinaryBloomFilter(0, 5)) {
      assertEquals(0, bf.getLength());
      assertEquals(0, bf.getK(), "k must be coerced to 0 for zero-length filters");
    }
  }

  @Test
  @DisplayName("zeroLength_whenCheckAlignedKey_expectTrue")
  void zeroLength_whenCheckAlignedKey_expectTrue() {
    try (BinaryBloomFilter bf = new BinaryBloomFilter(0, 5)) {
      assertTrue(bf.checkFilter(new byte[] {1, 2, 3, 4}));
      assertTrue(bf.checkFilter(new byte[] {9, 9, 9, 9}));
    }
  }

  @Test
  @DisplayName("checkFilter_whenKeyLengthNotMultipleOf4_expectIllegalArgumentException")
  void checkFilter_whenKeyLengthNotMultipleOf4_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> filter.checkFilter(new byte[] {1, 2, 3}));
  }

  @Test
  @DisplayName("addKey_whenKeyLengthNotMultipleOf4_expectIllegalArgumentException")
  void addKey_whenKeyLengthNotMultipleOf4_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> filter.addKey(new byte[] {1}));
  }

  @Test
  @DisplayName("addKey_whenNull_expectNullPointerException")
  void addKey_whenNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> filter.addKey(null));
  }

  @Test
  @DisplayName("checkFilter_whenNull_expectNullPointerException")
  void checkFilter_whenNull_expectNullPointerException() {
    assertThrows(NullPointerException.class, () -> filter.checkFilter(null));
  }

  @Test
  @DisplayName("createFilter_whenNegativeLength_expectIllegalArgumentException")
  void createFilter_whenNegativeLength_expectIllegalArgumentException() {
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          try (var _ = BloomFilter.createFilter(-8, 1, false)) {
            fail("Filter creation should have thrown before entering try block");
          }
        });
  }

  @Test
  @DisplayName("optimialK_whenVariousInputs_expectBounds")
  void optimialK_whenVariousInputs_expectBounds() {
    assertEquals(0, BloomFilter.optimalK(0, 100));
    assertEquals(64, BloomFilter.optimalK(1024, 1), "Large filter vs tiny set caps at 64");
    assertEquals(1, BloomFilter.optimalK(8, 1_000_000), "Small filter vs huge set floors at 1");
  }

  @Nested
  class FileBacked {
    private File tempDir;

    @BeforeEach
    void setupDir() throws IOException {
      File secureRoot = new File("build/securetmp-tests");
      // best-effort owner-only permissions
      if (!secureRoot.exists()) {
        assertTrue(secureRoot.mkdirs(), "Failed to create secure test temp root");
      }
      assertTrue(secureRoot.setReadable(true, true));
      assertTrue(secureRoot.setWritable(true, true));
      assertTrue(secureRoot.setExecutable(true, true));

      tempDir = Files.createTempDirectory(secureRoot.toPath(), "bbf-test-").toFile();
      assertTrue(tempDir.setReadable(true, true));
      assertTrue(tempDir.setWritable(true, true));
      assertTrue(tempDir.setExecutable(true, true));
      tempDir.deleteOnExit();
    }

    @Test
    @DisplayName("fileBacked_whenFirstOpen_expectNeedRebuildTrueThenFalse")
    void fileBacked_whenFirstOpen_expectNeedRebuildTrueThenFalse() throws IOException {
      File f = new File(tempDir, "filter.bin");

      try (BloomFilter bf1 = BloomFilter.createFilter(f, 64, 2, false)) {
        assertTrue(bf1.needRebuild(), "First open should signal rebuild (file missing)");
        assertFalse(bf1.needRebuild(), "Subsequent call should reset flag");
      }

      // Reopen with same size → should not need rebuild
      try (BloomFilter bf2 = BloomFilter.createFilter(f, 64, 2, false)) {
        assertFalse(bf2.needRebuild(), "Second open with correct size should not need rebuild");
      }
    }

    @Test
    @DisplayName("fileBacked_whenSizeChanges_expectNeedRebuildTrue")
    void fileBacked_whenSizeChanges_expectNeedRebuildTrue() throws IOException {
      File f = new File(tempDir, "filter2.bin");
      try (BloomFilter bf1 = BloomFilter.createFilter(f, 64, 2, false)) {
        bf1.needRebuild(); // consume initial true
      }

      // Reopen with different target size → constructor should flag rebuild
      try (BloomFilter bf2 = BloomFilter.createFilter(f, 128, 2, false)) {
        assertTrue(bf2.needRebuild(), "Changing on-disk size should trigger rebuild flag");
      }
    }

    @Test
    @DisplayName("fileBacked_forceAndReopen_expectDataPersists")
    void fileBacked_forceAndReopen_expectDataPersists() throws IOException {
      File f = new File(tempDir, "filter3.bin");
      BloomFilter bf1 = BloomFilter.createFilter(f, 256, 3, false);
      byte[] key = new byte[] {5, 4, 3, 2};
      try {
        bf1.addKey(key);
        bf1.force();
      } finally {
        bf1.close();
      }

      try (BloomFilter bf2 = BloomFilter.createFilter(f, 256, 3, false)) {
        assertTrue(bf2.checkFilter(key), "Mapped bytes should persist across reopen");
      }
    }
  }
}
