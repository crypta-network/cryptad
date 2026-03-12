package network.crypta.support;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;
import network.crypta.support.math.MersenneTwister;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Deterministic, comprehensive tests for {@link BloomFilter} public API across binary and counting
 * implementations.
 */
@SuppressWarnings("java:S100") // Allow descriptive test method names with underscores
class BloomFilterTest {

  // -------- Helpers --------

  private static int indexFor(byte[] key, int length) {
    return MersenneTwister.createUnsynchronized(key).nextInt(length);
  }

  private static byte[] keyWithDifferentIndex(byte[] base, int length) {
    int baseIdx = indexFor(base, length);
    for (int i = 0; i < 10_000; i++) {
      byte[] k = new byte[] {(byte) i, 0, 0, 0};
      if (indexFor(k, length) != baseIdx) return k;
    }
    throw new IllegalStateException("Failed to find non-colliding key deterministically");
  }

  private static byte[] keyDifferentFromAll(int length, int... usedIdx) {
    for (int i = 0; i < 20_000; i++) {
      byte[] k = new byte[] {(byte) (i & 0xFF), (byte) ((i >>> 8) & 0xFF), 0, 0};
      int idx = indexFor(k, length);
      boolean clash = false;
      for (int u : usedIdx)
        if (idx == u) {
          clash = true;
          break;
        }
      if (!clash) return k;
    }
    throw new IllegalStateException("Failed to find suitable distinct key deterministically");
  }

  /**
   * Helper used by assertThrows lambdas so each lambda performs a single invocation that may throw.
   * Ensures any created BloomFilter is properly closed while keeping the try block non-empty.
   */
  private static void createAndClose(int length, int k, boolean counting) {
    try (BloomFilter bf = BloomFilter.createFilter(length, k, counting)) {
      // Touch the resource so it's not flagged as unused, without performing any extra risky calls
      int ignore = bf.getK();
      if (ignore == Integer.MIN_VALUE) {
        throw new AssertionError("unreachable");
      }
    }
  }

  // -------- Creation & basics --------

  @Test
  @DisplayName("createFilter_whenNegativeLength_expectIllegalArgumentException")
  void createFilter_whenNegativeLength_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> createAndClose(-1, 1, false));
    assertThrows(IllegalArgumentException.class, () -> createAndClose(-1, 1, true));
  }

  @Test
  @DisplayName("createFilter_whenNegativeK_expectIllegalArgumentException")
  void createFilter_whenNegativeK_expectIllegalArgumentException() {
    assertThrows(IllegalArgumentException.class, () -> createAndClose(8, -1, false));
    assertThrows(IllegalArgumentException.class, () -> createAndClose(8, -2, true));
  }

  @ParameterizedTest
  @DisplayName("createFilter_whenLengthNotMultipleOf8_expectRoundedDownAndCorrectSize")
  @CsvSource({"false,1,0", "false,8,1", "false,9,1", "false,17,2", "true,8,2", "true,16,4"})
  void createFilter_whenLengthNotMultipleOf8_expectRoundedDownAndCorrectSize(
      boolean counting, int requestedBits, int expectedBytes) {
    try (BloomFilter bf = BloomFilter.createFilter(requestedBits, 3, counting)) {
      int expectedBits = requestedBits - (requestedBits % 8);
      assertEquals(expectedBits, bf.getLength());
      assertEquals(expectedBytes, bf.getSizeBytes());
    }
  }

  @Test
  @DisplayName("createFilter_whenZeroLength_expectNullBloomAndKZero")
  void createFilter_whenZeroLength_expectNullBloomAndKZero() {
    try (BloomFilter bf = BloomFilter.createFilter(0, 5, false)) {
      assertInstanceOf(NullBloomFilter.class, bf);
      assertEquals(0, bf.getK());
      assertTrue(bf.checkFilter(new byte[] {1, 2, 3, 4}));
    }
  }

  @Test
  @DisplayName("optimalK_whenVariousInputs_expectBoundsAndZeroForEmpty")
  void optimalK_whenVariousInputs_expectBoundsAndZeroForEmpty() {
    assertEquals(0, BloomFilter.optimalK(0, 100));
    assertEquals(64, BloomFilter.optimalK(1024, 1));
    assertEquals(1, BloomFilter.optimalK(8, 1_000_000));
  }

  // -------- Membership semantics --------

  @ParameterizedTest
  @DisplayName("addKeyAndCheck_whenSameKey_expectTrue")
  @CsvSource({"false", "true"})
  void addKeyAndCheck_whenSameKey_expectTrue(boolean counting) {
    try (BloomFilter bf = BloomFilter.createFilter(256, 3, counting)) {
      byte[] key = new byte[] {1, 2, 3, 4};
      bf.addKey(key);
      assertTrue(bf.checkFilter(key));
    }
  }

  @ParameterizedTest
  @DisplayName("addKey_whenK1DifferentKey_expectFalse")
  @CsvSource({"false", "true"})
  void addKey_whenK1DifferentKey_expectFalse(boolean counting) {
    int length = 512;
    try (BloomFilter bf = BloomFilter.createFilter(length, 1, counting)) {
      byte[] k1 = new byte[] {9, 9, 9, 9};
      byte[] k2 = keyWithDifferentIndex(k1, length);
      bf.addKey(k1);
      assertFalse(bf.checkFilter(k2));
    }
  }

  @ParameterizedTest
  @DisplayName("unsetAll_whenCalled_expectFilledCountZero")
  @CsvSource({"false", "true"})
  void unsetAll_whenCalled_expectFilledCountZero(boolean counting) {
    try (BloomFilter bf = BloomFilter.createFilter(256, 3, counting)) {
      bf.addKey(new byte[] {1, 1, 1, 1});
      bf.addKey(new byte[] {2, 2, 2, 2});
      assertTrue(bf.getFilledCount() > 0);
      bf.unsetAll();
      assertEquals(0, bf.getFilledCount());
    }
  }

  // -------- Fork/Merge/Discard --------

  @ParameterizedTest
  @DisplayName("fork_merge_whenApplied_expectMainEqualsForkAndPreForkLost")
  @CsvSource({"false", "true"})
  void fork_merge_whenApplied_expectMainEqualsForkAndPreForkLost(boolean counting) {
    int length = 1024; // ensure many indices to avoid incidental collisions
    try (BloomFilter bf = BloomFilter.createFilter(length, 1, counting)) {
      byte[] a = new byte[] {10, 20, 30, 40};
      int ia = indexFor(a, length);
      bf.addKey(a); // pre-fork content
      assertTrue(bf.checkFilter(a));

      bf.fork(bf.getK());

      byte[] b = keyDifferentFromAll(length, ia);
      int ib = indexFor(b, length);
      bf.addKey(b); // mirrored to fork
      assertTrue(bf.checkFilter(b));

      byte[] c = keyDifferentFromAll(length, ia, ib);
      bf.addKeyForked(c); // only on fork
      assertFalse(bf.checkFilter(c));

      bf.merge();

      // After merge, main should equal fork — contains b and c but not the pre-fork a
      assertTrue(bf.checkFilter(b));
      assertTrue(bf.checkFilter(c));
      assertFalse(bf.checkFilter(a));
    }
  }

  @ParameterizedTest
  @DisplayName("discard_whenCalled_expectForkAbandonedAndNoChangeOnMain")
  @CsvSource({"false", "true"})
  void discard_whenCalled_expectForkAbandonedAndNoChangeOnMain(boolean counting) {
    try (BloomFilter bf = BloomFilter.createFilter(256, 2, counting)) {
      byte[] base = new byte[] {1, 2, 3, 4};
      byte[] onlyFork = new byte[] {5, 6, 7, 8};

      bf.addKey(base);
      assertTrue(bf.checkFilter(base));

      bf.fork(bf.getK());
      bf.addKeyForked(onlyFork);
      assertFalse(bf.checkFilter(onlyFork));

      bf.discard();
      assertFalse(bf.checkFilter(onlyFork));
      assertTrue(bf.checkFilter(base));

      // Idempotent
      bf.discard();
    }
  }

  // -------- I/O & size --------

  @Test
  @DisplayName("copyToAndWriteTo_whenCounting_expectSameBytes")
  void copyToAndWriteTo_whenCounting_expectSameBytes() throws IOException {
    try (BloomFilter bf = BloomFilter.createFilter(16, 2, true)) { // 4 bytes backing array
      // Perform deterministic updates
      bf.addKey(new byte[] {1, 0, 0, 0});
      bf.addKey(new byte[] {2, 0, 0, 0});

      byte[] expected = new byte[bf.getSizeBytes()];
      int n = bf.copyTo(expected, 0);
      assertEquals(expected.length, n);

      OutputStream os = mock(OutputStream.class);
      bf.writeTo(os);

      ArgumentCaptor<byte[]> arrCap = ArgumentCaptor.forClass(byte[].class);
      ArgumentCaptor<Integer> offCap = ArgumentCaptor.forClass(Integer.class);
      ArgumentCaptor<Integer> lenCap = ArgumentCaptor.forClass(Integer.class);
      verify(os, times(1)).write(arrCap.capture(), offCap.capture(), lenCap.capture());

      byte[] actual =
          Arrays.copyOfRange(
              arrCap.getValue(), offCap.getValue(), offCap.getValue() + lenCap.getValue());
      assertArrayEquals(expected, actual);
    }
  }

  @Test
  @DisplayName("checkAndAdd_whenKeyLengthNotMultipleOf4_expectIllegalArgumentException")
  void checkAndAdd_whenKeyLengthNotMultipleOf4_expectIllegalArgumentException() {
    try (BloomFilter bf = BloomFilter.createFilter(64, 2, false)) {
      assertThrows(IllegalArgumentException.class, () -> bf.checkFilter(new byte[] {1, 2, 3}));
      assertThrows(IllegalArgumentException.class, () -> bf.addKey(new byte[] {1}));
    }
  }

  // -------- File-backed rebuild flag (Counting variant) --------

  @Test
  @DisplayName("fileBackedCounting_whenFirstOpen_expectNeedRebuildTrueThenFalse")
  void fileBackedCounting_whenFirstOpen_expectNeedRebuildTrueThenFalse(@TempDir File tempDir)
      throws IOException {
    File f = new File(tempDir, "counting.bloom");
    try (BloomFilter bf1 = BloomFilter.createFilter(f, 64, 2, true)) {
      assertTrue(bf1.needRebuild(), "First open should request rebuild");
      assertFalse(bf1.needRebuild(), "Flag resets after read");
    }

    try (BloomFilter bf2 = BloomFilter.createFilter(f, 64, 2, true)) {
      assertFalse(bf2.needRebuild(), "Second open with same size should not need rebuild");
    }
  }

  @Test
  @DisplayName("fileBackedCounting_whenSizeChanges_expectNeedRebuildTrue")
  void fileBackedCounting_whenSizeChanges_expectNeedRebuildTrue(@TempDir File tempDir)
      throws IOException {
    File f = new File(tempDir, "counting2.bloom");
    try (BloomFilter bf1 = BloomFilter.createFilter(f, 64, 2, true)) {
      bf1.needRebuild(); // consume initial true
    }

    try (BloomFilter bf2 = BloomFilter.createFilter(f, 128, 2, true)) {
      assertTrue(bf2.needRebuild(), "Changing target size should flag rebuild");
    }
  }

  @Test
  @DisplayName("fileBackedBinary_forceAndReopen_expectDataPersists")
  void fileBackedBinary_forceAndReopen_expectDataPersists(@TempDir File tempDir)
      throws IOException {
    File f = new File(tempDir, "binary.bloom");
    byte[] key = new byte[] {5, 4, 3, 2};
    try (BloomFilter bf1 = BloomFilter.createFilter(f, 256, 3, false)) {
      bf1.addKey(key);
      bf1.force();
    }

    try (BloomFilter bf2 = BloomFilter.createFilter(f, 256, 3, false)) {
      assertTrue(bf2.checkFilter(key));
    }
  }
}
