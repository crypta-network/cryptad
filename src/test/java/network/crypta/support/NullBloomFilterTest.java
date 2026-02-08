package network.crypta.support;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.File;
import java.io.IOException;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Tests for {@link NullBloomFilter} semantics. The null filter represents a zero-length Bloom
 * filter that always returns positive membership and ignores updates.
 */
@SuppressWarnings("java:S100") // Allow descriptive test method names with underscores
class NullBloomFilterTest {

  // -------- Test data providers --------

  static Stream<byte[]> anyKeysIncludingNull() {
    return Stream.of(
        null,
        new byte[] {},
        new byte[] {1},
        new byte[] {1, 2},
        new byte[] {1, 2, 3},
        new byte[] {1, 2, 3, 4},
        new byte[] {9, 8, 7, 6, 5});
  }

  // -------- Creation --------

  @Test
  @DisplayName("create_whenZeroLengthCountingFalse_expectNullBloomAndKZero")
  void create_whenZeroLengthCountingFalse_expectNullBloomAndKZero() {
    try (BloomFilter bf = BloomFilter.createFilter(0, 7, false)) {
      assertInstanceOf(NullBloomFilter.class, bf);
      assertEquals(0, bf.getK());
      assertEquals(0, bf.getLength());
    }
  }

  @Test
  @DisplayName("create_whenZeroLengthCountingTrue_expectNullBloomAndKZero")
  void create_whenZeroLengthCountingTrue_expectNullBloomAndKZero() {
    try (BloomFilter bf = BloomFilter.createFilter(0, 3, true)) {
      assertInstanceOf(NullBloomFilter.class, bf);
      assertEquals(0, bf.getK());
      assertEquals(0, bf.getLength());
    }
  }

  @Test
  @DisplayName("createFile_whenZeroLength_expectNullBloom")
  void createFile_whenZeroLength_expectNullBloom() throws IOException {
    File f = File.createTempFile("null-bloom", ".bin");
    try (BloomFilter bf = BloomFilter.createFilter(f, 0, 5, false)) {
      assertInstanceOf(NullBloomFilter.class, bf);
      assertEquals(0, bf.getK());
      assertEquals(0, bf.getLength());
    }
    if (!f.delete() && f.exists()) {
      f.deleteOnExit();
    }
  }

  // -------- Semantics --------

  @ParameterizedTest
  @MethodSource("anyKeysIncludingNull")
  @DisplayName("checkFilter_whenAnyKeyIncludingNull_expectAlwaysTrue")
  void checkFilter_whenAnyKeyIncludingNull_expectAlwaysTrue(byte[] key) {
    try (BloomFilter bf = BloomFilter.createFilter(0, 10, false)) {
      assertInstanceOf(NullBloomFilter.class, bf);
      assertTrue(bf.checkFilter(key));
    }
  }

  @ParameterizedTest
  @MethodSource("anyKeysIncludingNull")
  @DisplayName("addAndRemove_whenAnyKeyIncludingNull_expectNoExceptionAndNoChange")
  void addAndRemove_whenAnyKeyIncludingNull_expectNoExceptionAndNoChange(byte[] key) {
    try (BloomFilter bf = BloomFilter.createFilter(0, 10, true)) {
      assertInstanceOf(NullBloomFilter.class, bf);
      assertDoesNotThrow(() -> bf.addKey(key));
      assertDoesNotThrow(() -> bf.removeKey(key));
      // Membership remains true regardless of operations
      assertTrue(bf.checkFilter(key));
      assertEquals(0, bf.getFilledCount());
    }
  }

  // -------- Fork/Discard/Merge no-ops --------

  @Test
  @DisplayName("fork_discard_merge_whenCalled_expectNoEffectAndNoExceptions")
  void fork_discard_merge_whenCalled_expectNoEffectAndNoExceptions() {
    try (BloomFilter bf = BloomFilter.createFilter(0, 5, false)) {
      assertInstanceOf(NullBloomFilter.class, bf);

      // All should be safe no-ops on the null filter
      assertDoesNotThrow(() -> bf.fork(bf.getK()));
      assertDoesNotThrow(bf::discard);
      assertDoesNotThrow(bf::merge);

      // Still behaves as an always-positive, zero-length filter
      assertTrue(bf.checkFilter(new byte[] {1, 2, 3, 4}));
      assertEquals(0, bf.getLength());
    }
  }
}
