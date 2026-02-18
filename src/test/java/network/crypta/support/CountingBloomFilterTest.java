package network.crypta.support;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for {@link CountingBloomFilter} covering counter semantics, file-backed behavior, and
 * fork/merge orchestration.
 */
@SuppressWarnings(
    "java:S100") // Test method names use method_whenCondition_expectOutcome convention
class CountingBloomFilterTest {

  private static int readCounter(CountingBloomFilter f, int offset) {
    // Snapshot the in-memory buffer and decode the 2-bit counter at the given logical position.
    byte[] buf = new byte[f.getSizeBytes()];
    f.copyTo(buf, 0);
    int b = buf[offset / 4] & 0xFF;
    int shift = (offset % 4) * 2;
    return (b >>> shift) & 0x03;
  }

  @Test
  void constructor_whenLengthNotMultipleOf8_roundsDownAndAllocatesCorrectSize() {
    // Arrange + Assert
    try (CountingBloomFilter f = new CountingBloomFilter(10 /* bits */, 3)) {
      assertEquals(8, f.getLength(), "length rounded down to nearest multiple of 8");
      assertEquals(8 / 4, f.getSizeBytes(), "2-bit counters: bytes = length/4");
    }
  }

  @Test
  void setBit_whenCalledRepeatedly_saturatesAtThree() {
    try (CountingBloomFilter f = new CountingBloomFilter(32, 1)) {
      int pos = 0;

      // Initially zero / absent
      assertFalse(f.getBit(pos));
      assertEquals(0, readCounter(f, pos));

      // 1 -> 2 -> 3 -> 3 (saturating)
      f.setBit(pos);
      assertTrue(f.getBit(pos));
      assertEquals(1, readCounter(f, pos));

      f.setBit(pos);
      assertEquals(2, readCounter(f, pos));

      f.setBit(pos);
      assertEquals(3, readCounter(f, pos));

      f.setBit(pos); // still 3
      assertEquals(3, readCounter(f, pos));
    }
  }

  @Test
  void unsetBit_whenZero_noChangeAndRemainsAbsent() {
    try (CountingBloomFilter f = new CountingBloomFilter(32, 1)) {
      f.setWarnOnRemoveFromEmpty(); // should only log; state must remain unchanged

      int pos = 5;
      assertEquals(0, readCounter(f, pos));
      f.unsetBit(pos);
      assertEquals(0, readCounter(f, pos));
      assertFalse(f.getBit(pos));
    }
  }

  @Test
  void unsetBit_whenOne_becomesZero() {
    try (CountingBloomFilter f = new CountingBloomFilter(32, 1)) {
      int pos = 7;
      f.setBit(pos);
      assertEquals(1, readCounter(f, pos));

      f.unsetBit(pos);
      assertEquals(0, readCounter(f, pos));
      assertFalse(f.getBit(pos));
    }
  }

  @Test
  void unsetBit_whenTwo_becomesOne() {
    try (CountingBloomFilter f = new CountingBloomFilter(32, 1)) {
      int pos = 9;
      f.setBit(pos);
      f.setBit(pos);
      assertEquals(2, readCounter(f, pos));

      f.unsetBit(pos);
      assertEquals(1, readCounter(f, pos));
      assertTrue(f.getBit(pos));
    }
  }

  @Test
  void unsetBit_whenThree_noChange() {
    try (CountingBloomFilter f = new CountingBloomFilter(32, 1)) {
      int pos = 3;
      f.setBit(pos);
      f.setBit(pos);
      f.setBit(pos);
      assertEquals(3, readCounter(f, pos));

      f.unsetBit(pos); // 3 is treated as overflow sentinel; no decrement
      assertEquals(3, readCounter(f, pos));
      assertTrue(f.getBit(pos));
    }
  }

  @Test
  void addCheckRemove_whenKEqualsOne_clearsBackToAbsent() {
    try (CountingBloomFilter f = new CountingBloomFilter(64, 1)) {
      byte[] key = new byte[] {1, 2, 3, 4}; // length must be a multiple of 4

      assertFalse(f.checkFilter(key));
      f.addKey(key);
      assertTrue(f.checkFilter(key));

      f.removeKey(key);
      assertFalse(f.checkFilter(key));
    }
  }

  @Test
  void addAndRemove_whenCounterSaturatedAtThree_removalIsIgnored() {
    try (CountingBloomFilter f = new CountingBloomFilter(64, 1)) {
      byte[] key = new byte[] {9, 8, 7, 6};

      // Saturate the single hashed position by adding thrice
      f.addKey(key);
      f.addKey(key);
      f.addKey(key);
      assertTrue(f.checkFilter(key));

      // Removal is ignored at counter==3 per implementation
      f.removeKey(key);
      assertTrue(f.checkFilter(key));
    }
  }

  @Test
  void forkMerge_whenAddingOnlyToFork_appliesOnMerge() {
    try (CountingBloomFilter f = new CountingBloomFilter(64, 1)) {
      byte[] key = new byte[] {10, 11, 12, 13};

      assertFalse(f.checkFilter(key));
      f.fork(1);
      f.addKeyForked(key); // only staged in the fork
      assertFalse(f.checkFilter(key));

      f.merge();
      assertTrue(f.checkFilter(key));
    }
  }

  @Test
  void forkDiscard_whenAddingOnlyToFork_doesNotAffectMain() {
    try (CountingBloomFilter f = new CountingBloomFilter(64, 1)) {
      byte[] key = new byte[] {100, 101, 102, 103};

      f.fork(1);
      f.addKeyForked(key);
      f.discard();
      assertFalse(f.checkFilter(key));
    }
  }

  @Test
  void fileBacked_whenMissingOrWrongSize_setsNeedRebuild(@TempDir Path tmp) throws IOException {
    int length = 32; // bits; bytes for counting bloom = 8
    Path path = tmp.resolve("cbf.dat");
    File file = path.toFile();

    // Missing initially -> needRebuild=true
    CountingBloomFilter f1 = new CountingBloomFilter(file, length, 1);
    assertTrue(f1.needRebuild());
    assertFalse(f1.needRebuild(), "flag clears after read");
    f1.close();

    // Pre-create with wrong size -> still needRebuild
    Files.write(path, new byte[] {0});
    CountingBloomFilter f2 = new CountingBloomFilter(file, length, 1);
    assertTrue(f2.needRebuild());
    f2.close();

    // After resize to correct size by previous ctor, next ctor should not need rebuild
    CountingBloomFilter f3 = new CountingBloomFilter(file, length, 1);
    assertFalse(f3.needRebuild());
    f3.close();
  }

  @Test
  void filledCount_andUnsetAll_behaveAsExpected() {
    try (CountingBloomFilter f = new CountingBloomFilter(32, 1)) {
      assertEquals(0, f.getFilledCount());

      f.setBit(0);
      f.setBit(5);
      f.setBit(5); // counter>0 still counts once
      assertEquals(2, f.getFilledCount());

      f.unsetAll();
      assertEquals(0, f.getFilledCount());
    }
  }
}
