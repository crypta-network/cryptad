package network.crypta.crypt;

import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import network.crypta.fs.AppEnv;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.spaceroots.mantissa.random.ScalarSampleStatistics;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class YarrowTest {

  @TempDir Path tempDir;

  private File seedFile;

  @BeforeEach
  void setupSeedFile() throws IOException {
    seedFile = tempDir.resolve("prng-test.seed").toFile();
    // Create a small seed file with deterministic content (fewer than 32 longs)
    try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(seedFile))) {
      for (int i = 0; i < 4; i++) {
        dos.writeLong(i + 1);
      }
    }
  }

  @Test
  @DisplayName("nextDouble: mean≈0.5 and stddev≈1/(2√3) over moderate sample")
  void nextDouble_whenSampled_expectMeanAndStdDevWithinBounds() {
    // Arrange
    Yarrow y = new Yarrow(seedFile, "SHA1", "Rijndael", false, false, false);
    ScalarSampleStatistics sample = new ScalarSampleStatistics();

    // Act
    for (int i = 0; i < 10_000; ++i) {
      sample.add(y.nextDouble());
    }

    // Assert (broad, non‑flaky tolerance)
    assertEquals(0.5, sample.getMean(), 0.02);
    assertEquals(1.0 / (2.0 * Math.sqrt(3.0)), sample.getStandardDeviation(), 0.002);
  }

  @Test
  void nextIntBound_whenCalled_expectWithinRange() {
    // Arrange
    Yarrow y = new Yarrow(seedFile, "SHA1", "Rijndael", false, false, false);

    // Act: sample and bin by the returned index; any out-of-range value would throw
    // during array indexing and fail the test immediately.
    int bound = 37;
    int[] counts = new int[bound];
    int samples = 10_000;
    for (int i = 0; i < samples; i++) {
      counts[y.nextInt(bound)]++;
    }
    int total = 0;
    int min = Integer.MAX_VALUE, max = Integer.MIN_VALUE;
    for (int c : counts) {
      total += c;
      if (c < min) min = c;
      if (c > max) max = c;
    }

    // Assert: all samples accounted for; rough uniformity (max/min within 2x)
    assertEquals(samples, total);
    assertTrue(max <= 2 * Math.max(1, min));
  }

  @Test
  void next_whenRequestingSixteenBitsRepeatedly_expectNoArrayBoundsAndInRange() {
    // Arrange
    Yarrow y = new Yarrow(seedFile, "SHA1", "Rijndael", false, false, false);

    // Act + Assert: repeatedly crossing output buffer boundaries must remain safe.
    for (int i = 0; i < 10_000; i++) {
      int value = y.next(16);
      assertTrue(value >= 0 && value <= 0xFFFF);
    }
  }

  @Test
  void nextBoolean_whenSamplingLarge_expectBalancedCounts() {
    // Arrange
    Yarrow y = new Yarrow(seedFile, "SHA1", "Rijndael", false, false, false);

    // Act
    final int runs = 100_000; // balanced and fast; ~0.6% tolerance is ~3.8σ
    int trues = 0;
    for (int i = 0; i < runs; i++) {
      if (y.nextBoolean()) trues++;
    }

    // Assert
    int falses = runs - trues;
    assertEquals(runs, trues + falses);
    int tolerance = (int) (runs * 0.006); // 0.6%
    assertTrue(Math.abs(trues - falses) <= tolerance, "roughly balanced true/false");
  }

  @Test
  void constructor_whenReseedDisabledAndSeedMissing_expectDeterministicStream() {
    // Arrange: use a seed path that does not exist to avoid external entropy
    File missingSeed = tempDir.resolve("does-not-exist.seed").toFile();
    assertFalse(missingSeed.exists());

    // Act
    Yarrow y1 = new Yarrow(missingSeed, "SHA1", "Rijndael", true, false, false);
    Yarrow y2 = new Yarrow(missingSeed, "SHA1", "Rijndael", true, false, false);

    byte[] a = new byte[64];
    byte[] b = new byte[64];
    y1.nextBytes(a);
    y2.nextBytes(b);

    // Assert: same stream across identical initialization; not all zeros
    assertArrayEquals(a, b);
    boolean allZero = true;
    for (byte v : a)
      if (v != 0) {
        allZero = false;
        break;
      }
    assertFalse(allZero, "stream should not be all zeros");
  }

  @Test
  void writeSeed_whenRateLimited_expectSingleWriteUntilForced() throws Exception {
    // Arrange: updateSeed=true so seedfile is set; reseedOnStartup=false for deterministic test
    Yarrow y = new Yarrow(seedFile, "SHA1", "Rijndael", true, false, false);
    assertNotNull(y.seedfile);

    // Act: first write persists 32 longs
    y.writeSeed(false);
    byte[] first = Files.readAllBytes(seedFile.toPath());

    // Second write within rate limit should be skipped
    y.writeSeed(false);
    byte[] second = Files.readAllBytes(seedFile.toPath());
    Instant secondMtime = Files.getLastModifiedTime(seedFile.toPath()).toInstant();

    // Force write should bypass rate limit
    y.writeSeed(true);
    byte[] third = Files.readAllBytes(seedFile.toPath());
    Instant thirdMtime = Files.getLastModifiedTime(seedFile.toPath()).toInstant();

    // Assert
    assertEquals(32 * Long.BYTES, first.length);
    assertArrayEquals(first, second, "rate-limited write must not change file");
    assertTrue(!thirdMtime.equals(secondMtime) || third.length == first.length);
    // Content after forced write is very likely different; if equal, mtime must differ
    assertTrue(!java.util.Arrays.equals(second, third) || !thirdMtime.equals(secondMtime));
  }

  @Test
  void readSeed_whenShortFile_expectNoExceptionAndStateChanges() throws Exception {
    // Arrange
    Yarrow y = new Yarrow(seedFile, "SHA1", "Rijndael", true, false, false);

    byte[] before = new byte[32];
    y.nextBytes(before);

    // Act: overwrite seed with fewer than 32 longs to trigger EOF handling path
    try (DataOutputStream dos = new DataOutputStream(new FileOutputStream(seedFile))) {
      for (int i = 0; i < 3; i++) dos.writeLong(0xA5A5A5A5A5A5A5A5L + i);
    }
    y.readSeed(seedFile);

    byte[] after = new byte[32];
    y.nextBytes(after);

    // Assert: generator state changed (very unlikely to match previous stream)
    assertFalse(java.util.Arrays.equals(before, after));
  }

  @Test
  void acceptTimerEntropy_whenZeroBias_expectZeroContribution() {
    // Arrange
    Yarrow y = new Yarrow(seedFile, "SHA1", "Rijndael", false, false, false);
    EntropySource timer = new EntropySource();

    // Act
    int contributed = y.acceptTimerEntropy(timer, 0.0);

    // Assert
    assertEquals(0, contributed);
  }

  @Test
  void seedfile_whenPathIsDevUrandom_expectNull() {
    // Arrange & Act
    Yarrow y = new Yarrow(new File("/dev/urandom"), "SHA1", "Rijndael", true, false, false);

    // Assert
    if (new AppEnv().isWindows()) {
      assertNotNull(y.seedfile);
    } else {
      assertNull(y.seedfile);
    }
  }

  @Test
  void serialization_resets_entropy_counters() throws Exception {
    // Arrange: create a Yarrow with deterministic setup
    Yarrow y = new Yarrow(seedFile, "SHA1", "Rijndael", true, false, false);

    // Preload counters with arbitrary non-zero values via reflection
    var fastEntropyField = Yarrow.class.getDeclaredField("fastEntropy");
    fastEntropyField.setAccessible(true);
    fastEntropyField.setInt(y, 93);

    var slowEntropyField = Yarrow.class.getDeclaredField("slowEntropy");
    slowEntropyField.setAccessible(true);
    slowEntropyField.setInt(y, 77);

    // Act: serialize and deserialize
    java.io.ByteArrayOutputStream bout = new java.io.ByteArrayOutputStream();
    try (java.io.ObjectOutputStream oos = new java.io.ObjectOutputStream(bout)) {
      oos.writeObject(y);
    }
    byte[] bytes = bout.toByteArray();

    Yarrow y2;
    try (java.io.ObjectInputStream ois =
        new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(bytes))) {
      y2 = (Yarrow) ois.readObject();
    }

    // Assert: post-deserialization counters are reset to 0 to match empty digests
    var fe2 = Yarrow.class.getDeclaredField("fastEntropy");
    fe2.setAccessible(true);
    var se2 = Yarrow.class.getDeclaredField("slowEntropy");
    se2.setAccessible(true);
    assertEquals(0, fe2.getInt(y2));
    assertEquals(0, se2.getInt(y2));
  }

  @Test
  void serialization_preserves_generator_state() throws Exception {
    // Arrange: deterministic setup and consume some bytes to land mid-stream
    Yarrow y = new Yarrow(seedFile, "SHA1", "Rijndael", true, false, false);
    byte[] pre = new byte[17];
    y.nextBytes(pre);

    // Serialize current state
    byte[] snapshot;
    try (var bout = new java.io.ByteArrayOutputStream();
        var oos = new java.io.ObjectOutputStream(bout)) {
      oos.writeObject(y);
      oos.flush();
      snapshot = bout.toByteArray();
    }

    // Deserialize into a new instance
    Yarrow y2;
    try (var ois = new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(snapshot))) {
      y2 = (Yarrow) ois.readObject();
    }

    // Act: generate the same amount from both and compare
    byte[] a = new byte[64];
    byte[] b = new byte[64];
    y.nextBytes(a); // continue from original
    y2.nextBytes(b); // should match exactly

    // Assert: streams must match after deserialization
    assertArrayEquals(a, b);
  }
}
