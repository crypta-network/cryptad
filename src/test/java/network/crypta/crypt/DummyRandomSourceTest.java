package network.crypta.crypt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

@SuppressWarnings("java:S100")
class DummyRandomSourceTest {

  @Test
  void seededConstructor_whenSameSeed_producesIdenticalSequences() {
    // Arrange
    long seed = 123456789L;
    DummyRandomSource r1 = new DummyRandomSource(seed);
    DummyRandomSource r2 = new DummyRandomSource(seed);

    // Act
    int[] ints1 = new int[5];
    int[] ints2 = new int[5];
    long[] longs1 = new long[3];
    long[] longs2 = new long[3];
    byte[] bytes1 = new byte[32];
    byte[] bytes2 = new byte[32];

    for (int i = 0; i < ints1.length; i++) {
      ints1[i] = r1.nextInt();
      ints2[i] = r2.nextInt();
    }
    for (int i = 0; i < longs1.length; i++) {
      longs1[i] = r1.nextLong();
      longs2[i] = r2.nextLong();
    }
    r1.nextBytes(bytes1);
    r2.nextBytes(bytes2);

    // Assert
    assertArrayEquals(ints2, ints1, "nextInt() sequences must match for identical seeds");
    assertArrayEquals(longs2, longs1, "nextLong() sequences must match for identical seeds");
    assertArrayEquals(bytes2, bytes1, "nextBytes() output must match for identical seeds");
  }

  @Test
  void setSeed_whenCalled_resetsSequenceToSeededStart() {
    // Arrange
    DummyRandomSource r = new DummyRandomSource(98765L);
    // burn some values
    int before = r.nextInt();
    long beforeLong = r.nextLong();

    // Act
    r.setSeed(42L);
    DummyRandomSource expected = new DummyRandomSource(42L);

    int[] intsActual = new int[4];
    int[] intsExpected = new int[4];
    for (int i = 0; i < intsActual.length; i++) {
      intsActual[i] = r.nextInt();
      intsExpected[i] = expected.nextInt();
    }

    // Assert
    assertNotEquals(0, before ^ (int) beforeLong, "pre-seed-change values should be consumed");
    assertArrayEquals(
        intsExpected, intsActual, "setSeed must reset sequence to deterministic start");
  }

  @Test
  void defaultConstructor_thenSetSeed_matchesSeededConstructor() {
    // Arrange
    long seed = 24680L;
    DummyRandomSource r1 = new DummyRandomSource();
    DummyRandomSource r2 = new DummyRandomSource(seed);

    // Act
    r1.setSeed(seed);
    int[] a = new int[6];
    int[] b = new int[6];
    for (int i = 0; i < a.length; i++) {
      a[i] = r1.nextInt();
      b[i] = r2.nextInt();
    }

    // Assert
    assertArrayEquals(b, a, "Sequences must be identical when seeds are equal");
  }

  @Test
  void nextFullFloat_whenComparedWithNextInt_hasSameRawBits() {
    // Arrange
    long seed = 13579L;
    DummyRandomSource rFloat = new DummyRandomSource(seed);
    DummyRandomSource rInt = new DummyRandomSource(seed);

    // Act
    float f = rFloat.nextFullFloat();
    int i = rInt.nextInt();

    // Assert
    assertEquals(
        i, Float.floatToRawIntBits(f), "nextFullFloat must be constructed from nextInt bits");
  }

  @Test
  void nextFullDouble_whenComparedWithNextLong_hasSameRawBits() {
    // Arrange
    long seed = 86420L;
    DummyRandomSource rDouble = new DummyRandomSource(seed);
    DummyRandomSource rLong = new DummyRandomSource(seed);

    // Act
    double d = rDouble.nextFullDouble();
    long l = rLong.nextLong();

    // Assert
    assertEquals(
        l, Double.doubleToRawLongBits(d), "nextFullDouble must be constructed from nextLong bits");
  }

  @Test
  void acceptMethods_whenCalled_returnZeroAndPreserveSequence() {
    // Arrange
    long seed = 111L;
    DummyRandomSource rAffected = new DummyRandomSource(seed);
    DummyRandomSource rBaseline = new DummyRandomSource(seed);
    EntropySource source = new EntropySource();

    // Act
    int ret1 = rAffected.acceptEntropy(source, 123L, 7);
    int ret2 = rAffected.acceptTimerEntropy(source);
    int ret3 = rAffected.acceptTimerEntropy(source, 1.25); // out-of-range bias should still be ok
    int ret4 = rAffected.acceptEntropyBytes(source, null, 0, 0, -0.5); // null buffer allowed here

    // Assert
    assertEquals(0, ret1, "acceptEntropy must return 0");
    assertEquals(0, ret2, "acceptTimerEntropy(timer) must return 0");
    assertEquals(0, ret3, "acceptTimerEntropy(timer,bias) must return 0");
    assertEquals(0, ret4, "acceptEntropyBytes must return 0");

    // And PRNG stream must be unaffected by the above no-op methods
    for (int i = 0; i < 10; i++) {
      assertEquals(
          rBaseline.nextInt(),
          rAffected.nextInt(),
          "Entropy-accepting methods must not disturb the PRNG sequence");
    }
  }

  @Test
  void acceptEntropyBytes_whenNormalBuffer_returnsZeroAndDoesNotThrow() {
    // Arrange
    DummyRandomSource r = new DummyRandomSource(999L);
    EntropySource src = new EntropySource();
    byte[] buf = new byte[8];

    // Act & Assert
    assertEquals(
        0,
        r.acceptEntropyBytes(src, buf, 2, 4, 1.0),
        "Expected 0 from DummyRandomSource.acceptEntropyBytes");
  }

  @Test
  void close_whenCalled_doesNotThrow_andPRNGStillWorks() {
    // Arrange
    DummyRandomSource r1 = new DummyRandomSource(77L);
    DummyRandomSource r2 = new DummyRandomSource(77L);

    // Act
    assertDoesNotThrow(r1::close, "close() should be a no-op");

    // Assert
    for (int i = 0; i < 6; i++) {
      assertEquals(r2.nextInt(), r1.nextInt(), "close() must not alter the PRNG sequence");
    }
  }
}
