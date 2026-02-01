package network.crypta.support;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

// Mockito is available for I/O/time mocking; not needed here.

/** Tests for {@link BandwidthStatsContainer}. */
class BandwidthStatsContainerTest {

  private static BandwidthStatsContainer newContainer(long ct, long out, long in) {
    BandwidthStatsContainer b = new BandwidthStatsContainer();
    b.setCreationTime(ct);
    b.setTotalBytesOut(out);
    b.setTotalBytesIn(in);
    return b;
  }

  @Test
  void equalsWhenDefaultsExpectTrue() {
    // Arrange
    BandwidthStatsContainer a = new BandwidthStatsContainer();
    BandwidthStatsContainer b = new BandwidthStatsContainer();

    // Act & Assert
    assertEquals(a, b);
    assertEquals(b, a);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void equalsWhenComparedWithNullExpectFalse() {
    // Arrange
    BandwidthStatsContainer a = new BandwidthStatsContainer();

    // Act & Assert
    assertNotEquals(null, a);
  }

  @Test
  void equalsWhenComparedWithDifferentClassExpectFalse() {
    // Arrange
    BandwidthStatsContainer a = new BandwidthStatsContainer();
    Object other = new Object();

    // Act & Assert
    assertNotEquals(a, other);
  }

  static class BWSubclass extends BandwidthStatsContainer {}

  @Test
  void equalsWhenComparedWithSubclassExpectSymmetricEquality() {
    // Arrange
    BandwidthStatsContainer a = new BandwidthStatsContainer();
    BandwidthStatsContainer sub = new BWSubclass();

    // Act & Assert
    assertEquals(a, sub);
    assertEquals(sub, a);
  }

  @Test
  void equalsWhenReflexiveSymmetricTransitiveExpectAllHold() {
    // Arrange
    BandwidthStatsContainer a = newContainer(10L, 20L, 30L);
    BandwidthStatsContainer b = newContainer(10L, 20L, 30L);
    BandwidthStatsContainer c = newContainer(10L, 20L, 30L);

    // Assert reflexive
    //noinspection EqualsWithItself
    assertEquals(a, a);
    // Assert symmetric
    assertEquals(a, b);
    assertEquals(b, a);
    // Assert transitive
    assertEquals(a, b);
    assertEquals(b, c);
    assertEquals(a, c);
  }

  static Stream<Arguments> unequalFieldProvider() {
    return Stream.of(
        Arguments.of(newContainer(1L, 0L, 0L), newContainer(2L, 0L, 0L), "creationTime"),
        Arguments.of(newContainer(0L, 1L, 0L), newContainer(0L, 2L, 0L), "totalBytesOut"),
        Arguments.of(newContainer(0L, 0L, 1L), newContainer(0L, 0L, 2L), "totalBytesIn"));
  }

  @ParameterizedTest(name = "equals false when {2} differs")
  @MethodSource("unequalFieldProvider")
  void equalsWhenAnyFieldDiffersExpectFalse(
      BandwidthStatsContainer a, BandwidthStatsContainer b, String differingField) {
    // Act & Assert
    assertNotEquals(a, b, () -> "Expected inequality when " + differingField + " differs");
    assertNotEquals(
        b, a, () -> "Expected inequality when " + differingField + " differs (symmetry)");
  }

  @Test
  void hashCodeWhenObjectsEqualExpectSameHash() {
    // Arrange
    BandwidthStatsContainer a = newContainer(111L, 222L, 333L);
    BandwidthStatsContainer b = newContainer(111L, 222L, 333L);

    // Act & Assert
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void hashCodeWhenCalledRepeatedlyExpectConsistentValue() {
    // Arrange
    BandwidthStatsContainer a = newContainer(7L, 8L, 9L);

    // Act
    int first = a.hashCode();
    int second = a.hashCode();
    int third = a.hashCode();

    // Assert
    assertEquals(first, second);
    assertEquals(second, third);
  }

  @Test
  void addFromWhenAddingTypicalValuesExpectTotalsAddedAndCreationUnchanged() {
    // Arrange
    BandwidthStatsContainer base = newContainer(1000L, 10L, 20L);
    BandwidthStatsContainer inc = newContainer(2000L, 5L, 7L);

    // Act
    base.addFrom(inc);

    // Assert
    assertEquals(1000L, base.getCreationTime(), "creationTime must not change");
    assertEquals(15L, base.getTotalBytesOut());
    assertEquals(27L, base.getTotalBytesIn());
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void addFromWhenLatestIsNullExpectNullPointerException() {
    // Arrange
    BandwidthStatsContainer base = newContainer(0L, 1L, 1L);

    // Act & Assert
    assertThrows(NullPointerException.class, () -> base.addFrom(null));
  }

  @Test
  void addFromWhenBoundaryOverflowExpectWrapAround() {
    // Arrange
    BandwidthStatsContainer base = newContainer(0L, Long.MAX_VALUE, Long.MAX_VALUE);
    BandwidthStatsContainer inc = newContainer(0L, 1L, 1L);

    // Act
    base.addFrom(inc);

    // Assert (Java long overflow wraps per two's complement)
    assertEquals(Long.MIN_VALUE, base.getTotalBytesOut());
    assertEquals(Long.MIN_VALUE, base.getTotalBytesIn());
  }

  @Nested
  @DisplayName("Serialization")
  class SerializationTests {
    @Test
    void serializationWhenRoundTrippedExpectEqualObject() throws Exception {
      // Arrange
      BandwidthStatsContainer original = newContainer(123L, 456L, 789L);

      // Act
      byte[] bytes;
      try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
          ObjectOutputStream oos = new ObjectOutputStream(bos)) {
        oos.writeObject(original);
        oos.flush();
        bytes = bos.toByteArray();
      }
      BandwidthStatsContainer restored;
      try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes);
          ObjectInputStream ois = new ObjectInputStream(bis)) {
        restored = (BandwidthStatsContainer) ois.readObject();
      }

      // Assert
      assertEquals(original, restored);
      assertEquals(original.hashCode(), restored.hashCode());
      assertThat(restored.getCreationTime(), is(123L));
      assertThat(restored.getTotalBytesOut(), is(456L));
      assertThat(restored.getTotalBytesIn(), is(789L));
    }
  }
}
