package network.crypta.support;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // allow method names with underscores
class UptimeContainerTest {

  @Test
  void defaults_whenConstructed_expectZeroFields() {
    // Arrange & Act
    UptimeContainer uc = new UptimeContainer();

    // Assert
    assertEquals(0L, uc.getCreationTime(), "Default creationTime should be 0");
    assertEquals(0L, uc.getTotalUptime(), "Default totalUptime should be 0");
  }

  @Test
  @SuppressWarnings("EqualsWithItself")
  void equals_whenSameReference_expectTrue() {
    // Arrange
    UptimeContainer uc = new UptimeContainer();
    uc.setCreationTime(123L);
    uc.setTotalUptime(456L);

    // Act & Assert
    assertEquals(uc, uc);
  }

  @Test
  void equals_whenEqualFields_expectSymmetricAndTransitive() {
    // Arrange
    UptimeContainer a = new UptimeContainer();
    a.setCreationTime(10L);
    a.setTotalUptime(20L);

    UptimeContainer b = new UptimeContainer();
    b.setCreationTime(10L);
    b.setTotalUptime(20L);

    UptimeContainer c = new UptimeContainer();
    c.setCreationTime(10L);
    c.setTotalUptime(20L);

    // Act & Assert (symmetry)
    assertEquals(a, b);
    assertEquals(b, a);

    // Act & Assert (transitivity)
    assertTrue(a.equals(b) && b.equals(c) && a.equals(c));

    // Hash code contract for equal objects
    assertEquals(a.hashCode(), b.hashCode());
    assertEquals(b.hashCode(), c.hashCode());
  }

  @Test
  void equals_whenNull_expectFalse() {
    // Arrange
    UptimeContainer uc = new UptimeContainer();
    uc.setCreationTime(1L);
    uc.setTotalUptime(2L);

    // Act & Assert
    assertNotEquals(null, uc);
  }

  @Test
  @SuppressWarnings("AssertBetweenInconvertibleTypes")
  void equals_whenDifferentClass_expectFalse() {
    // Arrange
    UptimeContainer uc = new UptimeContainer();
    uc.setCreationTime(1L);
    uc.setTotalUptime(2L);

    // Act & Assert
    assertNotEquals("not-a-container", uc);
  }

  static class UptimeContainerSubclass extends UptimeContainer {}

  @Test
  void equals_whenSubclassWithSameFields_expectSymmetricEquality() {
    // Arrange
    UptimeContainer base = new UptimeContainer();
    base.setCreationTime(7L);
    base.setTotalUptime(9L);

    UptimeContainerSubclass sub = new UptimeContainerSubclass();
    sub.setCreationTime(7L);
    sub.setTotalUptime(9L);

    // Act & Assert
    assertEquals(base, sub);
    assertEquals(sub, base);
  }

  @Test
  void equals_whenFieldsDiffer_expectFalse() {
    // Arrange
    UptimeContainer a = new UptimeContainer();
    a.setCreationTime(1L);
    a.setTotalUptime(2L);

    UptimeContainer b = new UptimeContainer();
    b.setCreationTime(1L);
    b.setTotalUptime(3L); // differs

    // Act & Assert
    assertNotEquals(a, b);
  }

  @Test
  void equals_whenMutatedAfterEquality_expectNowFalse() {
    // Arrange
    UptimeContainer a = new UptimeContainer();
    a.setCreationTime(42L);
    a.setTotalUptime(100L);
    UptimeContainer b = new UptimeContainer();
    b.setCreationTime(42L);
    b.setTotalUptime(100L);
    assertEquals(a, b);

    // Act
    a.setTotalUptime(101L); // mutate

    // Assert
    assertNotEquals(a, b);
  }

  @Test
  void addFrom_whenValidInput_expectCreationFromLatestAndSumTotal() {
    // Arrange
    UptimeContainer base = new UptimeContainer();
    base.setCreationTime(1000L);
    base.setTotalUptime(500L);

    UptimeContainer latest = new UptimeContainer();
    latest.setCreationTime(2000L);
    latest.setTotalUptime(300L);

    // Act
    base.addFrom(latest);

    // Assert
    assertEquals(2000L, base.getCreationTime());
    assertEquals(800L, base.getTotalUptime());
    // Ensure source unchanged
    assertEquals(2000L, latest.getCreationTime());
    assertEquals(300L, latest.getTotalUptime());
  }

  @Test
  void addFrom_whenMultipleAdds_expectAccumulatedTotalAndLatestCreation() {
    // Arrange
    UptimeContainer base = new UptimeContainer();
    base.setCreationTime(10L);
    base.setTotalUptime(1L);

    UptimeContainer l1 = new UptimeContainer();
    l1.setCreationTime(20L);
    l1.setTotalUptime(2L);

    UptimeContainer l2 = new UptimeContainer();
    l2.setCreationTime(30L);
    l2.setTotalUptime(3L);

    // Act
    base.addFrom(l1);
    base.addFrom(l2);

    // Assert
    assertEquals(30L, base.getCreationTime());
    assertEquals(1L + 2L + 3L, base.getTotalUptime());
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void addFrom_whenNullLatest_expectNullPointerException() {
    // Arrange
    UptimeContainer base = new UptimeContainer();

    // Act & Assert
    assertThrows(NullPointerException.class, () -> base.addFrom(null));
  }

  @Test
  void addFrom_whenOverflowOccurs_expectJavaLongWraparound() {
    // Arrange
    UptimeContainer base = new UptimeContainer();
    base.setCreationTime(1L);
    base.setTotalUptime(Long.MAX_VALUE);

    UptimeContainer latest = new UptimeContainer();
    latest.setCreationTime(2L);
    latest.setTotalUptime(1L);

    long expected = base.getTotalUptime() + latest.getTotalUptime(); // wraparound to Long.MIN_VALUE

    // Act
    base.addFrom(latest);

    // Assert
    assertEquals(2L, base.getCreationTime());
    assertEquals(expected, base.getTotalUptime());
  }

  @Test
  void serialization_whenRoundTrip_expectEqualAndIndependentInstance()
      throws IOException, ClassNotFoundException {
    // Arrange
    UptimeContainer original = new UptimeContainer();
    original.setCreationTime(123456789L);
    original.setTotalUptime(987654321L);

    // Act — serialize then deserialize
    byte[] bytes;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(bos)) {
      oos.writeObject(original);
      oos.flush();
      bytes = bos.toByteArray();
    }

    UptimeContainer restored;
    try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(bytes))) {
      Object obj = ois.readObject();
      restored = (UptimeContainer) obj;
    }

    // Assert — equal by value and not the same reference
    assertEquals(original, restored);
    assertEquals(original.hashCode(), restored.hashCode());
    assertNotSame(original, restored);
  }
}
