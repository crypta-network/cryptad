package network.crypta.client.async;

import java.util.Arrays;
import java.util.function.Supplier;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class HealingDecisionSupplierTest {

  @Test
  void healingAlwaysTriggersForDarknet() {
    for (double randomValue :
        Arrays.asList(1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.00000001)) {
      assertHeals(getHealingDecisionSupplier(0.1, false, randomValue), 0.5, randomValue);
    }
  }

  @Test
  void healingAlwaysAcceptsAKeyAtTheNodeLocation() {
    for (double randomValue :
        Arrays.asList(1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.00000001)) {
      assertHeals(getHealingDecisionSupplier(0.1, true, randomValue), 0.1, randomValue);
    }
  }

  @Test
  void healingAccepts70PercentOfKeysInShortDistance() {
    for (double randomValue : Arrays.asList(1.0, 0.9, 0.8, 0.7, 0.6, 0.5, 0.4)) {
      assertHeals(getHealingDecisionSupplier(0.1, true, randomValue), 0.11, randomValue);
    }
    for (double randomValue : Arrays.asList(0.3, 0.2, 0.1, 0.00000001)) {
      assertDoesNotHeal(getHealingDecisionSupplier(0.1, true, randomValue), 0.11, randomValue);
    }
  }

  @Test
  void healingAccepts50PercentOfKeysAtTheLimitOfLongDistance() {
    for (double randomValue : Arrays.asList(1.0, 0.9, 0.8, 0.7, 0.6)) {
      assertHeals(getHealingDecisionSupplier(0.1, true, randomValue), 0.1999, randomValue);
    }
    for (double randomValue : Arrays.asList(0.5, 0.4, 0.3, 0.2, 0.1, 0.00000001)) {
      assertDoesNotHeal(getHealingDecisionSupplier(0.1, true, randomValue), 0.1999, randomValue);
    }
  }

  @Test
  void healingAccepts50PercentOfKeysAtTheLimitOfLongDistanceAtADifferentNodeLocationToo() {
    for (double randomValue : Arrays.asList(1.0, 0.9, 0.8, 0.7, 0.6)) {
      HealingDecisionSupplier healingDecisionSupplier =
          getHealingDecisionSupplier(0.6, true, randomValue);
      assertHeals(healingDecisionSupplier, 0.6999, randomValue);
      assertHeals(healingDecisionSupplier, 0.5001, randomValue);
    }
    for (double randomValue : Arrays.asList(0.5, 0.4, 0.3, 0.2, 0.1, 0.00000001)) {
      HealingDecisionSupplier healingDecisionSupplier =
          getHealingDecisionSupplier(0.6, true, randomValue);
      assertDoesNotHeal(healingDecisionSupplier, 0.1999, randomValue);
      assertDoesNotHeal(healingDecisionSupplier, 0.5001, randomValue);
    }
  }

  @Test
  void healingAccepts50PercentOfKeysAtTheLimitOfLongDistanceAroundZero() {
    for (double randomValue : Arrays.asList(1.0, 0.9, 0.8, 0.7, 0.6)) {
      HealingDecisionSupplier healingDecisionSupplier =
          getHealingDecisionSupplier(0.0001, true, randomValue);
      assertHeals(healingDecisionSupplier, 0.1, randomValue);
      assertHeals(healingDecisionSupplier, 0.9002, randomValue);
    }
    for (double randomValue : Arrays.asList(1.0, 0.9, 0.8, 0.7, 0.6)) {
      HealingDecisionSupplier healingDecisionSupplier =
          getHealingDecisionSupplier(0.9999, true, randomValue);
      assertHeals(healingDecisionSupplier, 0.0998, randomValue);
      assertHeals(healingDecisionSupplier, 0.9000, randomValue);
    }
    for (double randomValue : Arrays.asList(0.5, 0.4, 0.3, 0.2, 0.1, 0.00000001)) {
      HealingDecisionSupplier healingDecisionSupplier =
          getHealingDecisionSupplier(0.0001, true, randomValue);
      assertDoesNotHeal(healingDecisionSupplier, 0.1, randomValue);
      assertDoesNotHeal(healingDecisionSupplier, 0.9002, randomValue);
    }
    for (double randomValue : Arrays.asList(0.5, 0.4, 0.3, 0.2, 0.1, 0.00000001)) {
      HealingDecisionSupplier healingDecisionSupplier =
          getHealingDecisionSupplier(0.9999, true, randomValue);
      assertDoesNotHeal(healingDecisionSupplier, 0.0998, randomValue);
      assertDoesNotHeal(healingDecisionSupplier, 0.9000, randomValue);
    }
  }

  @Test
  void healingAccepts10PercentOfKeysAtLongDistance() {
    for (double randomValue : Arrays.asList(1.0, 0.91)) {
      assertHeals(getHealingDecisionSupplier(0.1, true, randomValue), 0.21, randomValue);
    }
    for (double randomValue :
        Arrays.asList(0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.00000001)) {
      assertDoesNotHeal(getHealingDecisionSupplier(0.1, true, randomValue), 0.21, randomValue);
    }
  }

  @Test
  void shouldHeal_whenOpennetDisabled_randomSupplierNotInvoked() {
    // Arrange: random supplier would fail if invoked
    Supplier<Double> randomThrowing =
        () -> {
          throw new AssertionError("Random supplier must not be called when opennet is disabled");
        };
    HealingDecisionSupplier supplier =
        new HealingDecisionSupplier(() -> 0.25, () -> false, randomThrowing);

    // Act
    boolean result = supplier.shouldHeal(0.33);

    // Assert
    assertThat("Darknet should always heal", result, Matchers.equalTo(true));
  }

  @Test
  void shouldHeal_whenDistanceExactlyPointOne_randomAboveThreshold_accepts() {
    // Arrange: node at 0.0, key at 0.1 -> distance = 0.1 (far branch)
    double randomValue = 0.95; // > 0.9 -> should accept in far branch
    HealingDecisionSupplier supplier = getHealingDecisionSupplier(0.0, true, randomValue);

    // Act / Assert
    assertHeals(supplier, 0.1, randomValue);
  }

  @Test
  void shouldHeal_whenDistanceExactlyPointOne_randomEqualPointNine_rejects() {
    // Arrange: node at 0.0, key at 0.1 -> distance = 0.1 (far branch)
    double randomValue = 0.9; // == 0.9 -> strictly not greater, should reject
    HealingDecisionSupplier supplier = getHealingDecisionSupplier(0.0, true, randomValue);

    // Act / Assert
    assertDoesNotHeal(supplier, 0.1, randomValue);
  }

  @Test
  void shouldHeal_whenDistanceEqualsRandomPower4_rejectsStrictInequality() {
    // Arrange: choose r=0.5 so r^4 = 0.0625 exactly; set distance exactly to 0.0625
    double randomValue = 0.5;
    HealingDecisionSupplier supplier = getHealingDecisionSupplier(0.0, true, randomValue);

    // Act / Assert: distance < r^4 must be false when equal
    assertDoesNotHeal(supplier, 0.0625, randomValue);
  }

  @Test
  void shouldHeal_whenInvalidKeyLocation_throws() {
    // Arrange
    HealingDecisionSupplier supplier = getHealingDecisionSupplier(0.2, true, 0.7);

    // Act / Assert
    assertThrows(IllegalArgumentException.class, () -> supplier.shouldHeal(-0.01));
  }

  @Test
  void shouldHeal_whenInvalidNodeLocation_throws() {
    // Arrange: invalid node location supplier
    HealingDecisionSupplier supplier =
        new HealingDecisionSupplier(() -> -0.5, () -> true, () -> 0.8);

    // Act / Assert
    assertThrows(IllegalArgumentException.class, () -> supplier.shouldHeal(0.25));
  }

  private static HealingDecisionSupplier getHealingDecisionSupplier(
      double nodeLocation, boolean isOpennet, double randomValue) {
    return new HealingDecisionSupplier(() -> nodeLocation, () -> isOpennet, () -> randomValue);
  }

  private static void assertHeals(
      HealingDecisionSupplier healingDecisionSupplier, double keyLocation, double randomValue) {
    assertThat(
        "Healing triggers at random value %g".formatted(randomValue),
        healingDecisionSupplier.shouldHeal(keyLocation),
        Matchers.equalTo(true));
  }

  private static void assertDoesNotHeal(
      HealingDecisionSupplier healingDecisionSupplier, double keyLocation, double randomValue) {
    assertThat(
        "Healing does not trigger at random value %g".formatted(randomValue),
        healingDecisionSupplier.shouldHeal(keyLocation),
        Matchers.equalTo(false));
  }
}
