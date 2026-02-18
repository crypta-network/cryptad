package org.spaceroots.mantissa.optimization;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class PointCostPairTest {

  private static PointCostPair constructPointCostPair(double[] point, double cost) {
    return new PointCostPair(point, cost);
  }

  @Test
  @DisplayName("Constructor clones the provided point array and stores cost")
  void constructor_whenGivenPointArray_clonesArrayAndStoresCost() {
    // Arrange
    double[] originalPoint = new double[] {1.0, -2.5, 3.5};
    double expectedCost = 42.0;

    // Act
    PointCostPair pair = new PointCostPair(originalPoint, expectedCost);

    // Assert
    assertArrayEquals(originalPoint, pair.point(), 1e-15);
    assertNotSame(originalPoint, pair.point());
    assertEquals(expectedCost, pair.cost(), 0.0);
  }

  @Test
  @DisplayName("Modifying the original array after construction does not change stored point")
  void constructor_whenOriginalArrayMutated_storedPointUnchanged() {
    // Arrange
    double[] originalPoint = new double[] {0.1, 0.2};
    PointCostPair pair = new PointCostPair(originalPoint, 5.0);

    // Act
    originalPoint[0] = 9.9;
    originalPoint[1] = -9.9;

    // Assert
    assertArrayEquals(new double[] {0.1, 0.2}, pair.point(), 1e-15);
  }

  @Test
  @DisplayName("Null point array triggers NullPointerException")
  void constructor_whenPointIsNull_throwsNullPointerException() {
    // Arrange
    // Act / Assert
    assertThrows(NullPointerException.class, () -> constructPointCostPair(null, 1.0));
  }

  @Test
  @DisplayName("equals compares array content and cost")
  void equals_whenPointAndCostMatch_returnsTrue() {
    // Arrange
    PointCostPair first = new PointCostPair(new double[] {1.0, 2.0}, 3.0);
    PointCostPair second = new PointCostPair(new double[] {1.0, 2.0}, 3.0);

    // Act + Assert
    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
  }

  @Test
  @DisplayName("equals returns false when cost differs")
  void equals_whenCostDiffers_returnsFalse() {
    // Arrange
    PointCostPair first = new PointCostPair(new double[] {1.0, 2.0}, 3.0);
    PointCostPair second = new PointCostPair(new double[] {1.0, 2.0}, 4.0);

    // Act + Assert
    assertNotEquals(first, second);
  }

  @Test
  @DisplayName("equals returns false when point content differs")
  void equals_whenPointDiffers_returnsFalse() {
    // Arrange
    PointCostPair first = new PointCostPair(new double[] {1.0, 2.0}, 3.0);
    PointCostPair second = new PointCostPair(new double[] {1.0, 2.1}, 3.0);

    // Act + Assert
    assertNotEquals(first, second);
  }

  @Test
  @DisplayName("toString includes point content and cost")
  void toString_whenCalled_formatsArrayAndCost() {
    // Arrange
    PointCostPair pair = new PointCostPair(new double[] {1.0, 2.0}, 3.0);

    // Act
    String text = pair.toString();

    // Assert
    assertEquals("PointCostPair[point=[1.0, 2.0], cost=3.0]", text);
  }
}
