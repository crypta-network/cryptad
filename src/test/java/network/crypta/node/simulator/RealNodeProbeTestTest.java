package network.crypta.node.simulator;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class RealNodeProbeTestTest {
  @Test
  void constants_whenComputingDarknetPortEnd_expectMatchesBasePlusNodeCount() {
    // Arrange
    int expected = RealNodeProbeTest.DARKNET_PORT_BASE + RealNodeProbeTest.NUMBER_OF_NODES;

    // Act
    int actual = RealNodeProbeTest.DARKNET_PORT_END;

    // Assert
    assertEquals(expected, actual);
  }

  @Test
  void constants_whenUsingDarknetPortRange_expectEndGreaterThanBase() {
    // Arrange
    int base = RealNodeProbeTest.DARKNET_PORT_BASE;

    // Act
    int end = RealNodeProbeTest.DARKNET_PORT_END;

    // Assert
    assertTrue(end > base);
  }

  @Test
  void constants_whenCheckingDegree_expectConfiguredValue() {
    // Arrange
    int expected = 10;

    // Act
    int actual = RealNodeProbeTest.DEGREE;

    // Assert
    assertEquals(expected, actual);
  }

  @Test
  void constants_whenCheckingMaxHtl_expectConfiguredValue() {
    // Arrange
    short expected = 5;

    // Act
    short actual = RealNodeProbeTest.MAX_HTL;

    // Assert
    assertEquals(expected, actual);
  }

  @Test
  void constants_whenCheckingOutputBandwidthLimit_expectConfiguredValue() {
    // Arrange
    int expected = 0;

    // Act
    int actual = RealNodeProbeTest.OUTPUT_BANDWIDTH_LIMIT;

    // Assert
    assertEquals(expected, actual);
  }
}
