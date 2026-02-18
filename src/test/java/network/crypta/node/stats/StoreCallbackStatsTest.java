package network.crypta.node.stats;

import network.crypta.store.StoreCallback;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class StoreCallbackStatsTest {

  @Mock StoreCallback<network.crypta.store.StorableBlock> storeCallback;
  @Mock StoreLocationStats nodeStats;
  @Mock StoreAccessStats sessionAccessStats;
  @Mock StoreAccessStats totalAccessStats;

  @Test
  @DisplayName("keys_whenDelegateReturnsValue_expectSame")
  void keys_whenDelegateReturnsValue_expectSame() {
    // Arrange
    when(storeCallback.keyCount()).thenReturn(42L);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    long result = stats.keys();

    // Assert
    assertEquals(42L, result);
  }

  @Test
  @DisplayName("capacity_whenDelegateReturnsValue_expectSame")
  void capacity_whenDelegateReturnsValue_expectSame() {
    // Arrange
    when(storeCallback.getMaxKeys()).thenReturn(1_000L);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    long result = stats.capacity();

    // Assert
    assertEquals(1_000L, result);
  }

  @Test
  @DisplayName("dataSize_whenMultipleKeysAndDataLength_expectProduct")
  void dataSize_whenMultipleKeysAndDataLength_expectProduct() {
    // Arrange
    when(storeCallback.keyCount()).thenReturn(7L);
    when(storeCallback.dataLength()).thenReturn(2_048);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    long result = stats.dataSize();

    // Assert
    assertEquals(7L * 2_048L, result);
  }

  @Test
  @DisplayName("utilization_whenNominal_expectFractionOfCapacity")
  void utilization_whenNominal_expectFractionOfCapacity() {
    // Arrange
    when(storeCallback.keyCount()).thenReturn(50L);
    when(storeCallback.getMaxKeys()).thenReturn(200L);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    double result = stats.utilization();

    // Assert
    assertEquals(0.25d, result, 1.0e-12);
  }

  @Test
  @DisplayName("utilization_whenZeroCapacityAndZeroKeys_expectNaN")
  void utilization_whenZeroCapacityAndZeroKeys_expectNaN() {
    // Arrange
    when(storeCallback.keyCount()).thenReturn(0L);
    when(storeCallback.getMaxKeys()).thenReturn(0L);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    double result = stats.utilization();

    // Assert
    assertTrue(Double.isNaN(result));
  }

  @Test
  @DisplayName("utilization_whenZeroCapacityAndPositiveKeys_expectPositiveInfinity")
  void utilization_whenZeroCapacityAndPositiveKeys_expectPositiveInfinity() {
    // Arrange
    when(storeCallback.keyCount()).thenReturn(10L);
    when(storeCallback.getMaxKeys()).thenReturn(0L);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    double result = stats.utilization();

    // Assert
    assertTrue(Double.isInfinite(result) && result > 0);
  }

  @Test
  @DisplayName("avgLocation_whenNodeProvidesValue_expectSame")
  void avgLocation_whenNodeProvidesValue_expectSame() throws StatsNotAvailableException {
    // Arrange
    when(nodeStats.avgLocation()).thenReturn(0.123);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    double result = stats.avgLocation();

    // Assert
    assertEquals(0.123, result, 0.0);
  }

  @Test
  @DisplayName("avgLocation_whenNodeThrows_expectPropagatedException")
  void avgLocation_whenNodeThrows_expectPropagatedException() throws StatsNotAvailableException {
    // Arrange
    when(nodeStats.avgLocation()).thenThrow(new StatsNotAvailableException("not ready"));
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act + Assert
    assertThrows(StatsNotAvailableException.class, stats::avgLocation);
  }

  @Test
  @DisplayName("avgSuccess_whenNodeProvidesValue_expectSame")
  void avgSuccess_whenNodeProvidesValue_expectSame() throws StatsNotAvailableException {
    // Arrange
    when(nodeStats.avgSuccess()).thenReturn(77.7);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    double result = stats.avgSuccess();

    // Assert
    assertEquals(77.7, result, 0.0);
  }

  @Test
  @DisplayName("avgSuccess_whenNodeThrows_expectPropagatedException")
  void avgSuccess_whenNodeThrows_expectPropagatedException() throws StatsNotAvailableException {
    // Arrange
    when(nodeStats.avgSuccess()).thenThrow(new StatsNotAvailableException());
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act + Assert
    assertThrows(StatsNotAvailableException.class, stats::avgSuccess);
  }

  @Test
  @DisplayName("furthestSuccess_whenNodeProvidesValue_expectSame")
  void furthestSuccess_whenNodeProvidesValue_expectSame() throws StatsNotAvailableException {
    // Arrange
    when(nodeStats.furthestSuccess()).thenReturn(9.5);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    double result = stats.furthestSuccess();

    // Assert
    assertEquals(9.5, result, 0.0);
  }

  @Test
  @DisplayName("furthestSuccess_whenNodeThrows_expectPropagatedException")
  void furthestSuccess_whenNodeThrows_expectPropagatedException()
      throws StatsNotAvailableException {
    // Arrange
    when(nodeStats.furthestSuccess()).thenThrow(new StatsNotAvailableException());
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act + Assert
    assertThrows(StatsNotAvailableException.class, stats::furthestSuccess);
  }

  @Test
  @DisplayName("avgDist_whenNodeProvidesValue_expectSame")
  void avgDist_whenNodeProvidesValue_expectSame() throws StatsNotAvailableException {
    // Arrange
    when(nodeStats.avgDist()).thenReturn(0.333);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    double result = stats.avgDist();

    // Assert
    assertEquals(0.333, result, 0.0);
  }

  @Test
  @DisplayName("avgDist_whenNodeThrows_expectPropagatedException")
  void avgDist_whenNodeThrows_expectPropagatedException() throws StatsNotAvailableException {
    // Arrange
    when(nodeStats.avgDist()).thenThrow(new StatsNotAvailableException());
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act + Assert
    assertThrows(StatsNotAvailableException.class, stats::avgDist);
  }

  @Test
  @DisplayName("distanceStats_whenNodeProvidesValue_expectSame")
  void distanceStats_whenNodeProvidesValue_expectSame() throws StatsNotAvailableException {
    // Arrange
    when(nodeStats.distanceStats()).thenReturn(1.234);
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act
    double result = stats.distanceStats();

    // Assert
    assertEquals(1.234, result, 0.0);
  }

  @Test
  @DisplayName("distanceStats_whenNodeThrows_expectPropagatedException")
  void distanceStats_whenNodeThrows_expectPropagatedException() throws StatsNotAvailableException {
    // Arrange
    when(nodeStats.distanceStats()).thenThrow(new StatsNotAvailableException());
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act + Assert
    assertThrows(StatsNotAvailableException.class, stats::distanceStats);
  }

  @Test
  @DisplayName("getSessionAccessStats_whenConstructed_returnsSnapshot")
  void getSessionAccessStats_whenConstructed_returnsSnapshot() {
    // Arrange
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Change delegate to a different object after construction to ensure snapshot semantics
    StoreAccessStats anotherSessionStats = org.mockito.Mockito.mock(StoreAccessStats.class);
    org.mockito.Mockito.lenient()
        .when(storeCallback.getSessionAccessStats())
        .thenReturn(anotherSessionStats);

    // Act
    StoreAccessStats result = stats.getSessionAccessStats();

    // Assert
    assertEquals(sessionAccessStats, result);
  }

  @Test
  @DisplayName("getTotalAccessStats_whenSupported_returnsSnapshot")
  void getTotalAccessStats_whenSupported_returnsSnapshot() throws StatsNotAvailableException {
    // Arrange
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(totalAccessStats);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Change delegate to a different object after construction to ensure snapshot semantics
    StoreAccessStats anotherTotal = org.mockito.Mockito.mock(StoreAccessStats.class);
    org.mockito.Mockito.lenient()
        .when(storeCallback.getTotalAccessStats())
        .thenReturn(anotherTotal);

    // Act
    StoreAccessStats result = stats.getTotalAccessStats();

    // Assert
    assertEquals(totalAccessStats, result);
  }

  @Test
  @DisplayName("getTotalAccessStats_whenUnsupported_expectStatsNotAvailableException")
  void getTotalAccessStats_whenUnsupported_expectStatsNotAvailableException() {
    // Arrange
    when(storeCallback.getSessionAccessStats()).thenReturn(sessionAccessStats);
    when(storeCallback.getTotalAccessStats()).thenReturn(null);
    StoreCallbackStats stats = new StoreCallbackStats(storeCallback, nodeStats);

    // Act + Assert
    assertThrows(StatsNotAvailableException.class, stats::getTotalAccessStats);
  }
}
