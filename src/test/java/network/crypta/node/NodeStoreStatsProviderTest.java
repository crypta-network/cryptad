package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.lang.reflect.Field;
import java.util.stream.Stream;
import network.crypta.node.stats.StatsNotAvailableException;
import network.crypta.node.stats.StoreLocationStats;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.store.CHKStore;
import network.crypta.store.SSKStore;
import network.crypta.store.StoreCallback;
import network.crypta.support.math.DecayingKeyspaceAverage;
import org.jspecify.annotations.NonNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeStoreStatsProviderTest {
  private static final double EPSILON = 1e-9;

  @ParameterizedTest(name = "{0}")
  @MethodSource("storeStatsCases")
  void storeStats_whenValuesConfigured_expectSnapshotValues(StoreStatsCase testCase)
      throws StatsNotAvailableException {
    // Arrange
    Node node = Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeStorageSubsystem storage = Mockito.mock(NodeStorageSubsystem.class);
    Mockito.when(node.storage()).thenReturn(storage);
    LocationManager locationManager = Mockito.mock(LocationManager.class);
    Mockito.when(locationManager.getLocation()).thenReturn(testCase.nodeLocation());
    Mockito.when(node.network().locationManager()).thenReturn(locationManager);

    NodeStats stats = Mockito.mock(NodeStats.class);
    setField(stats, "node", node);

    DecayingKeyspaceAverage avgLocation =
        mockAverageWithReports(testCase.avgLocation(), testCase.countReports());
    DecayingKeyspaceAverage avgSuccess = mockAverageWithCurrentValue(testCase.avgSuccess());

    setField(stats, testCase.avgLocationField(), avgLocation);
    setField(stats, testCase.avgSuccessField(), avgSuccess);
    setField(stats, testCase.furthestField(), testCase.furthestSuccess());

    StoreCallback<?> store = Mockito.mock(testCase.storeClass());
    Mockito.when(store.keyCount()).thenReturn(testCase.keyCount());
    testCase.storeSetter().stub(storage, store);

    NodeStoreStatsProvider provider = new NodeStoreStatsProvider(stats);

    // Act
    StoreLocationStats storeStats = testCase.statsAccessor().get(provider);

    // Assert
    assertEquals(testCase.avgLocation(), storeStats.avgLocation(), EPSILON);
    assertEquals(testCase.avgSuccess(), storeStats.avgSuccess(), EPSILON);
    assertEquals(testCase.furthestSuccess(), storeStats.furthestSuccess(), EPSILON);
    assertEquals(
        Location.distance(testCase.nodeLocation(), testCase.avgLocation()),
        storeStats.avgDist(),
        EPSILON);
    assertEquals(testCase.expectedDistanceStats(), storeStats.distanceStats(), EPSILON);
  }

  @Test
  void distanceStats_whenReportsExceedKeyCount_expectCappedAtOne()
      throws StatsNotAvailableException {
    // Arrange
    Node node = Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeStorageSubsystem storage = Mockito.mock(NodeStorageSubsystem.class);
    Mockito.when(node.storage()).thenReturn(storage);

    CHKStore store = Mockito.mock(CHKStore.class);
    Mockito.when(store.keyCount()).thenReturn(50L);
    Mockito.doReturn(store).when(storage).getChkDatacache();

    NodeStats stats = Mockito.mock(NodeStats.class);
    setField(stats, "node", node);
    DecayingKeyspaceAverage avgLocation = Mockito.mock(DecayingKeyspaceAverage.class);
    Mockito.when(avgLocation.countReports()).thenReturn(200L);
    setField(stats, "avgCacheCHKLocation", avgLocation);

    NodeStoreStatsProvider provider = new NodeStoreStatsProvider(stats);

    // Act
    double distanceStats = provider.chkCacheStats().distanceStats();

    // Assert
    assertEquals(1.0, distanceStats, EPSILON);
  }

  @Test
  void avgDist_whenAvgLocationInvalid_expectIllegalArgumentException() {
    // Arrange
    Node node = Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager locationManager = Mockito.mock(LocationManager.class);
    Mockito.when(locationManager.getLocation()).thenReturn(0.2);
    Mockito.when(node.network().locationManager()).thenReturn(locationManager);

    NodeStats stats = Mockito.mock(NodeStats.class);
    setField(stats, "node", node);
    setField(stats, "avgCacheSSKLocation", mockAverageWithCurrentValue(1.5));

    NodeStoreStatsProvider provider = new NodeStoreStatsProvider(stats);
    StoreLocationStats storeStats = provider.sskCacheStats();

    // Act + Assert
    assertThrows(IllegalArgumentException.class, storeStats::avgDist);
  }

  private static Stream<StoreStatsCase> storeStatsCases() {
    return Stream.of(
        StoreStatsCase.caseFor(
            1,
            "chkStoreStats",
            NodeStoreStatsProvider::chkStoreStats,
            (storage, store) -> Mockito.doReturn(store).when(storage).getChkDatastore(),
            CHKStore.class,
            "avgStoreCHKLocation",
            "avgStoreCHKSuccess",
            "furthestStoreCHKSuccess"),
        StoreStatsCase.caseFor(
            2,
            "chkCacheStats",
            NodeStoreStatsProvider::chkCacheStats,
            (storage, store) -> Mockito.doReturn(store).when(storage).getChkDatacache(),
            CHKStore.class,
            "avgCacheCHKLocation",
            "avgCacheCHKSuccess",
            "furthestCacheCHKSuccess"),
        StoreStatsCase.caseFor(
            3,
            "chkSlashDotCacheStats",
            NodeStoreStatsProvider::chkSlashDotCacheStats,
            (storage, store) -> Mockito.doReturn(store).when(storage).getChkSlashdotCache(),
            CHKStore.class,
            "avgSlashdotCacheCHKLocation",
            "avgSlashdotCacheCHKSucess",
            "furthestSlashdotCacheCHKSuccess"),
        StoreStatsCase.caseFor(
            4,
            "chkClientCacheStats",
            NodeStoreStatsProvider::chkClientCacheStats,
            (storage, store) -> Mockito.doReturn(store).when(storage).getChkClientCache(),
            CHKStore.class,
            "avgClientCacheCHKLocation",
            "avgClientCacheCHKSuccess",
            "furthestClientCacheCHKSuccess"),
        StoreStatsCase.caseFor(
            5,
            "sskStoreStats",
            NodeStoreStatsProvider::sskStoreStats,
            (storage, store) -> Mockito.doReturn(store).when(storage).getSskDatastore(),
            SSKStore.class,
            "avgStoreSSKLocation",
            "avgStoreSSKSuccess",
            "furthestStoreSSKSuccess"),
        StoreStatsCase.caseFor(
            6,
            "sskCacheStats",
            NodeStoreStatsProvider::sskCacheStats,
            (storage, store) -> Mockito.doReturn(store).when(storage).getSskDatacache(),
            SSKStore.class,
            "avgCacheSSKLocation",
            "avgCacheSSKSuccess",
            "furthestCacheSSKSuccess"),
        StoreStatsCase.caseFor(
            7,
            "sskSlashDotCacheStats",
            NodeStoreStatsProvider::sskSlashDotCacheStats,
            (storage, store) -> Mockito.doReturn(store).when(storage).getSskSlashdotCache(),
            SSKStore.class,
            "avgSlashdotCacheSSKLocation",
            "avgSlashdotCacheSSKSuccess",
            "furthestSlashdotCacheSSKSuccess"),
        StoreStatsCase.caseFor(
            8,
            "sskClientCacheStats",
            NodeStoreStatsProvider::sskClientCacheStats,
            (storage, store) -> Mockito.doReturn(store).when(storage).getSskClientCache(),
            SSKStore.class,
            "avgClientCacheSSKLocation",
            "avgClientCacheSSKSuccess",
            "furthestClientCacheSSKSuccess"));
  }

  private static DecayingKeyspaceAverage mockAverageWithCurrentValue(double currentValue) {
    DecayingKeyspaceAverage average = Mockito.mock(DecayingKeyspaceAverage.class);
    Mockito.when(average.currentValue()).thenReturn(currentValue);
    return average;
  }

  private static DecayingKeyspaceAverage mockAverageWithReports(double currentValue, long reports) {
    DecayingKeyspaceAverage average = mockAverageWithCurrentValue(currentValue);
    Mockito.when(average.countReports()).thenReturn(reports);
    return average;
  }

  @SuppressWarnings("java:S3011")
  private static void setField(Object target, String fieldName, Object value) {
    try {
      Field field = NodeStats.class.getDeclaredField(fieldName);
      field.setAccessible(true);
      field.set(target, value);
    } catch (ReflectiveOperationException ex) {
      throw new LinkageError("Failed to set field " + fieldName, ex);
    }
  }

  @FunctionalInterface
  private interface StatsAccessor {
    StoreLocationStats get(NodeStoreStatsProvider provider);
  }

  @FunctionalInterface
  private interface StoreSetter {
    void stub(NodeStorageSubsystem storage, StoreCallback<?> store);
  }

  private record StoreStatsCase(
      String label,
      StatsAccessor statsAccessor,
      StoreSetter storeSetter,
      Class<? extends StoreCallback<?>> storeClass,
      String avgLocationField,
      String avgSuccessField,
      String furthestField,
      double avgLocation,
      double avgSuccess,
      double furthestSuccess,
      double nodeLocation,
      long countReports,
      long keyCount) {
    private static StoreStatsCase caseFor(
        int index,
        String label,
        StatsAccessor statsAccessor,
        StoreSetter storeSetter,
        Class<? extends StoreCallback<?>> storeClass,
        String avgLocationField,
        String avgSuccessField,
        String furthestField) {
      double avgLocation = 0.05 * index;
      double avgSuccess = 0.07 * index;
      double furthestSuccess = 0.12 + (0.03 * index);
      double nodeLocation = 0.02 * index;
      long countReports = 10L * index;
      long keyCount = 200L + (10L * index);
      return new StoreStatsCase(
          label,
          statsAccessor,
          storeSetter,
          storeClass,
          avgLocationField,
          avgSuccessField,
          furthestField,
          avgLocation,
          avgSuccess,
          furthestSuccess,
          nodeLocation,
          countReports,
          keyCount);
    }

    private double expectedDistanceStats() {
      return (double) countReports / keyCount;
    }

    @Override
    public @NonNull String toString() {
      return label;
    }
  }
}
