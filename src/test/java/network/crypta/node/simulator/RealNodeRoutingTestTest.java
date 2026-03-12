package network.crypta.node.simulator;

import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.crypt.RandomSource;
import network.crypta.node.LocationManager;
import network.crypta.node.Node;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class RealNodeRoutingTestTest {

  @Test
  void waitForPingAverage_whenAllPingsSucceed_expectReturns() {
    Node node0 = mockNodeForPing(0.1, 1001);
    Node node1 = mockNodeForPing(0.9, 1002);
    Node[] nodes = new Node[] {node0, node1};
    RandomSource random = alternatingRandomSource();

    when(node1.network().darknetPubKeyHash()).thenReturn(new byte[32]);
    when(node0.network().routedPing(anyDouble(), any(byte[].class))).thenReturn(1);

    try (MockedStatic<RealNodeTest> realNodeTest = mockStatic(RealNodeTest.class);
        MockedStatic<LocationManager> locationManager = mockStatic(LocationManager.class)) {
      realNodeTest
          .when(() -> RealNodeTest.waitForAllConnected(nodes))
          .thenAnswer(invocation -> null);
      stubLocationManagerStats(locationManager, 2, 1);

      assertDoesNotThrow(() -> RealNodeRoutingTest.waitForPingAverage(0.9, nodes, random, 2, 0));
    }

    verify(node0.network(), times(20)).routedPing(anyDouble(), any(byte[].class));
  }

  @Test
  void waitForPingAverage_whenSomePingsFail_expectReturnsOnceAccuracyReached() {
    Node node0 = mockNodeForPing(0.2, 1101);
    Node node1 = mockNodeForPing(0.8, 1102);
    Node[] nodes = new Node[] {node0, node1};
    RandomSource random = alternatingRandomSource();

    when(node1.network().darknetPubKeyHash()).thenReturn(new byte[32]);
    AtomicInteger pingCount = new AtomicInteger();
    when(node0.network().routedPing(anyDouble(), any(byte[].class)))
        .thenAnswer(invocation -> pingCount.getAndIncrement() < 5 ? -1 : 1);

    try (MockedStatic<RealNodeTest> realNodeTest = mockStatic(RealNodeTest.class);
        MockedStatic<LocationManager> locationManager = mockStatic(LocationManager.class)) {
      realNodeTest
          .when(() -> RealNodeTest.waitForAllConnected(nodes))
          .thenAnswer(invocation -> null);
      stubLocationManagerStats(locationManager, 3, 1);

      assertDoesNotThrow(() -> RealNodeRoutingTest.waitForPingAverage(0.6, nodes, random, 2, 0));
    }

    verify(node0.network(), times(20)).routedPing(anyDouble(), any(byte[].class));
  }

  @Test
  void waitForPingAverage_whenWaitForAllConnectedInterrupted_expectThrowsInterruptedException() {
    Node node0 = mockNodeForSetup(0.4);
    Node node1 = mockNodeForSetup(0.6);
    Node[] nodes = new Node[] {node0, node1};
    RandomSource random = mock(RandomSource.class);

    try (MockedStatic<RealNodeTest> realNodeTest = mockStatic(RealNodeTest.class);
        MockedStatic<LocationManager> locationManager = mockStatic(LocationManager.class)) {
      realNodeTest
          .when(() -> RealNodeTest.waitForAllConnected(nodes))
          .thenThrow(new InterruptedException("interrupted"));
      stubLocationManagerStats(locationManager, 1, 0);

      assertThrows(
          InterruptedException.class,
          () -> RealNodeRoutingTest.waitForPingAverage(0.5, nodes, random, 1, 0));
    }
  }

  private static Node mockNodeForPing(double location, int port) {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager locationManager = mockLocationManager();
    when(node.network().location()).thenReturn(location);
    when(node.network().darknetPortNumber()).thenReturn(port);
    when(node.network().locationManager()).thenReturn(locationManager);
    return node;
  }

  private static Node mockNodeForSetup(double location) {
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    LocationManager locationManager = mockLocationManager();
    when(node.network().location()).thenReturn(location);
    when(node.network().locationManager()).thenReturn(locationManager);
    return node;
  }

  private static LocationManager mockLocationManager() {
    LocationManager locationManager = mock(LocationManager.class);
    when(locationManager.getSendSwapInterval()).thenReturn(1L);
    when(locationManager.getAverageSwapTime()).thenReturn(2);
    return locationManager;
  }

  private static RandomSource alternatingRandomSource() {
    RandomSource random = mock(RandomSource.class);
    AtomicInteger counter = new AtomicInteger();
    when(random.nextInt(anyInt()))
        .thenAnswer(
            invocation -> {
              int bound = invocation.getArgument(0);
              return Math.floorMod(counter.getAndIncrement(), bound);
            });
    return random;
  }

  @SuppressWarnings("ResultOfMethodCallIgnored")
  private static void stubLocationManagerStats(
      MockedStatic<LocationManager> locationManager, int swaps, int noSwaps) {
    locationManager.when(LocationManager::getSwaps).thenReturn(swaps);
    locationManager.when(LocationManager::getStartedSwaps).thenReturn(1);
    locationManager.when(LocationManager::getNoSwaps).thenReturn(noSwaps);
    locationManager.when(LocationManager::getSwapsRejectedAlreadyLocked).thenReturn(0);
    locationManager.when(LocationManager::getSwapsRejectedNowhereToGo).thenReturn(0);
    locationManager.when(LocationManager::getSwapsRejectedRateLimit).thenReturn(0);
    locationManager.when(LocationManager::getSwapsRejectedRecognizedID).thenReturn(0);
  }
}
