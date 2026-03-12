package network.crypta.node.simulator;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.keys.CHKBlock;
import network.crypta.node.NodeStarter;
import network.crypta.support.io.FileUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.api.parallel.Execution;
import org.junit.jupiter.api.parallel.ExecutionMode;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.junit.jupiter.api.parallel.Resources;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.event.Level;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.isNull;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@Execution(ExecutionMode.SAME_THREAD)
@ResourceLock(Resources.SYSTEM_OUT)
@ResourceLock(Resources.SYSTEM_ERR)
class RealNodeBusyNetworkTestTest {

  private static final String WORKING_DIR_PROPERTY = "user.dir";
  private static final String TEST_DIRECTORY_NAME = "realNodeRequestInsertTest";

  @TempDir Path tempDir;

  @Test
  @SuppressWarnings("java:S3415")
  void constants_whenPortRangeCalculated_expectContiguousRange() {
    int expectedEnd =
        RealNodeBusyNetworkTest.DARKNET_PORT_BASE + RealNodeBusyNetworkTest.NUMBER_OF_NODES;
    assertEquals(expectedEnd, RealNodeBusyNetworkTest.DARKNET_PORT_END);
  }

  @Test
  void main_whenGlobalTestInitThrows_expectExceptionPropagatesAndInitCalled() {
    Path defaultDir = Path.of(TEST_DIRECTORY_NAME);
    assumeTrue(
        Files.notExists(defaultDir),
        "Skipping to avoid deleting existing realNodeRequestInsertTest data");
    String originalUserDir = System.getProperty(WORKING_DIR_PROPERTY);
    File expectedDir = tempDir.resolve(TEST_DIRECTORY_NAME).toFile();
    RuntimeException failure = new RuntimeException("boom");

    System.setProperty(WORKING_DIR_PROPERTY, tempDir.toString());
    try (MockedStatic<FileUtil> fileUtilMock = mockStatic(FileUtil.class);
        MockedStatic<NodeStarter> nodeStarterMock = mockStatic(NodeStarter.class)) {
      fileUtilMock.when(() -> FileUtil.removeAll(any(File.class))).thenReturn(true);
      nodeStarterMock
          .when(
              () ->
                  NodeStarter.globalTestInit(
                      any(File.class), eq(false), eq(Level.ERROR), eq(""), eq(true), isNull()))
          .thenThrow(failure);

      RuntimeException thrown =
          assertThrows(RuntimeException.class, () -> RealNodeBusyNetworkTest.main(new String[0]));

      assertEquals(failure, thrown);
      assertTrue(
          Files.isDirectory(expectedDir.toPath()) || Files.isDirectory(defaultDir),
          "Expected test directory to be created in either temp or working directory");
      fileUtilMock.verify(
          () -> FileUtil.removeAll(argThat(file -> TEST_DIRECTORY_NAME.equals(file.getName()))),
          times(1));
      nodeStarterMock.verify(
          () ->
              NodeStarter.globalTestInit(
                  argThat(file -> TEST_DIRECTORY_NAME.equals(file.getName())),
                  eq(false),
                  eq(Level.ERROR),
                  eq(""),
                  eq(true),
                  isNull()),
          times(1));
    } finally {
      System.setProperty(WORKING_DIR_PROPERTY, originalUserDir);
      FileUtil.removeAll(expectedDir);
      if (Files.exists(defaultDir)) {
        FileUtil.removeAll(defaultDir.toFile());
      }
    }
  }

  @Test
  void main_whenCreateTestNodeThrows_expectParametersConfigured() {
    Path defaultDir = Path.of(TEST_DIRECTORY_NAME);
    assumeTrue(
        Files.notExists(defaultDir),
        "Skipping to avoid deleting existing realNodeRequestInsertTest data");
    String originalUserDir = System.getProperty(WORKING_DIR_PROPERTY);
    File expectedDir = tempDir.resolve(TEST_DIRECTORY_NAME).toFile();
    RuntimeException failure = new RuntimeException("boom");
    AtomicReference<NodeStarter.TestNodeParameters> captured = new AtomicReference<>();

    System.setProperty(WORKING_DIR_PROPERTY, tempDir.toString());
    try (MockedStatic<FileUtil> fileUtilMock = mockStatic(FileUtil.class);
        MockedStatic<NodeStarter> nodeStarterMock = mockStatic(NodeStarter.class)) {
      fileUtilMock.when(() -> FileUtil.removeAll(any(File.class))).thenReturn(true);
      nodeStarterMock
          .when(
              () ->
                  NodeStarter.globalTestInit(
                      any(File.class), eq(false), eq(Level.ERROR), eq(""), eq(true), isNull()))
          .thenReturn(null);
      nodeStarterMock
          .when(() -> NodeStarter.createTestNode(any(NodeStarter.TestNodeParameters.class)))
          .thenAnswer(
              invocation -> {
                NodeStarter.TestNodeParameters params = invocation.getArgument(0);
                captured.set(params);
                throw failure;
              });

      RuntimeException thrown =
          assertThrows(RuntimeException.class, () -> RealNodeBusyNetworkTest.main(new String[0]));

      assertEquals(failure, thrown);
      NodeStarter.TestNodeParameters params = captured.get();
      assertNotNull(params);
      assertEquals(RealNodeBusyNetworkTest.DARKNET_PORT_BASE, params.getPort());
      assertEquals(0, params.getOpennetPort());
      assertEquals(TEST_DIRECTORY_NAME, params.getBaseDirectory().getName());
      assertEquals(RealNodeBusyNetworkTest.MAX_HTL, params.getMaxHTL());
      assertEquals(20, params.getDropProb());
      assertNotNull(params.getRandom());
      assertNotNull(params.getExecutor());
      assertEquals(500 * RealNodeBusyNetworkTest.NUMBER_OF_NODES, params.getThreadLimit());
      assertEquals(
          (CHKBlock.DATA_LENGTH + CHKBlock.TOTAL_HEADERS_LENGTH) * 100L, params.getStoreSize());
      assertTrue(params.isRamStore());
      assertEquals(RealNodeBusyNetworkTest.ENABLE_SWAPPING, params.isEnableSwapping());
      assertEquals(RealNodeBusyNetworkTest.ENABLE_ULPRS, params.isEnableULPRs());
      assertEquals(
          RealNodeBusyNetworkTest.ENABLE_PER_NODE_FAILURE_TABLES,
          params.isEnablePerNodeFailureTables());
      assertEquals(RealNodeBusyNetworkTest.ENABLE_SWAP_QUEUEING, params.isEnableSwapQueueing());
      assertEquals(
          RealNodeBusyNetworkTest.ENABLE_PACKET_COALESCING, params.isEnablePacketCoalescing());
      assertEquals(8000, params.getOutputBandwidthLimit());
      assertEquals(RealNodeBusyNetworkTest.ENABLE_FOAF, params.isEnableFOAF());
      assertTrue(params.isLongPingTimes());
    } finally {
      System.setProperty(WORKING_DIR_PROPERTY, originalUserDir);
      FileUtil.removeAll(expectedDir);
      if (Files.exists(defaultDir)) {
        FileUtil.removeAll(defaultDir.toFile());
      }
    }
  }
}
