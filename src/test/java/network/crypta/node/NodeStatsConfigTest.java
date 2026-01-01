package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class NodeStatsConfigTest {

  @TempDir Path tempDir;

  @ParameterizedTest
  @CsvSource({
    "50,200",
    "100,300",
    "127,300",
    "128,400",
    "191,400",
    "192,500",
    "511,500",
    "512,1000",
    "0,1000",
    "-1,1000"
  })
  void configure_whenMemoryLimitMb_expectThreadLimitDefault(
      long memoryLimitMb, int expectedThreadLimit) throws Exception {
    // Arrange
    RecordingConfig config = new RecordingConfig(Map.of());
    SubConfig statsConfig = config.createSubConfig("node");
    NodeStats stats = mock(NodeStats.class);
    Node node = createNode(tempDir.toFile());

    // Act
    configureWithMemoryLimit(statsConfig, stats, node, 0, memoryLimitMb);

    // Assert
    verify(stats).updateThreadLimit(expectedThreadLimit);
    Option<?> threadLimit = statsConfig.getOption("threadLimit");
    assertNotNull(threadLimit);
    assertEquals(Integer.toString(expectedThreadLimit), threadLimit.getDefault());
  }

  @Test
  void configure_whenOverridesProvided_expectStatsUpdatedWithConfiguredValues() throws Exception {
    // Arrange
    Map<String, String> overrides =
        Map.of(
            "threadLimit", "450",
            "ignoreLocalVsRemoteBandwidthLiability", "true",
            "maxPingTime", "1234",
            "subMaxPingTime", "2345");
    RecordingConfig config = new RecordingConfig(overrides);
    SubConfig statsConfig = config.createSubConfig("node");
    NodeStats stats = mock(NodeStats.class);
    Node node = createNode(tempDir.toFile());

    // Act
    configureWithMemoryLimit(statsConfig, stats, node, 10, 1024L);

    // Assert
    verify(stats).updateThreadLimit(450);
    verify(stats).setIgnoreLocalVsRemoteBandwidthLiability(true);
    verify(stats).setMaxPingTime(1234L);
    verify(stats).setSubMaxPingTime(2345L);
  }

  @Test
  void configure_whenCalled_expectSortOrderAndPersisterPaths() throws Exception {
    // Arrange
    RecordingConfig config = new RecordingConfig(Map.of());
    SubConfig statsConfig = config.createSubConfig("node");
    NodeStats stats = mock(NodeStats.class);
    File runDir = tempDir.toFile();
    Node node = createNode(runDir);

    // Act
    int sortOrderBase = 7;
    NodeStatsConfig.Result result =
        configureWithMemoryLimit(statsConfig, stats, node, sortOrderBase, 2048L);

    // Assert
    assertEquals(sortOrderBase + 4, result.sortOrder());
    assertEquals(new File(runDir, "node-throttle.dat"), result.persister().persistTarget);
    assertEquals(new File(runDir, "node-throttle.dat.tmp"), result.persister().persistTemp);
  }

  @Test
  void configure_whenThrottleFileHasContent_expectResultThrottleFieldSetLoaded() throws Exception {
    // Arrange
    RecordingConfig config = new RecordingConfig(Map.of());
    SubConfig statsConfig = config.createSubConfig("node");
    NodeStats stats = mock(NodeStats.class);
    File runDir = tempDir.toFile();
    Node node = createNode(runDir);

    SimpleFieldSet persisted = new SimpleFieldSet(true);
    persisted.putSingle("throttleKey", "throttleValue");
    Path throttlePath = tempDir.resolve("node-throttle.dat");
    writeFieldSet(throttlePath, persisted);

    // Act
    NodeStatsConfig.Result result = configureWithMemoryLimit(statsConfig, stats, node, 0, 1024L);

    // Assert
    assertNotNull(result.throttleFS());
    assertEquals("throttleValue", result.throttleFS().get("throttleKey"));
  }

  @Test
  void configure_whenRunDirIsFile_expectNodeInitException() throws IOException {
    // Arrange
    RecordingConfig config = new RecordingConfig(Map.of());
    SubConfig statsConfig = config.createSubConfig("node");
    NodeStats stats = mock(NodeStats.class);
    Path runDir = tempDir.resolve("not-a-dir");
    Files.writeString(runDir, "content");
    Node node = createNode(runDir.toFile());

    // Act
    NodeInitException thrown =
        assertThrows(
            NodeInitException.class,
            () -> configureWithMemoryLimit(statsConfig, stats, node, 0, 1024L));

    // Assert
    assertEquals(NodeInitException.EXIT_THROTTLE_FILE_ERROR, thrown.exitCode);
  }

  @Test
  void threadLimitOption_whenBelowMinimum_expectInvalidConfigValueException() throws Exception {
    // Arrange
    RecordingConfig config = new RecordingConfig(Map.of());
    SubConfig statsConfig = config.createSubConfig("node");
    NodeStats stats = mock(NodeStats.class);
    Node node = createNode(tempDir.toFile());
    configureWithMemoryLimit(statsConfig, stats, node, 0, 1024L);
    clearInvocations(stats);
    when(stats.getThreadLimit()).thenReturn(100);
    Option<?> threadLimit = statsConfig.getOption("threadLimit");
    assertNotNull(threadLimit);

    // Act
    assertThrows(InvalidConfigValueException.class, () -> threadLimit.setValue("99"));

    // Assert
    verify(stats, never()).updateThreadLimit(anyInt());
  }

  @Test
  void threadLimitOption_whenSameValue_expectNoUpdate() throws Exception {
    // Arrange
    RecordingConfig config = new RecordingConfig(Map.of());
    SubConfig statsConfig = config.createSubConfig("node");
    NodeStats stats = mock(NodeStats.class);
    Node node = createNode(tempDir.toFile());
    configureWithMemoryLimit(statsConfig, stats, node, 0, 1024L);
    clearInvocations(stats);
    when(stats.getThreadLimit()).thenReturn(1000);
    Option<?> threadLimit = statsConfig.getOption("threadLimit");
    assertNotNull(threadLimit);

    // Act
    assertDoesNotThrow(() -> threadLimit.setValue("1000"));

    // Assert
    verify(stats, never()).updateThreadLimit(anyInt());
  }

  @Test
  void configure_whenCalled_expectIgnoredOptionsAndInitializationComplete() throws Exception {
    // Arrange
    RecordingConfig config = new RecordingConfig(Map.of());
    SubConfig statsConfig = config.createSubConfig("node");
    NodeStats stats = mock(NodeStats.class);
    Node node = createNode(tempDir.toFile());

    // Act
    configureWithMemoryLimit(statsConfig, stats, node, 0, 1024L);

    // Assert
    Set<String> expectedIgnored =
        Set.of(
            "aggressiveGC",
            "memoryChecker",
            "enableNewLoadManagementRT",
            "enableNewLoadManagementBulk");
    assertEquals(expectedIgnored, config.getIgnoredOptions());
    assertTrue(statsConfig.hasFinishedInitialization());
  }

  private static void writeFieldSet(Path file, SimpleFieldSet fieldSet) throws IOException {
    try (OutputStream outputStream = Files.newOutputStream(file)) {
      fieldSet.writeToBigBuffer(outputStream);
    }
  }

  private static Node createNode(File runDir) {
    Node node = mock(Node.class);
    Ticker ticker = mock(Ticker.class);
    when(node.getTicker()).thenReturn(ticker);
    when(node.getRunDir()).thenReturn(runDir);
    return node;
  }

  private static NodeStatsConfig.Result configureWithMemoryLimit(
      SubConfig statsConfig, NodeStats stats, Node node, int sortOrder, long memoryLimitMb)
      throws NodeInitException {
    try (MockedStatic<NodeStarter> mocked = mockStatic(NodeStarter.class)) {
      mocked.when(NodeStarter::getMemoryLimitMB).thenReturn(memoryLimitMb);
      return new NodeStatsConfig(statsConfig).configure(stats, node, sortOrder);
    }
  }

  private static final class RecordingConfig extends Config {
    private final Map<String, String> initialValues;
    private final Set<String> ignoredOptions = new LinkedHashSet<>();

    private RecordingConfig(Map<String, String> initialValues) {
      this.initialValues = initialValues;
    }

    @Override
    public void onRegister(SubConfig config, Option<?> option) {
      if (option.getDataType() == null) {
        ignoredOptions.add(option.getName());
        return;
      }
      String override = initialValues.get(option.getName());
      if (override == null) {
        return;
      }
      try {
        option.setInitialValue(override);
      } catch (InvalidConfigValueException e) {
        throw new IllegalArgumentException("Invalid override for " + option.getName(), e);
      }
    }

    private Set<String> getIgnoredOptions() {
      return ignoredOptions;
    }
  }
}
