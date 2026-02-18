package network.crypta.support.io;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import network.crypta.config.Config;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.Resolved;
import network.crypta.fs.ServiceDirs;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeStarter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Answers;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link DatastoreUtil}.
 *
 * <p>Tests follow AAA style, cover boundaries and error paths, and avoid flakiness where possible.
 */
class DatastoreUtilTest {

  // --- Helpers -----------------------------------------------------------------

  // Helper: returns a java.io.File mock with deterministic usable space

  private static Config configWithStoreSizeDefault(boolean isDefault) {
    Config cfg = mock(Config.class);
    SubConfig nodeSub = mock(SubConfig.class);
    Option<?> storeSize = mock(Option.class);
    when(cfg.get("node")).thenReturn(nodeSub);
    doReturn(storeSize).when(nodeSub).getOption("storeSize");
    when(storeSize.isDefault()).thenReturn(isDefault);
    return cfg;
  }

  private static NodeClientCore coreWithFreeSpace(long freeSpaceBytes) {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    when(core.getNode()).thenReturn(node);
    File f = mock(File.class);
    when(f.getUsableSpace()).thenReturn(freeSpaceBytes);
    when(node.getStoreDir()).thenReturn(f);
    return core;
  }

  private static long runtimeMemoryDerivedMax() {
    long maxMemory = NodeStarter.getMemoryLimitBytes();
    if (maxMemory == Long.MAX_VALUE || maxMemory < 128L * DatastoreUtil.ONE_MIB) {
      return DatastoreUtil.ONE_GIB;
    }
    long available = maxMemory - 100L * DatastoreUtil.ONE_MIB;
    available = available / 2; // 50%
    long slots = available / 4; // 4 bytes/slot
    slots = slots / 3; // 3 key types
    return slots * network.crypta.node.subsystem.NodeStorageSubsystem.SIZE_PER_KEY;
  }

  private static Path resolveDataDirPath() {
    AppEnv env = new AppEnv();
    Resolved dirs = env.isServiceMode() ? new ServiceDirs().resolve() : new AppDirs().resolve();
    return dirs.getDataDir();
  }

  // --- maxDatastoreSize() ------------------------------------------------------

  @Test
  @DisplayName("maxDatastoreSize_whenDiskBiggerThanMemory_expectMemoryCap")
  void maxDatastoreSize_whenDiskBiggerThanMemory_expectMemoryCap() {
    // Arrange: deterministically make disk larger than the memory cap by
    // (a) forcing the 1 GiB memory fallback and (b) mocking filesystem free space to 10 GiB.
    Path dataPath = resolveDataDirPath();
    try (MockedStatic<NodeStarter> ns = mockStatic(NodeStarter.class);
        MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      ns.when(NodeStarter::getMemoryLimitBytes).thenReturn(127L * DatastoreUtil.ONE_MIB);
      long memoryCap = runtimeMemoryDerivedMax(); // expected: 1 GiB fallback

      FileStore store = mock(FileStore.class);
      try {
        when(store.getUnallocatedSpace()).thenReturn(10L * DatastoreUtil.ONE_GIB);
      } catch (IOException e) {
        throw new AssertionError(e);
      }
      files.when(() -> Files.getFileStore(eq(dataPath))).thenReturn(store);

      // Act
      long actual = DatastoreUtil.maxDatastoreSize();

      // Assert
      assertEquals(memoryCap, actual, "Should return memory-derived cap when disk is larger");
    }
  }

  @Test
  @DisplayName("maxDatastoreSize_whenDiskSmallerThanMemory_expectDiskCap")
  void maxDatastoreSize_whenDiskSmallerThanMemory_expectDiskCap() throws Exception {
    // Arrange: Force a huge memory cap so disk space dominates
    try (MockedStatic<NodeStarter> ns = mockStatic(NodeStarter.class)) {
      ns.when(NodeStarter::getMemoryLimitBytes).thenReturn(10L * 1024 * DatastoreUtil.ONE_GIB);
      long expectedDisk = Files.getFileStore(resolveDataDirPath()).getUnallocatedSpace();

      // Act
      long actual = DatastoreUtil.maxDatastoreSize();

      // Assert with small tolerance for drift
      long delta = Math.abs(actual - expectedDisk);
      long tolerance = 16L * DatastoreUtil.ONE_MIB; // 16 MiB
      if (delta > tolerance) {
        long expectedDisk2 = Files.getFileStore(resolveDataDirPath()).getUnallocatedSpace();
        delta = Math.abs(actual - expectedDisk2);
      }
      assertTrue(
          delta <= tolerance,
          () ->
              "Disk cap should dominate: expected ~"
                  + expectedDisk
                  + " (±"
                  + tolerance
                  + ") but was "
                  + actual);
    }
  }

  @Test
  @DisplayName("maxDatastoreSize_whenFileStoreThrows_expectMemoryCap")
  void maxDatastoreSize_whenFileStoreThrows_expectMemoryCap() {
    // Arrange
    long memoryCap = runtimeMemoryDerivedMax();
    Path dataPath = resolveDataDirPath();
    try (MockedStatic<Files> files = mockStatic(Files.class, Answers.CALLS_REAL_METHODS)) {
      files.when(() -> Files.getFileStore(eq(dataPath))).thenThrow(new IOException("boom"));

      // Act
      long actual = DatastoreUtil.maxDatastoreSize();

      // Assert
      assertEquals(memoryCap, actual, "On IO error, should fall back to memory-derived cap");
    }
  }

  @Test
  @DisplayName("maxDatastoreSize_whenMemUnlimitedOrTiny_expectOneGiBBase")
  void maxDatastoreSize_whenMemUnlimitedOrTiny_expectOneGiBBase() {
    // Arrange
    try (MockedStatic<NodeStarter> ns = mockStatic(NodeStarter.class)) {
      // Case 1: Unlimited memory
      ns.when(NodeStarter::getMemoryLimitBytes).thenReturn(Long.MAX_VALUE);
      long actualUnlimited = DatastoreUtil.maxDatastoreSize();
      assertEquals(DatastoreUtil.ONE_GIB, actualUnlimited);

      // Case 2: Very small memory (< 128 MiB)
      ns.when(NodeStarter::getMemoryLimitBytes).thenReturn(127L * DatastoreUtil.ONE_MIB);
      long actualTiny = DatastoreUtil.maxDatastoreSize();
      assertEquals(DatastoreUtil.ONE_GIB, actualTiny);
    }
  }

  @Test
  @DisplayName("constants_whenDefined_expectTraditionalBinarySizes")
  void constants_whenDefined_expectTraditionalBinarySizes() {
    assertEquals(DatastoreUtil.ONE_MIB, 1024L * 1024);
    assertEquals(DatastoreUtil.ONE_GIB, 1024L * 1024 * 1024);
  }

  // --- autodetectDatastoreSize() ----------------------------------------------

  @Test
  @DisplayName("autodetectDatastoreSize_whenConfigOverridesStoreSize_expectMinusOne")
  void autodetectDatastoreSize_whenConfigOverridesStoreSize_expectMinusOne() {
    // Arrange
    NodeClientCore core = coreWithFreeSpace(10 * DatastoreUtil.ONE_GIB);
    Config cfg = configWithStoreSizeDefault(false /* not default */);

    // Act
    long actual = DatastoreUtil.autodetectDatastoreSize(core, cfg);

    // Assert
    assertEquals(-1, actual);
  }

  @Test
  @DisplayName("autodetectDatastoreSize_whenFreeSpaceNonPositive_expectMinusOne")
  void autodetectDatastoreSize_whenFreeSpaceNonPositive_expectMinusOne() {
    // Arrange
    NodeClientCore core = coreWithFreeSpace(0);
    Config cfg = configWithStoreSizeDefault(true);

    // Act
    long actual = DatastoreUtil.autodetectDatastoreSize(core, cfg);

    // Assert
    assertEquals(-1, actual);
  }

  @ParameterizedTest(name = "freeSpace={0} -> expected={1}")
  @MethodSource("heuristicCases")
  @DisplayName("autodetectDatastoreSize_whenFreeSpaceHeuristic_expectBoundedSuggestion")
  void autodetectDatastoreSize_whenFreeSpaceHeuristic_expectBoundedSuggestion(
      long freeSpace, long expected) {
    // Arrange
    NodeClientCore core = coreWithFreeSpace(freeSpace);
    Config cfg = configWithStoreSizeDefault(true);

    // Act
    long actual = DatastoreUtil.autodetectDatastoreSize(core, cfg);

    // Assert
    assertEquals(expected, actual);
  }

  @SuppressWarnings("PointlessArithmeticExpression")
  private static Stream<Arguments> heuristicCases() {
    long gib = DatastoreUtil.ONE_GIB;
    long mib = DatastoreUtil.ONE_MIB;
    return Stream.of(
        // > 50 GiB: 20% with 10 GiB minimum and 256 GiB cap
        Arguments.of(60L * gib, expectedAuto(60L * gib)),
        Arguments.of(55L * gib, expectedAuto(55L * gib)),
        Arguments.of(51L * gib, expectedAuto(51L * gib)),
        // Huge disk: capped at 256 GiB
        Arguments.of(10L * 1024 * gib, expectedAuto(10L * 1024 * gib)),
        // > 5 GiB and <= 50 GiB: 20% with 2 GiB minimum
        Arguments.of(50L * gib, expectedAuto(50L * gib)),
        Arguments.of(10L * gib, expectedAuto(10L * gib)),
        Arguments.of(6L * gib, expectedAuto(6L * gib)),
        // > 2 GiB and <= 5 GiB: 512 MiB
        Arguments.of(3L * gib, expectedAuto(3L * gib)),
        Arguments.of(2L * gib + 1, expectedAuto(2L * gib + 1)),
        // <= 2 GiB: 256 MiB
        Arguments.of(2L * gib, 256L * mib),
        Arguments.of(1L * gib, 256L * mib));
  }

  private static long expectedAuto(long freeSpace) {
    long gib = DatastoreUtil.ONE_GIB;
    long mib = DatastoreUtil.ONE_MIB;
    if (freeSpace <= 0) return -1;
    if (freeSpace > 50L * gib) {
      long bloomCap = 256L * gib;
      long base = Math.min(freeSpace / 5, bloomCap);
      return Math.max(10L * gib, base);
    } else if (freeSpace > 5L * gib) {
      return Math.max(freeSpace / 5, 2L * gib);
    } else if (freeSpace > 2L * gib) {
      return 512L * mib;
    } else {
      return 256L * mib;
    }
  }
}
