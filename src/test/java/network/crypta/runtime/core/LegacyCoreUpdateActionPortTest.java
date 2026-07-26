package network.crypta.runtime.core;

import java.io.File;
import java.nio.file.Path;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;
import network.crypta.node.Node;
import network.crypta.runtime.spi.CoreSupportLifecycleSnapshot;
import network.crypta.runtime.updater.CoreUpdater;
import network.crypta.runtime.updater.NodeUpdateManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyCoreUpdateActionPortTest {
  @TempDir Path tempDir;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeUpdateManager nodeUpdateManager;
  @Mock private CoreUpdater coreUpdater;

  @Test
  void isCoreUpdaterAvailable_whenUpdaterPresent_expectTrue() {
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getCoreUpdater()).thenReturn(coreUpdater);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertTrue(port.isCoreUpdaterAvailable());
  }

  @Test
  void isCoreUpdaterAvailable_whenUpdaterMissing_expectFalse() {
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getCoreUpdater()).thenReturn(null);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertFalse(port.isCoreUpdaterAvailable());
  }

  @Test
  void isCoreDownloadAvailable_whenSelectableUpdatePresent_expectTrue() {
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getCoreUpdater()).thenReturn(coreUpdater);
    when(coreUpdater.isUiDownloadAvailable()).thenReturn(true);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertTrue(port.isCoreDownloadAvailable());
  }

  @Test
  void isCoreDownloadAvailable_whenSelectableUpdateMissing_expectFalse() {
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getCoreUpdater()).thenReturn(coreUpdater);
    when(coreUpdater.isUiDownloadAvailable()).thenReturn(false);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertFalse(port.isCoreDownloadAvailable());
  }

  @Test
  void isCoreDownloadAvailable_whenUpdaterMissing_expectFalse() {
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getCoreUpdater()).thenReturn(null);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertFalse(port.isCoreDownloadAvailable());
  }

  @Test
  void startCoreDownloadFromUi_whenUpdaterPresent_expectDelegatesToCoreUpdater() {
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getCoreUpdater()).thenReturn(coreUpdater);
    when(coreUpdater.startDownloadFromUI()).thenReturn(true);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);
    assertTrue(port.startCoreDownloadFromUi());

    verify(coreUpdater).startDownloadFromUI();
  }

  @Test
  void startCoreDownloadFromUi_whenManagerMissing_expectFalse() {
    when(node.services().nodeUpdater()).thenReturn(null);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertFalse(port.startCoreDownloadFromUi());
  }

  @Test
  void withCurrentStoreTarget_whenUpdaterApprovesSelection_expectActionRunsThroughCoreUpdater() {
    String url = "https://flathub.org/apps/network.crypta.Cryptad";
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getCoreUpdater()).thenReturn(coreUpdater);
    doAnswer(
            invocation -> {
              @SuppressWarnings("unchecked")
              Supplier<String> action = invocation.getArgument(3, Supplier.class);
              return Optional.of(action.get());
            })
        .when(coreUpdater)
        .withCurrentStoreTarget(eq("flatpak"), eq("network.crypta.Cryptad"), eq(url), any());

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertEquals(
        Optional.of("launched"),
        port.withCurrentStoreTarget("flatpak", "network.crypta.Cryptad", url, () -> "launched"));
    verify(coreUpdater)
        .withCurrentStoreTarget(eq("flatpak"), eq("network.crypta.Cryptad"), eq(url), any());
  }

  @Test
  void withCurrentStoreTarget_whenUpdaterMissing_expectEmpty() {
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getCoreUpdater()).thenReturn(null);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertTrue(
        port.withCurrentStoreTarget(
                "flatpak",
                "network.crypta.Cryptad",
                "https://flathub.org/apps/network.crypta.Cryptad",
                () -> "launched")
            .isEmpty());
  }

  @Test
  void supportLifecycleSnapshot_whenManagerPresent_expectDetachedStateDelegated() {
    CoreSupportLifecycleSnapshot snapshot =
        CoreSupportLifecycleSnapshot.unknown(1200, java.util.List.of("lifecycle_unknown"));
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.supportLifecycleSnapshot()).thenReturn(snapshot);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertEquals(snapshot, port.supportLifecycleSnapshot());
  }

  @Test
  void supportLifecycleSnapshot_whenManagerMissing_expectFailClosedUnknownState() {
    when(node.services().nodeUpdater()).thenReturn(null);

    CoreSupportLifecycleSnapshot snapshot =
        new LegacyCoreUpdateActionPort(node).supportLifecycleSnapshot();

    assertFalse(snapshot.known());
    assertEquals(java.util.List.of("lifecycle_updater_unavailable"), snapshot.warnings());
  }

  @Test
  void withDownloadedInstaller_whenPathIsBlank_expectEmpty() {
    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    Optional<String> result = port.withDownloadedInstaller(" \t", Path::toString);

    assertTrue(result.isEmpty());
  }

  @Test
  void withDownloadedInstaller_whenPathContainsNul_expectEmpty() {
    File nodeDir = tempDir.resolve("node").toFile();
    when(node.getNodeDir()).thenReturn(nodeDir);
    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    Optional<String> result = port.withDownloadedInstaller("\0", Path::toString);

    assertTrue(result.isEmpty());
  }

  @Test
  void withDownloadedInstaller_whenPathInsideCoreUpdates_expectActionRunsWithCanonicalPath()
      throws Exception {
    File nodeDir = tempDir.resolve("node").toFile();
    File updatesDir = new File(nodeDir, "updates/core");
    File installer = new File(updatesDir, "version/../cryptad.deb");
    assertTrue(updatesDir.mkdirs() || updatesDir.isDirectory());
    when(node.getNodeDir()).thenReturn(nodeDir);
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getCoreUpdater()).thenReturn(coreUpdater);
    doAnswer(
            invocation -> {
              File submitted = invocation.getArgument(0);
              @SuppressWarnings("unchecked")
              Function<File, String> action = invocation.getArgument(1, Function.class);
              return Optional.of(action.apply(submitted));
            })
        .when(coreUpdater)
        .withDownloadedInstaller(any(File.class), any());

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    String launchedPath =
        port.withDownloadedInstaller(installer.getPath(), Path::toString).orElseThrow();

    assertEquals(installer.getCanonicalFile().toPath().toString(), launchedPath);
  }

  @Test
  void withDownloadedInstaller_whenLifecycleRevokesRenderedPackage_expectEmpty() {
    File nodeDir = tempDir.resolve("node").toFile();
    File updatesDir = new File(nodeDir, "updates/core");
    File installer = new File(updatesDir, "1501/cryptad.deb");
    assertTrue(installer.getParentFile().mkdirs());
    when(node.getNodeDir()).thenReturn(nodeDir);
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.getCoreUpdater()).thenReturn(coreUpdater);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertTrue(port.withDownloadedInstaller(installer.getPath(), Path::toString).isEmpty());
  }

  @Test
  void withDownloadedInstaller_whenPathOutsideCoreUpdates_expectEmpty() {
    File nodeDir = tempDir.resolve("node").toFile();
    File outside = tempDir.resolve("outside/cryptad.deb").toFile();
    when(node.getNodeDir()).thenReturn(nodeDir);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertTrue(port.withDownloadedInstaller(outside.getPath(), Path::toString).isEmpty());
  }
}
