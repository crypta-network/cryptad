package network.crypta.runtime.core;

import java.io.File;
import java.nio.file.Path;
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
  void supportLifecycleSnapshot_whenManagerPresent_expectDetachedStateDelegated() {
    CoreSupportLifecycleSnapshot snapshot =
        CoreSupportLifecycleSnapshot.unknown(1200, java.util.List.of("lifecycle_unknown"));
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(nodeUpdateManager.supportLifecycleSnapshot()).thenReturn(snapshot);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertEquals(snapshot, port.supportLifecycleSnapshot());
  }

  @Test
  void resolveDownloadedInstaller_whenPathInsideCoreUpdates_expectCanonicalPath() throws Exception {
    File nodeDir = tempDir.resolve("node").toFile();
    File updatesDir = new File(nodeDir, "updates/core");
    File installer = new File(updatesDir, "version/../cryptad.deb");
    assertTrue(updatesDir.mkdirs() || updatesDir.isDirectory());
    when(node.getNodeDir()).thenReturn(nodeDir);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    Path resolved = port.resolveDownloadedInstaller(installer.getPath()).orElseThrow();

    assertEquals(installer.getCanonicalFile().toPath(), resolved);
  }

  @Test
  void resolveDownloadedInstaller_whenPathOutsideCoreUpdates_expectEmpty() {
    File nodeDir = tempDir.resolve("node").toFile();
    File outside = tempDir.resolve("outside/cryptad.deb").toFile();
    when(node.getNodeDir()).thenReturn(nodeDir);

    LegacyCoreUpdateActionPort port = new LegacyCoreUpdateActionPort(node);

    assertTrue(port.resolveDownloadedInstaller(outside.getPath()).isEmpty());
  }
}
