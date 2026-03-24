package network.crypta.runtime.admin;

import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeStarter;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.node.useralerts.UpgradeConnectionSpeedUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class LegacyWelcomeActionPortTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private Ticker ticker;
  @Mock private PersistentConfig config;
  @Mock private SubConfig nodeConfig;
  @Mock private NodeStarter nodeStarter;
  @Mock private NodeUpdateManager nodeUpdateManager;
  @Mock private UserAlertManager alertManager;
  @Mock private UpgradeConnectionSpeedUserAlert upgradeAlert;

  private LegacyWelcomeActionPort port;

  @BeforeEach
  void setUp() {
    when(node.network().ticker()).thenReturn(ticker);
    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeConfig);
    when(node.getNodeStarter()).thenReturn(nodeStarter);
    when(node.services().nodeUpdater()).thenReturn(nodeUpdateManager);
    when(node.services().clientCore().getAlerts()).thenReturn(alertManager);

    port = new LegacyWelcomeActionPort(node);
  }

  @Test
  void armNodeUpdate_whenInvoked_delegatesToNodeUpdater() {
    port.armNodeUpdate();

    verify(nodeUpdateManager).arm();
  }

  @Test
  void queueShutdownFromWelcome_whenInvoked_schedulesNodeExit() {
    ArgumentCaptor<Runnable> shutdownJob = ArgumentCaptor.forClass(Runnable.class);

    port.queueShutdownFromWelcome();

    verify(ticker).queueTimedJob(shutdownJob.capture(), eq(1L));
    shutdownJob.getValue().run();
    verify(node).exit("Shutdown from fproxy");
  }

  @Test
  void queueRestartFromWelcome_whenInvoked_schedulesNodeRestart() {
    ArgumentCaptor<Runnable> restartJob = ArgumentCaptor.forClass(Runnable.class);

    port.queueRestartFromWelcome();

    verify(ticker).queueTimedJob(restartJob.capture(), eq(1L));
    restartJob.getValue().run();
    verify(nodeStarter).restart();
  }

  @Test
  void applyUpgradeConnectionSpeed_whenValuesValid_updatesConfigAndAlert() throws Exception {
    when(alertManager.getAlerts()).thenReturn(new UserAlert[] {upgradeAlert});

    port.applyUpgradeConnectionSpeed("32KiB", "16KiB");

    verify(nodeConfig).set("inputBandwidthLimit", "32KiB");
    verify(nodeConfig).set("outputBandwidthLimit", "16KiB");
    verify(upgradeAlert).setUpgraded(true);
  }

  @Test
  void applyUpgradeConnectionSpeed_whenValuesInvalid_setsAlertErrorWithoutWritingConfig() {
    ArgumentCaptor<String> errorMessage = ArgumentCaptor.forClass(String.class);
    when(alertManager.getAlerts()).thenReturn(new UserAlert[] {upgradeAlert});

    port.applyUpgradeConnectionSpeed("not-a-limit", "also-invalid");

    verify(upgradeAlert).setError(errorMessage.capture());
    assertNotNull(errorMessage.getValue());
    assertFalse(errorMessage.getValue().isBlank());
    verifyNoInteractions(nodeConfig);
  }

  @Test
  void applyUpgradeConnectionSpeed_whenConfigWriteNeedsRestart_swallowsException()
      throws Exception {
    when(alertManager.getAlerts()).thenReturn(new UserAlert[] {upgradeAlert});
    doThrow(new NodeNeedRestartException("restart required"))
        .when(nodeConfig)
        .set("outputBandwidthLimit", "16KiB");

    assertDoesNotThrow(() -> port.applyUpgradeConnectionSpeed("32KiB", "16KiB"));

    verify(nodeConfig).set("inputBandwidthLimit", "32KiB");
    verify(nodeConfig).set("outputBandwidthLimit", "16KiB");
    verify(upgradeAlert, never()).setUpgraded(true);
    verify(upgradeAlert, never()).setError(anyString());
  }
}
