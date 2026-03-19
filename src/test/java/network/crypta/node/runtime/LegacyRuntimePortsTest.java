package network.crypta.node.runtime;

import java.io.File;
import java.util.Random;
import network.crypta.crypt.RandomSource;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class LegacyRuntimePortsTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private NodeClientCore core;

  @Mock private PriorityAwareExecutor executor;
  @Mock private RandomSource secureRandom;

  private final Random weakRandom = new Random(1234L);
  private final File downloadsDir = new File("downloads");
  private final File persistentTempDir = new File("persistent");
  private final File[] allowedUploadDirs = {new File("upload-a"), new File("upload-b")};
  private final File[] allowedDownloadDirs = {new File("download-a"), new File("download-b")};

  private LegacyRuntimePorts ports;

  @BeforeEach
  void setUp() {
    when(node.network().executor()).thenReturn(executor);
    when(node.bootstrap().random()).thenReturn(secureRandom);
    when(node.bootstrap().fastWeakRandom()).thenReturn(weakRandom);
    when(core.getDownloadsDir()).thenReturn(downloadsDir);
    when(core.getPersistentTempDir()).thenReturn(persistentTempDir);
    when(core.getAllowedUploadDirs()).thenReturn(allowedUploadDirs);
    when(core.getAllowedDownloadDirs()).thenReturn(allowedDownloadDirs);

    ports = new LegacyRuntimePorts(node, core);
  }

  @Test
  void getters_whenRequested_expectStablePortReferences() {
    PortsSnapshot snapshot = capturePorts();

    assertStableInfrastructurePorts(snapshot);
    assertStableFeaturePorts(snapshot);
  }

  private void assertStableInfrastructurePorts(PortsSnapshot snapshot) {
    assertAll(
        () -> assertSame(snapshot.executionPort(), ports.execution()),
        () -> assertSame(snapshot.randomnessPort(), ports.randomness()),
        () -> assertSame(snapshot.transferAccessPort(), ports.transferAccess()),
        () -> assertSame(snapshot.lifecyclePort(), ports.lifecycle()),
        () -> assertSame(snapshot.configPort(), ports.config()),
        () -> assertSame(snapshot.connectivityPort(), ports.connectivity()),
        () -> assertSame(snapshot.connectionsPagePort(), ports.connectionsPage()),
        () -> assertSame(snapshot.connectionsSupportPort(), ports.connectionsSupport()),
        () -> assertSame(snapshot.darknetConnectionsPort(), ports.darknetConnections()),
        () -> assertSame(snapshot.darknetMessagingPort(), ports.darknetMessaging()),
        () -> assertSame(snapshot.diagnosticPort(), ports.diagnostic()),
        () -> assertSame(snapshot.pageChromePort(), ports.pageChrome()),
        () -> assertSame(snapshot.coreUpdateActionPort(), ports.coreUpdateAction()));
  }

  private void assertStableFeaturePorts(PortsSnapshot snapshot) {
    assertAll(
        () -> assertSame(snapshot.queueSupportPort(), ports.queueSupport()),
        () -> assertSame(snapshot.queueCompletionPort(), ports.queueCompletion()),
        () -> assertSame(snapshot.queuePagePort(), ports.queuePage()),
        () -> assertSame(snapshot.queueDownloadPort(), ports.queueDownload()),
        () -> assertSame(snapshot.queueInsertPort(), ports.queueInsert()),
        () -> assertSame(snapshot.queueMutationPort(), ports.queueMutation()),
        () -> assertSame(snapshot.statisticsPort(), ports.statistics()),
        () -> assertSame(snapshot.securityLevelsPort(), ports.securityLevels()),
        () -> assertSame(snapshot.firstTimeWizardPort(), ports.firstTimeWizard()),
        () -> assertSame(snapshot.toadletSymlinkPort(), ports.toadletSymlinks()),
        () -> assertSame(snapshot.welcomePagePort(), ports.welcomePage()),
        () -> assertSame(snapshot.welcomeActionPort(), ports.welcomeAction()),
        () -> assertSame(snapshot.requestQueuePort(), ports.requestQueue()),
        () -> assertSame(snapshot.nodeInfoPort(), ports.nodeInfo()),
        () -> assertSame(snapshot.peerPort(), ports.peer()));
  }

  @Test
  void getters_whenRequested_expectLegacyAdapterTypes() {
    PortsSnapshot snapshot = capturePorts();

    assertAll(
        () -> assertInstanceOf(LegacyConfigPort.class, snapshot.configPort()),
        () -> assertInstanceOf(LegacyConnectivityPort.class, snapshot.connectivityPort()),
        () -> assertInstanceOf(LegacyConnectionsPagePort.class, snapshot.connectionsPagePort()),
        () ->
            assertInstanceOf(LegacyConnectionsSupportPort.class, snapshot.connectionsSupportPort()),
        () ->
            assertInstanceOf(LegacyDarknetConnectionsPort.class, snapshot.darknetConnectionsPort()),
        () -> assertInstanceOf(LegacyDarknetMessagingPort.class, snapshot.darknetMessagingPort()),
        () -> assertInstanceOf(LegacyDiagnosticPort.class, snapshot.diagnosticPort()),
        () -> assertInstanceOf(LegacyPageChromePort.class, snapshot.pageChromePort()),
        () -> assertInstanceOf(LegacyCoreUpdateActionPort.class, snapshot.coreUpdateActionPort()),
        () -> assertInstanceOf(LegacyQueueSupportPort.class, snapshot.queueSupportPort()),
        () -> assertInstanceOf(LegacyQueueCompletionPort.class, snapshot.queueCompletionPort()),
        () -> assertInstanceOf(LegacyQueuePagePort.class, snapshot.queuePagePort()),
        () -> assertInstanceOf(LegacyQueueDownloadPort.class, snapshot.queueDownloadPort()),
        () -> assertInstanceOf(LegacyQueueInsertPort.class, snapshot.queueInsertPort()),
        () -> assertInstanceOf(LegacyQueueMutationPort.class, snapshot.queueMutationPort()),
        () -> assertInstanceOf(LegacyStatisticsPort.class, snapshot.statisticsPort()),
        () -> assertInstanceOf(LegacySecurityLevelsPort.class, snapshot.securityLevelsPort()),
        () -> assertInstanceOf(LegacyFirstTimeWizardPort.class, snapshot.firstTimeWizardPort()),
        () -> assertInstanceOf(LegacyToadletSymlinkPort.class, snapshot.toadletSymlinkPort()),
        () -> assertInstanceOf(LegacyWelcomePagePort.class, snapshot.welcomePagePort()),
        () -> assertInstanceOf(LegacyWelcomeActionPort.class, snapshot.welcomeActionPort()),
        () -> assertInstanceOf(LegacyRequestQueuePort.class, snapshot.requestQueuePort()),
        () -> assertInstanceOf(LegacyNodeInfoPort.class, snapshot.nodeInfoPort()),
        () -> assertInstanceOf(LegacyPeerPort.class, snapshot.peerPort()));
  }

  @Test
  void execution_whenTaskSubmitted_expectDelegatesToNodeExecutor() {
    Runnable task = () -> {};

    ports.execution().execute(task, "runtime-task");

    verify(executor).execute(task, "runtime-task");
  }

  @Test
  void randomness_whenRequested_expectDelegatesToBootstrapRandomSources() {
    byte[] target = new byte[8];

    ports.randomness().fillSecureRandom(target);
    Random fastWeakRandom = ports.randomness().fastWeakRandom();

    verify(secureRandom).nextBytes(target);
    assertSame(weakRandom, fastWeakRandom);
  }

  @Test
  void transferAccess_whenRequested_expectDelegatesToCoreTransferPolicy() {
    File uploadCandidate = new File("candidate-upload");
    File downloadCandidate = new File("candidate-download");
    when(core.allowUploadFrom(uploadCandidate)).thenReturn(true);
    when(core.allowDownloadTo(downloadCandidate)).thenReturn(true);

    boolean uploadAllowed = ports.transferAccess().allowUploadFrom(uploadCandidate);
    boolean downloadAllowed = ports.transferAccess().allowDownloadTo(downloadCandidate);

    assertTrue(uploadAllowed);
    assertTrue(downloadAllowed);
    assertSame(downloadsDir, ports.transferAccess().downloadsDir());
    assertSame(persistentTempDir, ports.transferAccess().persistentTempDir());
    assertArrayEquals(allowedUploadDirs, ports.transferAccess().allowedUploadDirs());
    assertArrayEquals(allowedDownloadDirs, ports.transferAccess().allowedDownloadDirs());
  }

  @Test
  void lifecycle_whenRequested_expectDelegatesToNodeLifecycleState() {
    when(node.isHasStarted()).thenReturn(true);
    when(node.isStopping()).thenReturn(false);
    when(node.isUsingWrapper()).thenReturn(true);
    when(node.getStartupTime()).thenReturn(123456789L);

    assertAll(
        () -> assertTrue(ports.lifecycle().hasStarted()),
        () -> assertFalse(ports.lifecycle().isStopping()),
        () -> assertTrue(ports.lifecycle().isUsingWrapper()),
        () -> assertEquals(123456789L, ports.lifecycle().startupTimeMillis()));
  }

  private PortsSnapshot capturePorts() {
    return new PortsSnapshot(
        ports.execution(),
        ports.randomness(),
        ports.transferAccess(),
        ports.lifecycle(),
        ports.config(),
        ports.connectivity(),
        ports.connectionsPage(),
        ports.connectionsSupport(),
        ports.darknetConnections(),
        ports.darknetMessaging(),
        ports.diagnostic(),
        ports.pageChrome(),
        ports.coreUpdateAction(),
        ports.queueSupport(),
        ports.queueCompletion(),
        ports.queuePage(),
        ports.queueDownload(),
        ports.queueInsert(),
        ports.queueMutation(),
        ports.statistics(),
        ports.securityLevels(),
        ports.firstTimeWizard(),
        ports.toadletSymlinks(),
        ports.welcomePage(),
        ports.welcomeAction(),
        ports.requestQueue(),
        ports.nodeInfo(),
        ports.peer());
  }

  private record PortsSnapshot(
      Object executionPort,
      Object randomnessPort,
      Object transferAccessPort,
      Object lifecyclePort,
      Object configPort,
      Object connectivityPort,
      Object connectionsPagePort,
      Object connectionsSupportPort,
      Object darknetConnectionsPort,
      Object darknetMessagingPort,
      Object diagnosticPort,
      Object pageChromePort,
      Object coreUpdateActionPort,
      Object queueSupportPort,
      Object queueCompletionPort,
      Object queuePagePort,
      Object queueDownloadPort,
      Object queueInsertPort,
      Object queueMutationPort,
      Object statisticsPort,
      Object securityLevelsPort,
      Object firstTimeWizardPort,
      Object toadletSymlinkPort,
      Object welcomePagePort,
      Object welcomeActionPort,
      Object requestQueuePort,
      Object nodeInfoPort,
      Object peerPort) {}
}
