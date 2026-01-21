package network.crypta.node.subsystem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.File;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeInitException;
import network.crypta.node.diagnostics.DefaultNodeDiagnostics;
import network.crypta.node.updater.NodeUpdateManager;
import network.crypta.node.useralerts.JVMVersionAlert;
import network.crypta.node.useralerts.MeaningfulNodeNameUserAlert;
import network.crypta.node.useralerts.NotEnoughNiceLevelsUserAlert;
import network.crypta.node.useralerts.PeersOffersUserAlert;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.TimeSkewDetectedUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.JVMVersion;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import network.crypta.support.api.BooleanCallback;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeServicesSubsystemTest {
  private static final String PEERS_OFFERS_DISMISSED = "peersOffersDismissed";

  @Mock private Node node;
  @Mock private NodeClientCore clientCore;
  @Mock private UserAlertManager alerts;
  @Mock private NodeNetworkSubsystem network;
  @Mock private NodeStorageSubsystem storage;
  @Mock private Ticker ticker;
  @Mock private PersistentConfig config;
  @Mock private SubConfig subConfig;
  @Mock private PriorityAwareExecutor executor;

  @Test
  void startWebInterface_whenInitialized_startsAndExposesToadletServer() throws Exception {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    when(config.createSubConfig("fproxy")).thenReturn(subConfig);

    try (MockedConstruction<SimpleToadletServer> construction =
        mockConstruction(SimpleToadletServer.class)) {
      subsystem.startWebInterface(config, executor);

      assertSame(construction.constructed().getFirst(), subsystem.toadlets());
      verify(subConfig).finishedInitialization();
      verify(construction.constructed().getFirst()).start();
    }
  }

  @Test
  void startWebInterface_whenConfigInvalid_throwsNodeInitException() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    when(config.createSubConfig("fproxy")).thenReturn(subConfig);
    when(subConfig.getString(anyString()))
        .thenAnswer(
            invocation -> {
              String key = invocation.getArgument(0, String.class);
              if ("css".equals(key)) {
                return "bad:css";
              }
              if ("refilterPolicy".equals(key)) {
                return "RE_FILTER";
              }
              return "";
            });

    NodeInitException ex =
        assertThrows(NodeInitException.class, () -> subsystem.startWebInterface(config, executor));

    assertEquals(NodeInitException.EXIT_COULD_NOT_START_FPROXY, ex.exitCode);
    assertTrue(ex.getMessage().contains("Could not start FProxy"));
  }

  @Test
  void initUpdater_whenMaybeCreateReturns_setsUpdater() throws Exception {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    NodeUpdateManager updater = mock(NodeUpdateManager.class);

    try (MockedStatic<NodeUpdateManager> mocked = mockStatic(NodeUpdateManager.class)) {
      mocked.when(() -> NodeUpdateManager.maybeCreate(node, config)).thenReturn(updater);

      subsystem.initUpdater(config);

      assertSame(updater, subsystem.nodeUpdater());
    }
  }

  @Test
  void initDiagnostics_whenNetworkProvided_createsDiagnostics() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    when(network.stats()).thenReturn(mock(network.crypta.node.NodeStats.class));
    when(network.ticker()).thenReturn(ticker);

    subsystem.initDiagnostics(network);

    DefaultNodeDiagnostics diagnostics = subsystem.nodeDiagnostics();
    assertNotNull(diagnostics);
  }

  @Test
  void initNodeNameUserAlert_whenCalled_createsAlert() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);

    subsystem.initNodeNameUserAlert();

    MeaningfulNodeNameUserAlert alert = subsystem.nodeNameUserAlert();
    assertNotNull(alert);
  }

  @Test
  void registerJvmVersionAlertIfNeeded_whenEol_registersAlert() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);

    try (MockedStatic<JVMVersion> mocked = mockStatic(JVMVersion.class)) {
      mocked.when(JVMVersion::isEOL).thenReturn(true);

      subsystem.registerJvmVersionAlertIfNeeded();

      verify(alerts).register(isA(JVMVersionAlert.class));
    }
  }

  @Test
  void registerNotEnoughNiceLevelsAlert_whenClientCorePresent_registersAlert() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);

    subsystem.registerNotEnoughNiceLevelsAlert();

    verify(alerts).register(isA(NotEnoughNiceLevelsUserAlert.class));
  }

  @Test
  void warnIfNotUsingWrapper_whenWarningRequired_registersAlert() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);

    subsystem.warnIfNotUsingWrapper(false, false);

    verify(alerts).register(isA(SimpleUserAlert.class));
  }

  @Test
  void warnIfNotUsingWrapper_whenUsingWrapper_skipsAlert() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setClientCore(clientCore);

    subsystem.warnIfNotUsingWrapper(true, false);

    verifyNoInteractions(alerts);
  }

  @Test
  void registerCantDeletePasswordFileAlert_whenClientCorePresent_registersCriticalAlert() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(node.storage()).thenReturn(storage);
    when(storage.getMasterKeysFile()).thenReturn(new File("master.keys"));

    subsystem.registerCantDeletePasswordFileAlert();

    verify(alerts).register(isA(SimpleUserAlert.class));
  }

  @Test
  void configurePeersOffersFrefFiles_whenDismissed_unregistersExistingAlert() throws Exception {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    PeersOffersUserAlert existingAlert = mock(PeersOffersUserAlert.class);
    when(alerts.getAlerts()).thenReturn(new UserAlert[] {existingAlert});
    when(subConfig.getBoolean(PEERS_OFFERS_DISMISSED)).thenReturn(false);

    ArgumentCaptor<BooleanCallback> captor = ArgumentCaptor.forClass(BooleanCallback.class);

    subsystem.configurePeersOffersFrefFiles(subConfig, 7);

    verify(subConfig)
        .register(eq(PEERS_OFFERS_DISMISSED), eq(false), any(Option.Meta.class), captor.capture());

    captor.getValue().set(Boolean.TRUE);

    verify(alerts).unregister(existingAlert);
  }

  @Test
  void configurePeersOffersFrefFiles_whenNotDismissed_createsAlert() throws Exception {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    when(subConfig.getBoolean(PEERS_OFFERS_DISMISSED)).thenReturn(false);

    ArgumentCaptor<BooleanCallback> captor = ArgumentCaptor.forClass(BooleanCallback.class);

    try (MockedStatic<PeersOffersUserAlert> mocked = mockStatic(PeersOffersUserAlert.class)) {
      subsystem.configurePeersOffersFrefFiles(subConfig, 3);

      verify(subConfig)
          .register(
              eq(PEERS_OFFERS_DISMISSED), eq(false), any(Option.Meta.class), captor.capture());

      captor.getValue().set(Boolean.FALSE);

      mocked.verify(() -> PeersOffersUserAlert.createAlert(node));
    }
  }

  @Test
  void maybeCreatePeersOffersAlertIfNeeded_whenNotDismissedAndHasFiles_createsAlert() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    when(subConfig.getBoolean(PEERS_OFFERS_DISMISSED)).thenReturn(false);

    subsystem.configurePeersOffersFrefFiles(subConfig, 1);

    try (MockedStatic<PeersOffersUserAlert> mocked = mockStatic(PeersOffersUserAlert.class)) {
      subsystem.maybeCreatePeersOffersAlertIfNeeded(true);

      mocked.verify(() -> PeersOffersUserAlert.createAlert(node));
    }
  }

  @Test
  void setTimeSkewDetectedUserAlert_whenCalledTwice_registersOnce() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);

    subsystem.setTimeSkewDetectedUserAlert();
    subsystem.setTimeSkewDetectedUserAlert();

    verify(alerts).register(isA(TimeSkewDetectedUserAlert.class));
  }

  @Test
  void createVisibilityAlert_whenNotShown_registersAndQueuesStore() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(node.network()).thenReturn(network);
    when(network.ticker()).thenReturn(ticker);
    when(node.getConfig()).thenReturn(config);

    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);

    subsystem.createVisibilityAlert();

    assertTrue(subsystem.isShowFriendsVisibilityAlert());
    verify(ticker).queueTimedJob(runnableCaptor.capture(), eq(0L));
    verify(alerts).register(isA(UserAlert.class));

    runnableCaptor.getValue().run();
    verify(config).store();
  }

  @Test
  void maybeRegisterVisibilityAlert_whenAlertsNotReady_queuesRetry() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setShowFriendsVisibilityAlert(true);
    when(node.network()).thenReturn(network);
    when(network.ticker()).thenReturn(ticker);

    subsystem.maybeRegisterVisibilityAlert();

    verify(ticker).queueTimedJob(any(Runnable.class), eq(0L));
    verifyNoInteractions(alerts);
  }

  @Test
  void clearVisibilityAlert_whenCalled_unregistersAlertAndResetsFlag() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setClientCore(clientCore);
    subsystem.setShowFriendsVisibilityAlert(true);
    when(clientCore.getAlerts()).thenReturn(alerts);

    subsystem.clearVisibilityAlert();

    assertFalse(subsystem.isShowFriendsVisibilityAlert());
    verify(alerts).unregister(isA(UserAlert.class));
  }

  @Test
  void registerJvmVersionAlertIfNeeded_whenNoClientCore_skipsAlert() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);

    subsystem.registerJvmVersionAlertIfNeeded();

    verifyNoInteractions(alerts);
  }

  @Test
  void registerNotEnoughNiceLevelsAlert_whenNoClientCore_skipsAlert() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);

    subsystem.registerNotEnoughNiceLevelsAlert();

    verifyNoInteractions(alerts);
  }

  @Test
  void warnIfNotUsingWrapper_whenSkipped_doesNotRegister() {
    NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);
    subsystem.setClientCore(clientCore);

    subsystem.warnIfNotUsingWrapper(false, true);

    verify(alerts, never()).register(any(UserAlert.class));
  }
}
