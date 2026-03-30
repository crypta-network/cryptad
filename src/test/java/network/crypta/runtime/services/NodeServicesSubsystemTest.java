package network.crypta.runtime.services;

import java.io.File;
import network.crypta.config.BooleanCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeInitException;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.runtime.alerts.JVMVersionAlert;
import network.crypta.runtime.alerts.MeaningfulNodeNameUserAlert;
import network.crypta.runtime.alerts.NotEnoughNiceLevelsUserAlert;
import network.crypta.runtime.alerts.PeersOffersUserAlert;
import network.crypta.runtime.alerts.SimpleUserAlert;
import network.crypta.runtime.alerts.TimeSkewDetectedUserAlert;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.diagnostics.DefaultNodeDiagnostics;
import network.crypta.runtime.endpoints.http.HttpShellContainer;
import network.crypta.runtime.endpoints.http.HttpShellContainerFactory;
import network.crypta.runtime.updater.NodeUpdateManager;
import network.crypta.support.JVMVersion;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

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
  @Mock private HttpShellContainerFactory httpShellContainerFactory;

  @Test
  void startWebInterface_whenInitialized_startsAndExposesToadletServer() throws Exception {
    NodeServicesSubsystem subsystem = newSubsystem();
    when(config.createSubConfig("fproxy")).thenReturn(subConfig);
    HttpShellContainer toadlets = mock(HttpShellContainer.class);
    when(httpShellContainerFactory.create(subConfig, executor)).thenReturn(toadlets);

    subsystem.startWebInterface(config, executor);

    assertSame(toadlets, subsystem.toadlets());
    InOrder order = inOrder(httpShellContainerFactory, subConfig, toadlets);
    order.verify(httpShellContainerFactory).create(subConfig, executor);
    order.verify(subConfig).finishedInitialization();
    order.verify(toadlets).start();
  }

  @Test
  void startWebInterface_whenConstructedWithDefaultFactory_usesDefaultFactorySeam()
      throws Exception {
    when(config.createSubConfig("fproxy")).thenReturn(subConfig);
    HttpShellContainer toadlets = mock(HttpShellContainer.class);

    try (MockedStatic<HttpShellContainerFactory> mocked =
        mockStatic(HttpShellContainerFactory.class)) {
      mocked.when(HttpShellContainerFactory::defaultFactory).thenReturn(httpShellContainerFactory);
      when(httpShellContainerFactory.create(subConfig, executor)).thenReturn(toadlets);
      NodeServicesSubsystem subsystem = new NodeServicesSubsystem(node);

      subsystem.startWebInterface(config, executor);

      mocked.verify(HttpShellContainerFactory::defaultFactory);
      assertSame(toadlets, subsystem.toadlets());
      InOrder order = inOrder(httpShellContainerFactory, subConfig, toadlets);
      order.verify(httpShellContainerFactory).create(subConfig, executor);
      order.verify(subConfig).finishedInitialization();
      order.verify(toadlets).start();
    }
  }

  @Test
  void startWebInterface_whenConfigInvalid_throwsNodeInitException() throws Exception {
    NodeServicesSubsystem subsystem = newSubsystem();
    when(config.createSubConfig("fproxy")).thenReturn(subConfig);
    when(httpShellContainerFactory.create(subConfig, executor))
        .thenThrow(new InvalidConfigValueException("bad:css"));

    NodeInitException ex =
        assertThrows(NodeInitException.class, () -> subsystem.startWebInterface(config, executor));

    assertEquals(NodeInitException.EXIT_COULD_NOT_START_FPROXY, ex.exitCode);
    assertTrue(ex.getMessage().contains("Could not start FProxy"));
  }

  @Test
  void initUpdater_whenMaybeCreateReturns_setsUpdater() throws Exception {
    NodeServicesSubsystem subsystem = newSubsystem();
    NodeUpdateManager updater = mock(NodeUpdateManager.class);

    try (MockedStatic<NodeUpdateManager> mocked = mockStatic(NodeUpdateManager.class)) {
      mocked.when(() -> NodeUpdateManager.maybeCreate(node, config)).thenReturn(updater);

      subsystem.initUpdater(config);

      assertSame(updater, subsystem.nodeUpdater());
    }
  }

  @Test
  void initDiagnostics_whenNetworkProvided_createsDiagnostics() {
    NodeServicesSubsystem subsystem = newSubsystem();
    when(network.stats()).thenReturn(mock(network.crypta.node.NodeStats.class));
    when(network.ticker()).thenReturn(ticker);

    subsystem.initDiagnostics(network);

    DefaultNodeDiagnostics diagnostics = subsystem.nodeDiagnostics();
    assertNotNull(diagnostics);
  }

  @Test
  void initNodeNameUserAlert_whenCalled_createsAlert() {
    NodeServicesSubsystem subsystem = newSubsystem();

    subsystem.initNodeNameUserAlert();

    MeaningfulNodeNameUserAlert alert = subsystem.nodeNameUserAlert();
    assertNotNull(alert);
  }

  @Test
  void registerJvmVersionAlertIfNeeded_whenEol_registersAlert() {
    NodeServicesSubsystem subsystem = newSubsystem();
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
    NodeServicesSubsystem subsystem = newSubsystem();
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);

    subsystem.registerNotEnoughNiceLevelsAlert();

    verify(alerts).register(isA(NotEnoughNiceLevelsUserAlert.class));
  }

  @Test
  void warnIfNotUsingWrapper_whenWarningRequired_registersAlert() {
    NodeServicesSubsystem subsystem = newSubsystem();
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);

    subsystem.warnIfNotUsingWrapper(false, false);

    verify(alerts).register(isA(SimpleUserAlert.class));
  }

  @Test
  void warnIfNotUsingWrapper_whenUsingWrapper_skipsAlert() {
    NodeServicesSubsystem subsystem = newSubsystem();
    subsystem.setClientCore(clientCore);

    subsystem.warnIfNotUsingWrapper(true, false);

    verifyNoInteractions(alerts);
  }

  @Test
  void registerCantDeletePasswordFileAlert_whenClientCorePresent_registersCriticalAlert() {
    NodeServicesSubsystem subsystem = newSubsystem();
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(node.storage()).thenReturn(storage);
    when(storage.getMasterKeysFile()).thenReturn(new File("master.keys"));

    subsystem.registerCantDeletePasswordFileAlert();

    verify(alerts).register(isA(SimpleUserAlert.class));
  }

  @Test
  void configurePeersOffersFrefFiles_whenDismissed_unregistersExistingAlert() throws Exception {
    NodeServicesSubsystem subsystem = newSubsystem();
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
    NodeServicesSubsystem subsystem = newSubsystem();
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
    NodeServicesSubsystem subsystem = newSubsystem();
    when(subConfig.getBoolean(PEERS_OFFERS_DISMISSED)).thenReturn(false);

    subsystem.configurePeersOffersFrefFiles(subConfig, 1);

    try (MockedStatic<PeersOffersUserAlert> mocked = mockStatic(PeersOffersUserAlert.class)) {
      subsystem.maybeCreatePeersOffersAlertIfNeeded(true);

      mocked.verify(() -> PeersOffersUserAlert.createAlert(node));
    }
  }

  @Test
  void setTimeSkewDetectedUserAlert_whenCalledTwice_registersOnce() {
    NodeServicesSubsystem subsystem = newSubsystem();
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);

    subsystem.setTimeSkewDetectedUserAlert();
    subsystem.setTimeSkewDetectedUserAlert();

    verify(alerts).register(isA(TimeSkewDetectedUserAlert.class));
  }

  @Test
  void createVisibilityAlert_whenNotShown_registersAndQueuesStore() {
    NodeServicesSubsystem subsystem = newSubsystem();
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
  void createVisibilityAlert_whenDismissed_clearsFlagPersistsAndUnregistersAlert() {
    NodeServicesSubsystem subsystem = newSubsystem();
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(node.network()).thenReturn(network);
    when(network.ticker()).thenReturn(ticker);
    when(node.getConfig()).thenReturn(config);

    ArgumentCaptor<UserAlert> alertCaptor = ArgumentCaptor.forClass(UserAlert.class);

    subsystem.createVisibilityAlert();

    verify(alerts).register(alertCaptor.capture());
    UserAlert registeredAlert = alertCaptor.getValue();
    registeredAlert.onDismiss();

    assertFalse(subsystem.isShowFriendsVisibilityAlert());
    verify(config).store();
    verify(alerts).unregister(registeredAlert);
  }

  @Test
  void createVisibilityAlert_whenRegistered_usesExistingLocalizedVisibilityStrings() {
    NodeServicesSubsystem subsystem = newSubsystem();
    subsystem.setClientCore(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(node.network()).thenReturn(network);
    when(network.ticker()).thenReturn(ticker);
    when(node.getConfig()).thenReturn(config);

    ArgumentCaptor<UserAlert> alertCaptor = ArgumentCaptor.forClass(UserAlert.class);

    subsystem.createVisibilityAlert();

    verify(alerts).register(alertCaptor.capture());
    UserAlert registeredAlert = alertCaptor.getValue();

    assertEquals(
        NodeL10n.getBase().getString("Node.pleaseSetPeersVisibilityAlertTitle"),
        registeredAlert.getTitle());
    assertEquals(
        NodeL10n.getBase().getString("Node.pleaseSetPeersVisibilityAlert"),
        registeredAlert.getText());
    assertEquals(
        NodeL10n.getBase().getString("Node.pleaseSetPeersVisibilityAlert"),
        registeredAlert.getShortText());
    assertEquals(UserAlert.ERROR, registeredAlert.getPriorityClass());
  }

  @Test
  void maybeRegisterVisibilityAlert_whenAlertsNotReady_queuesRetry() {
    NodeServicesSubsystem subsystem = newSubsystem();
    subsystem.setShowFriendsVisibilityAlert(true);
    when(node.network()).thenReturn(network);
    when(network.ticker()).thenReturn(ticker);

    subsystem.maybeRegisterVisibilityAlert();

    verify(ticker).queueTimedJob(any(Runnable.class), eq(0L));
    verifyNoInteractions(alerts);
  }

  @Test
  void clearVisibilityAlert_whenCalled_unregistersAlertAndResetsFlag() {
    NodeServicesSubsystem subsystem = newSubsystem();
    subsystem.setClientCore(clientCore);
    subsystem.setShowFriendsVisibilityAlert(true);
    when(clientCore.getAlerts()).thenReturn(alerts);

    subsystem.clearVisibilityAlert();

    assertFalse(subsystem.isShowFriendsVisibilityAlert());
    verify(alerts).unregister(isA(UserAlert.class));
  }

  @Test
  void registerJvmVersionAlertIfNeeded_whenNoClientCore_skipsAlert() {
    NodeServicesSubsystem subsystem = newSubsystem();

    subsystem.registerJvmVersionAlertIfNeeded();

    verifyNoInteractions(alerts);
  }

  @Test
  void registerNotEnoughNiceLevelsAlert_whenNoClientCore_skipsAlert() {
    NodeServicesSubsystem subsystem = newSubsystem();

    subsystem.registerNotEnoughNiceLevelsAlert();

    verifyNoInteractions(alerts);
  }

  @Test
  void warnIfNotUsingWrapper_whenSkipped_doesNotRegister() {
    NodeServicesSubsystem subsystem = newSubsystem();
    subsystem.setClientCore(clientCore);

    subsystem.warnIfNotUsingWrapper(false, true);

    verify(alerts, never()).register(any(UserAlert.class));
  }

  private NodeServicesSubsystem newSubsystem() {
    return new NodeServicesSubsystem(node, httpShellContainerFactory);
  }
}
