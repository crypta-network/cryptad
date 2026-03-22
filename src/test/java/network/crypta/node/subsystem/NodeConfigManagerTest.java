package network.crypta.node.subsystem;

import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.useralerts.MeaningfulNodeNameUserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeConfigManagerTest {
  private static final String DEFAULT_NODE_NAME = "MyFirstCryptaNode";
  private static final String CUSTOM_NODE_NAME = "Custom Node";

  @TempDir Path tempDir;

  @AfterEach
  void resetLocalization() {
    // Ensure any test-modified localization state does not leak to other tests.
    new network.crypta.l10n.NodeL10n();
  }

  @Test
  void configureLocalization_registersOptionAndReturnsIncrementedSortOrder() {
    Node node = mock(Node.class);
    NodeConfigManager manager = new NodeConfigManager(node);
    SubConfig nodeConfig = mock(SubConfig.class);
    ProgramDirectory cfgDir = mock(ProgramDirectory.class);
    Option<?> option = mock(Option.class);

    when(nodeConfig.getString("l10n")).thenReturn("en");
    lenient().when(nodeConfig.getOption("l10n")).thenAnswer(_ -> option);
    lenient().when(option.getDefault()).thenReturn("en");
    when(cfgDir.dir()).thenReturn(tempDir.toFile());

    int startOrder = 7;
    int result = manager.configureLocalization(nodeConfig, cfgDir, startOrder);

    assertEquals(startOrder + 1, result);

    ArgumentCaptor<network.crypta.config.StringCallback> callbackCaptor =
        ArgumentCaptor.forClass(network.crypta.config.StringCallback.class);
    verify(nodeConfig)
        .register(
            eq("l10n"),
            eq(Locale.getDefault().getLanguage().toLowerCase(Locale.ROOT)),
            any(Option.Meta.class),
            callbackCaptor.capture());
    assertInstanceOf(EnumerableOptionCallback.class, callbackCaptor.getValue());
  }

  @Test
  void nodeNameCallback_get_whenDefaultName_registersAlert() {
    AtomicReference<String> name = new AtomicReference<>(DEFAULT_NODE_NAME);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    network.crypta.node.NodeClientCore clientCore = mock(network.crypta.node.NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    MeaningfulNodeNameUserAlert alert = mock(MeaningfulNodeNameUserAlert.class);

    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(services.nodeNameUserAlert()).thenReturn(alert);
    when(node.getMyName()).thenAnswer(_ -> name.get());

    NodeConfigManager.NodeNameCallback callback =
        new NodeConfigManager(node).new NodeNameCallback();

    String result = callback.get();

    assertEquals(DEFAULT_NODE_NAME, result);
    verify(alerts).register(alert);
    verify(alerts, never()).unregister(alert);
  }

  @Test
  void nodeNameCallback_get_whenCustomName_unregistersAlert() {
    AtomicReference<String> name = new AtomicReference<>(CUSTOM_NODE_NAME);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    network.crypta.node.NodeClientCore clientCore = mock(network.crypta.node.NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    MeaningfulNodeNameUserAlert alert = mock(MeaningfulNodeNameUserAlert.class);

    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(services.nodeNameUserAlert()).thenReturn(alert);
    when(node.getMyName()).thenAnswer(_ -> name.get());

    NodeConfigManager.NodeNameCallback callback =
        new NodeConfigManager(node).new NodeNameCallback();

    String result = callback.get();

    assertEquals(CUSTOM_NODE_NAME, result);
    verify(alerts).unregister(alert);
    verify(alerts, never()).register(alert);
  }

  @Test
  void nodeNameCallback_set_whenSameValue_noChanges() throws InvalidConfigValueException {
    AtomicReference<String> name = new AtomicReference<>(CUSTOM_NODE_NAME);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    network.crypta.node.NodeClientCore clientCore = mock(network.crypta.node.NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    MeaningfulNodeNameUserAlert alert = mock(MeaningfulNodeNameUserAlert.class);

    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(services.nodeNameUserAlert()).thenReturn(alert);
    when(node.getMyName()).thenAnswer(_ -> name.get());

    NodeConfigManager.NodeNameCallback callback =
        new NodeConfigManager(node).new NodeNameCallback();

    callback.set(CUSTOM_NODE_NAME);

    verify(node, never()).setMyNameInternal(anyString());
  }

  @Test
  void nodeNameCallback_set_whenEmpty_setsNoneAndBroadcasts() throws InvalidConfigValueException {
    AtomicReference<String> name = new AtomicReference<>(DEFAULT_NODE_NAME);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    network.crypta.node.NodeClientCore clientCore = mock(network.crypta.node.NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    MeaningfulNodeNameUserAlert alert = mock(MeaningfulNodeNameUserAlert.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    network.crypta.node.PeerManager peerManager = mock(network.crypta.node.PeerManager.class);
    network.crypta.node.PeerMessenger messenger = mock(network.crypta.node.PeerMessenger.class);

    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(services.nodeNameUserAlert()).thenReturn(alert);
    when(node.getMyName()).thenAnswer(_ -> name.get());
    doAnswer(
            invocation -> {
              name.set(invocation.getArgument(0));
              return null;
            })
        .when(node)
        .setMyNameInternal(anyString());

    when(node.network()).thenReturn(network);
    when(network.peers()).thenReturn(peerManager);
    when(peerManager.messenger()).thenReturn(messenger);

    NodeConfigManager.NodeNameCallback callback =
        new NodeConfigManager(node).new NodeNameCallback();

    callback.set("");

    verify(node).setMyNameInternal("~none~");
    ArgumentCaptor<SimpleFieldSet> fieldSetCaptor = ArgumentCaptor.forClass(SimpleFieldSet.class);
    verify(messenger).locallyBroadcastDiffNodeRef(fieldSetCaptor.capture(), eq(true), eq(false));
    assertEquals("~none~", fieldSetCaptor.getValue().get("myName"));
    verify(alerts).register(alert);
    verify(alerts).unregister(alert);
  }

  @Test
  void nodeNameCallback_set_whenTooLong_throwsInvalidConfigValueException() {
    AtomicReference<String> name = new AtomicReference<>(CUSTOM_NODE_NAME);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    network.crypta.node.NodeClientCore clientCore = mock(network.crypta.node.NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    MeaningfulNodeNameUserAlert alert = mock(MeaningfulNodeNameUserAlert.class);

    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(services.nodeNameUserAlert()).thenReturn(alert);
    when(node.getMyName()).thenAnswer(_ -> name.get());

    NodeConfigManager.NodeNameCallback callback =
        new NodeConfigManager(node).new NodeNameCallback();

    String tooLong = "a".repeat(129);
    assertThrows(InvalidConfigValueException.class, () -> callback.set(tooLong));

    verify(node, never()).setMyNameInternal(anyString());
  }

  @Test
  void nodeNameCallback_set_whenValidChange_broadcastsAndUnregistersAlert()
      throws InvalidConfigValueException {
    AtomicReference<String> name = new AtomicReference<>(DEFAULT_NODE_NAME);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    network.crypta.node.NodeClientCore clientCore = mock(network.crypta.node.NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    MeaningfulNodeNameUserAlert alert = mock(MeaningfulNodeNameUserAlert.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    network.crypta.node.PeerManager peerManager = mock(network.crypta.node.PeerManager.class);
    network.crypta.node.PeerMessenger messenger = mock(network.crypta.node.PeerMessenger.class);

    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    when(services.nodeNameUserAlert()).thenReturn(alert);
    when(node.getMyName()).thenAnswer(_ -> name.get());
    doAnswer(
            invocation -> {
              name.set(invocation.getArgument(0));
              return null;
            })
        .when(node)
        .setMyNameInternal(anyString());

    when(node.network()).thenReturn(network);
    when(network.peers()).thenReturn(peerManager);
    when(peerManager.messenger()).thenReturn(messenger);

    NodeConfigManager.NodeNameCallback callback =
        new NodeConfigManager(node).new NodeNameCallback();

    callback.set("My Node");

    verify(node).setMyNameInternal("My Node");
    verify(messenger).locallyBroadcastDiffNodeRef(any(SimpleFieldSet.class), eq(true), eq(false));
    verify(alerts).register(alert);
    verify(alerts).unregister(alert);
  }

  @Test
  void storeTypeCallback_get_returnsStoreType() {
    Node node = mock(Node.class);
    NodeStorageSubsystem storage = mock(NodeStorageSubsystem.class);
    when(node.storage()).thenReturn(storage);
    when(storage.getStoreType()).thenReturn("ram");

    NodeConfigManager.StoreTypeCallback callback =
        new NodeConfigManager(node).new StoreTypeCallback();

    assertEquals("ram", callback.get());
  }

  @Test
  void storeTypeCallback_set_whenInvalid_throwsInvalidConfigValueException() {
    Node node = mock(Node.class);

    NodeConfigManager.StoreTypeCallback callback =
        new NodeConfigManager(node).new StoreTypeCallback();

    assertThrows(InvalidConfigValueException.class, () -> callback.set("invalid"));
    verify(node, never()).storage();
  }

  @Test
  void storeTypeCallback_set_whenCurrentRam_callsMakeStore() throws InvalidConfigValueException {
    Node node = mock(Node.class);
    NodeStorageSubsystem storage = mock(NodeStorageSubsystem.class);
    when(node.storage()).thenReturn(storage);
    when(storage.getStoreType()).thenReturn("ram");

    NodeConfigManager.StoreTypeCallback callback =
        new NodeConfigManager(node).new StoreTypeCallback();

    assertDoesNotThrow(() -> callback.set(Node.TYPE_SALT_HASH));
    verify(storage).makeStore(Node.TYPE_SALT_HASH);
    verify(storage, never()).setStoreType(anyString());
  }

  @Test
  void storeTypeCallback_set_whenNonRam_throwsNodeNeedRestartExceptionAndSetsStoreType()
      throws InvalidConfigValueException {
    Node node = mock(Node.class);
    NodeStorageSubsystem storage = mock(NodeStorageSubsystem.class);
    when(node.storage()).thenReturn(storage);
    when(storage.getStoreType()).thenReturn(Node.TYPE_SALT_HASH);

    NodeConfigManager.StoreTypeCallback callback =
        new NodeConfigManager(node).new StoreTypeCallback();

    assertThrows(NodeNeedRestartException.class, () -> callback.set("ram"));
    verify(storage).setStoreType("ram");
    verify(storage, never()).makeStore(anyString());
  }

  @Test
  void clientCacheTypeCallback_get_returnsClientCacheType() {
    Node node = mock(Node.class);
    NodeStorageSubsystem storage = mock(NodeStorageSubsystem.class);
    when(node.storage()).thenReturn(storage);
    when(storage.getClientCacheType()).thenReturn("none");

    NodeConfigManager.ClientCacheTypeCallback callback =
        new NodeConfigManager(node).new ClientCacheTypeCallback();

    assertEquals("none", callback.get());
  }

  @Test
  void clientCacheTypeCallback_set_whenInvalid_throwsInvalidConfigValueException() {
    Node node = mock(Node.class);

    NodeConfigManager.ClientCacheTypeCallback callback =
        new NodeConfigManager(node).new ClientCacheTypeCallback();

    assertThrows(InvalidConfigValueException.class, () -> callback.set("invalid"));
    verify(node, never()).storage();
  }

  @Test
  void clientCacheTypeCallback_set_whenValid_callsChangeClientCacheType()
      throws InvalidConfigValueException, NodeNeedRestartException {
    Node node = mock(Node.class);
    NodeStorageSubsystem storage = mock(NodeStorageSubsystem.class);
    when(node.storage()).thenReturn(storage);

    NodeConfigManager.ClientCacheTypeCallback callback =
        new NodeConfigManager(node).new ClientCacheTypeCallback();

    callback.set("none");

    verify(storage).changeClientCacheType("none");
  }
}
