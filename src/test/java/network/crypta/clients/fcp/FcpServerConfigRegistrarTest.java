package network.crypta.clients.fcp;

import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.io.NetworkInterface;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.spi.ExecutionPort;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FcpServerConfigRegistrarTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private NodeClientCore core;

  @Mock private RuntimePorts runtimePorts;
  @Mock private ExecutionPort executionPort;

  @Test
  void maybeCreate_whenDefaults_expectConfiguredServerAndInitializedSubConfig() {
    // Arrange
    Config config = new Config();
    PersistentRequestRoot root = new PersistentRequestRoot();
    when(runtimePorts.execution()).thenReturn(executionPort);

    // Act
    FCPServer server = FcpServerConfigRegistrar.maybeCreate(node, core, runtimePorts, config, root);
    SubConfig subConfig = config.get("fcp");

    // Assert
    assertNotNull(server);
    assertNotNull(subConfig);
    assertTrue(subConfig.hasFinishedInitialization());
    assertEquals(FCPServer.DEFAULT_FCP_PORT, server.port);
    assertTrue(server.enabled);
    assertEquals(NetworkInterface.DEFAULT_BIND_TO, server.bindTo);
    assertEquals(NetworkInterface.DEFAULT_BIND_TO, server.allowedHostsFullAccess.getAllowedHosts());
    assertFalse(server.assumeDownloadDDAIsAllowed);
    assertFalse(server.assumeUploadDDAIsAllowed);
    assertFalse(server.neverDropAMessage);
    assertEquals(1024, server.maxMessageQueueLength);
    assertEquals(runtimePorts, server.runtime());
    assertNotNull(subConfig.getOption("enabled"));
    assertNotNull(subConfig.getOption("ssl"));
    assertNotNull(subConfig.getOption("port"));
  }

  @Test
  void fcpPortNumberCallback_whenValueUnchanged_expectNoException() {
    // Arrange
    FCPServer server = newServer();
    when(core.getEndpoints().getFCPServer()).thenReturn(server);
    FcpServerConfigRegistrar.FCPPortNumberCallback callback =
        new FcpServerConfigRegistrar.FCPPortNumberCallback(core);

    // Act & Assert
    assertEquals(server.port, callback.get());
    assertDoesNotThrow(() -> callback.set(server.port));
  }

  @Test
  void fcpPortNumberCallback_whenValueChanged_expectInvalidConfigValueException() {
    // Arrange
    FCPServer server = newServer();
    when(core.getEndpoints().getFCPServer()).thenReturn(server);
    FcpServerConfigRegistrar.FCPPortNumberCallback callback =
        new FcpServerConfigRegistrar.FCPPortNumberCallback(core);

    // Act & Assert
    assertThrows(InvalidConfigValueException.class, () -> callback.set(server.port + 1));
  }

  @Test
  void fcpEnabledCallback_whenValueUnchanged_expectNoException() {
    // Arrange
    FCPServer server = newServer();
    when(core.getEndpoints().getFCPServer()).thenReturn(server);
    FcpServerConfigRegistrar.FCPEnabledCallback callback =
        new FcpServerConfigRegistrar.FCPEnabledCallback(core);

    // Act & Assert
    assertEquals(server.enabled, callback.get());
    assertDoesNotThrow(() -> callback.set(server.enabled));
  }

  @Test
  void fcpSslCallback_whenValueUnchanged_expectNoException() {
    // Arrange
    FcpServerListener.setSslEnabled(false);
    FcpServerConfigRegistrar.FCPSSLCallback callback =
        new FcpServerConfigRegistrar.FCPSSLCallback();

    // Act & Assert
    assertFalse(callback.get());
    assertDoesNotThrow(() -> callback.set(false));
  }

  @Test
  void fcpAllowedHostsCallback_whenServerMissing_expectDefaultBind() {
    // Arrange
    when(core.getEndpoints().getFCPServer()).thenReturn(null);
    FcpServerConfigRegistrar.FCPAllowedHostsCallback callback =
        new FcpServerConfigRegistrar.FCPAllowedHostsCallback(core);

    // Act & Assert
    assertEquals(NetworkInterface.DEFAULT_BIND_TO, callback.get());
  }

  @Test
  void fcpAllowedHostsCallback_whenValueUnchanged_expectNoException() {
    // Arrange
    FCPServer server = newServer();
    when(core.getEndpoints().getFCPServer()).thenReturn(server);
    FcpServerConfigRegistrar.FCPAllowedHostsCallback callback =
        new FcpServerConfigRegistrar.FCPAllowedHostsCallback(core);

    // Act & Assert
    assertDoesNotThrow(() -> callback.set(NetworkInterface.DEFAULT_BIND_TO));
  }

  @Test
  void fcpBindToCallback_whenGetCalled_expectServerBindTo() {
    // Arrange
    FCPServer server = newServer();
    when(core.getEndpoints().getFCPServer()).thenReturn(server);
    FcpServerConfigRegistrar.FCPBindtoCallback callback =
        new FcpServerConfigRegistrar.FCPBindtoCallback(core);

    // Act & Assert
    assertEquals(server.bindTo, callback.get());
  }

  @Test
  void fcpAllowedHostsFullAccessCallback_whenValueUnchanged_expectNoException() {
    // Arrange
    FCPServer server = newServer();
    when(core.getEndpoints().getFCPServer()).thenReturn(server);
    FcpServerConfigRegistrar.FCPAllowedHostsFullAccessCallback callback =
        new FcpServerConfigRegistrar.FCPAllowedHostsFullAccessCallback(core);

    // Act & Assert
    assertEquals(server.allowedHostsFullAccess.getAllowedHosts(), callback.get());
    assertDoesNotThrow(() -> callback.set(server.allowedHostsFullAccess.getAllowedHosts()));
  }

  @Test
  void assumeDDADownloadIsAllowedCallback_whenSet_expectServerUpdated() {
    // Arrange
    FCPServer server = newServer();
    FcpServerConfigRegistrar.AssumeDDADownloadIsAllowedCallback callback =
        new FcpServerConfigRegistrar.AssumeDDADownloadIsAllowedCallback();
    callback.server = server;

    // Act
    assertDoesNotThrow(() -> callback.set(true));

    // Assert
    assertTrue(server.assumeDownloadDDAIsAllowed);
  }

  @Test
  void assumeDDAUploadIsAllowedCallback_whenSet_expectServerUpdated() {
    // Arrange
    FCPServer server = newServer();
    FcpServerConfigRegistrar.AssumeDDAUploadIsAllowedCallback callback =
        new FcpServerConfigRegistrar.AssumeDDAUploadIsAllowedCallback();
    callback.server = server;

    // Act
    assertDoesNotThrow(() -> callback.set(true));

    // Assert
    assertTrue(server.assumeUploadDDAIsAllowed);
  }

  @Test
  void neverDropAMessageCallback_whenSet_expectServerUpdated() {
    // Arrange
    FCPServer server = newServer();
    FcpServerConfigRegistrar.NeverDropAMessageCallback callback =
        new FcpServerConfigRegistrar.NeverDropAMessageCallback();
    callback.server = server;

    // Act
    assertDoesNotThrow(() -> callback.set(true));

    // Assert
    assertTrue(server.neverDropAMessage);
  }

  @Test
  void maxMessageQueueLengthCallback_whenSet_expectServerUpdated() {
    // Arrange
    FCPServer server = newServer();
    FcpServerConfigRegistrar.MaxMessageQueueLengthCallback callback =
        new FcpServerConfigRegistrar.MaxMessageQueueLengthCallback();
    callback.server = server;

    // Act
    assertDoesNotThrow(() -> callback.set(42));

    // Assert
    assertEquals(42, server.maxMessageQueueLength);
    assertEquals(42, callback.get());
  }

  private FCPServer newServer() {
    when(runtimePorts.execution()).thenReturn(executionPort);
    FcpServerConfig config =
        new FcpServerConfig(
            "127.0.0.1",
            NetworkInterface.DEFAULT_BIND_TO,
            NetworkInterface.DEFAULT_BIND_TO,
            FCPServer.DEFAULT_FCP_PORT,
            true,
            false,
            false,
            false,
            10);
    return new FCPServer(
        config, new FcpServerDependencies(node, core, runtimePorts, new PersistentRequestRoot()));
  }
}
