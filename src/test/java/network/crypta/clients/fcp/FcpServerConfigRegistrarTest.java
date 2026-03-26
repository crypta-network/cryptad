package network.crypta.clients.fcp;

import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.io.NetworkInterface;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.endpoints.fcp.CoreFcpServerDependenciesFactory;
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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FcpServerConfigRegistrarTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private NodeClientCore core;

  @Mock private RuntimePorts runtimePorts;
  @Mock private ExecutionPort executionPort;

  @Test
  void maybeCreate_whenDefaults_expectConfiguredServerAndInitializedSubConfig() {
    // Arrange
    Config config = new Config();
    FCPServer server = FcpServerConfigRegistrar.maybeCreate(newDependencies(), config);
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
  void fcpPortNumberCallback_whenBeforeBind_expectInitialValue() {
    // Arrange
    FcpServerConfigRegistrar.FCPPortNumberCallback callback =
        new FcpServerConfigRegistrar.FCPPortNumberCallback(FCPServer.DEFAULT_FCP_PORT);

    // Act & Assert
    assertEquals(FCPServer.DEFAULT_FCP_PORT, callback.get());
    assertDoesNotThrow(() -> callback.set(FCPServer.DEFAULT_FCP_PORT));
  }

  @Test
  void fcpPortNumberCallback_whenBoundAndValueChanged_expectInvalidConfigValueException() {
    // Arrange
    FCPServer server = newServer(null);
    FcpServerConfigRegistrar.FCPPortNumberCallback callback =
        new FcpServerConfigRegistrar.FCPPortNumberCallback(FCPServer.DEFAULT_FCP_PORT);
    callback.bind(server);

    // Act & Assert
    assertEquals(server.port, callback.get());
    assertThrows(InvalidConfigValueException.class, () -> callback.set(server.port + 1));
  }

  @Test
  void fcpEnabledCallback_whenBeforeBind_expectInitialValue() {
    // Arrange
    FcpServerConfigRegistrar.FCPEnabledCallback callback =
        new FcpServerConfigRegistrar.FCPEnabledCallback(true);

    // Act & Assert
    assertTrue(callback.get());
    assertDoesNotThrow(() -> callback.set(true));
  }

  @Test
  void fcpEnabledCallback_whenBound_expectLiveServerValue() {
    // Arrange
    FCPServer server = newServer(null);
    FcpServerConfigRegistrar.FCPEnabledCallback callback =
        new FcpServerConfigRegistrar.FCPEnabledCallback(true);
    callback.bind(server);

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
  void fcpAllowedHostsCallback_whenBeforeBind_expectInitialValue() {
    // Arrange
    FcpServerConfigRegistrar.FCPAllowedHostsCallback callback =
        new FcpServerConfigRegistrar.FCPAllowedHostsCallback(NetworkInterface.DEFAULT_BIND_TO);

    // Act & Assert
    assertEquals(NetworkInterface.DEFAULT_BIND_TO, callback.get());
  }

  @Test
  void fcpAllowedHostsCallback_whenBoundAndValueChanged_expectListenerUpdated() {
    // Arrange
    FcpServerListener listener = mock(FcpServerListener.class);
    final String[] allowedHosts = {NetworkInterface.DEFAULT_BIND_TO};
    doAnswer(
            invocation -> {
              allowedHosts[0] = invocation.getArgument(0);
              return null;
            })
        .when(listener)
        .setAllowedHosts(anyString());
    when(listener.getAllowedHosts()).thenAnswer(_ -> allowedHosts[0]);

    FCPServer server = newServer(listener);
    FcpServerConfigRegistrar.FCPAllowedHostsCallback callback =
        new FcpServerConfigRegistrar.FCPAllowedHostsCallback(NetworkInterface.DEFAULT_BIND_TO);
    callback.bind(server);

    // Act
    assertDoesNotThrow(() -> callback.set("127.0.0.1,192.168.0.1"));

    // Assert
    assertEquals("127.0.0.1,192.168.0.1", callback.get());
    verify(listener).setAllowedHosts("127.0.0.1,192.168.0.1");
  }

  @Test
  void fcpBindToCallback_whenBeforeBind_expectInitialValue() {
    // Arrange
    FcpServerConfigRegistrar.FCPBindtoCallback callback =
        new FcpServerConfigRegistrar.FCPBindtoCallback("127.0.0.1");

    // Act & Assert
    assertEquals("127.0.0.1", callback.get());
  }

  @Test
  void fcpBindToCallback_whenBoundAndValueChanged_expectServerUpdated() {
    // Arrange
    FcpServerListener listener = mock(FcpServerListener.class);
    doNothing().when(listener).updateBindTo(anyString());
    when(listener.setBindTo(anyString(), eq(true))).thenReturn(null);

    FCPServer server = newServer(listener);
    server.bindTo = "127.0.0.1";
    FcpServerConfigRegistrar.FCPBindtoCallback callback =
        new FcpServerConfigRegistrar.FCPBindtoCallback("127.0.0.1");
    callback.bind(server);

    // Act
    assertDoesNotThrow(() -> callback.set("0.0.0.0"));

    // Assert
    assertEquals("0.0.0.0", server.bindTo);
    verify(listener).setBindTo("0.0.0.0", true);
    verify(listener).updateBindTo("0.0.0.0");
  }

  @Test
  void fcpBindToCallback_whenListenerRejectsValue_expectInvalidConfigValueException() {
    // Arrange
    FcpServerListener listener = mock(FcpServerListener.class);
    doNothing().when(listener).updateBindTo(anyString());
    when(listener.setBindTo("0.0.0.0", true)).thenReturn(new String[] {"0.0.0.0"});
    when(listener.setBindTo("127.0.0.1", true)).thenReturn(null);
    FCPServer server = newServer(listener);
    server.bindTo = "127.0.0.1";
    FcpServerConfigRegistrar.FCPBindtoCallback callback =
        new FcpServerConfigRegistrar.FCPBindtoCallback("127.0.0.1");
    callback.bind(server);

    // Act & Assert
    assertThrows(InvalidConfigValueException.class, () -> callback.set("0.0.0.0"));

    // Assert
    assertEquals("127.0.0.1", server.bindTo);
    assertEquals("127.0.0.1", callback.get());
    verify(listener).setBindTo("0.0.0.0", true);
    verify(listener).setBindTo("127.0.0.1", true);
    verify(listener, never()).updateBindTo("0.0.0.0");
  }

  @Test
  void fcpAllowedHostsFullAccessCallback_whenBeforeBind_expectInitialValue() {
    // Arrange
    FcpServerConfigRegistrar.FCPAllowedHostsFullAccessCallback callback =
        new FcpServerConfigRegistrar.FCPAllowedHostsFullAccessCallback(
            NetworkInterface.DEFAULT_BIND_TO);

    // Act & Assert
    assertEquals(NetworkInterface.DEFAULT_BIND_TO, callback.get());
  }

  @Test
  void fcpAllowedHostsFullAccessCallback_whenBoundAndValueChanged_expectServerUpdated() {
    // Arrange
    FCPServer server = newServer(null);
    FcpServerConfigRegistrar.FCPAllowedHostsFullAccessCallback callback =
        new FcpServerConfigRegistrar.FCPAllowedHostsFullAccessCallback(
            NetworkInterface.DEFAULT_BIND_TO);
    callback.bind(server);

    // Act
    assertDoesNotThrow(() -> callback.set("127.0.0.1,192.168.0.1"));

    // Assert
    assertEquals("127.0.0.1,192.168.0.1", callback.get());
    assertEquals("127.0.0.1,192.168.0.1", server.allowedHostsFullAccess.getAllowedHosts());
  }

  @Test
  void assumeDDADownloadIsAllowedCallback_whenSet_expectServerUpdated() {
    // Arrange
    FCPServer server = newServer(null);
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
    FCPServer server = newServer(null);
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
    FCPServer server = newServer(null);
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
    FCPServer server = newServer(null);
    FcpServerConfigRegistrar.MaxMessageQueueLengthCallback callback =
        new FcpServerConfigRegistrar.MaxMessageQueueLengthCallback();
    callback.server = server;

    // Act
    assertDoesNotThrow(() -> callback.set(42));

    // Assert
    assertEquals(42, server.maxMessageQueueLength);
    assertEquals(42, callback.get());
  }

  private FcpServerDependencies newDependencies() {
    when(runtimePorts.execution()).thenReturn(executionPort);
    return CoreFcpServerDependenciesFactory.create(core, runtimePorts, new PersistentRequestRoot());
  }

  private FCPServer newServer(FcpServerListener listenerOverride) {
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
    FcpServerDependencies dependencies = newDependencies();
    if (listenerOverride == null) {
      return new FCPServer(config, dependencies);
    }
    return new TestServer(config, dependencies, listenerOverride);
  }

  private static final class TestServer extends FCPServer {
    private final FcpServerListener listener;

    private TestServer(
        FcpServerConfig config, FcpServerDependencies dependencies, FcpServerListener listener) {
      super(config, dependencies);
      this.listener = listener;
    }

    @Override
    FcpServerListener listener() {
      return listener;
    }
  }
}
