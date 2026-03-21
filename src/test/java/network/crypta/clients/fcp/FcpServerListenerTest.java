package network.crypta.clients.fcp;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.Socket;
import network.crypta.io.NetworkInterface;
import network.crypta.runtime.spi.ExecutionPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.RuntimePorts;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;
import org.tanukisoftware.wrapper.WrapperManager;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FcpServerListenerTest {

  @Mock private FCPServer server;
  @Mock private RuntimePorts runtimePorts;
  @Mock private ExecutionPort executionPort;
  @Mock private LifecyclePort lifecyclePort;

  @Test
  void isSslEnabled_whenToggled_expectUpdatedValue() {
    // Arrange
    FcpServerListener.setSslEnabled(false);

    // Act
    FcpServerListener.setSslEnabled(true);

    // Assert
    assertTrue(FcpServerListener.isSslEnabled());
  }

  @Test
  void getAllowedHosts_whenNetworkInterfaceMissing_expectConfiguredHosts() {
    // Arrange
    FcpServerListener listener = newListener(true);

    // Act
    String allowedHosts = listener.getAllowedHosts();

    // Assert
    assertEquals(NetworkInterface.DEFAULT_BIND_TO, allowedHosts);
  }

  @Test
  void getAllowedHosts_whenConfiguredAndNetworkInterfaceMissing_expectConfiguredHosts() {
    // Arrange
    FcpServerListener listener = newListener(true, "127.0.0.1");

    // Act
    String allowedHosts = listener.getAllowedHosts();

    // Assert
    assertEquals("127.0.0.1", allowedHosts);
  }

  @Test
  void getAllowedHosts_whenNetworkInterfacePresent_expectConfiguredHosts() throws Exception {
    // Arrange
    FcpServerListener listener = newListener(true);
    NetworkInterface networkInterface = mock(NetworkInterface.class);
    setNetworkInterface(listener, networkInterface);
    when(networkInterface.getAllowedHosts()).thenReturn("127.0.0.1");

    // Act
    String allowedHosts = listener.getAllowedHosts();

    // Assert
    assertEquals("127.0.0.1", allowedHosts);
  }

  @Test
  void setAllowedHosts_whenInvoked_expectDelegation() throws Exception {
    // Arrange
    FcpServerListener listener = newListener(true);
    NetworkInterface networkInterface = mock(NetworkInterface.class);
    setNetworkInterface(listener, networkInterface);

    // Act
    listener.setAllowedHosts("127.0.0.1");

    // Assert
    verify(networkInterface).setAllowedHosts("127.0.0.1");
  }

  @Test
  void setAllowedHosts_whenNetworkInterfaceMissing_expectValueCachedForFutureReads() {
    // Arrange
    FcpServerListener listener = newListener(true);

    // Act
    listener.setAllowedHosts("127.0.0.1");

    // Assert
    assertEquals("127.0.0.1", listener.getAllowedHosts());
  }

  @Test
  void setBindTo_whenInvoked_expectDelegationResult() throws Exception {
    // Arrange
    FcpServerListener listener = newListener(true);
    NetworkInterface networkInterface = mock(NetworkInterface.class);
    String[] expected = new String[] {"failed"};
    setNetworkInterface(listener, networkInterface);
    when(networkInterface.setBindTo("0.0.0.0", true)).thenReturn(expected);

    // Act
    String[] result = listener.setBindTo("0.0.0.0", true);

    // Assert
    assertArrayEquals(expected, result);
  }

  @Test
  void updateBindTo_whenInvoked_expectFieldUpdated() throws Exception {
    // Arrange
    FcpServerListener listener = newListener(true);

    // Act
    listener.updateBindTo("0.0.0.0");

    // Assert
    assertEquals("0.0.0.0", getBindTo(listener));
  }

  @Test
  void maybeStart_whenDisabled_expectNetworkInterfaceCleared() throws Exception {
    // Arrange
    FcpServerListener listener = newListener(false);
    NetworkInterface networkInterface = mock(NetworkInterface.class);
    setNetworkInterface(listener, networkInterface);

    // Act
    listener.maybeStart();

    // Assert
    assertNull(getNetworkInterface(listener));
  }

  @Test
  void maybeStart_whenEnabledAndInterfacePreset_expectInterfaceRetained() throws Exception {
    // Arrange
    FcpServerListener listener = newListener(true);
    NetworkInterface networkInterface = mock(NetworkInterface.class);
    setNetworkInterface(listener, networkInterface);

    // Act
    listener.maybeStart();

    // Assert
    assertSame(networkInterface, getNetworkInterface(listener));
  }

  @Test
  void maybeStart_whenAllowedHostsUpdatedBeforeStart_expectInterfaceCreatedWithUpdatedHosts()
      throws Exception {
    // Arrange
    FcpServerListener.setSslEnabled(false);
    FcpServerListener listener = newListener(true);
    NetworkInterface networkInterface = mock(NetworkInterface.class);
    listener.setAllowedHosts("127.0.0.1");

    // Act
    try (var networkInterfaceMock = mockStatic(NetworkInterface.class)) {
      networkInterfaceMock
          .when(
              () ->
                  NetworkInterface.create(anyInt(), anyString(), anyString(), any(), anyBoolean()))
          .thenAnswer(
              invocation -> {
                assertEquals(FCPServer.DEFAULT_FCP_PORT, invocation.<Integer>getArgument(0));
                assertEquals("127.0.0.1", invocation.getArgument(2));
                return networkInterface;
              });

      listener.maybeStart();
    }

    // Assert
    assertSame(networkInterface, getNetworkInterface(listener));
  }

  @Test
  void run_whenWaitBoundThrowsAndShutdownTriggered_expectExit() throws Exception {
    // Arrange
    FcpServerListener listener = newListener(true);
    NetworkInterface networkInterface = mock(NetworkInterface.class);
    setNetworkInterface(listener, networkInterface);
    doThrow(new IllegalStateException("boom")).when(networkInterface).waitBound();

    // Act
    try (var wrapper = mockStatic(WrapperManager.class)) {
      //noinspection ResultOfMethodCallIgnored
      wrapper.when(WrapperManager::hasShutdownHookBeenTriggered).thenReturn(true);
      listener.run();
    }

    // Assert
    verify(networkInterface).waitBound();
  }

  @Test
  void realRun_whenRuntimeNotStarted_expectAcceptSkipped() throws Exception {
    // Arrange
    FcpServerListener listener = newListener(true);
    NetworkInterface networkInterface = mock(NetworkInterface.class);
    setNetworkInterface(listener, networkInterface);
    when(runtimePorts.lifecycle()).thenReturn(lifecyclePort);
    when(lifecyclePort.hasStarted()).thenReturn(false);

    // Act
    invokeRealRun(listener);

    // Assert
    verify(networkInterface, never()).accept();
  }

  @Test
  void realRun_whenRuntimeStarted_expectConnectionHandlerStarted() throws Exception {
    // Arrange
    FcpServerListener listener = newListener(true);
    NetworkInterface networkInterface = mock(NetworkInterface.class);
    Socket socket = mock(Socket.class);
    setNetworkInterface(listener, networkInterface);
    when(runtimePorts.lifecycle()).thenReturn(lifecyclePort);
    when(lifecyclePort.hasStarted()).thenReturn(true);
    when(networkInterface.accept()).thenReturn(socket);

    // Act
    try (MockedConstruction<FCPConnectionHandler> construction =
        mockConstruction(FCPConnectionHandler.class)) {
      invokeRealRun(listener);

      // Assert
      assertEquals(1, construction.constructed().size());
      verify(networkInterface).accept();
      verify(construction.constructed().getFirst()).start();
    }
  }

  private FcpServerListener newListener(boolean enabled) {
    return newListener(enabled, NetworkInterface.DEFAULT_BIND_TO);
  }

  private FcpServerListener newListener(boolean enabled, String allowedHosts) {
    FcpServerListener.setSslEnabled(false);
    when(runtimePorts.execution()).thenReturn(executionPort);
    FcpServerConfig config =
        new FcpServerConfig(
            "127.0.0.1",
            allowedHosts,
            NetworkInterface.DEFAULT_BIND_TO,
            FCPServer.DEFAULT_FCP_PORT,
            enabled,
            false,
            false,
            false,
            10);
    return new FcpServerListener(server, runtimePorts, config);
  }

  private void setNetworkInterface(FcpServerListener listener, NetworkInterface value)
      throws Exception {
    Field field = FcpServerListener.class.getDeclaredField("networkInterface");
    field.setAccessible(true);
    field.set(listener, value);
  }

  private NetworkInterface getNetworkInterface(FcpServerListener listener) throws Exception {
    Field field = FcpServerListener.class.getDeclaredField("networkInterface");
    field.setAccessible(true);
    return (NetworkInterface) field.get(listener);
  }

  private String getBindTo(FcpServerListener listener) throws Exception {
    Field field = FcpServerListener.class.getDeclaredField("bindTo");
    field.setAccessible(true);
    Object value = field.get(listener);
    assertNotNull(value);
    return (String) value;
  }

  private void invokeRealRun(FcpServerListener listener) throws Exception {
    Method method = FcpServerListener.class.getDeclaredMethod("realRun");
    method.setAccessible(true);
    method.invoke(listener);
  }
}
