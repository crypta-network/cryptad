package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import network.crypta.io.NetworkInterface;
import network.crypta.node.Node;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.tanukisoftware.wrapper.WrapperManager;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FcpServerListenerTest {

  @Mock private Node node;

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
  void getAllowedHosts_whenNetworkInterfaceMissing_expectDefaultBind() {
    // Arrange
    FcpServerListener listener = newListener(true);

    // Act
    String allowedHosts = listener.getAllowedHosts();

    // Assert
    assertEquals(NetworkInterface.DEFAULT_BIND_TO, allowedHosts);
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

  private FcpServerListener newListener(boolean enabled) {
    FCPServer server = mock(FCPServer.class);
    FcpServerConfig config =
        new FcpServerConfig(
            "127.0.0.1",
            NetworkInterface.DEFAULT_BIND_TO,
            NetworkInterface.DEFAULT_BIND_TO,
            FCPServer.DEFAULT_FCP_PORT,
            enabled,
            false,
            false,
            false,
            10);
    return new FcpServerListener(server, node, config);
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
}
