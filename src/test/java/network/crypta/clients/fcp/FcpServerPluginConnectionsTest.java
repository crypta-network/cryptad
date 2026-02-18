package network.crypta.clients.fcp;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.UUID;
import network.crypta.clients.fcp.FCPPluginConnection.SendDirection;
import network.crypta.node.Node;
import network.crypta.pluginmanager.FredPluginFCPMessageHandler.ClientSideFCPMessageHandler;
import network.crypta.pluginmanager.PluginManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class FcpServerPluginConnectionsTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Test
  void startTrackerIfEnabled_whenEnabled_expectTrackerStarted() throws Exception {
    // Arrange
    FcpServerPluginConnections connections = new FcpServerPluginConnections(node);
    FCPPluginConnectionTracker tracker = mock(FCPPluginConnectionTracker.class);
    setTracker(connections, tracker);
    when(node.services().pluginManager().isEnabled()).thenReturn(true);

    // Act
    connections.startTrackerIfEnabled();

    // Assert
    verify(tracker).start();
  }

  @Test
  void startTrackerIfEnabled_whenDisabled_expectNoStart() throws Exception {
    // Arrange
    FcpServerPluginConnections connections = new FcpServerPluginConnections(node);
    FCPPluginConnectionTracker tracker = mock(FCPPluginConnectionTracker.class);
    setTracker(connections, tracker);
    when(node.services().pluginManager().isEnabled()).thenReturn(false);

    // Act
    connections.startTrackerIfEnabled();

    // Assert
    verify(tracker, never()).start();
  }

  @Test
  void createFCPPluginConnectionForNetworkedFCP_whenInvoked_expectStaticFactoryUsed()
      throws Exception {
    // Arrange
    FcpServerPluginConnections connections = new FcpServerPluginConnections(node);
    FCPPluginConnectionTracker tracker = getTracker(connections);
    FCPConnectionHandler handler = mock(FCPConnectionHandler.class);
    FCPPluginConnectionImpl expected = mock(FCPPluginConnectionImpl.class);
    PluginManager pluginManager = node.services().pluginManager();

    try (MockedStatic<FCPPluginConnectionImpl> mocked = mockStatic(FCPPluginConnectionImpl.class)) {
      mocked
          .when(
              () ->
                  FCPPluginConnectionImpl.constructForNetworkedFCP(
                      tracker, node.network().executor(), pluginManager, "plugin", handler))
          .thenReturn(expected);

      // Act
      FCPPluginConnectionImpl result =
          connections.createFCPPluginConnectionForNetworkedFCP("plugin", handler);

      // Assert
      assertSame(expected, result);
    }
  }

  @Test
  void createFCPPluginConnectionForIntraNodeFCP_whenInvoked_expectAdapterReturned()
      throws Exception {
    // Arrange
    FcpServerPluginConnections connections = new FcpServerPluginConnections(node);
    FCPPluginConnectionTracker tracker = getTracker(connections);
    ClientSideFCPMessageHandler handler = mock(ClientSideFCPMessageHandler.class);
    FCPPluginConnectionImpl connection = mock(FCPPluginConnectionImpl.class);
    FCPPluginConnection adapter = mock(FCPPluginConnection.class);
    PluginManager pluginManager = node.services().pluginManager();
    when(connection.getDefaultSendDirectionAdapter(SendDirection.TO_SERVER)).thenReturn(adapter);

    try (MockedStatic<FCPPluginConnectionImpl> mocked = mockStatic(FCPPluginConnectionImpl.class)) {
      mocked
          .when(
              () ->
                  FCPPluginConnectionImpl.constructForIntraNodeFCP(
                      tracker, node.network().executor(), pluginManager, "plugin", handler))
          .thenReturn(connection);

      // Act
      FCPPluginConnection result =
          connections.createFCPPluginConnectionForIntraNodeFCP("plugin", handler);

      // Assert
      assertSame(adapter, result);
      verify(connection).getDefaultSendDirectionAdapter(SendDirection.TO_SERVER);
    }
  }

  @Test
  void getPluginConnectionByID_whenInvoked_expectAdapterReturned() throws Exception {
    // Arrange
    FcpServerPluginConnections connections = new FcpServerPluginConnections(node);
    FCPPluginConnectionTracker tracker = mock(FCPPluginConnectionTracker.class);
    FCPPluginConnectionImpl connection = mock(FCPPluginConnectionImpl.class);
    FCPPluginConnection adapter = mock(FCPPluginConnection.class);
    UUID id = UUID.randomUUID();
    when(tracker.getConnection(id)).thenReturn(connection);
    when(connection.getDefaultSendDirectionAdapter(SendDirection.TO_CLIENT)).thenReturn(adapter);
    setTracker(connections, tracker);

    // Act
    FCPPluginConnection result = connections.getPluginConnectionByID(id);

    // Assert
    assertSame(adapter, result);
    verify(tracker).getConnection(id);
  }

  @Test
  void getPluginConnectionByID_whenTrackerThrows_expectIOException() throws Exception {
    // Arrange
    FcpServerPluginConnections connections = new FcpServerPluginConnections(node);
    FCPPluginConnectionTracker tracker = mock(FCPPluginConnectionTracker.class);
    UUID id = UUID.randomUUID();
    IOException failure = new IOException("boom");
    when(tracker.getConnection(id)).thenThrow(failure);
    setTracker(connections, tracker);

    // Act
    IOException result =
        org.junit.jupiter.api.Assertions.assertThrows(
            IOException.class, () -> connections.getPluginConnectionByID(id));

    // Assert
    assertSame(failure, result);
  }

  private static FCPPluginConnectionTracker getTracker(FcpServerPluginConnections connections)
      throws Exception {
    Field field = FcpServerPluginConnections.class.getDeclaredField("pluginConnectionTracker");
    field.setAccessible(true);
    return (FCPPluginConnectionTracker) field.get(connections);
  }

  private static void setTracker(FcpServerPluginConnections connections, Object tracker)
      throws Exception {
    Field field = FcpServerPluginConnections.class.getDeclaredField("pluginConnectionTracker");
    field.setAccessible(true);
    field.set(connections, tracker);
  }
}
