package network.crypta.clients.fcp;

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import network.crypta.pluginmanager.PluginNotFoundException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PluginConnectionRegistryTest {

  private static final String PLUGIN_NAME = "TestPlugin";

  private final PluginConnectionRegistry registry = new PluginConnectionRegistry();

  @Mock private FCPServer server;
  @Mock private FCPConnectionHandler handler;
  @Mock private FCPPluginConnectionImpl cachedConnection;
  @Mock private FCPPluginConnectionImpl replacementConnection;

  @Test
  void get_whenConnectionCachedAndAlive_returnsExistingWithoutNewCreation()
      throws PluginNotFoundException {
    when(server.createFCPPluginConnectionForNetworkedFCP(PLUGIN_NAME, handler))
        .thenReturn(cachedConnection);
    when(cachedConnection.isServerDead()).thenReturn(false);

    FCPPluginConnection first = registry.get(PLUGIN_NAME, server, handler);
    FCPPluginConnection second = registry.get(PLUGIN_NAME, server, handler);

    assertSame(cachedConnection, first);
    assertSame(cachedConnection, second);
    verify(server, times(1)).createFCPPluginConnectionForNetworkedFCP(PLUGIN_NAME, handler);
    verify(cachedConnection, times(1)).isServerDead();
    verifyNoMoreInteractions(server);
  }

  @Test
  void get_whenExistingConnectionDead_createsReplacementAndCachesIt()
      throws PluginNotFoundException {
    when(server.createFCPPluginConnectionForNetworkedFCP(PLUGIN_NAME, handler))
        .thenReturn(cachedConnection, replacementConnection);
    when(cachedConnection.isServerDead()).thenReturn(true);
    when(replacementConnection.isServerDead()).thenReturn(false);

    FCPPluginConnection first = registry.get(PLUGIN_NAME, server, handler);
    FCPPluginConnection second = registry.get(PLUGIN_NAME, server, handler);
    FCPPluginConnection third = registry.get(PLUGIN_NAME, server, handler);

    assertSame(cachedConnection, first);
    assertSame(replacementConnection, second);
    assertSame(replacementConnection, third);

    verify(server, times(2)).createFCPPluginConnectionForNetworkedFCP(PLUGIN_NAME, handler);
    verify(cachedConnection, times(2)).isServerDead();
    verify(replacementConnection, times(1)).isServerDead();
  }

  @Test
  void get_whenServerThrows_propagatesAndDoesNotCachePartialEntry() throws PluginNotFoundException {
    PluginNotFoundException failure = new PluginNotFoundException("missing");
    when(server.createFCPPluginConnectionForNetworkedFCP(PLUGIN_NAME, handler))
        .thenThrow(failure)
        .thenReturn(cachedConnection);
    when(cachedConnection.isServerDead()).thenReturn(false);

    PluginNotFoundException thrown =
        assertThrows(
            PluginNotFoundException.class, () -> registry.get(PLUGIN_NAME, server, handler));
    assertSame(failure, thrown);

    FCPPluginConnection second = registry.get(PLUGIN_NAME, server, handler);
    FCPPluginConnection third = registry.get(PLUGIN_NAME, server, handler);

    assertSame(cachedConnection, second);
    assertSame(cachedConnection, third);

    verify(server, times(2)).createFCPPluginConnectionForNetworkedFCP(PLUGIN_NAME, handler);
    verify(cachedConnection, times(1)).isServerDead();
  }
}
