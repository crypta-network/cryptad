package network.crypta.runtime.endpoints.http;

import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.SubConfig;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.runtime.http.HttpShellRuntimeSupport;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;

@SuppressWarnings("java:S100")
class HttpShellBridgeFactoriesTest {

  @Test
  void defaultContainerFactory_whenCreateCalled_returnsEndpointBackedHttpShellContainer()
      throws Exception {
    // Arrange
    SubConfig fproxyConfig = mock(SubConfig.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);

    try (MockedConstruction<SimpleToadletServer> construction =
        mockConstruction(SimpleToadletServer.class)) {
      // Act
      HttpShellContainer container =
          HttpShellBridgeFactories.defaultContainerFactory().create(fproxyConfig, executor);

      // Assert
      assertEquals(1, construction.constructed().size());
      assertInstanceOf(SimpleToadletServerHttpShellContainer.class, container);
    }
  }

  @Test
  void coreBackedRuntimeSupportFactory_whenCreateCalled_returnsCoreBackedRuntimeSupport() {
    NodeClientCore core = mock(NodeClientCore.class);

    HttpShellRuntimeSupport runtimeSupport =
        HttpShellBridgeFactories.coreBackedRuntimeSupportFactory().create(core);

    CoreHttpShellRuntimeSupport coreRuntimeSupport =
        assertInstanceOf(CoreHttpShellRuntimeSupport.class, runtimeSupport);
    assertInstanceOf(network.crypta.clients.http.HttpShellRuntimeSupport.class, runtimeSupport);
    assertSame(core, coreRuntimeSupport.core());
  }
}
