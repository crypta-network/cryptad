package network.crypta.runtime.endpoints;

import network.crypta.config.Config;
import network.crypta.config.SubConfig;
import network.crypta.runtime.http.HttpShellContainer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeClientCoreInitTest {
  @Mock private Config config;
  @Mock private SubConfig nodeConfig;
  @Mock private SubConfig installConfig;
  @Mock private HttpShellContainer toadlets;

  @Test
  void constructor_withNonNullDependencies_storesReferences() {
    // Arrange
    NodeClientCoreInit init = new NodeClientCoreInit(config, nodeConfig, installConfig, toadlets);

    // Act + Assert
    assertSame(config, init.config());
    assertSame(nodeConfig, init.nodeConfig());
    assertSame(installConfig, init.installConfig());
    assertSame(toadlets, init.toadlets());
  }

  @Test
  void constructor_withNullDependencies_allowsNullState() {
    // Arrange
    NodeClientCoreInit init = new NodeClientCoreInit(null, null, null, null);

    // Act + Assert
    assertNull(init.config());
    assertNull(init.nodeConfig());
    assertNull(init.installConfig());
    assertNull(init.toadlets());
  }
}
