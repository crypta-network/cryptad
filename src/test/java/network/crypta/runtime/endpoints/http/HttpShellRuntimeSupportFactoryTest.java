package network.crypta.runtime.endpoints.http;

import network.crypta.clients.http.HttpShellRuntimeSupport;
import network.crypta.node.NodeClientCore;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;

@SuppressWarnings("java:S100")
class HttpShellRuntimeSupportFactoryTest {

  @Test
  void coreBacked_whenCreateCalled_returnsCoreBackedRuntimeSupport() {
    NodeClientCore core = mock(NodeClientCore.class);

    HttpShellRuntimeSupport runtimeSupport =
        HttpShellRuntimeSupportFactory.coreBacked().create(core);

    CoreHttpShellRuntimeSupport coreRuntimeSupport =
        assertInstanceOf(CoreHttpShellRuntimeSupport.class, runtimeSupport);
    assertSame(core, coreRuntimeSupport.core());
  }
}
