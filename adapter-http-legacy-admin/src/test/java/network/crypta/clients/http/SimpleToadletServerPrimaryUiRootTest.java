package network.crypta.clients.http;

import java.util.concurrent.atomic.AtomicReference;
import network.crypta.config.Config;
import network.crypta.config.SubConfig;
import network.crypta.fs.readiness.LauncherReadinessInfo;
import network.crypta.io.NetworkInterface;
import network.crypta.io.SSLNetworkInterface;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.BucketFactory;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

@SuppressWarnings({"java:S100", "resource", "MustBeClosedChecker"})
class SimpleToadletServerPrimaryUiRootTest {

  @Test
  void primaryUiRoot_whenWizardCompleteAndJavascriptDisabled_returnsLegacyRoot() throws Exception {
    SubConfig fproxyConfig = newFproxyConfig();
    SimpleToadletServer server = newServerWithDefaults(fproxyConfig);
    fproxyConfig.set("hasCompletedWizard", true);
    server.enableFProxyJavascript(false);

    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, server.primaryUiRoot());
  }

  @Test
  void enableFProxyJavascript_whenWizardCompleteAfterStartupNotifiesLegacyRoot() throws Exception {
    SubConfig fproxyConfig = newFproxyConfig();
    SimpleToadletServer server = newServerWithDefaults(fproxyConfig);
    AtomicReference<String> notifiedUiRoot = new AtomicReference<>();

    fproxyConfig.set("hasCompletedWizard", true);
    server.setRuntimeSupport(mock(HttpShellRuntimeSupport.class));
    server.setPrimaryUiRootListener(notifiedUiRoot::set);
    server.finishStart();

    server.enableFProxyJavascript(false);

    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, notifiedUiRoot.get());
    assertEquals(LauncherReadinessInfo.DEFAULT_UI_ROOT, server.primaryUiRoot());
  }

  private static SubConfig newFproxyConfig() {
    return new Config().createSubConfig("fproxy");
  }

  private static SimpleToadletServer newServerWithDefaults(SubConfig fproxyConfig)
      throws Exception {
    BucketFactory bucketFactory = mock(BucketFactory.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);

    try (MockedStatic<NetworkInterface> netMock = mockStatic(NetworkInterface.class);
        MockedStatic<SSLNetworkInterface> sslMock = mockStatic(SSLNetworkInterface.class)) {
      NetworkInterface iface = mock(NetworkInterface.class);
      netMock
          .when(() -> NetworkInterface.create(anyInt(), any(), any(), any(), anyBoolean()))
          .thenReturn(iface);
      sslMock
          .when(() -> SSLNetworkInterface.createSsl(anyInt(), any(), any(), any(), anyBoolean()))
          .thenReturn(iface);
      return new SimpleToadletServer(fproxyConfig, bucketFactory, executor);
    }
  }
}
