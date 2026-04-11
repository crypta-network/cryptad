package network.crypta.clients.http.bridge;

import java.io.File;
import java.util.stream.Stream;
import network.crypta.client.async.ClientContext;
import network.crypta.clients.http.FProxyRuntimeSupport;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.node.SecurityLevels.PHYSICAL_THREAT_LEVEL;
import network.crypta.node.SecurityLevels;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.services.NodeServicesSubsystem;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class CoreFProxyRuntimeSupportTest {

  @Test
  void constructor_whenCoreIsNull_throwsNullPointerException() {
    assertThrows(NullPointerException.class, () -> new CoreFProxyRuntimeSupport(null));
  }

  @Test
  void delegates_whenCoreProvidesValues_expectSameValuesAndBackgroundExecution() {
    RuntimeContext context =
        newRuntimeContext(NETWORK_THREAT_LEVEL.NORMAL, PHYSICAL_THREAT_LEVEL.HIGH);
    ClientContext clientContext = mock(ClientContext.class);
    File downloadsDir = new File("build/tmp/downloads");
    File downloadTarget = new File(downloadsDir, "target.bin");
    File[] allowedDirs = {downloadsDir, new File("build/tmp/shared")};
    when(context.core().getClientContext()).thenReturn(clientContext);
    when(context.core().isDownloadDisabled()).thenReturn(true);
    when(context.core().getDownloadsDir()).thenReturn(downloadsDir);
    when(context.core().allowDownloadTo(downloadTarget)).thenReturn(false);
    when(context.core().getAllowedDownloadDirs()).thenReturn(allowedDirs);

    assertSame(clientContext, context.runtimeSupport().clientContext());
    assertSame(downloadsDir, context.runtimeSupport().downloadsDir());
    assertSame(allowedDirs, context.runtimeSupport().allowedDownloadDirs());
    assertTrue(context.runtimeSupport().isDownloadDisabled());
    assertFalse(context.runtimeSupport().allowDownloadTo(downloadTarget));
    assertSame(context.fproxyConfig(), context.runtimeSupport().fproxyConfig());

    Runnable task = mock(Runnable.class);
    context.runtimeSupport().executeBackground(task);

    verify(context.executor()).execute(task);
  }

  @ParameterizedTest
  @MethodSource("physicalThreatLevelMappings")
  void physicalThreatLevel_whenSecurityLevelsProvideValue_expectDetachedEnumReturned(
      PHYSICAL_THREAT_LEVEL threatLevel, FProxyRuntimeSupport.PhysicalThreatLevel expected) {
    RuntimeContext context = newRuntimeContext(NETWORK_THREAT_LEVEL.NORMAL, threatLevel);

    assertEquals(expected, context.runtimeSupport().physicalThreatLevel());
  }

  @ParameterizedTest
  @MethodSource("networkThreatLevelMappings")
  void networkThreatLevel_whenSecurityLevelsProvideValue_expectDetachedEnumReturned(
      NETWORK_THREAT_LEVEL threatLevel, FProxyRuntimeSupport.NetworkThreatLevel expected) {
    RuntimeContext context = newRuntimeContext(threatLevel, PHYSICAL_THREAT_LEVEL.NORMAL);

    assertEquals(expected, context.runtimeSupport().networkThreatLevel());
  }

  private static Stream<Arguments> physicalThreatLevelMappings() {
    return Stream.of(
        Arguments.of(PHYSICAL_THREAT_LEVEL.LOW, FProxyRuntimeSupport.PhysicalThreatLevel.LOW),
        Arguments.of(PHYSICAL_THREAT_LEVEL.NORMAL, FProxyRuntimeSupport.PhysicalThreatLevel.NORMAL),
        Arguments.of(PHYSICAL_THREAT_LEVEL.HIGH, FProxyRuntimeSupport.PhysicalThreatLevel.HIGH),
        Arguments.of(
            PHYSICAL_THREAT_LEVEL.MAXIMUM, FProxyRuntimeSupport.PhysicalThreatLevel.MAXIMUM));
  }

  private static Stream<Arguments> networkThreatLevelMappings() {
    return Stream.of(
        Arguments.of(NETWORK_THREAT_LEVEL.LOW, FProxyRuntimeSupport.NetworkThreatLevel.LOW),
        Arguments.of(NETWORK_THREAT_LEVEL.NORMAL, FProxyRuntimeSupport.NetworkThreatLevel.NORMAL),
        Arguments.of(NETWORK_THREAT_LEVEL.HIGH, FProxyRuntimeSupport.NetworkThreatLevel.HIGH),
        Arguments.of(
            NETWORK_THREAT_LEVEL.MAXIMUM, FProxyRuntimeSupport.NetworkThreatLevel.MAXIMUM));
  }

  private static RuntimeContext newRuntimeContext(
      NETWORK_THREAT_LEVEL networkThreatLevel, PHYSICAL_THREAT_LEVEL physicalThreatLevel) {
    NodeClientCore core = mock(NodeClientCore.class);
    Node node = mock(Node.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    SecurityLevels securityLevels = mock(SecurityLevels.class);
    NodeNetworkSubsystem network = mock(NodeNetworkSubsystem.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);
    PersistentConfig config = mock(PersistentConfig.class);
    SubConfig fproxyConfig = mock(SubConfig.class);
    when(core.getNode()).thenReturn(node);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getNetworkThreatLevel()).thenReturn(networkThreatLevel);
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(physicalThreatLevel);
    when(node.network()).thenReturn(network);
    when(network.executor()).thenReturn(executor);
    when(node.getConfig()).thenReturn(config);
    when(config.get("fproxy")).thenReturn(fproxyConfig);
    return new RuntimeContext(new CoreFProxyRuntimeSupport(core), core, executor, fproxyConfig);
  }

  private record RuntimeContext(
      CoreFProxyRuntimeSupport runtimeSupport,
      NodeClientCore core,
      PriorityAwareExecutor executor,
      SubConfig fproxyConfig) {}
}
