package network.crypta.runtime.admin;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.runtime.admin.geoip.GeoIpCountryLookup;
import network.crypta.runtime.admin.queue.QueueAdminBackend;
import network.crypta.runtime.admin.queue.page.QueuePageBackend;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.spi.QueueCompletionPort;
import network.crypta.runtime.spi.QueueDownloadPort;
import network.crypta.runtime.spi.QueueInsertPort;
import network.crypta.support.http.HttpFetchSizeLimits;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AdminRuntimePortsFactoryTest {

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock(answer = Answers.RETURNS_DEEP_STUBS)
  private NodeClientCore core;

  @Mock private HighLevelSimpleClient peerReferenceClient;
  @Mock private QueueAdminBackend queueAdminBackend;
  @Mock private QueuePageBackend queuePageBackend;
  @Mock private QueueCompletionPort queueCompletionPort;
  @Mock private QueueDownloadPort queueDownloadPort;
  @Mock private QueueInsertPort queueInsertPort;
  @Mock private GeoIpCountryLookup geoIpCountryLookup;
  @Mock private UserAlertManager alertManager;

  @Test
  void create_whenBuildingBundle_usesRealtimeSizeCappedClientForPeerReferenceLoading() {
    AdminRuntimeBridgeInputs bridgeInputs =
        new AdminRuntimeBridgeInputs(
            queueAdminBackend,
            queuePageBackend,
            queueCompletionPort,
            queueDownloadPort,
            queueInsertPort,
            geoIpCountryLookup);
    when(core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true))
        .thenReturn(peerReferenceClient);
    when(core.getAlerts()).thenReturn(alertManager);

    AdminRuntimePortsBundle bundle = AdminRuntimePortsFactory.create(node, core, bridgeInputs);

    assertNotNull(bundle.connectionsSupport());
    assertInstanceOf(LegacyAlertPort.class, bundle.alertFeed());
    assertSame(bundle.alertFeed(), bundle.alertMutation());
    verify(core).makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true);
    verify(peerReferenceClient).setMaxLength(HttpFetchSizeLimits.getMaxLengthNoProgress());
    verify(peerReferenceClient)
        .setMaxIntermediateLength(HttpFetchSizeLimits.getMaxLengthNoProgress());
    verify(core, never()).makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, false);
  }

  @Test
  void create_whenAlertManagerMissing_expectNullPointerException() {
    AdminRuntimeBridgeInputs bridgeInputs =
        new AdminRuntimeBridgeInputs(
            queueAdminBackend,
            queuePageBackend,
            queueCompletionPort,
            queueDownloadPort,
            queueInsertPort,
            geoIpCountryLookup);
    when(core.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, true, true))
        .thenReturn(peerReferenceClient);
    when(core.getAlerts()).thenReturn(null);

    NullPointerException error =
        assertThrows(
            NullPointerException.class,
            () -> AdminRuntimePortsFactory.create(node, core, bridgeInputs));

    assertEquals("alerts", error.getMessage());
  }
}
