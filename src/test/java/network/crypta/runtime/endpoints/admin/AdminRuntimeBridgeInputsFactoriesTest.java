package network.crypta.runtime.endpoints.admin;

import java.io.File;
import java.lang.reflect.Field;
import network.crypta.clients.fcp.bridge.FcpQueueAdminBackend;
import network.crypta.clients.fcp.bridge.FcpQueuePageBackend;
import network.crypta.clients.fcp.bridge.LegacyQueueCompletionPort;
import network.crypta.clients.fcp.bridge.LegacyQueueDownloadPort;
import network.crypta.clients.fcp.bridge.LegacyQueueInsertPort;
import network.crypta.clients.http.bridge.geoip.HttpGeoIpCountryLookup;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.ProgramDirectory;
import network.crypta.runtime.admin.AdminRuntimeBridgeInputs;
import network.crypta.runtime.admin.AdminRuntimeBridgeInputsFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class AdminRuntimeBridgeInputsFactoriesTest {

  @Test
  void coreBacked_whenCreateCalled_returnsBridgeInputsBackedByEndpointFactories() {
    BridgeFactoryFixture fixture = new BridgeFactoryFixture();

    AdminRuntimeBridgeInputsFactory factory = AdminRuntimeBridgeInputsFactories.coreBacked();

    AdminRuntimeBridgeInputs bridgeInputs = factory.create(fixture.node(), fixture.core());

    assertAll(
        () -> assertNotNull(factory),
        () -> assertNotNull(bridgeInputs),
        () -> assertInstanceOf(FcpQueueAdminBackend.class, bridgeInputs.queueAdminBackend()),
        () -> assertInstanceOf(FcpQueuePageBackend.class, bridgeInputs.queuePageBackend()),
        () -> assertInstanceOf(LegacyQueueCompletionPort.class, bridgeInputs.queueCompletionPort()),
        () -> assertInstanceOf(LegacyQueueDownloadPort.class, bridgeInputs.queueDownloadPort()),
        () -> assertInstanceOf(LegacyQueueInsertPort.class, bridgeInputs.queueInsertPort()),
        () -> assertInstanceOf(HttpGeoIpCountryLookup.class, bridgeInputs.geoIpCountryLookup()));
  }

  @Test
  void coreBacked_whenCreateCalled_wiresQueueAdaptersToCoreAndGeoIpLookupToNodeFile() {
    BridgeFactoryFixture fixture = new BridgeFactoryFixture();

    AdminRuntimeBridgeInputs bridgeInputs =
        AdminRuntimeBridgeInputsFactories.coreBacked().create(fixture.node(), fixture.core());

    assertAll(
        () -> assertSame(fixture.core(), readField(bridgeInputs.queueAdminBackend(), "core")),
        () -> assertSame(fixture.core(), readField(bridgeInputs.queuePageBackend(), "core")),
        () -> assertSame(fixture.core(), readField(bridgeInputs.queueCompletionPort(), "core")),
        () -> assertSame(fixture.core(), readField(bridgeInputs.queueDownloadPort(), "core")),
        () -> assertSame(fixture.core(), readField(bridgeInputs.queueInsertPort(), "core")),
        () ->
            assertSame(fixture.geoIpDb(), readField(bridgeInputs.geoIpCountryLookup(), "dbFile")));
  }

  private static Object readField(Object target, String fieldName) {
    try {
      Field field = target.getClass().getDeclaredField(fieldName);
      field.setAccessible(true);
      return field.get(target);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Failed reading field '" + fieldName + "'", e);
    }
  }

  private record BridgeFactoryFixture(Node node, NodeClientCore core, File geoIpDb) {
    private BridgeFactoryFixture() {
      this(mock(Node.class), mock(NodeClientCore.class), new File("run/IpToCountry.dat"));

      ProgramDirectory runDir = mock(ProgramDirectory.class);
      when(node.runDir()).thenReturn(runDir);
      when(runDir.file("IpToCountry.dat")).thenReturn(geoIpDb);
    }
  }
}
