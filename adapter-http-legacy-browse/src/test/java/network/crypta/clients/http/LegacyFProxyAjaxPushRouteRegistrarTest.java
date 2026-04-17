package network.crypta.clients.http;

import java.util.List;
import network.crypta.clients.http.ajaxpush.PushDataToadlet;
import network.crypta.clients.http.ajaxpush.PushFailoverToadlet;
import network.crypta.clients.http.ajaxpush.PushKeepaliveToadlet;
import network.crypta.clients.http.ajaxpush.PushLeavingToadlet;
import network.crypta.clients.http.ajaxpush.PushNotificationToadlet;
import network.crypta.clients.http.ajaxpush.PushTesterToadlet;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100")
class LegacyFProxyAjaxPushRouteRegistrarTest {

  @Test
  void registerRoutes_whenInvoked_registersAjaxPushRoutesInHistoricalOrder() {
    BrowseContentClient client = mock(BrowseContentClient.class);
    SimpleToadletServer server = mock(SimpleToadletServer.class);

    new LegacyFProxyAjaxPushRouteRegistrar().registerRoutes(client, server);

    ArgumentCaptor<Toadlet> toadletCaptor = ArgumentCaptor.forClass(Toadlet.class);
    ArgumentCaptor<ToadletRegistration> registrationCaptor =
        ArgumentCaptor.forClass(ToadletRegistration.class);
    verify(server, times(6)).register(toadletCaptor.capture(), registrationCaptor.capture());

    List<Toadlet> toadlets = toadletCaptor.getAllValues();
    assertEquals(
        List.of(
            PushDataToadlet.class,
            PushNotificationToadlet.class,
            PushKeepaliveToadlet.class,
            PushFailoverToadlet.class,
            PushTesterToadlet.class,
            PushLeavingToadlet.class),
        toadlets.stream().map(Object::getClass).toList());
    toadlets.forEach(LegacyFProxyAjaxPushRouteRegistrarTest::assertContentToadlet);
    assertEquals(
        toadlets.stream().map(Toadlet::path).toList(),
        registrationCaptor.getAllValues().stream().map(ToadletRegistration::urlPrefix).toList());
  }

  private static void assertContentToadlet(Toadlet toadlet) {
    assertInstanceOf(
        ContentToadlet.class,
        toadlet,
        toadlet.getClass().getName() + " must extend ContentToadlet");
  }
}
