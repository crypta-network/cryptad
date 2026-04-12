package network.crypta.clients.http;

import java.lang.reflect.Field;
import java.util.List;
import java.util.stream.IntStream;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.ajaxpush.DismissAlertToadlet;
import network.crypta.clients.http.ajaxpush.LogWritebackToadlet;
import network.crypta.clients.http.ajaxpush.PushDataToadlet;
import network.crypta.clients.http.ajaxpush.PushFailoverToadlet;
import network.crypta.clients.http.ajaxpush.PushKeepaliveToadlet;
import network.crypta.clients.http.ajaxpush.PushLeavingToadlet;
import network.crypta.clients.http.ajaxpush.PushNotificationToadlet;
import network.crypta.clients.http.ajaxpush.PushTesterToadlet;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.runtime.spi.LifecyclePort;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.runtime.spi.WelcomeActionPort;
import network.crypta.runtime.spi.WelcomePagePort;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacyFProxyBrowseRouteRegistrarTest {

  @Mock private HighLevelSimpleClient client;
  @Mock private RuntimePorts runtimePorts;
  @Mock private WelcomePagePort welcomePagePort;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private LifecyclePort lifecyclePort;
  @Mock private WelcomeActionPort welcomeActionPort;
  @Mock private DarknetMessagingPort darknetMessagingPort;
  @Mock private TransferAccessPort transferAccess;
  @Mock private Toadlet browseRoot;
  @Mock private SimpleToadletServer server;

  private LegacyHttpBrowseRouteRegistrarContext context;
  private LegacyFProxyBrowseRouteRegistrar registrar;

  @BeforeEach
  void setUp() {
    context = new LegacyHttpBrowseRouteRegistrarContext(client, runtimePorts, browseRoot);
    registrar = new LegacyFProxyBrowseRouteRegistrar();
  }

  @Test
  void registerRoutes_whenPhaseRootMenu_registersBrowsingMenu() {
    registrar.registerRoutes(LegacyHttpBrowseRouteRegistrar.Phase.ROOT_MENU, context, server);

    verify(server)
        .registerMenu(
            "/", LegacyHttpCategories.CATEGORY_BROWSING, "FProxyToadlet.categoryTitleBrowsing");
    verifyNoMoreInteractions(server);
  }

  @Test
  void registerRoutes_whenPhaseIntroRoutes_registersBrowseRootDecodeAndInsertInOrder() {
    registrar.registerRoutes(LegacyHttpBrowseRouteRegistrar.Phase.INTRO_ROUTES, context, server);

    List<RegisteredToadlet> registrations = capturedRegistrations(3);
    assertSame(browseRoot, registrations.get(0).toadlet());
    assertInstanceOf(DecodeToadlet.class, registrations.get(1).toadlet());
    assertInstanceOf(InsertFreesiteToadlet.class, registrations.get(2).toadlet());
    assertEquals(List.of("/", "/decode/", "/insertsite/"), registrationPrefixes(registrations));
  }

  @Test
  void registerRoutes_whenPhaseQueueFilterRoutes_registersFilterRoutesAndTransferAccess() {
    when(runtimePorts.transferAccess()).thenReturn(transferAccess);

    registrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.QUEUE_FILTER_ROUTES, context, server);

    List<RegisteredToadlet> registrations = capturedRegistrations(2);
    assertInstanceOf(ContentFilterToadlet.class, registrations.get(0).toadlet());
    assertInstanceOf(LocalFileFilterToadlet.class, registrations.get(1).toadlet());
    assertEquals(
        List.of(ContentFilterToadlet.CONTENT_FILTER_PATH, LocalFileFilterToadlet.BROWSE_PATH),
        registrationPrefixes(registrations));
    assertSame(registrations.get(0).toadlet(), registrations.get(0).registration().callback());
    assertSame(transferAccess, readField(registrations.get(1).toadlet(), "transferAccess"));
  }

  @Test
  void registerRoutes_whenPhasePostConfigRoutes_registersWelcomeAndExternalLinkWithPorts() {
    when(runtimePorts.welcomePage()).thenReturn(welcomePagePort);
    when(runtimePorts.darknetConnections()).thenReturn(darknetConnectionsPort);
    when(runtimePorts.lifecycle()).thenReturn(lifecyclePort);
    when(runtimePorts.welcomeAction()).thenReturn(welcomeActionPort);

    registrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.POST_CONFIG_ROUTES, context, server);

    List<RegisteredToadlet> registrations = capturedRegistrations(2);
    assertInstanceOf(WelcomeToadlet.class, registrations.get(0).toadlet());
    assertInstanceOf(ExternalLinkToadlet.class, registrations.get(1).toadlet());
    assertEquals(
        List.of(LegacyHttpPaths.WELCOME_PATH, ExternalLinkToadlet.EXTERNAL_LINK_PATH),
        registrationPrefixes(registrations));

    WelcomeToadletRuntimePorts welcomeRuntimePorts =
        (WelcomeToadletRuntimePorts) readField(registrations.get(0).toadlet(), "runtimePorts");
    assertSame(welcomePagePort, welcomeRuntimePorts.welcomePagePort());
    assertSame(darknetConnectionsPort, welcomeRuntimePorts.darknetConnectionsPort());
    assertSame(lifecyclePort, welcomeRuntimePorts.lifecyclePort());
    assertSame(welcomeActionPort, welcomeRuntimePorts.welcomeActionPort());
  }

  @Test
  void registerRoutes_whenPhasePostMessagingRoutes_registersBookmarkEditorWithPorts() {
    when(runtimePorts.darknetConnections()).thenReturn(darknetConnectionsPort);
    when(runtimePorts.darknetMessaging()).thenReturn(darknetMessagingPort);

    registrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.POST_MESSAGING_ROUTES, context, server);

    List<RegisteredToadlet> registrations = capturedRegistrations(1);
    assertInstanceOf(BookmarkEditorToadlet.class, registrations.getFirst().toadlet());
    assertEquals(List.of("/bookmarkEditor/"), registrationPrefixes(registrations));

    BookmarkEditorToadletRuntimePorts bookmarkRuntimePorts =
        (BookmarkEditorToadletRuntimePorts)
            readField(registrations.getFirst().toadlet(), "runtimePorts");
    assertSame(darknetConnectionsPort, bookmarkRuntimePorts.darknetConnectionsPort());
    assertSame(darknetMessagingPort, bookmarkRuntimePorts.darknetMessagingPort());
  }

  @Test
  void registerRoutes_whenPhasePostPlatformApiRoutes_registersBrowserTest() {
    registrar.registerRoutes(
        LegacyHttpBrowseRouteRegistrar.Phase.POST_PLATFORM_API_ROUTES, context, server);

    List<RegisteredToadlet> registrations = capturedRegistrations(1);
    assertInstanceOf(BrowserTestToadlet.class, registrations.getFirst().toadlet());
    assertEquals(List.of("/test/"), registrationPrefixes(registrations));
  }

  @Test
  void registerRoutes_whenPhaseTailRoutes_registersAjaxPushThenRemainingTailRoutes() {
    registrar.registerRoutes(LegacyHttpBrowseRouteRegistrar.Phase.TAIL_ROUTES, context, server);

    List<RegisteredToadlet> registrations = capturedRegistrations(9);
    assertEquals(
        List.of(
            PushDataToadlet.class,
            PushNotificationToadlet.class,
            PushKeepaliveToadlet.class,
            PushFailoverToadlet.class,
            PushTesterToadlet.class,
            PushLeavingToadlet.class,
            ImageCreatorToadlet.class,
            LogWritebackToadlet.class,
            DismissAlertToadlet.class),
        registrations.stream().map(RegisteredToadlet::toadlet).map(Object::getClass).toList());
    assertEquals(
        registrations.stream().map(RegisteredToadlet::toadlet).map(Toadlet::path).toList(),
        registrationPrefixes(registrations));
  }

  private List<RegisteredToadlet> capturedRegistrations(int expectedCount) {
    ArgumentCaptor<Toadlet> toadletCaptor = ArgumentCaptor.forClass(Toadlet.class);
    ArgumentCaptor<ToadletRegistration> registrationCaptor =
        ArgumentCaptor.forClass(ToadletRegistration.class);
    verify(server, times(expectedCount))
        .register(toadletCaptor.capture(), registrationCaptor.capture());

    List<Toadlet> toadlets = toadletCaptor.getAllValues();
    List<ToadletRegistration> registrations = registrationCaptor.getAllValues();
    return IntStream.range(0, expectedCount)
        .mapToObj(index -> new RegisteredToadlet(toadlets.get(index), registrations.get(index)))
        .toList();
  }

  private static List<String> registrationPrefixes(List<RegisteredToadlet> registrations) {
    return registrations.stream()
        .map(RegisteredToadlet::registration)
        .map(ToadletRegistration::urlPrefix)
        .toList();
  }

  private static Object readField(Object target, String fieldName) {
    try {
      for (Class<?> type = target.getClass(); type != null; type = type.getSuperclass()) {
        try {
          Field field = type.getDeclaredField(fieldName);
          field.setAccessible(true);
          return field.get(target);
        } catch (NoSuchFieldException _) {
          // Search the next superclass.
        }
      }
      throw new NoSuchFieldException(fieldName);
    } catch (ReflectiveOperationException e) {
      throw new LinkageError("Unable to read field " + fieldName + " from " + target.getClass(), e);
    }
  }

  private record RegisteredToadlet(Toadlet toadlet, ToadletRegistration registration) {}
}
