package network.crypta.node;

import network.crypta.client.async.ClientContext;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.http.FProxyToadlet;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.Config;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.runtime.spi.RuntimePorts;
import network.crypta.support.io.TempBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class ClientEndpointsTest {

  @Mock private FCPServer fcpServer;
  @Mock private TextModeClientInterfaceServer tmci;
  @Mock private SimpleToadletServer toadletContainer;
  @Mock private FProxyToadlet fproxy;
  @Mock private TextModeClientInterface directTmci;
  @Mock private UserAlertManager userAlertManager;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;
  @Mock private NodeClientPersistence persistence;
  @Mock private ClientContext clientContext;
  @Mock private RuntimePorts runtimePorts;

  @Test
  void constructor_whenProvidedDependencies_returnsSameInstances() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, tmci, toadletContainer);

    assertSame(fcpServer, endpoints.getFCPServer());
    assertSame(tmci, endpoints.getTextModeClientInterface());
    assertSame(toadletContainer, endpoints.getToadletContainer());
    assertNull(endpoints.getFProxy());
    assertNull(endpoints.getDirectTMCI());
  }

  @Test
  void setFProxy_whenAssigned_updatesGetter() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, tmci, toadletContainer);

    endpoints.setFProxy(fproxy);

    assertSame(fproxy, endpoints.getFProxy());
  }

  @Test
  void setDirectTMCI_whenAssigned_updatesGetter() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, tmci, toadletContainer);

    endpoints.setDirectTMCI(directTmci);

    assertSame(directTmci, endpoints.getDirectTMCI());
  }

  @Test
  void loadPersistentRequestsIfNeeded_whenCalled_loadInvoked() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, tmci, toadletContainer);

    endpoints.loadPersistentRequestsIfNeeded();

    Mockito.verify(fcpServer).load();
  }

  @Test
  void maybeStart_whenTmciPresent_startsFcpAndTmci() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, tmci, toadletContainer);

    endpoints.maybeStart();

    Mockito.verify(fcpServer).maybeStart();
    Mockito.verify(tmci).start();
  }

  @Test
  void maybeStart_whenTmciNull_startsFcpOnly() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, null, toadletContainer);

    endpoints.maybeStart();

    Mockito.verify(fcpServer).maybeStart();
  }

  @Test
  void configureBucketFactory_whenCalled_delegatesToToadletContainer() {
    TempBucketFactory tempBucketFactory = Mockito.mock(TempBucketFactory.class);
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, tmci, toadletContainer);

    endpoints.configureBucketFactory(tempBucketFactory);

    Mockito.verify(toadletContainer).setBucketFactory(tempBucketFactory);
  }

  @Test
  void registerStartupAlerts_whenCalled_registersAlertAndStoresForUnregister() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, tmci, toadletContainer);
    UserAlert alert = Mockito.mock(UserAlert.class);
    String title = "Title";
    String longText = "Long";
    String shortText = "Short";

    try (MockedStatic<NodeClientCoreSupport> mocked =
        Mockito.mockStatic(NodeClientCoreSupport.class)) {
      mocked
          .when(() -> NodeClientCoreSupport.createStartingUpAlert(title, longText, shortText))
          .thenReturn(alert);

      endpoints.registerStartupAlerts(userAlertManager, core, title, longText, shortText);

      mocked.verify(() -> NodeClientCoreSupport.createStartingUpAlert(title, longText, shortText));
      mocked.verify(
          () -> NodeClientCoreSupport.registerFProxyAlerts(userAlertManager, core, alert));
    }

    endpoints.unregisterStartupAlert(userAlertManager);

    Mockito.verify(userAlertManager).unregister(alert);
  }

  @Test
  void unregisterStartupAlert_whenMissing_doesNothing() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, tmci, toadletContainer);

    endpoints.unregisterStartupAlert(userAlertManager);

    Mockito.verifyNoInteractions(userAlertManager);
  }

  @Test
  void isAdvancedModeEnabled_whenQueried_delegatesToToadletContainer() {
    Mockito.when(toadletContainer.isAdvancedModeEnabled()).thenReturn(true);
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, tmci, toadletContainer);

    boolean enabled = endpoints.isAdvancedModeEnabled();

    assertTrue(enabled);
  }

  @Test
  void isFProxyJavascriptEnabled_whenQueried_delegatesToToadletContainer() {
    Mockito.when(toadletContainer.isFProxyJavascriptEnabled()).thenReturn(false);
    ClientEndpoints endpoints = new ClientEndpoints(fcpServer, tmci, toadletContainer);

    boolean enabled = endpoints.isFProxyJavascriptEnabled();

    assertFalse(enabled);
  }

  @Test
  void create_whenDatabaseHealthy_loadsFcpAndWiresEndpoints() {
    Config config = Mockito.mock(Config.class);
    SimpleToadletServer toadlets = Mockito.mock(SimpleToadletServer.class);
    NodeClientCoreInit init = new NodeClientCoreInit(config, null, null, toadlets);

    Mockito.when(persistence.createFcpServer(node, core, runtimePorts)).thenReturn(fcpServer);
    Mockito.when(core.killedDatabase()).thenReturn(false);

    try (MockedStatic<TextModeClientInterfaceServer> tmciMock =
        Mockito.mockStatic(TextModeClientInterfaceServer.class)) {
      tmciMock
          .when(() -> TextModeClientInterfaceServer.maybeCreate(node, core, config))
          .thenReturn(new TextModeClientInterfaceServer.InitResult(tmci, null));

      ClientEndpoints.InitResult initResult =
          ClientEndpoints.create(node, core, runtimePorts, init, persistence, clientContext);
      ClientEndpoints endpoints = initResult.endpoints();

      assertSame(fcpServer, endpoints.getFCPServer());
      assertSame(tmci, endpoints.getTextModeClientInterface());
      assertSame(toadlets, endpoints.getToadletContainer());
      tmciMock.verify(() -> TextModeClientInterfaceServer.maybeCreate(node, core, config));
    }

    Mockito.verify(persistence).createFcpServer(node, core, runtimePorts);
    Mockito.verify(clientContext).setDownloadCache(fcpServer);
    Mockito.verify(fcpServer).load();
  }

  @Test
  void create_whenDatabaseKilled_skipsFcpLoad() {
    Config config = Mockito.mock(Config.class);
    SimpleToadletServer toadlets = Mockito.mock(SimpleToadletServer.class);
    NodeClientCoreInit init = new NodeClientCoreInit(config, null, null, toadlets);

    Mockito.when(persistence.createFcpServer(node, core, runtimePorts)).thenReturn(fcpServer);
    Mockito.when(core.killedDatabase()).thenReturn(true);

    try (MockedStatic<TextModeClientInterfaceServer> tmciMock =
        Mockito.mockStatic(TextModeClientInterfaceServer.class)) {
      tmciMock
          .when(() -> TextModeClientInterfaceServer.maybeCreate(node, core, config))
          .thenReturn(new TextModeClientInterfaceServer.InitResult(tmci, null));

      ClientEndpoints.InitResult initResult =
          ClientEndpoints.create(node, core, runtimePorts, init, persistence, clientContext);
      ClientEndpoints endpoints = initResult.endpoints();

      assertSame(fcpServer, endpoints.getFCPServer());
      assertSame(tmci, endpoints.getTextModeClientInterface());
      assertSame(toadlets, endpoints.getToadletContainer());
    }

    Mockito.verify(fcpServer, Mockito.never()).load();
    Mockito.verify(clientContext).setDownloadCache(fcpServer);
  }
}
