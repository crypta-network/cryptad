package network.crypta.runtime.endpoints;

import network.crypta.client.async.ClientContext;
import network.crypta.config.Config;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.core.NodeClientCoreSupport;
import network.crypta.runtime.endpoints.fcp.FcpEndpointHandle;
import network.crypta.runtime.endpoints.http.HttpShellContainer;
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

  @Mock private FcpEndpointHandle fcpEndpoint;
  @Mock private TextModeClientInterfaceServer tmci;
  @Mock private HttpShellContainer toadletContainer;
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
    ClientEndpoints endpoints = new ClientEndpoints(fcpEndpoint, tmci, toadletContainer);

    assertSame(fcpEndpoint, endpoints.getFcpEndpoint());
    assertSame(tmci, endpoints.getTextModeClientInterface());
    assertSame(toadletContainer, endpoints.getToadletContainer());
    assertNull(endpoints.getDirectTMCI());
  }

  @Test
  void setDirectTMCI_whenAssigned_updatesGetter() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpEndpoint, tmci, toadletContainer);

    endpoints.setDirectTMCI(directTmci);

    assertSame(directTmci, endpoints.getDirectTMCI());
  }

  @Test
  void loadPersistentRequestsIfNeeded_whenCalled_loadInvoked() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpEndpoint, tmci, toadletContainer);

    endpoints.loadPersistentRequestsIfNeeded();

    Mockito.verify(fcpEndpoint).load();
  }

  @Test
  void maybeStart_whenTmciPresent_startsFcpAndTmci() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpEndpoint, tmci, toadletContainer);

    endpoints.maybeStart();

    Mockito.verify(fcpEndpoint).maybeStart();
    Mockito.verify(tmci).start();
  }

  @Test
  void maybeStart_whenTmciNull_startsFcpOnly() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpEndpoint, null, toadletContainer);

    endpoints.maybeStart();

    Mockito.verify(fcpEndpoint).maybeStart();
  }

  @Test
  void configureBucketFactory_whenCalled_delegatesToToadletContainer() {
    TempBucketFactory tempBucketFactory = Mockito.mock(TempBucketFactory.class);
    ClientEndpoints endpoints = new ClientEndpoints(fcpEndpoint, tmci, toadletContainer);

    endpoints.configureBucketFactory(tempBucketFactory);

    Mockito.verify(toadletContainer).setBucketFactory(tempBucketFactory);
  }

  @Test
  void registerStartupAlerts_whenCalled_registersAlertAndStoresForUnregister() {
    ClientEndpoints endpoints = new ClientEndpoints(fcpEndpoint, tmci, toadletContainer);
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
    ClientEndpoints endpoints = new ClientEndpoints(fcpEndpoint, tmci, toadletContainer);

    endpoints.unregisterStartupAlert(userAlertManager);

    Mockito.verifyNoInteractions(userAlertManager);
  }

  @Test
  void isAdvancedModeEnabled_whenQueried_delegatesToToadletContainer() {
    Mockito.when(toadletContainer.isAdvancedModeEnabled()).thenReturn(true);
    ClientEndpoints endpoints = new ClientEndpoints(fcpEndpoint, tmci, toadletContainer);

    boolean enabled = endpoints.isAdvancedModeEnabled();

    assertTrue(enabled);
  }

  @Test
  void isFProxyJavascriptEnabled_whenQueried_delegatesToToadletContainer() {
    Mockito.when(toadletContainer.isFProxyJavascriptEnabled()).thenReturn(false);
    ClientEndpoints endpoints = new ClientEndpoints(fcpEndpoint, tmci, toadletContainer);

    boolean enabled = endpoints.isFProxyJavascriptEnabled();

    assertFalse(enabled);
  }

  @Test
  void create_whenDatabaseHealthy_loadsFcpAndWiresEndpoints() {
    Config config = Mockito.mock(Config.class);
    HttpShellContainer toadlets = Mockito.mock(HttpShellContainer.class);
    NodeClientCoreInit init = new NodeClientCoreInit(config, null, null, toadlets);

    Mockito.when(persistence.createFcpEndpointHandle(node, core, runtimePorts))
        .thenReturn(fcpEndpoint);
    Mockito.when(core.killedDatabase()).thenReturn(false);

    try (MockedStatic<TextModeClientInterfaceServer> tmciMock =
        Mockito.mockStatic(TextModeClientInterfaceServer.class)) {
      tmciMock
          .when(() -> TextModeClientInterfaceServer.maybeCreate(node, core, config))
          .thenReturn(new TextModeClientInterfaceServer.InitResult(tmci, null));

      ClientEndpoints.InitResult initResult =
          ClientEndpoints.create(node, core, runtimePorts, init, persistence, clientContext);
      ClientEndpoints endpoints = initResult.endpoints();

      assertSame(fcpEndpoint, endpoints.getFcpEndpoint());
      assertSame(tmci, endpoints.getTextModeClientInterface());
      assertSame(toadlets, endpoints.getToadletContainer());
      tmciMock.verify(() -> TextModeClientInterfaceServer.maybeCreate(node, core, config));
    }

    Mockito.verify(persistence).createFcpEndpointHandle(node, core, runtimePorts);
    Mockito.verify(clientContext).setDownloadCache(fcpEndpoint);
    Mockito.verify(fcpEndpoint).load();
  }

  @Test
  void create_whenDatabaseKilled_skipsFcpLoad() {
    Config config = Mockito.mock(Config.class);
    HttpShellContainer toadlets = Mockito.mock(HttpShellContainer.class);
    NodeClientCoreInit init = new NodeClientCoreInit(config, null, null, toadlets);

    Mockito.when(persistence.createFcpEndpointHandle(node, core, runtimePorts))
        .thenReturn(fcpEndpoint);
    Mockito.when(core.killedDatabase()).thenReturn(true);

    try (MockedStatic<TextModeClientInterfaceServer> tmciMock =
        Mockito.mockStatic(TextModeClientInterfaceServer.class)) {
      tmciMock
          .when(() -> TextModeClientInterfaceServer.maybeCreate(node, core, config))
          .thenReturn(new TextModeClientInterfaceServer.InitResult(tmci, null));

      ClientEndpoints.InitResult initResult =
          ClientEndpoints.create(node, core, runtimePorts, init, persistence, clientContext);
      ClientEndpoints endpoints = initResult.endpoints();

      assertSame(fcpEndpoint, endpoints.getFcpEndpoint());
      assertSame(tmci, endpoints.getTextModeClientInterface());
      assertSame(toadlets, endpoints.getToadletContainer());
    }

    Mockito.verify(fcpEndpoint, Mockito.never()).load();
    Mockito.verify(clientContext).setDownloadCache(fcpEndpoint);
  }
}
