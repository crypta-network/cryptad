package network.crypta.pluginmanager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.UUID;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.filter.FilterCallback;
import network.crypta.client.filter.GenericReadFilterCallback;
import network.crypta.clients.fcp.FCPPluginConnection;
import network.crypta.clients.fcp.FCPServer;
import network.crypta.clients.http.PageMaker;
import network.crypta.clients.http.SessionManager;
import network.crypta.clients.http.SimpleToadletServer;
import network.crypta.config.Config;
import network.crypta.config.SubConfig;
import network.crypta.node.ClientEndpoints;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.RequestStarter;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PluginRespiratorTest {

  static final class TestPlugin implements FredPlugin {
    @Override
    public void terminate() {
      // Intentionally empty: this test stub is never started and therefore has nothing to shut
      // down.
    }

    @Override
    public void runPlugin(PluginRespirator pr) {
      // Intentionally empty: PluginRespirator tests only need a stable plugin class identity.
    }
  }

  @Mock private Node node;
  @Mock private NodeClientCore nodeClientCore;
  @Mock private HighLevelSimpleClient highLevelSimpleClient;
  @Mock private PluginStores pluginStores;
  @Mock private PluginInfoWrapper pluginInfoWrapper;
  @Mock private FilterCallback filterCallback;
  @Mock private SimpleToadletServer toadletContainer;
  @Mock private ClientEndpoints endpoints;
  @Mock private PageMaker pageMaker;
  @Mock private FCPServer fcpServer;
  @Mock private FCPPluginConnection pluginConnection;
  @Mock private FredPluginFCPMessageHandler.ClientSideFCPMessageHandler messageHandler;
  @Mock private SubConfig subConfig;
  @Mock private Config config;

  private final FredPlugin plugin = new TestPlugin();

  @BeforeEach
  void setUp() {
    clearSessionManagers();

    when(pluginInfoWrapper.getPlugin()).thenReturn(plugin);
    when(node.getClientCore()).thenReturn(nodeClientCore);
    lenient().when(nodeClientCore.getEndpoints()).thenReturn(endpoints);
    when(nodeClientCore.makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, false, false))
        .thenReturn(highLevelSimpleClient);
    when(nodeClientCore.getPluginStores()).thenReturn(pluginStores);
  }

  @AfterEach
  void tearDown() {
    clearSessionManagers();
  }

  @Test
  void constructor_whenCreated_initializesClientAndStores() {
    // Arrange
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    HighLevelSimpleClient hlsc = respirator.getHLSimpleClient();
    Node returnedNode = respirator.getNode();

    // Assert
    assertSame(highLevelSimpleClient, hlsc);
    assertSame(node, returnedNode);
    verify(nodeClientCore).makeClient(RequestStarter.INTERACTIVE_PRIORITY_CLASS, false, false);
    verify(nodeClientCore).getPluginStores();
    verify(pluginInfoWrapper).getPlugin();
  }

  @Test
  void makeFilterCallback_whenPathRequiresEncoding_passesEncodedUriToCore() throws Exception {
    // Arrange
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);
    String rawPath = "http://example.invalid/a b?q=c d";
    when(endpoints.getToadletContainer()).thenReturn(toadletContainer);

    // Act
    FilterCallback result = respirator.makeFilterCallback(rawPath);

    // Assert
    assertNotNull(result);
    assertInstanceOf(GenericReadFilterCallback.class, result);
  }

  @Test
  void
      makeFilterCallback_whenInputContainsInvalidPercentEscape_throwsErrorWrappingURISyntaxException() {
    // Arrange
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);
    String invalidUri = "http://example.invalid/%zz";

    // Act
    Error error = assertThrows(Error.class, () -> respirator.makeFilterCallback(invalidUri));

    // Assert
    assertInstanceOf(URISyntaxException.class, error.getCause());
  }

  @Test
  void getPageMaker_whenToadletContainerNull_returnsNull() {
    // Arrange
    when(endpoints.getToadletContainer()).thenReturn(null);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    PageMaker result = respirator.getPageMaker();

    // Assert
    assertNull(result);
  }

  @Test
  void getPageMaker_whenToadletContainerPresent_returnsItsPageMaker() {
    // Arrange
    when(endpoints.getToadletContainer()).thenReturn(toadletContainer);
    when(toadletContainer.getPageMaker()).thenReturn(pageMaker);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    PageMaker result = respirator.getPageMaker();

    // Assert
    assertSame(pageMaker, result);
    verify(toadletContainer).getPageMaker();
  }

  @Test
  void getToadletContainer_whenAvailable_returnsContainerFromCore() {
    // Arrange
    when(endpoints.getToadletContainer()).thenReturn(toadletContainer);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    Object result = respirator.getToadletContainer();

    // Assert
    assertSame(toadletContainer, result);
  }

  @Test
  void addFormChild_whenCalled_addsFormWithFormPasswordHiddenField() {
    // Arrange
    when(nodeClientCore.getFormPassword()).thenReturn("pw123");
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);
    HTMLNode parent = new HTMLNode("div");

    // Act
    HTMLNode form = respirator.addFormChild(parent, "/submit", "myForm");

    // Assert
    assertEquals("form", form.getName());
    assertEquals("/submit", form.getAttribute("action"));
    assertEquals("post", form.getAttribute("method"));
    assertEquals("multipart/form-data", form.getAttribute("enctype"));
    assertEquals("myForm", form.getAttribute("id"));
    assertEquals("myForm", form.getAttribute("name"));
    assertEquals("utf-8", form.getAttribute("accept-charset"));

    assertEquals(1, parent.getChildren().size());
    assertSame(form, parent.getChildren().getFirst());

    assertEquals(1, form.getChildren().size());
    HTMLNode hiddenField = form.getChildren().getFirst();
    assertEquals("input", hiddenField.getName());
    assertEquals("hidden", hiddenField.getAttribute("type"));
    assertEquals("formPassword", hiddenField.getAttribute("name"));
    assertEquals("pw123", hiddenField.getAttribute("value"));
  }

  @Test
  void connectToOtherPlugin_whenMessageHandlerNull_throwsNullPointerExceptionWithMessage() {
    // Arrange
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    NullPointerException exception =
        assertThrows(NullPointerException.class, () -> respirator.connectToOtherPlugin("X", null));

    // Assert
    assertEquals("messageHandler must not be null", exception.getMessage());
  }

  @Test
  void connectToOtherPlugin_whenPluginNameNull_delegatesToFcpServerWithNullName() throws Exception {
    // Arrange
    when(endpoints.getFCPServer()).thenReturn(fcpServer);
    when(fcpServer.createFCPPluginConnectionForIntraNodeFCP(null, messageHandler))
        .thenReturn(pluginConnection);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    FCPPluginConnection result = respirator.connectToOtherPlugin(null, messageHandler);

    // Assert
    assertSame(pluginConnection, result);
    verify(fcpServer).createFCPPluginConnectionForIntraNodeFCP(null, messageHandler);
  }

  @Test
  void connectToOtherPlugin_whenValid_delegatesToFcpServer() throws Exception {
    // Arrange
    when(endpoints.getFCPServer()).thenReturn(fcpServer);
    when(fcpServer.createFCPPluginConnectionForIntraNodeFCP("serverPlugin", messageHandler))
        .thenReturn(pluginConnection);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    FCPPluginConnection result = respirator.connectToOtherPlugin("serverPlugin", messageHandler);

    // Assert
    assertSame(pluginConnection, result);
    verify(fcpServer).createFCPPluginConnectionForIntraNodeFCP("serverPlugin", messageHandler);
  }

  @Test
  void getPluginConnectionByID_whenFound_delegatesToFcpServer() throws Exception {
    // Arrange
    UUID id = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef");
    when(endpoints.getFCPServer()).thenReturn(fcpServer);
    when(fcpServer.getPluginConnectionByID(id)).thenReturn(pluginConnection);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    FCPPluginConnection result = respirator.getPluginConnectionByID(id);

    // Assert
    assertSame(pluginConnection, result);
    verify(fcpServer).getPluginConnectionByID(id);
  }

  @Test
  void getPluginConnectionByID_whenMissing_propagatesIOException() throws Exception {
    // Arrange
    UUID id = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    IOException failure = new IOException("missing");
    when(endpoints.getFCPServer()).thenReturn(fcpServer);
    when(fcpServer.getPluginConnectionByID(id)).thenThrow(failure);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    IOException exception =
        assertThrows(IOException.class, () -> respirator.getPluginConnectionByID(id));

    // Assert
    assertSame(failure, exception);
  }

  @Test
  void getStore_whenLoadReturnsNull_createsNewStoreAndCachesIt() {
    // Arrange
    String expectedKey = plugin.getClass().getCanonicalName();
    when(pluginStores.loadPluginStore(expectedKey)).thenReturn(null);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    PluginStore store1 = respirator.getStore();
    PluginStore store2 = respirator.getStore();

    // Assert
    assertNotNull(store1);
    assertSame(store1, store2);
    verify(pluginStores, times(1)).loadPluginStore(expectedKey);
  }

  @Test
  void getStore_whenLoadReturnsStore_returnsLoadedStoreAndCachesIt() {
    // Arrange
    String expectedKey = plugin.getClass().getCanonicalName();
    PluginStore loadedStore = new PluginStore();
    when(pluginStores.loadPluginStore(expectedKey)).thenReturn(loadedStore);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    PluginStore store1 = respirator.getStore();
    PluginStore store2 = respirator.getStore();

    // Assert
    assertSame(loadedStore, store1);
    assertSame(store1, store2);
    verify(pluginStores, times(1)).loadPluginStore(expectedKey);
  }

  @Test
  void putStore_whenWriteSucceeds_delegatesToPluginStoresWithPluginCanonicalName()
      throws Exception {
    // Arrange
    String expectedKey = plugin.getClass().getCanonicalName();
    PluginStore store = new PluginStore();
    doNothing().when(pluginStores).writePluginStore(expectedKey, store);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    respirator.putStore(store);

    // Assert
    verify(pluginStores).writePluginStore(expectedKey, store);
  }

  @Test
  void putStore_whenWriteThrowsIOException_doesNotPropagateException() throws Exception {
    // Arrange
    String expectedKey = plugin.getClass().getCanonicalName();
    PluginStore store = new PluginStore();
    doThrow(new IOException("disk full")).when(pluginStores).writePluginStore(expectedKey, store);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);
    // Act
    respirator.putStore(store);

    // Assert
    verify(pluginStores).writePluginStore(expectedKey, store);
  }

  @Test
  void getSessionManager_whenCookieNamespaceMatchesLowercase_returnsSameManagerInstance() {
    // Arrange
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);
    String cookieNamespace = "plugin";

    // Act
    SessionManager first = respirator.getSessionManager(cookieNamespace);
    SessionManager second = respirator.getSessionManager(cookieNamespace);

    // Assert
    assertSame(first, second);
    assertEquals("/", first.getCookiePath().toString());
    assertEquals(cookieNamespace, first.getCookieNamespace());
  }

  @Test
  void getSessionManager_whenCookieNamespaceDiffers_returnsDifferentManagerInstances() {
    // Arrange
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    SessionManager first = respirator.getSessionManager("plugin1");
    SessionManager second = respirator.getSessionManager("plugin2");

    // Assert
    assertNotSame(first, second);
  }

  @Test
  void getSessionManager_whenCookieNamespaceMatches_returnsSameManagerInstance() {
    // Arrange
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    SessionManager first = respirator.getSessionManager("MyPlugin");
    SessionManager second = respirator.getSessionManager("MyPlugin");

    // Assert
    assertSame(first, second);
    assertEquals("/", first.getCookiePath().toString());
    assertEquals("MyPlugin", first.getCookieNamespace());
  }

  @ParameterizedTest
  @ValueSource(strings = {"/plugin", "", "bad-namespace"})
  void getSessionManager_whenCookieNamespaceInvalid_propagatesIllegalArgumentException(
      String cookieNamespace) {
    // Arrange
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act / Assert
    assertThrows(
        IllegalArgumentException.class, () -> respirator.getSessionManager(cookieNamespace));
  }

  @Test
  void getSubConfig_whenProvided_returnsValueFromPluginInfoWrapper() {
    // Arrange
    when(pluginInfoWrapper.getSubConfig()).thenReturn(subConfig);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    SubConfig result = respirator.getSubConfig();

    // Assert
    assertSame(subConfig, result);
  }

  @Test
  void storeConfig_whenCalled_delegatesToPluginInfoWrapperConfig() {
    // Arrange
    when(pluginInfoWrapper.getConfig()).thenReturn(config);
    PluginRespirator respirator = new PluginRespirator(node, pluginInfoWrapper);

    // Act
    respirator.storeConfig();

    // Assert
    verify(config).store();
  }

  private static void clearSessionManagers() {
    try {
      Field field = PluginRespirator.class.getDeclaredField("sessionManagers");
      field.setAccessible(true);
      @SuppressWarnings("unchecked")
      ArrayList<SessionManager> managers = (ArrayList<SessionManager>) field.get(null);
      managers.clear();
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Failed to reset PluginRespirator sessionManagers", e);
    }
  }
}
