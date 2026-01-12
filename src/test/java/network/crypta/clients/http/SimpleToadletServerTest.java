package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.net.InetAddress;
import java.net.URI;
import network.crypta.config.Config;
import network.crypta.config.SubConfig;
import network.crypta.io.NetworkInterface;
import network.crypta.io.SSLNetworkInterface;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.io.ArrayBucketFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SimpleToadletServerTest {

  @Test
  void findToadlet_whenRegisteredPrefixMatches_returnsRegisteredToadlet() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    DummyToadlet toadlet = new DummyToadlet("/test/");

    server.register(toadlet, ToadletRegistration.basic(null, "/test/", true, false));

    Toadlet result = server.findToadlet(new URI("http://localhost/test/resource"));

    assertSame(toadlet, result);
  }

  @Test
  void findToadlet_whenMissingTrailingSlash_redirectsToNormalizedPrefix() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    DummyToadlet toadlet = new DummyToadlet("/redirect/");
    server.register(toadlet, ToadletRegistration.basic(null, "/redirect/", true, false));

    PermanentRedirectException ex =
        assertThrows(
            PermanentRedirectException.class,
            () -> server.findToadlet(new URI("http://localhost/redirect")));

    assertEquals("/redirect/", ex.newuri.getPath());
  }

  @Test
  void findToadlet_whenWizardIncomplete_redirectsToWizard() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getNode()).thenReturn(node);
    server.setCore(core);

    PermanentRedirectException ex =
        assertThrows(
            PermanentRedirectException.class,
            () -> server.findToadlet(new URI("http://localhost/hidden")));

    assertEquals(FirstTimeWizardToadlet.TOADLET_URL, ex.newuri.getPath());
  }

  @Test
  void isLinkExcepted_whenToadletDeclaresException_usesToadletDecision() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    ExceptedToadlet toadlet = new ExceptedToadlet("/except/");
    server.register(toadlet, ToadletRegistration.basic(null, "/except/", true, false));

    boolean result = server.isLinkExcepted(new URI("http://localhost/except/page"));

    assertTrue(result);
  }

  @Test
  void isLinkExcepted_whenNoExceptedToadlet_returnsFalse() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();

    boolean result = server.isLinkExcepted(new URI("http://localhost/nowhere"));

    assertFalse(result);
  }

  @Test
  void addFormChild_whenCoreProvidesPassword_includesHiddenInput() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    NodeClientCore core = mock(NodeClientCore.class);
    when(core.getFormPassword()).thenReturn("secret-token");
    server.setCore(core);

    HTMLNode parent = new HTMLNode("div");

    HTMLNode form = server.addFormChild(parent, "/target", "form-id");

    assertEquals("/target", form.getAttribute("action"));
    HTMLNode inputNode =
        form.getChildren().stream()
            .filter(child -> "input".equals(child.getFirstTag()))
            .findFirst()
            .orElseThrow();
    assertEquals("hidden", inputNode.getAttribute("type"));
    assertEquals("formPassword", inputNode.getAttribute("name"));
    assertEquals("secret-token", inputNode.getAttribute("value"));
  }

  @Test
  void getURL_whenHostProvided_buildsHttpUrlWithPort() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();

    String url = server.getURL("example.com");

    assertEquals("http://example.com:" + SimpleToadletServer.DEFAULT_FPROXY_PORT + "/", url);
  }

  @Test
  void allowPosts_whenUsingArrayBucketFactory_returnsFalse() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();
    server.setBucketFactory(new ArrayBucketFactory());

    assertFalse(server.allowPosts());
  }

  @Test
  void isAllowedFullAccess_whenAddressMatchesAllowList_returnsTrue() throws Exception {
    SimpleToadletServer server = newServerWithDefaults();

    assertTrue(server.isAllowedFullAccess(InetAddress.getByName("127.0.0.1")));
    assertFalse(server.isAllowedFullAccess(InetAddress.getByName("8.8.8.8")));
  }

  @SuppressWarnings({"resource", "MustBeClosedChecker"})
  private SimpleToadletServer newServerWithDefaults() throws Exception {
    Config rootConfig = new Config();
    SubConfig config = rootConfig.createSubConfig("fproxy");
    Node node = mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    BucketFactory bucketFactory = mock(BucketFactory.class);
    PriorityAwareExecutor executor = mock(PriorityAwareExecutor.class);

    try (MockedStatic<NetworkInterface> netMock = mockStatic(NetworkInterface.class);
        MockedStatic<SSLNetworkInterface> sslMock = mockStatic(SSLNetworkInterface.class)) {
      NetworkInterface iface = mock(NetworkInterface.class);
      netMock
          .when(() -> NetworkInterface.create(anyInt(), any(), any(), any(), anyBoolean()))
          .thenReturn(iface);
      sslMock
          .when(() -> SSLNetworkInterface.create(anyInt(), any(), any(), any(), anyBoolean()))
          .thenReturn(iface);
      return new SimpleToadletServer(config, bucketFactory, executor, node);
    }
  }

  private static class DummyToadlet extends Toadlet {
    private final String path;

    DummyToadlet(String path) {
      super(null);
      this.path = path;
    }

    @Override
    public void handleMethodGET(
        URI uri, network.crypta.support.api.HTTPRequest request, ToadletContext ctx) {
      // Intentionally no-op: tests only need a concrete Toadlet for registration/lookup behavior.
    }

    @Override
    public String path() {
      return path;
    }
  }

  private static final class ExceptedToadlet extends DummyToadlet
      implements LinkFilterExceptedToadlet {

    ExceptedToadlet(String path) {
      super(path);
    }

    @Override
    public boolean isLinkExcepted(URI link) {
      return link.getPath().startsWith(path());
    }
  }
}
