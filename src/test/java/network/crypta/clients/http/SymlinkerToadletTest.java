package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SymlinkerToadletTest {

  @Mock private HighLevelSimpleClient client;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private PersistentConfig persistentConfig;
  @Mock private SubConfig subConfig;
  @Mock private NodeClientCore nodeClientCore;
  @Mock private ToadletContext ctx;
  @Mock private HTTPRequest request;

  @BeforeEach
  void setUp() {
    when(node.getConfig()).thenReturn(persistentConfig);
    when(persistentConfig.createSubConfig("toadletsymlinker")).thenReturn(subConfig);

    doNothing().when(subConfig).finishedInitialization();
  }

  @Test
  void handleMethodGET_whenAliasMatches_redirectsWithOriginalQueryAndFragment() throws Exception {
    SymlinkerToadlet toadlet = createToadletWithConfigLinks("/cfg/#/target/");

    URI incoming = new URI("http://localhost/cfg/path?foo=bar#frag");

    RedirectException redirect =
        assertThrows(
            RedirectException.class, () -> toadlet.handleMethodGET(incoming, request, ctx));

    assertEquals("/target/path", redirect.getTarget().getPath());
    assertEquals("foo=bar", redirect.getTarget().getQuery());
    assertEquals("frag", redirect.getTarget().getFragment());
  }

  @Test
  void addLink_whenStoreTrue_persistsAndRedirects() {
    when(subConfig.getStringArr("symlinks")).thenReturn(new String[0]);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(nodeClientCore);
    SymlinkerToadlet toadlet = new SymlinkerToadlet(client, node);

    boolean added = toadlet.addLink("/alias/", "/dest/", true);

    assertFalse(added);
    verify(nodeClientCore, times(1)).storeConfig();

    RedirectException redirect =
        assertThrows(
            RedirectException.class,
            () -> toadlet.handleMethodGET(new URI("http://x/alias/file"), request, ctx));

    assertEquals("/dest/file", redirect.getTarget().getPath());
  }

  @Test
  void removeLink_whenExistingAlias_returnsTrueAndPreventsRedirect() throws Exception {
    when(subConfig.getStringArr("symlinks")).thenReturn(new String[0]);
    network.crypta.node.subsystem.NodeServicesSubsystem services =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(nodeClientCore);
    SymlinkerToadlet toadlet = new SymlinkerToadlet(client, node);

    toadlet.addLink("/remove/", "/kept/", false);
    reset(nodeClientCore);

    boolean removed = toadlet.removeLink("/remove/", true);

    assertTrue(removed);
    verify(nodeClientCore, times(1)).storeConfig();

    assertDoesNotThrow(
        () -> toadlet.handleMethodGET(new URI("http://localhost/remove/x"), request, ctx));

    verify(ctx)
        .sendReplyHeaders(
            org.mockito.ArgumentMatchers.eq(404),
            org.mockito.ArgumentMatchers.eq("Not found"),
            isNull(),
            org.mockito.ArgumentMatchers.eq("text/plain; charset=utf-8"),
            anyLong(),
            org.mockito.ArgumentMatchers.eq(true));
    verify(ctx).writeData(any(byte[].class), anyInt(), anyInt());
  }

  @Test
  void handleMethodGET_whenNoMatchingAlias_sends404Response() throws Exception {
    when(subConfig.getStringArr("symlinks")).thenReturn(new String[0]);
    SymlinkerToadlet toadlet = new SymlinkerToadlet(client, node);

    assertDoesNotThrow(
        () -> toadlet.handleMethodGET(new URI("http://localhost/unknown"), request, ctx));

    verify(ctx)
        .sendReplyHeaders(
            org.mockito.ArgumentMatchers.eq(404),
            org.mockito.ArgumentMatchers.eq("Not found"),
            isNull(),
            org.mockito.ArgumentMatchers.eq("text/plain; charset=utf-8"),
            anyLong(),
            org.mockito.ArgumentMatchers.eq(true));
    verify(ctx).writeData(any(byte[].class), anyInt(), anyInt());
  }

  @Test
  void handleMethodGET_whenTargetContainsSpaces_redirectsWithEncodedPath() throws Exception {
    when(subConfig.getStringArr("symlinks")).thenReturn(new String[0]);
    SymlinkerToadlet toadlet = new SymlinkerToadlet(client, node);
    toadlet.addLink("/bad/", "/target with space/", false);

    RedirectException redirect =
        assertThrows(
            RedirectException.class,
            () -> toadlet.handleMethodGET(new URI("http://localhost/bad/here"), request, ctx));

    assertEquals("/target with space/here", redirect.getTarget().getPath());
    assertEquals("/target%20with%20space/here", redirect.getTarget().getRawPath());
  }

  private SymlinkerToadlet createToadletWithConfigLinks(String... links) {
    when(subConfig.getStringArr("symlinks")).thenReturn(links);
    return new SymlinkerToadlet(client, node);
  }
}
