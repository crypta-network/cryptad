package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.Arrays;
import java.util.Comparator;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.l10n.BaseL10n;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.OpennetPeerNodeStatus;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNodeStatus;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class OpennetConnectionsToadletTest {

  @Mock private Node node;
  @Mock private NodeClientCore core;
  @Mock private HighLevelSimpleClient client;
  @Mock private PeerManager peerManager;
  @Mock private SimpleFieldSet noderef;

  private OpennetConnectionsToadlet toadlet;

  @BeforeEach
  void setUp() {
    toadlet = new TestOpennetConnectionsToadlet(node, core, client);
  }

  @Test
  void hasNameAndPrivateNoteColumns_disabledForOpennet() {
    assertFalse(toadlet.hasNameColumn());
    assertFalse(toadlet.hasPrivateNoteColumn());
  }

  @Test
  void getNoderef_delegatesToNodeExport() {
    when(node.exportOpennetPublicFieldSet()).thenReturn(noderef);

    SimpleFieldSet result = toadlet.getNoderef();

    assertSame(noderef, result);
    verify(node).exportOpennetPublicFieldSet();
  }

  @Test
  void getPeerNodeStatuses_fetchesFromPeerManager() {
    OpennetPeerNodeStatus[] statuses =
        new OpennetPeerNodeStatus[] {mock(OpennetPeerNodeStatus.class)};
    when(node.getPeers()).thenReturn(peerManager);
    when(peerManager.getOpennetPeerNodeStatuses(false)).thenReturn(statuses);

    PeerNodeStatus[] result = toadlet.getPeerNodeStatuses(false);

    assertSame(statuses, result);
    verify(node, atLeastOnce()).getPeers();
    verify(peerManager).getOpennetPeerNodeStatuses(false);
  }

  @Test
  void isEnabled_returnsNodeFlag() {
    when(node.isOpennetEnabled()).thenReturn(true).thenReturn(false);

    assertTrue(toadlet.isEnabled(null));
    assertFalse(toadlet.isEnabled(null));
  }

  @Test
  void shouldDrawNoderefBox_matchesAdvancedMode() {
    assertTrue(toadlet.shouldDrawNoderefBox(true));
    assertFalse(toadlet.shouldDrawNoderefBox(false));
  }

  @Test
  void peerActionsAndAcceptRefPosts_flagsAreConstant() {
    assertFalse(toadlet.showPeerActionsBox());
    assertTrue(toadlet.acceptRefPosts());
    assertEquals("/opennet/", toadlet.defaultRedirectLocation());
    assertTrue(toadlet.isOpennet());
    assertEquals("/strangers/", toadlet.path());
  }

  @Test
  void comparator_successTimeOrdersByLastSuccess() {
    Comparator<PeerNodeStatus> comparator = toadlet.comparator("successTime", false);
    OpennetConnectionsToadlet.OpennetComparator opennetComparator =
        (OpennetConnectionsToadlet.OpennetComparator) comparator;

    OpennetPeerNodeStatus newer = statusWithLastSuccess(2000L);
    OpennetPeerNodeStatus older = statusWithLastSuccess(1000L);

    int result = opennetComparator.customCompare(newer, older);

    assertEquals(-1, result, "Newer success should sort before older by default");
  }

  @Test
  void comparator_successTimeHonoursReversedFlag() {
    OpennetConnectionsToadlet.OpennetComparator comparator =
        (OpennetConnectionsToadlet.OpennetComparator) toadlet.comparator("successTime", true);

    OpennetPeerNodeStatus newer = statusWithLastSuccess(2000L);
    OpennetPeerNodeStatus older = statusWithLastSuccess(1000L);

    int result = comparator.customCompare(newer, older);

    assertEquals(1, result, "Reversed comparator should flip ordering");
  }

  @Test
  void endColumnHeaders_returnsNullWhenNotAdvanced() {
    assertEquals(0, toadlet.endColumnHeaders(false).length);
  }

  @Test
  void endColumnHeaders_rendersNeverWhenNoSuccess() {
    OpennetPeerNodeStatus status = statusWithLastSuccess(-1);
    HTMLNode row = new HTMLNode("tr");

    OpennetConnectionsToadlet.SimpleColumn[] columns = toadlet.endColumnHeaders(true);
    assertNotNull(columns);
    columns[0].drawColumn(row, status);

    HTMLNode td = row.getChildren().getFirst();
    assertEquals("td", td.getName());
    assertEquals("peer-last-success", td.getAttribute("class"));
    assertEquals("NEVER", td.getChildren().getFirst().getContent());
  }

  @Test
  void endColumnHeaders_rendersFormattedDurationWhenSuccessKnown() {
    long now = System.currentTimeMillis();
    OpennetPeerNodeStatus status = statusWithLastSuccess(now - 5000);
    HTMLNode row = new HTMLNode("tr");

    OpennetConnectionsToadlet.SimpleColumn[] columns = toadlet.endColumnHeaders(true);
    columns[0].drawColumn(row, status);

    String rendered = row.getChildren().getFirst().getChildren().getFirst().getContent();
    assertNotNull(rendered);
    assertNotEquals("NEVER", rendered);
    assertFalse(rendered.isEmpty());
  }

  @Test
  void getPageTitle_usesLocalizationKey() {
    try (MockedStatic<NodeL10n> mockedStatic = mockStatic(NodeL10n.class)) {
      BaseL10n l10n = mock(BaseL10n.class);
      mockedStatic.when(NodeL10n::getBase).thenReturn(l10n);
      when(l10n.getString(
              eq("OpennetConnectionsToadlet.fullTitle"),
              any(String[].class),
              argThat(values -> Arrays.equals(values, new String[] {"3"}))))
          .thenReturn("localized");

      String title = toadlet.getPageTitle("3");

      assertEquals("localized", title);
      mockedStatic.verify(NodeL10n::getBase);
    }
  }

  @Test
  void getPeerListTitle_usesLocalizationKey() {
    try (MockedStatic<NodeL10n> mockedStatic = mockStatic(NodeL10n.class)) {
      BaseL10n l10n = mock(BaseL10n.class);
      mockedStatic.when(NodeL10n::getBase).thenReturn(l10n);
      when(l10n.getString("OpennetConnectionsToadlet.peersListTitle")).thenReturn("peers");

      assertEquals("peers", toadlet.getPeerListTitle());
      mockedStatic.verify(NodeL10n::getBase);
    }
  }

  private OpennetPeerNodeStatus statusWithLastSuccess(long timestamp) {
    OpennetPeerNodeStatus status = mock(OpennetPeerNodeStatus.class);
    setTimeLastSuccess(status, timestamp);
    return status;
  }

  private void setTimeLastSuccess(OpennetPeerNodeStatus status, long timestamp) {
    try {
      Field field = OpennetPeerNodeStatus.class.getField("timeLastSuccess");
      field.setAccessible(true);
      field.setLong(status, timestamp);
    } catch (ReflectiveOperationException e) {
      throw new AssertionError("Unable to set timeLastSuccess on mock", e);
    }
  }

  /** Minimal concrete subclass to expose the protected constructor for testing. */
  private static final class TestOpennetConnectionsToadlet extends OpennetConnectionsToadlet {
    TestOpennetConnectionsToadlet(Node n, NodeClientCore core, HighLevelSimpleClient client) {
      super(n, core, client);
    }

    @Override
    public void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx) {
      // Avoid invoking heavy superclass logic during unit tests.
    }

    @Override
    public void handleMethodPOST(URI uri, HTTPRequest request, ToadletContext ctx) {
      // Avoid invoking heavy superclass logic during unit tests.
    }
  }
}
