package network.crypta.clients.http;

import java.lang.reflect.Field;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import network.crypta.clients.http.bookmark.Bookmark;
import network.crypta.clients.http.bookmark.BookmarkCategory;
import network.crypta.clients.http.bookmark.BookmarkItem;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.keys.FreenetURI;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.spi.DarknetConnectionPeerSnapshot;
import network.crypta.runtime.spi.DarknetConnectionsPort;
import network.crypta.runtime.spi.DarknetMessagingPort;
import network.crypta.support.HTMLNode;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BookmarkEditorToadletTest {

  private static final URI DUMMY_URI = URI.create("http://localhost/bookmarkEditor/");

  @Mock private BrowseContentClient client;
  @Mock private DarknetConnectionsPort darknetConnectionsPort;
  @Mock private DarknetMessagingPort darknetMessagingPort;

  @Mock private BookmarkManager bookmarkManager;
  @Mock private PageMaker pageMaker;
  @Mock private ToadletContext context;
  @Mock private ToadletContainer container;
  @Mock private UserAlertManager alertManager;

  private BookmarkEditorToadlet toadlet;

  @BeforeEach
  void setUp() throws Exception {
    toadlet =
        new BookmarkEditorToadlet(
            client,
            new BookmarkEditorToadletRuntimePorts(darknetConnectionsPort, darknetMessagingPort));

    when(darknetConnectionsPort.listPeers()).thenReturn(List.of());

    when(context.getPageMaker()).thenReturn(pageMaker);
    when(context.getBookmarkManager()).thenReturn(bookmarkManager);
    when(context.getContainer()).thenReturn(container);
    when(context.getAlertManager()).thenReturn(alertManager);
    when(context.checkFullAccess(any(Toadlet.class))).thenReturn(true);
    when(container.isFProxyJavascriptEnabled()).thenReturn(false);
    when(context.addFormChild(any(HTMLNode.class), anyString(), anyString()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              HTMLNode form = new HTMLNode("form");
              parent.addChild(form);
              return form;
            });

    doNothing()
        .when(context)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
    doNothing()
        .when(context)
        .sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong(), anyBoolean());
    doNothing().when(context).writeData(any(byte[].class), anyInt(), anyInt());

    when(pageMaker.getPageNode(anyString(), any(ToadletContext.class)))
        .thenAnswer(_ -> createPageNode());
    when(pageMaker.getInfobox(
            anyString(), anyString(), any(HTMLNode.class), anyString(), anyBoolean()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(2);
              HTMLNode infobox = new HTMLNode("div");
              parent.addChild(infobox);
              return infobox;
            });
  }

  @Test
  void path_whenCalled_returnsBookmarkEditorPath() {
    assertEquals("/bookmarkEditor/", toadlet.path());
  }

  @Test
  void handleMethodPOST_whenAddDefaultBookmarks_redirectsAndReloads() throws Exception {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.isPartSet("AddDefaultBookmarks")).thenReturn(true);

    toadlet.handleMethodPOST(DUMMY_URI, request, context);

    verify(bookmarkManager).reAddDefaultBookmarks();
    verify(context).sendReplyHeaders(anyInt(), anyString(), any(), anyString(), anyLong());
  }

  @Test
  void handleMethodPOST_whenNameInvalid_addsErrorWithoutPersisting() throws Exception {
    String bookmarkPath = "/parent/item";
    BookmarkItem item = mock(BookmarkItem.class);
    HTTPRequest request = mock(HTTPRequest.class);

    when(request.isPartSet("AddDefaultBookmarks")).thenReturn(false);
    when(request.getPartAsStringFailsafe("bookmark", 5000)).thenReturn(bookmarkPath);
    when(request.getPartAsStringFailsafe("action", 20)).thenReturn("edit");
    when(request.isPartSet("confirmdelete")).thenReturn(false);
    when(request.isPartSet("cancelCut")).thenReturn(false);
    when(request.isPartSet("name")).thenReturn(true);
    when(request.getPartAsStringFailsafe("name", 500)).thenReturn("bad/name");

    when(bookmarkManager.getItemByPath(bookmarkPath)).thenReturn(item);
    when(bookmarkManager.parentPath(bookmarkPath)).thenReturn("/parent/");
    when(bookmarkManager.getBookmarkByPath("/parent/bad/name")).thenReturn(null);

    toadlet.handleMethodPOST(DUMMY_URI, request, context);

    verify(bookmarkManager, never()).renameBookmark(anyString(), anyString());
    verify(bookmarkManager, never()).storeBookmarks();
  }

  @Test
  void handleMethodPOST_whenEditBookmark_updatesAndStoresChanges() throws Exception {
    String bookmarkPath = "/parent/item";
    BookmarkItem item = mock(BookmarkItem.class);
    HTTPRequest request = mock(HTTPRequest.class);

    when(request.isPartSet("AddDefaultBookmarks")).thenReturn(false);
    when(request.getPartAsStringFailsafe("bookmark", 5000)).thenReturn(bookmarkPath);
    when(request.getPartAsStringFailsafe("action", 20)).thenReturn("edit");
    when(request.isPartSet("confirmdelete")).thenReturn(false);
    when(request.isPartSet("cancelCut")).thenReturn(false);
    when(request.isPartSet("name")).thenReturn(true);
    when(request.getPartAsStringFailsafe("name", 500)).thenReturn("newName");
    when(request.isPartSet("hasAnActivelink")).thenReturn(true);
    when(request.getPartAsStringFailsafe("key", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("KSK@newkey");
    when(request.getPartAsStringFailsafe("descB", QueueToadlet.MAX_KEY_LENGTH)).thenReturn("desc");
    when(request.getPartAsStringFailsafe("explain", 1024)).thenReturn("expl");
    when(request.getPartAsStringFailsafe("publicDescB", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("publicDesc");

    when(bookmarkManager.getItemByPath(bookmarkPath)).thenReturn(item);
    when(bookmarkManager.parentPath(bookmarkPath)).thenReturn("/parent/");
    when(bookmarkManager.getBookmarkByPath("/parent/newName")).thenReturn(null);

    toadlet.handleMethodPOST(DUMMY_URI, request, context);

    verify(bookmarkManager).renameBookmark(bookmarkPath, "newName");
    ArgumentCaptor<FreenetURI> uriCaptor = ArgumentCaptor.forClass(FreenetURI.class);
    verify(item).update(uriCaptor.capture(), eq(true), eq("desc"), eq("expl"));
    assertEquals("KSK@newkey", uriCaptor.getValue().toString());
    verify(bookmarkManager).storeBookmarks();
  }

  @Test
  void handleMethodPOST_whenShareActionSelected_delegatesBookmarkSharesViaRuntimePorts()
      throws Exception {
    String bookmarkPath = "/parent/item";
    BookmarkItem item = mock(BookmarkItem.class);
    HTTPRequest request = mock(HTTPRequest.class);
    DarknetConnectionPeerSnapshot selectedPeer =
        new DarknetConnectionPeerSnapshot(101, "peer-1", "Alice", "", false);
    DarknetConnectionPeerSnapshot unselectedPeer =
        new DarknetConnectionPeerSnapshot(202, "peer-2", "Bob", "", false);

    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(selectedPeer, unselectedPeer));
    when(request.isPartSet("AddDefaultBookmarks")).thenReturn(false);
    when(request.getPartAsStringFailsafe("bookmark", 5000)).thenReturn(bookmarkPath);
    when(request.getPartAsStringFailsafe("action", 20)).thenReturn("share");
    when(request.isPartSet("confirmdelete")).thenReturn(false);
    when(request.isPartSet("cancelCut")).thenReturn(false);
    when(request.isPartSet("node_101")).thenReturn(true);
    when(request.isPartSet("node_202")).thenReturn(false);
    when(request.getPartAsStringFailsafe("publicDescB", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("publicDesc");
    when(bookmarkManager.getItemByPath(bookmarkPath)).thenReturn(item);
    when(item.getURI()).thenReturn(new FreenetURI("KSK@shared"));
    when(item.getName()).thenReturn("shared-name");
    when(item.hasAnActivelink()).thenReturn(true);

    toadlet.handleMethodPOST(DUMMY_URI, request, context);

    verify(darknetMessagingPort)
        .shareBookmark("peer-1", "KSK@shared", "shared-name", "publicDesc", true);
    verify(darknetMessagingPort, never())
        .shareBookmark(eq("peer-2"), anyString(), anyString(), anyString(), anyBoolean());
  }

  @Test
  void handleMethodPOST_whenAddingBookmarkItem_usesContextAlertManagerForCreatedBookmark()
      throws Exception {
    HTTPRequest request = mock(HTTPRequest.class);
    BookmarkCategory targetCategory = mock(BookmarkCategory.class);

    when(request.isPartSet("AddDefaultBookmarks")).thenReturn(false);
    when(request.getPartAsStringFailsafe("bookmark", 5000)).thenReturn("/target/");
    when(request.getPartAsStringFailsafe("action", 20)).thenReturn("addItem");
    when(request.isPartSet("confirmdelete")).thenReturn(false);
    when(request.isPartSet("cancelCut")).thenReturn(false);
    when(request.isPartSet("name")).thenReturn(true);
    when(request.getPartAsStringFailsafe("name", 500)).thenReturn("newItem");
    when(request.getPartAsStringFailsafe("key", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("KSK@newkey");
    when(request.getPartAsStringFailsafe("descB", QueueToadlet.MAX_KEY_LENGTH)).thenReturn("desc");
    when(request.getPartAsStringFailsafe("explain", 1024)).thenReturn("expl");
    when(request.getPartAsStringFailsafe("publicDescB", QueueToadlet.MAX_KEY_LENGTH))
        .thenReturn("publicDesc");
    when(bookmarkManager.getCategoryByPath("/target/")).thenReturn(targetCategory);
    when(bookmarkManager.parentPath("/target/")).thenReturn("/target/");
    when(bookmarkManager.getBookmarkByPath("/target/newItem")).thenReturn(null);

    toadlet.handleMethodPOST(DUMMY_URI, request, context);

    ArgumentCaptor<Bookmark> bookmarkCaptor = ArgumentCaptor.forClass(Bookmark.class);
    verify(bookmarkManager).addBookmark(eq("/target/"), bookmarkCaptor.capture());
    BookmarkItem bookmarkItem = assertInstanceOf(BookmarkItem.class, bookmarkCaptor.getValue());
    Field alertsField = BookmarkItem.class.getDeclaredField("alerts");
    alertsField.setAccessible(true);
    assertSame(alertManager, alertsField.get(bookmarkItem));
  }

  @Test
  void handleMethodGET_whenPasteAction_movesBookmarkAndClearsCutBuffer() throws Exception {
    setCutedPathToSource(toadlet);

    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getParam("action")).thenReturn("paste");
    when(request.getParam("bookmark")).thenReturn("/target/");

    BookmarkCategory targetCategory = mock(BookmarkCategory.class);
    when(bookmarkManager.getCategoryByPath("/target/")).thenReturn(targetCategory);

    toadlet.handleMethodGET(DUMMY_URI, request, context);

    verify(bookmarkManager).moveBookmark("/source/", "/target/");
    verify(bookmarkManager).storeBookmarks();
    assertNull(getCutedPath(toadlet));
  }

  @Test
  void handleMethodGET_whenBookmarkMissing_showsErrorAndReturns() throws Exception {
    HTTPRequest request = mock(HTTPRequest.class);
    when(request.getParam("action")).thenReturn("edit");
    when(request.getParam("bookmark")).thenReturn("/missing");

    when(bookmarkManager.getItemByPath("/missing")).thenReturn(null);

    toadlet.handleMethodGET(DUMMY_URI, request, context);

    verify(bookmarkManager).getItemByPath("/missing");
    verify(bookmarkManager, never()).moveBookmark(anyString(), anyString());
  }

  @Test
  void handleMethodGET_whenShareActionAndJavascriptEnabled_rendersDetachedFriendCheckboxes()
      throws Exception {
    BookmarkItem item = mock(BookmarkItem.class);
    HTTPRequest request = mock(HTTPRequest.class);
    DarknetConnectionPeerSnapshot peer =
        new DarknetConnectionPeerSnapshot(101, "peer-1", "Alice", "", false);
    when(container.isFProxyJavascriptEnabled()).thenReturn(true);
    when(darknetConnectionsPort.listPeers()).thenReturn(List.of(peer));
    when(request.getParam("action")).thenReturn("share");
    when(request.getParam("bookmark")).thenReturn("/item");
    when(bookmarkManager.getItemByPath("/item")).thenReturn(item);
    when(item.getVisibleName()).thenReturn("Item");
    when(item.getKey()).thenReturn("KSK@item");
    when(item.hasAnActivelink()).thenReturn(true);
    when(item.getDescription()).thenReturn("description");

    toadlet.handleMethodGET(DUMMY_URI, request, context);

    ArgumentCaptor<byte[]> bodyCaptor = ArgumentCaptor.forClass(byte[].class);
    ArgumentCaptor<Integer> offsetCaptor = ArgumentCaptor.forClass(Integer.class);
    ArgumentCaptor<Integer> lengthCaptor = ArgumentCaptor.forClass(Integer.class);
    verify(context).writeData(bodyCaptor.capture(), offsetCaptor.capture(), lengthCaptor.capture());
    String html =
        new String(
            bodyCaptor.getValue(),
            offsetCaptor.getValue(),
            lengthCaptor.getValue(),
            StandardCharsets.UTF_8);
    assertTrue(html.contains("name=\"node_101\""));
    assertTrue(html.contains("Alice"));
    assertTrue(html.contains("/static/js/checkall.js"));
  }

  private PageNode createPageNode() {
    HTMLNode outer = new HTMLNode("html");
    HTMLNode head = outer.addChild("head");
    HTMLNode body = outer.addChild("body");
    HTMLNode content = body.addChild("div");
    return new PageNode(outer, head, content);
  }

  private void setCutedPathToSource(BookmarkEditorToadlet target) throws Exception {
    Field field = BookmarkEditorToadlet.class.getDeclaredField("cutedPath");
    field.setAccessible(true);
    field.set(target, "/source/");
  }

  private String getCutedPath(BookmarkEditorToadlet target) throws Exception {
    Field field = BookmarkEditorToadlet.class.getDeclaredField("cutedPath");
    field.setAccessible(true);
    return (String) field.get(target);
  }
}
