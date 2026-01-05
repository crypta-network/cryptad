package network.crypta.clients.http;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
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

import java.lang.reflect.Field;
import java.net.URI;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.clients.http.bookmark.BookmarkCategory;
import network.crypta.clients.http.bookmark.BookmarkItem;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.keys.FreenetURI;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
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

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BookmarkEditorToadletTest {

  private static final URI DUMMY_URI = URI.create("http://localhost/bookmarkEditor/");

  @Mock private HighLevelSimpleClient client;
  @Mock private NodeClientCore core;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private BookmarkManager bookmarkManager;
  @Mock private PageMaker pageMaker;
  @Mock private ToadletContext context;

  private BookmarkEditorToadlet toadlet;

  @BeforeEach
  void setUp() throws Exception {
    toadlet = new BookmarkEditorToadlet(client, core);

    when(core.getNode()).thenReturn(node);
    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        org.mockito.Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.darknetConnections()).thenReturn(new network.crypta.node.DarknetPeerNode[0]);
    when(node.isFProxyJavascriptEnabled()).thenReturn(false);

    when(context.getPageMaker()).thenReturn(pageMaker);
    when(context.getBookmarkManager()).thenReturn(bookmarkManager);
    when(context.checkFullAccess(any(Toadlet.class))).thenReturn(true);
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
        .thenAnswer(invocation -> createPageNode());
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
