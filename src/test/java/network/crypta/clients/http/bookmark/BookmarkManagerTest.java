package network.crypta.clients.http.bookmark;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import network.crypta.client.async.USKManager;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.CleanupMode;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings({"java:S100", "java:S3011", "java:S1075"})
@ExtendWith(MockitoExtension.class)
class BookmarkManagerTest {

  private static final AtomicInteger DIR_COUNTER = new AtomicInteger();
  private static final Object CATEGORY_CLEAR_LOCK = new Object();
  private static final String CAT_PATH = "/cat/";
  private static final String SITE_PATH = "/site";

  @TempDir(cleanup = CleanupMode.NEVER)
  static Path rootTempDir;

  private Path testDir;

  @BeforeEach
  void setUp() throws IOException {
    clearCategoryTree(BookmarkManager.MAIN_CATEGORY);
    clearCategoryTree(BookmarkManager.DEFAULT_CATEGORY);
    testDir = Files.createDirectories(rootTempDir.resolve("bm-" + DIR_COUNTER.getAndIncrement()));
  }

  @ParameterizedTest
  @CsvSource({"/,/", "/a,/", "/a/,/", "/a/b,/a/", "/a/b/,/a/", "/a/b/c/,/a/b/"})
  void parentPath_whenGivenPath_expectParent(String input, String expected) {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);

    String parent = manager.parentPath(input);

    assertEquals(expected, parent);
  }

  @Test
  void getCategoryByPath_whenPathIsCategory_expectCategoryInstance() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    BookmarkCategory category = new BookmarkCategory("cat");
    manager.addBookmark("/", category);

    BookmarkCategory byPath = manager.getCategoryByPath(CAT_PATH);

    assertSame(category, byPath);
  }

  @Test
  void getCategoryByPath_whenPathIsItem_expectNull() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    BookmarkItem item = mockBookmarkItem("item", "KSK");
    manager.addBookmark("/", item);

    BookmarkCategory byPath = manager.getCategoryByPath("/item");

    assertNull(byPath);
  }

  @Test
  void getItemByPath_whenPathIsItem_expectItemInstance() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    BookmarkItem item = mockBookmarkItem("item", "KSK");
    manager.addBookmark("/", item);

    BookmarkItem byPath = manager.getItemByPath("/item");

    assertSame(item, byPath);
  }

  @Test
  void getItemByPath_whenPathIsCategory_expectNull() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    BookmarkCategory category = new BookmarkCategory("cat");
    manager.addBookmark("/", category);

    BookmarkItem byPath = manager.getItemByPath(CAT_PATH);

    assertNull(byPath);
  }

  @Test
  void addBookmark_whenAddingUskItem_expectSubscribeCalled() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir, uskManager);

    USK usk = mock(USK.class);
    BookmarkItem item = mockBookmarkItem("site", "USK");
    when(item.getUSK()).thenReturn(usk);

    manager.addBookmark("/", item);

    assertSame(item, manager.getItemByPath(SITE_PATH));
    verify(uskManager).subscribe(eq(usk), any(), eq(true), eq(manager));
  }

  @Test
  void renameBookmark_whenRenamingCategory_expectPathsUpdatedForSubtree() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    BookmarkCategory category = new BookmarkCategory("cat");
    manager.addBookmark("/", category);
    BookmarkItem item = mockBookmarkItem("item", "KSK");
    manager.addBookmark(CAT_PATH, item);

    manager.renameBookmark(CAT_PATH, "newcat");

    assertNull(manager.getBookmarkByPath(CAT_PATH));
    assertSame(category, manager.getCategoryByPath("/newcat/"));
    assertSame(item, manager.getItemByPath("/newcat/item"));
  }

  @Test
  void moveBookmark_whenMovingItem_expectPathAndParentUpdated() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    BookmarkCategory from = new BookmarkCategory("from");
    BookmarkCategory to = new BookmarkCategory("to");
    manager.addBookmark("/", from);
    manager.addBookmark("/", to);
    BookmarkItem item = mockBookmarkItem("item", "KSK");
    manager.addBookmark("/from/", item);

    manager.moveBookmark("/from/item", "/to/");

    assertNull(manager.getBookmarkByPath("/from/item"));
    assertSame(item, manager.getItemByPath("/to/item"));
    assertTrue(from.getItems().isEmpty());
    assertEquals(List.of(item), to.getItems());
  }

  @Test
  void removeBookmark_whenPathUnknown_expectNoop() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);

    manager.removeBookmark("/missing");

    assertSame(BookmarkManager.MAIN_CATEGORY, manager.getCategoryByPath("/"));
  }

  @Test
  void removeBookmark_whenRemovingUskItem_expectUnsubscribeWhenNoOtherWantsUsk() throws Exception {
    USKManager uskManager = mock(USKManager.class);
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir, uskManager);

    USK usk = mock(USK.class);
    BookmarkItem item = mockBookmarkItem("site", "USK");
    when(item.getUSK()).thenReturn(usk);
    manager.addBookmark("/", item);

    manager.removeBookmark(SITE_PATH);

    assertNull(manager.getBookmarkByPath(SITE_PATH));
    verify(uskManager).unsubscribe(eq(usk), any());
  }

  @Test
  void moveBookmarkDown_whenStoreFalse_expectReorderedWithoutSaving() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    BookmarkItem a = mockBookmarkItem("a", "KSK");
    BookmarkItem b = mockBookmarkItem("b", "KSK");
    BookmarkItem c = mockBookmarkItem("c", "KSK");
    manager.addBookmark("/", a);
    manager.addBookmark("/", b);
    manager.addBookmark("/", c);

    manager.moveBookmarkDown("/a", false);

    assertEquals(List.of(b, a, c), BookmarkManager.MAIN_CATEGORY.getItems());
  }

  @Test
  void moveBookmarkUp_whenStoreFalse_expectReorderedWithoutSaving() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    BookmarkItem a = mockBookmarkItem("a", "KSK");
    BookmarkItem b = mockBookmarkItem("b", "KSK");
    BookmarkItem c = mockBookmarkItem("c", "KSK");
    manager.addBookmark("/", a);
    manager.addBookmark("/", b);
    manager.addBookmark("/", c);

    manager.moveBookmarkUp("/c", false);

    assertEquals(List.of(a, c, b), BookmarkManager.MAIN_CATEGORY.getItems());
  }

  @Test
  void getBookmarkURIs_whenItemsPresent_expectUrisInTraversalOrder() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    FreenetURI uri1 = mock(FreenetURI.class);
    FreenetURI uri2 = mock(FreenetURI.class);
    BookmarkItem item1 = mockKskBookmarkItemWithUri("one", uri1);
    BookmarkItem item2 = mockKskBookmarkItemWithUri("two", uri2);
    manager.addBookmark("/", item1);
    manager.addBookmark("/", item2);

    FreenetURI[] uris = manager.getBookmarkURIs();

    assertArrayEquals(new FreenetURI[] {uri1, uri2}, uris);
  }

  @Test
  void storeBookmarksLazy_whenCalledTwiceBeforeJobRuns_expectQueuedOnce() {
    Ticker ticker = mock(Ticker.class);
    BookmarkManager manager = spy(newManagerWithEmptyBookmarksFile(testDir, ticker));
    doNothing().when(manager).storeBookmarks();
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);

    manager.storeBookmarksLazy();
    manager.storeBookmarksLazy();

    verify(ticker, times(1)).queueTimedJob(runnableCaptor.capture(), eq(5L * 60L * 1000L));
    verify(manager, never()).storeBookmarks();

    runnableCaptor.getValue().run();

    verify(manager, times(1)).storeBookmarks();
  }

  @Test
  void storeBookmarksLazy_whenJobCompleted_expectSubsequentCallQueuesAgain() {
    Ticker ticker = mock(Ticker.class);
    BookmarkManager manager = spy(newManagerWithEmptyBookmarksFile(testDir, ticker));
    doNothing().when(manager).storeBookmarks();
    ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);

    manager.storeBookmarksLazy();
    verify(ticker).queueTimedJob(runnableCaptor.capture(), anyLong());

    runnableCaptor.getValue().run();

    manager.storeBookmarksLazy();

    verify(ticker, times(2)).queueTimedJob(any(Runnable.class), anyLong());
  }

  @Test
  void toSimpleFieldSet_whenEmpty_expectVersionAndZeroCounts() throws Exception {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);

    SimpleFieldSet sfs = manager.toSimpleFieldSet();

    assertEquals(1, sfs.getInt("Version"));
    assertEquals(0, sfs.getInt(BookmarkItem.BOOKMARK_PREFIX));
    assertEquals(0, sfs.getInt(BookmarkCategory.SFS_KEY));
  }

  @Test
  void toSimpleFieldSet_whenCategoryAndItemPresent_expectCountsMatch() throws Exception {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    BookmarkCategory category = new BookmarkCategory("cat");
    manager.addBookmark("/", category);
    BookmarkItem item = mockBookmarkItem("item", "KSK");
    manager.addBookmark(CAT_PATH, item);

    SimpleFieldSet root = manager.toSimpleFieldSet();
    SimpleFieldSet categorySfs =
        root.getSubset(BookmarkCategory.SFS_KEY + "0").getSubset("Content");

    assertEquals(1, root.getInt(BookmarkCategory.SFS_KEY));
    assertEquals(0, root.getInt(BookmarkItem.BOOKMARK_PREFIX));
    assertEquals(0, categorySfs.getInt(BookmarkCategory.SFS_KEY));
    assertEquals(1, categorySfs.getInt(BookmarkItem.BOOKMARK_PREFIX));
  }

  @Test
  void reAddDefaultBookmarks_whenDefaultBookmarksAvailable_expectCategoryAdded() throws Exception {
    assertNotNull(BookmarkManager.DEFAULT_BOOKMARKS);

    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);

    manager.reAddDefaultBookmarks();

    String prefix = manager.l10n("defaultBookmarks") + " - ";
    Optional<BookmarkCategory> added =
        BookmarkManager.MAIN_CATEGORY.getSubCategories().stream()
            .filter(c -> c.getName().startsWith(prefix))
            .findFirst();
    assertTrue(added.isPresent());

    BookmarkCategory category = added.get();
    assertSame(category, manager.getCategoryByPath("/" + category.getName() + "/"));
    SimpleFieldSet content = BookmarkManager.toSimpleFieldSet(category);
    assertTrue(
        content.getInt(BookmarkItem.BOOKMARK_PREFIX) > 0
            || content.getInt(BookmarkCategory.SFS_KEY) > 0);
  }

  @Test
  void storeBookmarks_whenCalled_expectBookmarksFileWritten() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);
    manager.addBookmark("/", new BookmarkCategory("cat"));

    manager.storeBookmarks();

    File bookmarksFile = testDir.resolve("bookmarks.dat").toFile();
    assertTrue(bookmarksFile.isFile());
    assertTrue(bookmarksFile.length() > 0);
  }

  @Test
  void persistent_whenCalled_expectFalse() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);

    assertFalse(manager.persistent());
  }

  @Test
  void realTimeFlag_whenCalled_expectFalse() {
    BookmarkManager manager = newManagerWithEmptyBookmarksFile(testDir);

    assertFalse(manager.realTimeFlag());
  }

  private static BookmarkItem mockBookmarkItem(String name, String keyType) {
    BookmarkItem item = mock(BookmarkItem.class);
    when(item.getName()).thenReturn(name);
    when(item.getKeyType()).thenReturn(keyType);
    return item;
  }

  private static BookmarkItem mockKskBookmarkItemWithUri(String name, FreenetURI uri) {
    BookmarkItem item = mockBookmarkItem(name, "KSK");
    when(item.getURI()).thenReturn(uri);
    return item;
  }

  private static BookmarkManager newManagerWithEmptyBookmarksFile(Path tmp) {
    return newManagerWithEmptyBookmarksFile(tmp, mock(Ticker.class), mock(USKManager.class));
  }

  private static BookmarkManager newManagerWithEmptyBookmarksFile(Path tmp, USKManager uskManager) {
    return newManagerWithEmptyBookmarksFile(tmp, mock(Ticker.class), uskManager);
  }

  private static BookmarkManager newManagerWithEmptyBookmarksFile(Path tmp, Ticker ticker) {
    return newManagerWithEmptyBookmarksFile(tmp, ticker, mock(USKManager.class));
  }

  private static BookmarkManager newManagerWithEmptyBookmarksFile(
      Path tmp, Ticker ticker, USKManager uskManager) {
    try {
      File bookmarksFile = tmp.resolve("bookmarks.dat").toFile();
      SimpleFieldSet empty = new SimpleFieldSet(true);
      empty.put(BookmarkItem.BOOKMARK_PREFIX, 0);
      empty.put(BookmarkCategory.SFS_KEY, 0);
      writeSimpleFieldSet(bookmarksFile, empty);
    } catch (IOException e) {
      throw new IllegalStateException("Failed to write initial bookmarks file for test", e);
    }

    NodeClientCore core = mock(NodeClientCore.class);
    UserAlertManager alerts = mock(UserAlertManager.class);
    Node node = mock(Node.class);
    network.crypta.node.ProgramDirectory userDir = new network.crypta.node.ProgramDirectory();
    try {
      userDir.move(tmp.toString());
    } catch (IOException e) {
      throw new IllegalStateException("Failed to initialize ProgramDirectory for test", e);
    }

    when(node.userDir()).thenReturn(userDir);
    lenient().when(node.getTicker()).thenReturn(ticker);
    when(core.getNode()).thenReturn(node);
    lenient().when(core.getUskManager()).thenReturn(uskManager);
    lenient().when(core.getAlerts()).thenReturn(alerts);

    return new BookmarkManager(core, false);
  }

  private static void writeSimpleFieldSet(File file, SimpleFieldSet sfs) throws IOException {
    try (FileOutputStream out = new FileOutputStream(file)) {
      sfs.writeToBigBuffer(out);
    }
  }

  private static void clearCategoryTree(BookmarkCategory category) {
    try {
      Field field = BookmarkCategory.class.getDeclaredField("bookmarks");
      field.setAccessible(true);
      Object raw = field.get(category);
      @SuppressWarnings("unchecked")
      List<Bookmark> list = (List<Bookmark>) raw;
      synchronized (CATEGORY_CLEAR_LOCK) {
        list.clear();
      }
    } catch (NoSuchFieldException | IllegalAccessException e) {
      throw new IllegalStateException(
          "Failed to clear BookmarkCategory state for test isolation", e);
    }
  }
}
