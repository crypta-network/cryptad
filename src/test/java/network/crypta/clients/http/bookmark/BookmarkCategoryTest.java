package network.crypta.clients.http.bookmark;

import java.net.MalformedURLException;
import java.util.List;
import network.crypta.keys.FreenetURI;
import network.crypta.node.FSParseException;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class BookmarkCategoryTest {

  private static final String CATEGORY_CHILD = "Child";
  private static final String CATEGORY_EXISTING = "Existing";
  private static final String CATEGORY_ABSENT = "Absent";
  private static final String ROOT_PATH_PREFIX = "Root/";

  private static final String USK_1 =
      "USK@62H8KFSZWMyQ2MQgwvNhEYJ2m3SQl696PfsVfWQ-HQo,"
          + "cJrPvdNz4AnrHJQXNteDV7k3YnAVY-MClt84gwH2qEo,AQACAAE/"
          + "freenet-first-steps/24/";

  private static final String USK_2 =
      "USK@5ijbfKSJ4kPZTRDzq363CHteEUiSZjrO-E36vbHvnIU,"
          + "ZEZqPXeuYiyokY2r0wkhJr5cy7KBH9omkuWDqSC6PLs,AQACAAE/"
          + "clean-spider/399/";

  @Mock BookmarkManager bookmarkManager;

  @Mock UserAlertManager userAlertManager;

  private BookmarkItem newBookmarkItem(String name, String description, boolean hasAnActiveLink) {
    try {
      FreenetURI uri = new FreenetURI(hasAnActiveLink ? USK_1 : USK_2);
      return new BookmarkItem(
          uri, name, description, "short", hasAnActiveLink, bookmarkManager, userAlertManager);
    } catch (MalformedURLException e) {
      throw new AssertionError("Test URI must be valid", e);
    }
  }

  @Test
  void constructor_whenNameProvided_expectNameStored() {
    // Arrange / Act
    BookmarkCategory category = new BookmarkCategory("Root");

    // Assert
    assertEquals("Root", category.getName());
  }

  @Test
  void constructor_whenSimpleFieldSetMissingName_expectThrows() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);

    // Act / Assert
    assertThrows(FSParseException.class, () -> new BookmarkCategory(sfs));
  }

  @Test
  void constructor_whenSimpleFieldSetHasName_expectNameStored() throws FSParseException {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("Name", "FromSfs");

    // Act
    BookmarkCategory category = new BookmarkCategory(sfs);

    // Assert
    assertEquals("FromSfs", category.getName());
  }

  @Test
  @SuppressWarnings("ConstantValue")
  void addBookmark_whenNull_expectReturnsNullAndDoesNotChangeSize() {
    // Arrange
    BookmarkCategory category = new BookmarkCategory("Root");

    // Act
    Bookmark added = category.addBookmark(null);

    // Assert
    assertNull(added);
    assertEquals(0, category.size());
  }

  @Test
  void addBookmark_whenNewBookmark_expectAddedAndReturned() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory child = new BookmarkCategory(CATEGORY_CHILD);

    // Act
    Bookmark added = root.addBookmark(child);

    // Assert
    assertSame(child, added);
    assertEquals(1, root.size());
    assertSame(child, root.get(0));
  }

  @Test
  void addBookmark_whenSameNameAlreadyExists_expectExistingReturnedAndNotAdded() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory first = new BookmarkCategory("Duplicate");
    BookmarkCategory second = new BookmarkCategory("Duplicate");
    root.addBookmark(first);

    // Act
    Bookmark result = root.addBookmark(second);

    // Assert
    assertSame(first, result);
    assertEquals(1, root.size());
    assertSame(first, root.get(0));
  }

  @Test
  void removeBookmark_whenBookmarkNotPresent_expectNoChange() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory existing = new BookmarkCategory(CATEGORY_EXISTING);
    BookmarkCategory absent = new BookmarkCategory(CATEGORY_ABSENT);
    root.addBookmark(existing);

    // Act
    root.removeBookmark(absent);

    // Assert
    assertEquals(1, root.size());
    assertSame(existing, root.get(0));
  }

  @Test
  void removeBookmark_whenBookmarkPresent_expectRemoved() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory existing = new BookmarkCategory(CATEGORY_EXISTING);
    root.addBookmark(existing);

    // Act
    root.removeBookmark(existing);

    // Assert
    assertEquals(0, root.size());
  }

  @ParameterizedTest
  @CsvSource({"-1", "0", "1"})
  void get_whenEmpty_expectIndexOutOfBounds(int index) {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");

    // Act / Assert
    assertThrows(IndexOutOfBoundsException.class, () -> root.get(index));
  }

  @Test
  void moveBookmarkUp_whenNotPresent_expectNoChange() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory existing = new BookmarkCategory(CATEGORY_EXISTING);
    BookmarkCategory absent = new BookmarkCategory(CATEGORY_ABSENT);
    root.addBookmark(existing);

    // Act
    root.moveBookmarkUp(absent);

    // Assert
    assertEquals(1, root.size());
    assertSame(existing, root.get(0));
  }

  @Test
  void moveBookmarkUp_whenFirst_expectStaysAtBeginning() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory first = new BookmarkCategory("A");
    BookmarkCategory second = new BookmarkCategory("B");
    root.addBookmark(first);
    root.addBookmark(second);

    // Act
    root.moveBookmarkUp(first);

    // Assert
    assertSame(first, root.get(0));
    assertSame(second, root.get(1));
  }

  @Test
  void moveBookmarkUp_whenMiddle_expectMovesUpOne() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory first = new BookmarkCategory("A");
    BookmarkCategory middle = new BookmarkCategory("B");
    BookmarkCategory third = new BookmarkCategory("C");
    root.addBookmark(first);
    root.addBookmark(middle);
    root.addBookmark(third);

    // Act
    root.moveBookmarkUp(middle);

    // Assert
    assertSame(middle, root.get(0));
    assertSame(first, root.get(1));
    assertSame(third, root.get(2));
  }

  @Test
  void moveBookmarkDown_whenNotPresent_expectNoChange() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory existing = new BookmarkCategory(CATEGORY_EXISTING);
    BookmarkCategory absent = new BookmarkCategory(CATEGORY_ABSENT);
    root.addBookmark(existing);

    // Act
    root.moveBookmarkDown(absent);

    // Assert
    assertEquals(1, root.size());
    assertSame(existing, root.get(0));
  }

  @Test
  void moveBookmarkDown_whenLast_expectStaysAtEnd() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory first = new BookmarkCategory("A");
    BookmarkCategory last = new BookmarkCategory("B");
    root.addBookmark(first);
    root.addBookmark(last);

    // Act
    root.moveBookmarkDown(last);

    // Assert
    assertSame(first, root.get(0));
    assertSame(last, root.get(1));
  }

  @Test
  void moveBookmarkDown_whenMiddle_expectMovesDownOne() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory first = new BookmarkCategory("A");
    BookmarkCategory middle = new BookmarkCategory("B");
    BookmarkCategory third = new BookmarkCategory("C");
    root.addBookmark(first);
    root.addBookmark(middle);
    root.addBookmark(third);

    // Act
    root.moveBookmarkDown(middle);

    // Assert
    assertSame(first, root.get(0));
    assertSame(third, root.get(1));
    assertSame(middle, root.get(2));
  }

  @Test
  void getItems_whenMixedBookmarks_expectOnlyItemsReturnedInListOrder() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkItem item1 = newBookmarkItem("Item1", "Desc1", true);
    BookmarkCategory child = new BookmarkCategory(CATEGORY_CHILD);
    BookmarkItem item2 = newBookmarkItem("Item2", "Desc2", false);
    root.addBookmark(item1);
    root.addBookmark(child);
    root.addBookmark(item2);

    // Act
    List<BookmarkItem> items = root.getItems();

    // Assert
    assertEquals(2, items.size());
    assertSame(item1, items.get(0));
    assertSame(item2, items.get(1));
  }

  @Test
  void getSubCategories_whenMixedBookmarks_expectOnlyCategoriesReturnedInListOrder() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory cat1 = new BookmarkCategory("Cat1");
    BookmarkItem item = newBookmarkItem("Item", "Desc", true);
    BookmarkCategory cat2 = new BookmarkCategory("Cat2");
    root.addBookmark(cat1);
    root.addBookmark(item);
    root.addBookmark(cat2);

    // Act
    List<BookmarkCategory> categories = root.getSubCategories();

    // Assert
    assertEquals(2, categories.size());
    assertSame(cat1, categories.get(0));
    assertSame(cat2, categories.get(1));
  }

  @Test
  void getAllItems_whenNestedCategories_expectDepthFirstItems() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkItem rootItem = newBookmarkItem("RootItem", "RootDesc", true);
    BookmarkCategory firstChild = new BookmarkCategory("ChildA");
    BookmarkItem childItem = newBookmarkItem("ChildItem", "ChildDesc", false);
    BookmarkCategory secondChild = new BookmarkCategory("ChildB");
    BookmarkItem secondChildItem = newBookmarkItem("ChildBItem", "ChildBDesc", true);
    root.addBookmark(rootItem);
    root.addBookmark(firstChild);
    root.addBookmark(secondChild);
    firstChild.addBookmark(childItem);
    secondChild.addBookmark(secondChildItem);

    // Act
    List<BookmarkItem> items = root.getAllItems();

    // Assert
    assertEquals(3, items.size());
    assertSame(rootItem, items.get(0));
    assertSame(childItem, items.get(1));
    assertSame(secondChildItem, items.get(2));
  }

  @Test
  void getAllSubCategories_whenNestedCategories_expectImmediateThenRecursive() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory childA = new BookmarkCategory("ChildA");
    BookmarkCategory childB = new BookmarkCategory("ChildB");
    BookmarkCategory grandChildA1 = new BookmarkCategory("GrandChildA1");
    root.addBookmark(childA);
    root.addBookmark(childB);
    childA.addBookmark(grandChildA1);

    // Act
    List<BookmarkCategory> categories = root.getAllSubCategories();

    // Assert
    assertEquals(3, categories.size());
    assertSame(childA, categories.get(0));
    assertSame(childB, categories.get(1));
    assertSame(grandChildA1, categories.get(2));
  }

  @Test
  void toStrings_whenMixedBookmarks_expectItemsBeforeSubCategories() {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory child = new BookmarkCategory(CATEGORY_CHILD);
    BookmarkItem rootItem1 = newBookmarkItem("RootItem1", "Desc1", true);
    BookmarkItem rootItem2 = newBookmarkItem("RootItem2", "Desc2", false);
    BookmarkItem childItem = newBookmarkItem("ChildItem", "Desc3", true);
    root.addBookmark(rootItem1);
    root.addBookmark(child);
    root.addBookmark(rootItem2);
    child.addBookmark(childItem);

    // Act
    String[] strings = root.toStrings();

    // Assert
    assertArrayEquals(
        new String[] {
          ROOT_PATH_PREFIX + rootItem1,
          ROOT_PATH_PREFIX + rootItem2,
          ROOT_PATH_PREFIX + CATEGORY_CHILD + "/" + childItem,
        },
        strings);
  }

  @Test
  void getSimpleFieldSet_whenEmpty_expectNameAndZeroCounts() throws FSParseException {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");

    // Act
    SimpleFieldSet sfs = root.getSimpleFieldSet();

    // Assert
    assertEquals("Root", sfs.get("Name"));
    SimpleFieldSet content = sfs.getSubset("Content");
    assertEquals(0, content.getInt(BookmarkCategory.SFS_KEY));
    assertEquals(0, content.getInt(BookmarkItem.BOOKMARK_PREFIX));
  }

  @Test
  void getSimpleFieldSet_whenHasChildAndItem_expectChildAndItemSerialized()
      throws FSParseException {
    // Arrange
    BookmarkCategory root = new BookmarkCategory("Root");
    BookmarkCategory child = new BookmarkCategory(CATEGORY_CHILD);
    BookmarkItem item = newBookmarkItem("Item", "Desc", true);
    root.addBookmark(child);
    root.addBookmark(item);

    // Act
    SimpleFieldSet sfs = root.getSimpleFieldSet();

    // Assert
    assertEquals("Root", sfs.get("Name"));

    SimpleFieldSet content = sfs.getSubset("Content");
    assertEquals(1, content.getInt(BookmarkCategory.SFS_KEY));
    assertEquals(1, content.getInt(BookmarkItem.BOOKMARK_PREFIX));

    SimpleFieldSet childSfs = content.getSubset(BookmarkCategory.SFS_KEY + "0");
    assertEquals(CATEGORY_CHILD, childSfs.get("Name"));

    SimpleFieldSet itemSfs = content.getSubset(BookmarkItem.BOOKMARK_PREFIX + "0");
    assertEquals("Item", itemSfs.get("Name"));
    assertEquals("Desc", itemSfs.get("Description"));
  }
}
