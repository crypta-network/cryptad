package network.crypta.clients.http.bookmark;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import java.net.MalformedURLException;
import java.util.stream.Stream;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.NodeClientCore;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class BookmarkItemTest {

  private static final String SFS_NAME = "Name";
  private static final String SFS_DESCRIPTION = "Description";
  private static final String SFS_SHORT_DESCRIPTION = "ShortDescription";
  private static final String SFS_HAS_AN_ACTIVE_LINK = "hasAnActivelink";
  private static final String SFS_UPDATED = "Updated";
  private static final String SFS_URI = "URI";

  private static final String DEFAULT_SFS_NAME_VALUE = "N";
  private static final String DEFAULT_SFS_DESCRIPTION_VALUE = "D";
  private static final String DEFAULT_SFS_SHORT_DESCRIPTION_VALUE = "S";

  private static final String USK_24 =
      "USK@62H8KFSZWMyQ2MQgwvNhEYJ2m3SQl696PfsVfWQ-HQo,"
          + "cJrPvdNz4AnrHJQXNteDV7k3YnAVY-MClt84gwH2qEo,AQACAAE/"
          + "freenet-first-steps/24/";

  private static final String CHK_1 =
      "CHK@OR904t6ylZOwoobMJRmSn7HsPGefHSP7zAjoLyenSPw,"
          + "x2EzszO4Kqot8akqmKYXJbkD-fSj6noOVGB-K2YisZ4,AAIC--8/1-works.html";

  @Mock BookmarkManager bookmarkManager;
  @Mock UserAlertManager userAlertManager;
  @Mock NodeClientCore nodeClientCore;

  private static FreenetURI uri(String uri) {
    try {
      return new FreenetURI(uri);
    } catch (MalformedURLException e) {
      throw new AssertionError("Test URI must be valid: " + uri, e);
    }
  }

  private BookmarkItem newBookmarkItem(
      FreenetURI uri,
      String name,
      String description,
      String shortDescription,
      boolean hasAnActiveLink) {
    return new BookmarkItem(
        uri,
        name,
        description,
        shortDescription,
        hasAnActiveLink,
        bookmarkManager,
        userAlertManager);
  }

  private SimpleFieldSet newBookmarkItemSfs(
      String name,
      String description,
      String shortDescription,
      boolean hasAnActiveLink,
      boolean updated,
      String uri) {
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    if (name != null) {
      sfs.putSingle(SFS_NAME, name);
    }
    if (description != null) {
      sfs.putSingle(SFS_DESCRIPTION, description);
    }
    if (shortDescription != null) {
      sfs.putSingle(SFS_SHORT_DESCRIPTION, shortDescription);
    }
    sfs.put(SFS_HAS_AN_ACTIVE_LINK, hasAnActiveLink);
    sfs.put(SFS_UPDATED, updated);
    sfs.putSingle(SFS_URI, uri);
    return sfs;
  }

  private SimpleFieldSet newDefaultBookmarkItemSfs(
      boolean hasAnActiveLink, boolean updated, String uri) {
    return newBookmarkItemSfs(
        DEFAULT_SFS_NAME_VALUE,
        DEFAULT_SFS_DESCRIPTION_VALUE,
        DEFAULT_SFS_SHORT_DESCRIPTION_VALUE,
        hasAnActiveLink,
        updated,
        uri);
  }

  @Test
  void constructor_whenExplicitValues_expectAccessorsReturnThoseValues() {
    // Arrange / Act
    FreenetURI uri = uri(USK_24);
    BookmarkItem item = newBookmarkItem(uri, "Name", "Desc", "Short", true);

    // Assert
    assertEquals("Name", item.getName());
    assertSame(uri, item.getURI());
    assertEquals(uri.toString(), item.getKey());
    assertEquals("Desc", item.getDescription());
    assertEquals("Short", item.getShortDescription());
    assertTrue(item.hasAnActivelink());
    assertFalse(item.hasUpdated());
    assertNotNull(item.getUserAlert());
  }

  @Test
  void constructor_whenSimpleFieldSetMissingUpdated_expectDefaultsToNotUpdated() throws Exception {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle(SFS_NAME, "FromSfs");
    sfs.putSingle(SFS_URI, USK_24);
    sfs.put(SFS_HAS_AN_ACTIVE_LINK, true);

    // Act
    BookmarkItem item = new BookmarkItem(sfs, bookmarkManager, userAlertManager);

    // Assert
    assertEquals("FromSfs", item.getName());
    assertFalse(item.hasUpdated());
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void constructor_whenSimpleFieldSetNameMissing_expectLocalizedFallbackNameIsNonEmpty()
      throws Exception {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle(SFS_NAME, "");
    sfs.putSingle(SFS_URI, USK_24);
    sfs.put(SFS_HAS_AN_ACTIVE_LINK, false);

    // Act
    BookmarkItem item = new BookmarkItem(sfs, bookmarkManager, userAlertManager);

    // Assert
    assertNotNull(item.getName());
    assertFalse(item.getName().isEmpty());
  }

  @Test
  void constructor_whenSimpleFieldSetDescriptionMissing_expectDefaultsToEmptyStrings()
      throws Exception {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle(SFS_NAME, DEFAULT_SFS_NAME_VALUE);
    sfs.putSingle(SFS_URI, USK_24);
    sfs.put(SFS_HAS_AN_ACTIVE_LINK, true);

    // Act
    BookmarkItem item = new BookmarkItem(sfs, bookmarkManager, userAlertManager);

    // Assert
    assertEquals("", item.getDescription());
    assertEquals("", item.getShortDescription());
  }

  @Test
  void constructor_whenSimpleFieldSetInvalidUri_expectThrowsMalformedURLException() {
    // Arrange
    SimpleFieldSet sfs = newDefaultBookmarkItemSfs(false, false, "NOT_A_URI");

    // Act / Assert
    assertThrows(
        MalformedURLException.class,
        () -> new BookmarkItem(sfs, bookmarkManager, userAlertManager));
  }

  @Test
  void constructor_whenSimpleFieldSetProvidesValues_expectValuesExposedByAccessors()
      throws Exception {
    // Arrange
    SimpleFieldSet sfs = newBookmarkItemSfs("MyName", "MyDesc", "MyShort", true, false, USK_24);

    // Act
    BookmarkItem item = new BookmarkItem(sfs, bookmarkManager, userAlertManager);

    // Assert
    assertEquals("MyName", item.getName());
    assertEquals("MyDesc", item.getDescription());
    assertEquals("MyShort", item.getShortDescription());
    assertTrue(item.hasAnActivelink());
  }

  @Test
  void registerUserAlert_whenNotUpdated_expectDoesNotRegister() throws Exception {
    // Arrange
    SimpleFieldSet sfs = newDefaultBookmarkItemSfs(false, false, USK_24);
    BookmarkItem item = new BookmarkItem(sfs, bookmarkManager, userAlertManager);

    // Act
    item.registerUserAlert();

    // Assert
    verify(userAlertManager, never()).register(any(UserAlert.class));
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void registerUserAlert_whenUpdatedAndUSK_expectRegistersAlert() throws Exception {
    // Arrange
    SimpleFieldSet sfs = newDefaultBookmarkItemSfs(true, true, USK_24);
    BookmarkItem item = new BookmarkItem(sfs, bookmarkManager, userAlertManager);

    // Act
    item.registerUserAlert();

    // Assert
    verify(userAlertManager).register(same(item.getUserAlert()));
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void setEdition_whenNewerEdition_expectUpdatesKeyMarksUpdatedAndRegistersOnce() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "S", false);

    // Act
    boolean updated = item.setEdition(25, nodeClientCore);

    // Assert
    assertTrue(updated);
    assertTrue(item.hasUpdated());
    assertEquals(25, item.getURI().getSuggestedEdition());
    verify(userAlertManager).register(same(item.getUserAlert()));
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void setEdition_whenOlderOrSameEdition_expectNoUpdateAndNoRegister() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "S", false);
    long currentEdition = item.getURI().getSuggestedEdition();

    // Act
    boolean updated = item.setEdition(currentEdition, nodeClientCore);

    // Assert
    assertFalse(updated);
    assertFalse(item.hasUpdated());
    assertEquals(currentEdition, item.getURI().getSuggestedEdition());
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void setEdition_whenCalledMultipleTimes_expectRegistersOnlyOnce() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "S", false);

    // Act
    assertTrue(item.setEdition(25, nodeClientCore));
    assertTrue(item.setEdition(26, nodeClientCore));

    // Assert
    assertEquals(26, item.getURI().getSuggestedEdition());
    verify(userAlertManager, times(1)).register(same(item.getUserAlert()));
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void update_whenNewKeyIsNotUSK_expectDisablesBookmarkAndUnregistersAlert() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "S", true);
    assertTrue(item.setEdition(25, nodeClientCore));
    verify(userAlertManager).register(same(item.getUserAlert()));

    // Act
    item.update(uri(CHK_1), false, "NewDesc", "NewShort");

    // Assert
    assertFalse(item.hasUpdated());
    assertEquals("CHK", item.getKeyType());
    assertFalse(item.hasAnActivelink());
    assertEquals("NewDesc", item.getDescription());
    assertEquals("NewShort", item.getShortDescription());
    verify(userAlertManager).unregister(same(item.getUserAlert()));
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void clearUpdated_whenUpdated_expectClearsFlagButDoesNotUnregister() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "S", false);
    assertTrue(item.setEdition(25, nodeClientCore));
    verify(userAlertManager).register(same(item.getUserAlert()));

    // Act
    item.clearUpdated();

    // Assert
    assertFalse(item.hasUpdated());
    verify(userAlertManager, never()).unregister(any(UserAlert.class));
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void userAlert_whenMarkedInvalid_expectUnregistersAndClearsUpdated() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "S", false);
    assertTrue(item.setEdition(25, nodeClientCore));
    verify(userAlertManager).register(same(item.getUserAlert()));

    // Act
    item.getUserAlert().isValid(false);

    // Assert
    assertFalse(item.hasUpdated());
    verify(userAlertManager).unregister(same(item.getUserAlert()));
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void userAlert_onDismiss_expectUnregistersClearsUpdatedAndStoresBookmarks() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "S", false);
    assertTrue(item.setEdition(25, nodeClientCore));
    verify(userAlertManager).register(same(item.getUserAlert()));

    // Act
    item.getUserAlert().onDismiss();

    // Assert
    assertFalse(item.hasUpdated());
    verify(userAlertManager).unregister(same(item.getUserAlert()));
    verify(bookmarkManager).storeBookmarks();
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void getDescription_whenNull_expectEmptyString() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", null, "S", false);

    // Act
    String description = item.getDescription();

    // Assert
    assertEquals("", description);
  }

  @Test
  void getDescription_whenL10nPrefixed_expectResolvedValueNotRawPrefix() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "L10N:SomeKey", "S", false);

    // Act
    String description = item.getDescription();

    // Assert
    assertNotNull(description);
    assertNotEquals("L10N:SomeKey", description);
    assertFalse(description.toLowerCase().startsWith("l10n:"));
  }

  @Test
  void getShortDescription_whenNull_expectEmptyString() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", null, false);

    // Act
    String shortDescription = item.getShortDescription();

    // Assert
    assertEquals("", shortDescription);
  }

  @Test
  void getShortDescription_whenL10nPrefixed_expectResolvedValueNotRawPrefix() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "l10n:SomeKey", false);

    // Act
    String shortDescription = item.getShortDescription();

    // Assert
    assertNotNull(shortDescription);
    assertNotEquals("l10n:SomeKey", shortDescription);
    assertFalse(shortDescription.toLowerCase().startsWith("l10n:"));
  }

  @Test
  void getSimpleFieldSet_whenCalled_expectContainsPersistedFields() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "S", true);
    assertTrue(item.setEdition(25, nodeClientCore));
    verify(userAlertManager).register(same(item.getUserAlert()));

    // Act
    SimpleFieldSet sfs = item.getSimpleFieldSet();

    // Assert
    assertEquals("N", sfs.get(SFS_NAME));
    assertEquals("D", sfs.get(SFS_DESCRIPTION));
    assertEquals("S", sfs.get(SFS_SHORT_DESCRIPTION));
    assertTrue(sfs.getBoolean(SFS_HAS_AN_ACTIVE_LINK, false));
    assertTrue(sfs.getBoolean(SFS_UPDATED, false));
    assertEquals(item.getKey(), sfs.get(SFS_URI));
    verifyNoMoreInteractions(userAlertManager);
  }

  @Test
  void toString_whenDescriptionNull_expectDoesNotContainNullLiteral() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", null, "S", false);

    // Act
    String value = item.toString();

    // Assert
    assertTrue(value.contains("###"));
    assertFalse(value.contains("null"));
    assertTrue(value.endsWith(item.getKey()));
  }

  @Test
  void getUSK_whenKeyIsUSK_expectReturnsEquivalentUsk() throws Exception {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "S", false);

    // Act
    USK usk = item.getUSK();

    // Assert
    assertNotNull(usk);
    assertTrue(USK.create(item.getURI()).equals(usk, true));
  }

  @Test
  void getUSK_whenKeyIsNotUSK_expectThrowsMalformedURLException() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(CHK_1), "N", "D", "S", false);

    // Act / Assert
    assertThrows(MalformedURLException.class, item::getUSK);
  }

  @Test
  void equals_whenSameInstance_expectTrue() {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(USK_24), "N", "D", "S", false);

    // Act / Assert
    //noinspection EqualsWithItself
    assertEquals(item, item);
  }

  @Test
  void equals_whenSameBookmarkButDifferentSuggestedEdition_expectEqualAndHashCodesMatch() {
    // Arrange
    BookmarkItem a = newBookmarkItem(uri(USK_24), "N", "D", "S", false);
    BookmarkItem b = newBookmarkItem(uri(USK_24).setSuggestedEdition(12345), "N", "D", "S", false);

    // Act / Assert
    assertEquals(a, b);
    assertEquals(b, a);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void equals_whenDifferentAlertManager_expectNotEqual() {
    // Arrange
    UserAlertManager otherAlertManager = org.mockito.Mockito.mock(UserAlertManager.class);
    BookmarkItem a = newBookmarkItem(uri(USK_24), "N", "D", "S", false);
    BookmarkItem b =
        new BookmarkItem(uri(USK_24), "N", "D", "S", false, bookmarkManager, otherAlertManager);

    // Act / Assert
    assertNotEquals(a, b);
    assertNotEquals(b, a);
  }

  @Test
  void equals_whenOtherHasNullDescription_expectNotEqualAndNoNpe() {
    // Arrange
    BookmarkItem a = newBookmarkItem(uri(USK_24), "N", "D", "S", false);
    BookmarkItem b = newBookmarkItem(uri(USK_24), "N", null, "S", false);

    // Act / Assert
    assertNotEquals(a, b);
    assertNotEquals(b, a);
  }

  @Test
  void equals_whenBothDescriptionsNull_expectEqualAndHashCodesMatch() {
    // Arrange
    BookmarkItem a = newBookmarkItem(uri(USK_24), "N", null, "S", false);
    BookmarkItem b = newBookmarkItem(uri(USK_24), "N", null, "S", false);

    // Act / Assert
    assertEquals(a, b);
    assertEquals(b, a);
    assertEquals(a.hashCode(), b.hashCode());
  }

  static Stream<Arguments> keyTypes() {
    return Stream.of(Arguments.of(USK_24, "USK"), Arguments.of(CHK_1, "CHK"));
  }

  @ParameterizedTest
  @MethodSource("keyTypes")
  void getKeyType_whenUriProvided_expectMatchesUnderlyingKeyType(String uri, String expectedType) {
    // Arrange
    BookmarkItem item = newBookmarkItem(uri(uri), "N", "D", "S", false);

    // Act
    String keyType = item.getKeyType();

    // Assert
    assertEquals(expectedType, keyType);
  }

  @Test
  void constructor_whenSimpleFieldSetInvalidContents_expectThrowsMalformedURLException() {
    // Arrange
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle(SFS_NAME, "N");
    sfs.putSingle(SFS_URI, "USK@/broken/0");
    sfs.put(SFS_HAS_AN_ACTIVE_LINK, false);

    // Act / Assert
    assertThrows(
        MalformedURLException.class,
        () -> new BookmarkItem(sfs, bookmarkManager, userAlertManager));
  }
}
