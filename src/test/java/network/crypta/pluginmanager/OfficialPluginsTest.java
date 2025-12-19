package network.crypta.pluginmanager;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.MalformedURLException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;
import network.crypta.keys.FreenetURI;
import network.crypta.pluginmanager.OfficialPlugins.OfficialPluginDescription;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class OfficialPluginsTest {

  private static final String PLUGIN_HELLO_WORLD = "HelloWorld";

  private static final String USK_POSITIVE_EDITION =
      "USK@ZLwcSLwqpM1527Tw1YmnSiXgzITU0neHQ11Cyl0iLmk,"
          + "f6FLo3TvsEijIcJq-X3BTjjtm0ErVZwAPO7AUd9V7lY,AQACAAE/fix-link-length/22/";

  private static final String USK_NEGATIVE_EDITION =
      "USK@t5zaONbYd5DvGNNSokVnDCdrIEytn9U5SSD~pYF0RTE,"
          + "guWyS9aCMcywU5PFBrKsMiXs7LzwKfQlGSRi17fpffc,AQACAAE/fsng/-56/";

  @Test
  void get_whenUnknownPlugin_expectNull() {
    // Arrange
    OfficialPlugins officialPlugins = new OfficialPlugins();

    // Act
    OfficialPluginDescription description = officialPlugins.get("DoesNotExist");

    // Assert
    assertNull(description);
  }

  @ParameterizedTest
  @MethodSource("knownPluginCases")
  void get_whenKnownPlugin_expectExpectedDescriptionFields(
      String pluginName,
      String expectedGroup,
      boolean expectedEssential,
      boolean expectedAdvanced,
      boolean expectedExperimental,
      boolean expectedUsesXml,
      long expectedMinimumVersion,
      long expectedRecommendedVersion) {
    // Arrange
    OfficialPlugins officialPlugins = new OfficialPlugins();

    // Act
    OfficialPluginDescription description = officialPlugins.get(pluginName);

    // Assert
    assertNotNull(description);
    assertAll(
        () -> assertEquals(pluginName, description.name),
        () -> assertEquals(expectedGroup, description.group),
        () -> assertEquals(expectedEssential, description.essential),
        () -> assertEquals(expectedAdvanced, description.advanced),
        () -> assertEquals(expectedExperimental, description.experimental),
        () -> assertEquals(expectedUsesXml, description.usesXML),
        () -> assertEquals(expectedMinimumVersion, description.minimumVersion),
        () -> assertEquals(expectedRecommendedVersion, description.recommendedVersion),
        () -> assertNotNull(description.uri),
        () -> assertTrue(description.uri.isCHK()),
        () -> assertFalse(description.deprecated),
        () -> assertFalse(description.unsupported));
  }

  private static Stream<Arguments> knownPluginCases() {
    return Stream.of(
        Arguments.of(PLUGIN_HELLO_WORLD, "example", false, true, false, false, -1L, -1L),
        Arguments.of("TestGallery", "example", false, false, true, false, 1L, -1L),
        Arguments.of("WebOfTrust", "communication", false, false, false, true, 20L, 20L),
        Arguments.of("UPnP", "connectivity", true, true, false, false, 10007L, 10007L),
        Arguments.of("KeepAlive", "file-transfer", false, false, false, false, -1L, -1L));
  }

  @Test
  void getAll_whenCalled_expectContainsKnownPlugins() {
    // Arrange
    OfficialPlugins officialPlugins = new OfficialPlugins();

    // Act
    Collection<OfficialPluginDescription> all = officialPlugins.getAll();
    Set<String> names = new HashSet<>();
    for (OfficialPluginDescription description : all) {
      names.add(description.name);
    }

    // Assert
    assertTrue(names.contains("WebOfTrust"));
    assertTrue(names.contains("UPnP"));
    assertTrue(names.contains(PLUGIN_HELLO_WORLD));
    assertTrue(names.contains("Freemail_wot"));
    assertTrue(names.contains("Sharesite"));
  }

  @Test
  void getAll_whenModified_expectUnsupportedOperationException() {
    // Arrange
    OfficialPlugins officialPlugins = new OfficialPlugins();
    Collection<OfficialPluginDescription> all = officialPlugins.getAll();

    // Act + Assert
    assertThrows(UnsupportedOperationException.class, all::clear);
  }

  @ParameterizedTest
  @MethodSource("alwaysFetchLatestVersionEditionCases")
  void officialPluginDescription_whenAlwaysFetchLatestVersion_expectNegativeEdition(
      FreenetURI uri, long expectedSuggestedEdition) {
    // Arrange
    boolean alwaysFetchLatestVersion = true;

    // Act
    OfficialPluginDescription description =
        new OfficialPluginDescription(
            "SomePlugin",
            "someGroup",
            false,
            -1,
            -1,
            alwaysFetchLatestVersion,
            false,
            uri,
            false,
            false,
            false,
            false);

    // Assert
    assertEquals(expectedSuggestedEdition, description.uri.getSuggestedEdition());
  }

  private static Stream<Arguments> alwaysFetchLatestVersionEditionCases() {
    FreenetURI positiveEdition = parseUriUnchecked(USK_POSITIVE_EDITION);
    FreenetURI zeroEdition = positiveEdition.setSuggestedEdition(0);
    FreenetURI negativeEdition = parseUriUnchecked(USK_NEGATIVE_EDITION);

    return Stream.of(
        Arguments.of(positiveEdition, -22L),
        Arguments.of(zeroEdition, -1L),
        Arguments.of(negativeEdition, -56L));
  }

  @Test
  void getLocalisedPluginName_whenPluginManagerReturnsValue_expectDelegatedResult() {
    // Arrange
    OfficialPlugins officialPlugins = new OfficialPlugins();
    OfficialPluginDescription description = officialPlugins.get(PLUGIN_HELLO_WORLD);
    assertNotNull(description);

    try (MockedStatic<PluginManager> pluginManager = Mockito.mockStatic(PluginManager.class)) {
      pluginManager
          .when(() -> PluginManager.getOfficialPluginLocalisedName(PLUGIN_HELLO_WORLD))
          .thenReturn("Hello World (Localized)");

      // Act
      String localizedName = description.getLocalisedPluginName();

      // Assert
      assertEquals("Hello World (Localized)", localizedName);
    }
  }

  @Test
  void getLocalisedPluginDescription_whenPluginManagerReturnsValue_expectDelegatedResult() {
    // Arrange
    OfficialPlugins officialPlugins = new OfficialPlugins();
    OfficialPluginDescription description = officialPlugins.get(PLUGIN_HELLO_WORLD);
    assertNotNull(description);

    try (MockedStatic<PluginManager> pluginManager = Mockito.mockStatic(PluginManager.class)) {
      pluginManager
          .when(() -> PluginManager.l10n("pluginDesc." + PLUGIN_HELLO_WORLD))
          .thenReturn("Desc");

      // Act
      String localizedDescription = description.getLocalisedPluginDescription();

      // Assert
      assertEquals("Desc", localizedDescription);
    }
  }

  private static FreenetURI parseUriUnchecked(String uri) {
    try {
      return new FreenetURI(uri);
    } catch (MalformedURLException e) {
      throw new AssertionError("Test URI should be valid: " + uri, e);
    }
  }
}
