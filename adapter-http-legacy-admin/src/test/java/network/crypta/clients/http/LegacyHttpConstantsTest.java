package network.crypta.clients.http;

import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SuppressWarnings("java:S100")
class LegacyHttpConstantsTest {
  private static final String DOWNLOADS_PROPERTY = "crypta.fproxy.downloadsPath";
  private static final String FRIENDS_PROPERTY = "crypta.fproxy.friendsPath";
  private static final String CONFIG_PROPERTY = "crypta.fproxy.configPath";
  private static final String WELCOME_PROPERTY = "crypta.fproxy.welcomePath";

  @Test
  void legacyHttpPaths_whenPropertiesAbsent_useHistoricalDefaults() throws Exception {
    PathSnapshot snapshot =
        loadPathSnapshot(
            overrides(
                DOWNLOADS_PROPERTY, null,
                FRIENDS_PROPERTY, null,
                CONFIG_PROPERTY, null,
                WELCOME_PROPERTY, null));

    assertEquals("/downloads/", snapshot.downloadsPath());
    assertEquals("/friends/", snapshot.friendsPath());
    assertEquals("/config/", snapshot.configPath());
    assertEquals("/welcome/", snapshot.welcomePath());
  }

  @Test
  void legacyHttpPaths_whenPropertiesProvided_normalizeConfiguredOverrides() throws Exception {
    PathSnapshot snapshot =
        loadPathSnapshot(
            overrides(
                DOWNLOADS_PROPERTY, "downloads-custom",
                FRIENDS_PROPERTY, "/friends-custom",
                CONFIG_PROPERTY, "config-custom/",
                WELCOME_PROPERTY, "/welcome-custom/"));

    assertEquals("/downloads-custom/", snapshot.downloadsPath());
    assertEquals("/friends-custom/", snapshot.friendsPath());
    assertEquals("/config-custom/", snapshot.configPath());
    assertEquals("/welcome-custom/", snapshot.welcomePath());
  }

  @Test
  void legacyHttpCategories_whenAccessed_exposeHistoricalCategoryKeys() {
    assertEquals("FProxyToadlet.categoryBrowsing", LegacyHttpCategories.CATEGORY_BROWSING);
    assertEquals("FProxyToadlet.categoryQueue", LegacyHttpCategories.CATEGORY_QUEUE);
    assertEquals("FProxyToadlet.categoryFriends", LegacyHttpCategories.CATEGORY_FRIENDS);
    assertEquals("FProxyToadlet.categoryStatus", LegacyHttpCategories.CATEGORY_STATUS);
    assertEquals("FProxyToadlet.categoryConfig", LegacyHttpCategories.CATEGORY_CONFIG);
  }

  private static PathSnapshot loadPathSnapshot(Map<String, String> overrides) throws Exception {
    Map<String, String> previousValues = new LinkedHashMap<>();
    for (String property : overrides.keySet()) {
      previousValues.put(property, System.getProperty(property));
    }

    try {
      for (Map.Entry<String, String> entry : overrides.entrySet()) {
        if (entry.getValue() == null) {
          System.clearProperty(entry.getKey());
        } else {
          System.setProperty(entry.getKey(), entry.getValue());
        }
      }

      URL classesLocation =
          LegacyHttpPaths.class.getProtectionDomain().getCodeSource().getLocation();
      try (URLClassLoader loader = new URLClassLoader(new URL[] {classesLocation}, null)) {
        Class<?> reloadedClass =
            Class.forName("network.crypta.clients.http.LegacyHttpPaths", true, loader);
        return new PathSnapshot(
            readStaticString(reloadedClass, "DOWNLOADS_PATH"),
            readStaticString(reloadedClass, "FRIENDS_PATH"),
            readStaticString(reloadedClass, "CONFIG_PATH"),
            readStaticString(reloadedClass, "WELCOME_PATH"));
      }
    } finally {
      for (Map.Entry<String, String> entry : previousValues.entrySet()) {
        if (entry.getValue() == null) {
          System.clearProperty(entry.getKey());
        } else {
          System.setProperty(entry.getKey(), entry.getValue());
        }
      }
    }
  }

  private static String readStaticString(Class<?> clazz, String fieldName) throws Exception {
    Field field = clazz.getDeclaredField(fieldName);
    field.setAccessible(true);
    return (String) field.get(null);
  }

  private static Map<String, String> overrides(String... entries) {
    Map<String, String> overrides = new LinkedHashMap<>();
    for (int i = 0; i < entries.length; i += 2) {
      overrides.put(entries[i], entries[i + 1]);
    }
    return overrides;
  }

  private record PathSnapshot(
      String downloadsPath, String friendsPath, String configPath, String welcomePath) {}
}
