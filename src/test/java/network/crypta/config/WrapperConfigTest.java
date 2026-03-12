package network.crypta.config;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.tanukisoftware.wrapper.WrapperManager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings({"java:S100", "java:S3011"})
@ExtendWith(MockitoExtension.class)
class WrapperConfigTest {

  @BeforeEach
  void setUp() throws Exception {
    // Clear static overrides map to avoid cross-test pollution
    Field f = WrapperConfig.class.getDeclaredField("overrides");
    f.setAccessible(true);
    @SuppressWarnings("unchecked")
    Map<String, String> map = (Map<String, String>) f.get(null);
    map.clear();

    // Ensure repository-root wrapper artifacts are absent before each test
    cleanupRootWrapperFiles();
  }

  @AfterEach
  void tearDown() {
    cleanupRootWrapperFiles();
  }

  private static Path repoRoot() {
    return Path.of(System.getProperty("user.dir")).toAbsolutePath();
  }

  @SuppressWarnings(
      "java:S1166") // best-effort cleanup in tests; ignoring deletion failures is OK here
  private static void cleanupRootWrapperFiles() {
    try {
      Path root = repoRoot();
      Path wrapperDir = root.resolve("wrapper");
      // Top-level variants
      Files.deleteIfExists(root.resolve("wrapper.conf"));
      Files.deleteIfExists(root.resolve("wrapper.conf.new"));
      Files.deleteIfExists(root.resolve("wrapper.conf.old"));
      // Nested variants under wrapper/
      Files.deleteIfExists(wrapperDir.resolve("wrapper.conf"));
      Files.deleteIfExists(wrapperDir.resolve("wrapper.conf.new"));
      Files.deleteIfExists(wrapperDir.resolve("wrapper.conf.old"));
    } catch (IOException _) {
      // ignore cleanup errors
    }
  }

  @Test
  void getWrapperProperty_whenOverridePresent_returnsOverride() throws Exception {
    // Arrange
    Field f = WrapperConfig.class.getDeclaredField("overrides");
    f.setAccessible(true);
    @SuppressWarnings("unchecked")
    Map<String, String> map = (Map<String, String>) f.get(null);
    map.put("my.prop", "override");

    // Also mock WrapperManager to prove override takes precedence
    try (MockedStatic<WrapperManager> mocked = Mockito.mockStatic(WrapperManager.class)) {
      Properties props = new Properties();
      props.setProperty("my.prop", "fromWrapper");
      mocked.when(WrapperManager::getProperties).thenReturn(props);

      // Act
      String value = WrapperConfig.getWrapperProperty("my.prop");

      // Assert
      assertEquals("override", value);
    }
  }

  @Test
  void getWrapperProperty_whenNoOverride_readsFromWrapperManager() {
    // Arrange
    try (MockedStatic<WrapperManager> mocked = Mockito.mockStatic(WrapperManager.class)) {
      Properties props = new Properties();
      props.setProperty("foo", "bar");
      mocked.when(WrapperManager::getProperties).thenReturn(props);

      // Act
      String value = WrapperConfig.getWrapperProperty("foo");

      // Assert
      assertEquals("bar", value);
    }
  }

  @Test
  void getWrapperProperty_whenAbsent_returnsNull() {
    // Arrange
    try (MockedStatic<WrapperManager> mocked = Mockito.mockStatic(WrapperManager.class)) {
      Properties props = new Properties();
      mocked.when(WrapperManager::getProperties).thenReturn(props);

      // Act
      String value = WrapperConfig.getWrapperProperty("does.not.exist");

      // Assert
      assertNull(value);
    }
  }

  @Test
  void canChangeProperties_whenNotUnderWrapper_returnsFalse() {
    // Arrange
    try (MockedStatic<WrapperManager> mocked = Mockito.mockStatic(WrapperManager.class)) {
      mocked.when(WrapperManager::isControlledByNativeWrapper).thenReturn(false);

      // Act / Assert
      assertFalse(WrapperConfig.canChangeProperties());
    }
  }

  @Test
  void canChangeProperties_whenWrapperConfMissing_returnsFalse() {
    // Arrange
    try (MockedStatic<WrapperManager> mocked = Mockito.mockStatic(WrapperManager.class)) {
      mocked.when(WrapperManager::isControlledByNativeWrapper).thenReturn(true);

      // No wrapper.conf anywhere under tempDir
      // Act / Assert
      assertFalse(WrapperConfig.canChangeProperties());
    }
  }

  @Test
  void canChangeProperties_whenReadableWritable_parentWritable_returnsTrue() throws IOException {
    // Arrange
    try (MockedStatic<WrapperManager> mocked = Mockito.mockStatic(WrapperManager.class)) {
      mocked.when(WrapperManager::isControlledByNativeWrapper).thenReturn(true);

      Path wrapper = repoRoot().resolve("wrapper");
      Files.createDirectories(wrapper);
      Path conf = wrapper.resolve("wrapper.conf");
      Files.writeString(conf, "# test conf\n");

      // Act / Assert
      assertTrue(WrapperConfig.canChangeProperties());
    }
  }

  @Test
  @Tag("io")
  void setWrapperProperty_whenPropertyExists_updatesValueAndKeepsReload() throws Exception {
    // Arrange: wrapper/wrapper.conf exists with the target property and reload flag present
    Path wrapper = repoRoot().resolve("wrapper");
    Files.createDirectories(wrapper);
    Path conf = wrapper.resolve("wrapper.conf");
    String initial =
        """
        foo=bar
        my.key=old
        wrapper.restart.reload_configuration=TRUE
        other=val
        """
            .stripTrailing();
    Files.writeString(conf, initial + "\n");

    // Act
    boolean ok = WrapperConfig.setWrapperProperty("my.key", "new");

    // Assert
    assertTrue(ok);
    String content = Files.readString(conf, StandardCharsets.UTF_8);
    // Ensure updated exactly once and reload flag preserved exactly once
    assertTrue(content.contains("my.key=new"));
    assertFalse(content.contains("my.key=old"));

    long reloadCount =
        content
            .lines()
            .filter(l -> l.equalsIgnoreCase("wrapper.restart.reload_configuration=TRUE"))
            .count();
    assertEquals(1L, reloadCount);

    // And getWrapperProperty should reflect the override set by setWrapperProperty
    try (MockedStatic<WrapperManager> mocked = Mockito.mockStatic(WrapperManager.class)) {
      Properties props = new Properties();
      mocked.when(WrapperManager::getProperties).thenReturn(props);
      assertEquals("new", WrapperConfig.getWrapperProperty("my.key"));
    }
  }

  @Test
  @Tag("io")
  void setWrapperProperty_whenMissingProperty_appendsPropertyAndReload() throws Exception {
    // Arrange: wrapper.conf without the target property and without reload flag
    Path wrapper = repoRoot().resolve("wrapper");
    Files.createDirectories(wrapper);
    Path conf = wrapper.resolve("wrapper.conf");
    Files.writeString(conf, "foo=bar\n");

    // Act
    boolean ok = WrapperConfig.setWrapperProperty("added.key", "value");

    // Assert
    assertTrue(ok);
    String content = Files.readString(conf, StandardCharsets.UTF_8);
    assertTrue(content.contains("added.key=value"));
    assertTrue(
        content.toLowerCase(Locale.ROOT).contains("wrapper.restart.reload_configuration=true"));
  }

  @Test
  @Tag("io")
  void setWrapperProperty_whenNoWrapperConf_returnsFalse() {
    // Arrange: no wrapper/ and no top-level wrapper.conf
    // Act
    boolean ok = WrapperConfig.setWrapperProperty("k", "v");

    // Assert
    assertFalse(ok);
    // Ensure no config files were created implicitly
    Path root = repoRoot();
    assertFalse(Files.exists(root.resolve("wrapper.conf")));
    assertFalse(Files.exists(root.resolve("wrapper.conf.new")));
  }

  @Test
  @Tag("io")
  void setWrapperProperty_whenTopLevelConf_updatesUsingFallbackLocation() throws Exception {
    // Arrange: Only top-level wrapper.conf exists (no wrapper/ directory)
    Path conf = repoRoot().resolve("wrapper.conf");
    Files.writeString(conf, "foo=bar\n");

    // Act
    boolean ok = WrapperConfig.setWrapperProperty("top.level", "ok");

    // Assert
    assertTrue(ok);
    String content = Files.readString(conf, StandardCharsets.UTF_8);
    assertTrue(content.contains("top.level=ok"));
    assertTrue(
        content.toLowerCase(Locale.ROOT).contains("wrapper.restart.reload_configuration=true"));
  }
}
