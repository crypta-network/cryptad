package network.crypta.l10n;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.pluginmanager.FredPluginBaseL10n;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class PluginL10nTest {

  @Mock private FredPluginBaseL10n plugin;

  @TempDir Path tempDir;

  private BaseL10n nodeBaseBefore;

  @BeforeEach
  void captureNodeL10n() {
    // Capture current NodeL10n Base to restore after tests that change it.
    nodeBaseBefore = NodeL10n.getBase();
  }

  @AfterEach
  void restoreNodeL10n() {
    // Restore static NodeL10n Base to avoid cross-test interference.
    NodeL10n.setBase(nodeBaseBefore);
  }

  @Test
  void constructor_withExplicitLanguage_initializesBaseWithPluginParameters() {
    // Arrange
    String basePathNoSlash = "com/acme/plugin/l10n"; // deliberately no trailing '/'
    String mask = "messages_${lang}.l10n";
    String overrideMask = tempDir.resolve("plugin-${lang}.override").toString();

    RecordingClassLoader rcl = new RecordingClassLoader(PluginL10nTest.class.getClassLoader());

    org.mockito.Mockito.when(plugin.getL10nFilesBasePath()).thenReturn(basePathNoSlash);
    org.mockito.Mockito.when(plugin.getL10nFilesMask()).thenReturn(mask);
    org.mockito.Mockito.when(plugin.getL10nOverrideFilesMask()).thenReturn(overrideMask);
    org.mockito.Mockito.when(plugin.getPluginClassLoader()).thenReturn(rcl);

    LANGUAGE lang = LANGUAGE.FRENCH;
    String expectedResource =
        normalizedPath(basePathNoSlash) + mask.replace("${lang}", lang.shortCode);

    // Provide minimal valid SimpleFieldSet content for the expected resource path.
    rcl.addResource(expectedResource, "hello=world\nEnd\n");

    // Act
    PluginL10n underTest = new PluginL10n(plugin, lang);
    BaseL10n base = underTest.getBase();

    // Assert
    assertNotNull(base, "BaseL10n must be created");
    assertEquals(
        lang, base.getSelectedLanguage(), "Selected language should match the constructor");
    assertEquals(
        expectedResource, base.getL10nFileName(lang), "Resource path must reflect plugin masks");
    assertEquals(
        overrideMask.replace("${lang}", lang.shortCode),
        base.getL10nOverrideFileName(lang),
        "Override mask must reflect plugin mask");
    assertEquals(
        expectedResource,
        rcl.getLastRequested(),
        "ClassLoader should be asked for the expected resource");
  }

  @Test
  void constructor_withNodeSelectedLanguage_usesNodeLanguage() {
    // Arrange: set NodeL10n to a non-default language to verify the 1-arg constructor picks it up.
    LANGUAGE nodeLang = LANGUAGE.SPANISH;
    new NodeL10n(nodeLang, tempDir.toFile());

    String basePath = "com/acme/plugin/l10n/"; // already normalized
    String mask = "messages_${lang}.l10n";
    String overrideMask = tempDir.resolve("plugin-${lang}.override").toString();

    RecordingClassLoader rcl = new RecordingClassLoader(PluginL10nTest.class.getClassLoader());
    org.mockito.Mockito.when(plugin.getL10nFilesBasePath()).thenReturn(basePath);
    org.mockito.Mockito.when(plugin.getL10nFilesMask()).thenReturn(mask);
    org.mockito.Mockito.when(plugin.getL10nOverrideFilesMask()).thenReturn(overrideMask);
    org.mockito.Mockito.when(plugin.getPluginClassLoader()).thenReturn(rcl);

    String expectedResource = basePath + mask.replace("${lang}", nodeLang.shortCode);
    rcl.addResource(expectedResource, "k=v\nEnd\n");

    // Act
    PluginL10n underTest = new PluginL10n(plugin);
    BaseL10n base = underTest.getBase();

    // Assert
    assertEquals(
        nodeLang, base.getSelectedLanguage(), "Constructor must use NodeL10n's selected language");
    assertEquals(
        expectedResource,
        rcl.getLastRequested(),
        "ClassLoader should be asked for resource in Node language");
  }

  @Test
  void constructor_withNullPlugin_expectNullPointerException() {
    // Arrange/Act/Assert
    assertThrows(NullPointerException.class, () -> new PluginL10n(null));
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> new PluginL10n(null, LANGUAGE.ENGLISH));
  }

  @Test
  void getBase_whenCalledTwice_returnsSameInstance() {
    // Arrange
    org.mockito.Mockito.when(plugin.getL10nFilesBasePath()).thenReturn("com/acme/plugin/l10n");
    org.mockito.Mockito.when(plugin.getL10nFilesMask()).thenReturn("messages_${lang}.l10n");
    org.mockito.Mockito.when(plugin.getL10nOverrideFilesMask())
        .thenReturn(tempDir.resolve("plugin-${lang}.override").toString());
    org.mockito.Mockito.when(plugin.getPluginClassLoader())
        .thenReturn(new RecordingClassLoader(PluginL10nTest.class.getClassLoader()));

    PluginL10n underTest = new PluginL10n(plugin, LANGUAGE.GERMAN);

    // Act
    BaseL10n first = underTest.getBase();
    BaseL10n second = underTest.getBase();

    // Assert
    assertSame(first, second, "getBase() should consistently return the same instance");
  }

  // --- helpers ---

  private static String normalizedPath(String basePath) {
    return basePath.endsWith("/") ? basePath : (basePath + "/");
  }

  /** ClassLoader that records the last requested resource name and can serve predefined content. */
  private static final class RecordingClassLoader extends ClassLoader {
    private volatile String lastRequested;
    private String resourceName;
    private byte[] payload;

    RecordingClassLoader(ClassLoader parent) {
      super(parent);
    }

    void addResource(String name, String content) {
      this.resourceName = name;
      this.payload = content.getBytes(StandardCharsets.UTF_8);
    }

    String getLastRequested() {
      return lastRequested;
    }

    @Override
    public InputStream getResourceAsStream(String name) {
      lastRequested = name;
      if (resourceName != null && resourceName.equals(name)) {
        return new ByteArrayInputStream(payload);
      }
      return null;
    }
  }
}
