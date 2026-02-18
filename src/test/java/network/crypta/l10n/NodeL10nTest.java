package network.crypta.l10n;

import java.io.File;
import java.nio.file.Path;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;

@SuppressWarnings("java:S100") // descriptive test method names
class NodeL10nTest {

  private BaseL10n originalBase;

  @BeforeEach
  void captureOriginalBase() {
    // Capture and restore to avoid leaking global state into other tests
    originalBase = NodeL10n.getBase();
  }

  @AfterEach
  void restoreOriginalBase() {
    NodeL10n.setBase(originalBase);
  }

  @Test
  void getBase_whenUninitialized_initializesWithDefaultLanguageAndPaths() {
    // Arrange
    NodeL10n.setBase(null); // force lazy initialization path

    // Act
    BaseL10n base = NodeL10n.getBase();

    // Assert
    assertNotNull(base);
    assertEquals(LANGUAGE.ENGLISH, base.getSelectedLanguage());

    String expectedOverride =
        new File(new File(".").getPath(), "crypta.l10n.en.override.properties").toString();
    assertEquals(expectedOverride, base.getL10nOverrideFileName(LANGUAGE.ENGLISH));

    assertEquals(
        "network/crypta/l10n/crypta.l10n.en.properties", base.getL10nFileName(LANGUAGE.ENGLISH));
  }

  @Test
  void constructor_withLanguageAndOverrideDir_setsLanguageAndOverrideMask(@TempDir Path tmp) {
    // Arrange
    new NodeL10n(LANGUAGE.GERMAN, tmp.toFile());

    // Act
    BaseL10n base = NodeL10n.getBase();

    // Assert
    assertEquals(LANGUAGE.GERMAN, base.getSelectedLanguage());
    String expected = tmp.resolve("crypta.l10n.de.override.properties").toString();
    assertEquals(expected, base.getL10nOverrideFileName(LANGUAGE.GERMAN));
  }

  @Test
  void setBase_whenProvided_replacesGlobalInstance() {
    // Arrange: install a dedicated BaseL10n that uses test resources
    BaseL10n custom = L10nTestUtils.createTestL10n(LANGUAGE.ENGLISH);

    // Act
    NodeL10n.setBase(custom);

    // Assert
    assertSame(custom, NodeL10n.getBase());
    // sanity: verify the test resource is actually used
    assertEquals("Sane", NodeL10n.getBase().getString("test.sanity"));
  }

  @Test
  void getBase_whenCalledTwice_returnsSameInstance() {
    // Arrange
    BaseL10n first = NodeL10n.getBase();

    // Act
    BaseL10n second = NodeL10n.getBase();

    // Assert
    assertSame(first, second);
  }
}
