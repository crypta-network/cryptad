package network.crypta.l10n;

import java.io.File;
import network.crypta.l10n.BaseL10n.LANGUAGE;
import network.crypta.support.TestProperty;

/**
 * Shared helper for tests outside {@code network.crypta.l10n} that need {@link BaseL10n} instances
 * or to install the test translation bundle. The utilities live in a dedicated class so tests can
 * keep package-private visibility without exposing {@code BaseL10nTest} as public.
 */
public final class L10nTestUtils {

  private L10nTestUtils() {}

  public static BaseL10n createL10n(LANGUAGE lang) {
    File overrideFile =
        new File(TestProperty.L10nPath_main, "crypta.l10n.${lang}.override.properties");
    return new BaseL10n(
        "network/crypta/l10n/", "crypta.l10n.${lang}.properties", overrideFile.getPath(), lang);
  }

  public static BaseL10n createTestL10n(LANGUAGE lang) {
    File overrideFile =
        new File(TestProperty.L10nPath_test, "crypta.l10n.${lang}.override.properties");
    return new BaseL10n(
        "network/crypta/l10n/",
        "crypta.l10n.${lang}.test.properties",
        overrideFile.getPath(),
        lang);
  }

  /**
   * Installs a test {@link BaseL10n} with translations read from the test classpath into the global
   * {@link NodeL10n}, allowing tests for translation keys.
   */
  public static void useTestTranslation() {
    NodeL10n.setBase(createTestL10n(LANGUAGE.ENGLISH));
  }
}
