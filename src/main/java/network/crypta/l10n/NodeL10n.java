package network.crypta.l10n;

import java.io.File;
import network.crypta.l10n.BaseL10n.LANGUAGE;

/**
 * Static façade for node localization.
 *
 * <p>This class configures and exposes a single shared {@link BaseL10n} instance used across the
 * node. Application code obtains the instance via {@link #getBase()} and calls its methods to look
 * up translations.
 *
 * <p>Constructing {@code NodeL10n} reinitializes the shared {@link BaseL10n} with the provided
 * language and override location. This design keeps call sites simple (static access) while still
 * allowing the language to be switched during startup or tests by creating a new {@code NodeL10n}.
 *
 * <h2>Thread-safety</h2>
 *
 * <p>Initialization is lazy and not synchronized. Creating multiple {@code NodeL10n} instances
 * concurrently may cause the underlying instance to be assigned more than once; the last write
 * wins. Typical usage initializes this class once during startup.
 */
public final class NodeL10n {
  /** Ensure the newly created BaseL10n is non-null (instance-only helper). */
  private void ensureInitialized(BaseL10n base) {
    if (base == null) {
      throw new IllegalArgumentException("baseL10n must not be null");
    }
  }

  /**
   * Initialize localization using the default language and working-directory overrides.
   *
   * <p>Side effect: replaces the shared {@link BaseL10n} used by the application. Subsequent calls
   * to {@link #getBase()} return the new instance.
   */
  public NodeL10n() {
    BaseL10n created =
        new BaseL10n(
            "network/crypta/l10n/",
            "crypta.l10n.${lang}.properties",
            new File(".").getPath() + File.separator + "crypta.l10n.${lang}.override.properties",
            LANGUAGE.getDefault());
    setBase(created);
    ensureInitialized(created);
  }

  /**
   * Initialize localization for a specific language and override directory.
   *
   * <p>Side effect: replaces the shared {@link BaseL10n} used by the application. Subsequent calls
   * to {@link #getBase()} return the new instance.
   *
   * @param lang the language to use; must not be {@code null}
   * @param overrideDir directory whose path is used to resolve on-disk override files; must not be
   *     {@code null}
   * @throws java.util.MissingResourceException if {@code lang} is {@code null}
   * @see LANGUAGE#mapToLanguage(String)
   */
  public NodeL10n(final LANGUAGE lang, File overrideDir) {
    BaseL10n created =
        new BaseL10n(
            "network/crypta/l10n/",
            "crypta.l10n.${lang}.properties",
            overrideDir.getPath() + File.separator + "crypta.l10n.${lang}.override.properties",
            lang);
    setBase(created);
    ensureInitialized(created);
  }

  /**
   * Return the shared {@link BaseL10n} used for localization.
   *
   * <p>Lazy-initializes the instance to the default language with working-directory overrides when
   * first called.
   *
   * @return the non-{@code null} shared instance
   * @see BaseL10n
   */
  public static BaseL10n getBase() {
    if (b == null) {
      // Lazily create the default configuration on first access.
      new NodeL10n();
    }
    return b;
  }

  /**
   * Replace the shared {@link BaseL10n} used by the node.
   *
   * <p>Primarily intended for tests and bootstrap wiring. Calling this method updates the instance
   * returned by {@link #getBase()} for all callers.
   *
   * @param baseL10n the instance to expose globally; may be {@code null} to clear and trigger lazy
   *     reinitialization on next {@link #getBase()} call
   */
  static void setBase(BaseL10n baseL10n) {
    b = baseL10n;
  }

  /** Lazily-initialized shared localization instance. Guarded by {@link #getBase()}. */
  private static BaseL10n b;
}
