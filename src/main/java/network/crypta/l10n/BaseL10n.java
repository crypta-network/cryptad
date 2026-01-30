package network.crypta.l10n;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.MissingResourceException;
import java.util.NoSuchElementException;
import java.util.regex.Pattern;
import network.crypta.clients.http.TranslationToadlet;
import network.crypta.support.HTMLNode;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.FileUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Core localization utility for loading translated strings from {@link SimpleFieldSet} resources.
 * Supports explicit language selection, lookup with a fallback language, and on-disk overrides.
 *
 * <p>Resolution order for a key:
 *
 * <ol>
 *   <li>Override file for the selected language, if present
 *   <li>Translation for the selected language
 *   <li>Translation in the fallback language ({@link LANGUAGE#getDefault()}; currently English)
 *   <li>The key itself if no translation is available
 * </ol>
 *
 * <p>Instances are stateful (selected language and overrides). Only {@link #loadFallback()} is
 * synchronized; coordinate externally if sharing an instance across threads.
 *
 * <p>Do not use this class directly in application code; prefer {@code NodeL10n.getBase()} or
 * {@code PluginL10n.getBase()}.
 *
 * <p>This class also supports reading, saving, and editing overridden translations on disk.
 *
 * @author Florent Daigni&egrave;re &lt;nextgens@freenetproject.org&gt;
 * @author Artefact2
 */
public class BaseL10n {
  private static final Logger LOG = LoggerFactory.getLogger(BaseL10n.class);

  // Sonar: de-duplicate common literals used in this class
  private static final String L10N_VAR_PREFIX = "\\$\\{"; // matches "${"
  private static final String L10N_VAR_SUFFIX = "}"; // matches "}"
  private static final String UNLISTED_LITERAL = "unlisted";

  /**
   * Registry of supported languages. Each enum constant defines a short code (RFC 5646 or ISO 639),
   * a display name, an installer {@code isoCode}, and optional Windows locale aliases.
   *
   * <p>Note: This list is manually maintained. If it is ever replaced, prefer a standards-based
   * source backed by {@link Locale}. The preferred target is IETF language tags (RFC 5646), which
   * combine ISO 639-3 with standard region tags and are natively understood by {@link Locale}.
   *
   * @see "http://www.omniglot.com/language/names.htm"
   * @see "http://loc.gov/standards/iso639-2/php/code_list.php"
   * @see "http://tools.ietf.org/html/rfc5646"
   */
  @SuppressWarnings("ImmutableEnumChecker")
  public enum LANGUAGE {

    // Windows language codes must be preceded with WINDOWS and be in upper case hex, 4 digits.
    // See http://www.autohotkey.com/docs/misc/Languages.htm

    CROATIAN("hr", "Hrvatski", "hrv", new String[] {"WINDOWS041A"}),
    ENGLISH(
        "en",
        "English",
        "eng",
        new String[] {
          "WINDOWS0409",
          "WINDOWS0809",
          "WINDOWS0C09",
          "WINDOWS1009",
          "WINDOWS1409",
          "WINDOWS1809",
          "WINDOWS1C09",
          "WINDOWS2009",
          "WINDOWS2409",
          "WINDOWS2809",
          "WINDOWS2C09",
          "WINDOWS3009",
          "WINDOWS3409"
        }),
    HUNGARIAN("hu", "magyar", "hun", new String[] {"WINDOWS040E"}),
    SPANISH(
        "es",
        "Español",
        "spa",
        new String[] {
          "WINDOWS040A",
          "WINDOWS080A",
          "WINDOWS0C0A",
          "WINDOWS100A",
          "WINDOWS140A",
          "WINDOWS180A",
          "WINDOWS1C0A",
          "WINDOWS200A",
          "WINDOWS240A",
          "WINDOWS280A",
          "WINDOWS2C0A",
          "WINDOWS300A",
          "WINDOWS340A",
          "WINDOWS380A",
          "WINDOWS3C0A",
          "WINDOWS400A",
          "WINDOWS440A",
          "WINDOWS480A",
          "WINDOWS4C0A",
          "WINDOWS500A"
        }),
    DANISH("da", "Dansk", "dan", new String[] {"WINDOWS0406"}),
    DUTCH("nl", "Nederlands", "nld", new String[] {"WINDOWS0413", "WINDOWS0813"}),
    GERMAN(
        "de",
        "Deutsch",
        "deu",
        new String[] {"WINDOWS0407", "WINDOWS0807", "WINDOWS0C07", "WINDOWS1007", "WINDOWS1407"}),
    FINNISH("fi", "Suomi", "fin", new String[] {"WINDOWS040B"}),
    FRENCH(
        "fr",
        "Français",
        "fra",
        new String[] {
          "WINDOWS040C", "WINDOWS080C", "WINDOWS0C0C", "WINDOWS100C", "WINDOWS140C", "WINDOWS180C"
        }),
    ITALIAN("it", "Italiano", "ita", new String[] {"WINDOWS0410", "WINDOWS0810"}),
    // RFC 5646 non-compliant. Rename when converting the entire list to RFC 5646; provide a
    // migration path to avoid breaking plugin identifiers.
    NORWEGIAN("nb-no", "Bokmål", "nob", new String[] {"WINDOWS0414", "WINDOWS0814"}),
    POLISH("pl", "Polski", "pol", new String[] {"WINDOWS0415"}),
    SWEDISH("sv", "Svenska", "swe", new String[] {"WINDOWS041D", "WINDOWS081D"}),
    // RFC 5646 non-compliant. Rename when converting the entire list to RFC 5646; provide a
    // migration path to avoid breaking plugin identifiers.
    CHINESE("zh-cn", "中文(简体)", "chn", new String[] {"WINDOWS0804", "WINDOWS1004"}),
    // simplified chinese, used on mainland, Singapore and Malaysia
    // RFC 5646 non-compliant. Rename when converting the entire list to RFC 5646; provide a
    // migration path to avoid breaking plugin identifiers.
    CHINESE_TAIWAN(
        "zh-tw", "中文(繁體)", "zh-tw", new String[] {"WINDOWS0404", "WINDOWS0C04", "WINDOWS1404"}),
    // traditional chinese, used in Taiwan, Hong Kong and Macau
    RUSSIAN(
        "ru",
        "Русский",
        "rus",
        new String[] {
          "WINDOWS0419"
        }), // Just one variant for russian. Belorussian is separate, code page 423, speakers may or
    // may not speak russian, I'm not including it.
    JAPANESE("ja", "日本語", "jpn", new String[] {"WINDOWS0411"}),
    PORTUGUESE("pt-PT", "Português do Portugal", "pt", new String[] {"WINDOWS0816"}),
    // RFC 5646 non-compliant. Rename when converting the entire list to RFC 5646; provide a
    // migration path to avoid breaking plugin identifiers.
    BRAZILIAN_PORTUGUESE("pt-br", "Português do Brasil", "pt-br", new String[] {"WINDOWS0416"}),
    GREEK("el", "Ελληνικά", "ell", new String[] {"WINDOWS0408"}),
    UNLISTED(UNLISTED_LITERAL, UNLISTED_LITERAL, UNLISTED_LITERAL, new String[] {});

    /** Internal identifier; must be unique. */
    public final String shortCode;

    /** Display name shown to users. */
    public final String fullName;

    /** Installer-facing language identifier; must be unique (see bug #2424). */
    public final String isoCode;

    private final String[] aliases;

    LANGUAGE(String shortCode, String fullName, String isoCode, String[] aliases) {
      this.shortCode = shortCode;
      this.fullName = fullName;
      this.isoCode = isoCode;
      this.aliases = aliases;
    }

    // No copy-constructor; enum constants are fixed.

    /**
     * Map a string to a {@link LANGUAGE} by matching short code, display name, ISO code, enum name
     * (case-insensitive), or platform-specific aliases.
     *
     * @param whatever Short code, full name, ISO code, enum name, or alias.
     * @return The matching language, or {@code null} if none matches.
     */
    public static LANGUAGE mapToLanguage(String whatever) {
      for (LANGUAGE currentLanguage : LANGUAGE.values()) {
        if (currentLanguage.shortCode.equalsIgnoreCase(whatever)
            || currentLanguage.fullName.equalsIgnoreCase(whatever)
            || currentLanguage.isoCode.equalsIgnoreCase(whatever)
            || currentLanguage.toString().equalsIgnoreCase(whatever)) {
          return currentLanguage;
        }
        if (currentLanguage.aliases != null) {
          for (String s : currentLanguage.aliases)
            if (whatever.equalsIgnoreCase(s)) return currentLanguage;
        }
      }
      return null;
    }

    /**
     * Return all display names in alphabetical order, with the special {@code UNLISTED} entry
     * appended at the end.
     *
     * @return Sorted array of display names ending with {@code "unlisted"}.
     */
    public static String[] valuesWithFullNames() {
      LANGUAGE[] allValues = values();
      ArrayList<String> result = new ArrayList<>(allValues.length);
      for (LANGUAGE allValue : allValues) {
        // We will return the full names sorted alphabetically. To ensure that the user
        // notices the special "UNLISTED" language code, we add it to the end of the list
        // after sorting, so now we skip it.
        if (allValue != UNLISTED) result.add(allValue.fullName);
      }

      Collections.sort(result);
      result.add(UNLISTED.fullName);

      return result.toArray(new String[0]);
    }

    /**
     * Default language used as fallback for missing translations.
     *
     * @return Default language constant.
     */
    public static LANGUAGE getDefault() {
      return ENGLISH;
    }
  }

  /**
   * State enum for {@link L10nStringIterator}. Declared here for {@link #getStrings(String,
   * FallbackState)}.
   */
  private enum FallbackState {
    CURRENT_LANG,
    FALLBACK_LANG,
    KEY,
    END
  }

  /**
   * Iterator that returns the strings associated with a key in order of preference. First the value
   * in the current language (if any), then the value in the fallback language (if any), and then
   * just the key itself.
   */
  private class L10nStringIterator implements Iterator<String> {
    private final String key;
    private FallbackState state;

    public L10nStringIterator(String key, FallbackState state) {
      this.key = key;
      this.state = state;
    }

    @Override
    public boolean hasNext() {
      return state != FallbackState.END;
    }

    @Override
    public String next() {
      if (state == FallbackState.CURRENT_LANG) {
        state = FallbackState.FALLBACK_LANG;
        String value = getString(key, true);
        if (value != null) {
          return value;
        }
      }
      if (state == FallbackState.FALLBACK_LANG) {
        state = FallbackState.KEY;
        if (getSelectedLanguage() != LANGUAGE.getDefault()) {
          String value = getFallbackString(key);
          if (value != null) {
            return value;
          }
        }
      }
      if (state == FallbackState.KEY) {
        state = FallbackState.END;
        return key;
      }
      throw new NoSuchElementException();
    }

    @Override
    public void remove() {
      throw new UnsupportedOperationException();
    }

    private String getFallbackString(String key) {
      BaseL10n.this.loadFallback();
      String result = BaseL10n.this.fallbackTranslation.get(key);
      if (result == null) {
        LOG.error("The default translation for {} hasn't been found!", key);
      }
      return result;
    }
  }

  private LANGUAGE lang;
  private final String l10nFilesBasePath;
  private final String l10nFilesMask;
  private final String l10nOverrideFilesMask;
  private SimpleFieldSet currentTranslation = null;
  private SimpleFieldSet fallbackTranslation = null;
  private SimpleFieldSet translationOverride;
  private final ClassLoader cl;

  /**
   * Resolve a class loader for resource lookups. Falls back to the system class loader when the
   * defining loader is {@code null} (e.g., boot class loader).
   */
  private static ClassLoader getClassLoaderFallback() {
    ClassLoader loader;
    // getClassLoader() can return null on some implementations if the boot classloader was used.
    loader = BaseL10n.class.getClassLoader();
    if (loader == null) {
      loader = ClassLoader.getSystemClassLoader();
    }
    return loader;
  }

  public BaseL10n(String l10nFilesBasePath, String l10nFilesMask, String l10nOverrideFilesMask) {
    this(l10nFilesBasePath, l10nFilesMask, l10nOverrideFilesMask, LANGUAGE.getDefault());
  }

  public BaseL10n(
      String l10nFilesBasePath,
      String l10nFilesMask,
      String l10nOverrideFilesMask,
      final LANGUAGE lang) {
    this(l10nFilesBasePath, l10nFilesMask, l10nOverrideFilesMask, lang, getClassLoaderFallback());
  }

  /**
   * Create a new instance.
   *
   * <p>Prefer using higher-level helpers in application code ({@code NodeL10n} / {@code
   * PluginL10n}).
   *
   * @param l10nFilesBasePath Base path under which l10n resources live, for example {@code
   *     "com/mycorp/myproject/l10n"}. A trailing slash is added if missing.
   * @param l10nFilesMask File mask for the language resources, for example {@code
   *     "messages_${lang}.l10n"} where {@code ${lang}} is replaced by the language short code.
   * @param l10nOverrideFilesMask File path for on-disk overrides for the selected language.
   * @param lang Language to select initially.
   * @param cl Class loader used to resolve bundled l10n resources.
   */
  public BaseL10n(
      String l10nFilesBasePath,
      String l10nFilesMask,
      String l10nOverrideFilesMask,
      final LANGUAGE lang,
      final ClassLoader cl) {
    if (!l10nFilesBasePath.endsWith("/")) {
      l10nFilesBasePath += "/";
    }

    this.l10nFilesBasePath = l10nFilesBasePath;
    this.l10nFilesMask = l10nFilesMask;
    this.l10nOverrideFilesMask = l10nOverrideFilesMask;
    this.cl = cl;
    this.setLanguage(lang);
  }

  /**
   * Build the resource path for the specified language using the configured mask.
   *
   * @param lang Language whose resource path should be generated.
   * @return Resource path constructed from {@code l10nFilesBasePath} and {@code l10nFilesMask}.
   */
  public String getL10nFileName(LANGUAGE lang) {
    return this.l10nFilesBasePath + this.l10nFilesMask.replace("${lang}", lang.shortCode);
  }

  /**
   * Build the on-disk override file path for the specified language using the configured mask.
   *
   * @param lang Language whose override path should be generated.
   * @return File path constructed from {@code l10nOverrideFilesMask}.
   */
  public String getL10nOverrideFileName(LANGUAGE lang) {
    return this.l10nOverrideFilesMask.replace("${lang}", lang.shortCode);
  }

  /**
   * Select a new language and load its translation and overrides.
   *
   * <p>If no bundled translation exists for the language, the instance keeps an empty translation
   * set and will fall back to the default language at lookup time. Override files (or their backup)
   * are also loaded when present.
   *
   * @param selectedLanguage New language to use (must not be {@code null}).
   * @throws MissingResourceException If {@code selectedLanguage} is {@code null}.
   */
  public void setLanguage(final LANGUAGE selectedLanguage) throws MissingResourceException {
    if (selectedLanguage == null) {
      throw new MissingResourceException("LANGUAGE given is null !", this.getClass().getName(), "");
    }

    this.lang = selectedLanguage;

    LOG.info("Changing the current language to : {}", this.lang);

    try {
      this.loadOverrideFileOrBackup();
    } catch (IOException e) {
      this.translationOverride = null;
      LOG.error("IOError while accessing the file!{}", e.getMessage(), e);
    }

    this.currentTranslation = this.loadTranslation(lang);
    if (this.currentTranslation == null) {
      LOG.error(
          "The translation file for {} is invalid. The node will load an empty template.", lang);
      this.currentTranslation = null;
    }
  }

  /**
   * Load the override file for the current language, or its {@code .bak} backup if necessary. Sets
   * {@link #translationOverride} accordingly.
   *
   * @throws IOException If reading either file fails.
   */
  private void loadOverrideFileOrBackup() throws IOException {
    final File tmpFile = new File(this.getL10nOverrideFileName(this.lang));
    if (tmpFile.exists() && tmpFile.canRead() && tmpFile.length() > 0) {
      LOG.info("Override file detected : let's try to load it");
      this.translationOverride = SimpleFieldSet.readFrom(tmpFile, false, false);
    } else {
      // try to restore a backup
      final File backup = new File(tmpFile.getParentFile(), tmpFile.getName() + ".bak");
      if (backup.exists() && backup.length() > 0) {
        LOG.info("Override-backup file detected : let's try to load it");
        this.translationOverride = SimpleFieldSet.readFrom(backup, false, false);
      } else {
        this.translationOverride = null;
      }
    }
  }

  /**
   * Load and parse the bundled l10n resource for a language.
   *
   * @param lang Language to use.
   * @return Parsed {@link SimpleFieldSet}, or {@code null} when the resource is missing or invalid.
   */
  private SimpleFieldSet loadTranslation(LANGUAGE lang) {
    SimpleFieldSet result = null;

    // Returns null on lookup failures:
    try (InputStream in = this.cl.getResourceAsStream(this.getL10nFileName(lang))) {
      if (in != null) {
        result = SimpleFieldSet.readFrom(in, false, false);
      } else {
        if (LOG.isWarnEnabled()) {
          LOG.warn("Could not get resource: {}", this.getL10nFileName(lang));
        }
      }
    } catch (Exception e) {
      if (LOG.isErrorEnabled()) {
        LOG.error(
            "Error while loading the l10n file from {}: {}",
            this.getL10nFileName(lang),
            e.getMessage(),
            e);
      }
      result = null;
    }

    return result;
  }

  /** Ensure the fallback (default) translation is loaded; synchronized for safe init. */
  private synchronized void loadFallback() {
    if (this.fallbackTranslation == null) {
      this.fallbackTranslation = loadTranslation(LANGUAGE.getDefault());
      if (fallbackTranslation == null) fallbackTranslation = new SimpleFieldSet(true);
    }
  }

  /**
   * Return the currently selected language.
   *
   * @return Selected {@link LANGUAGE}; never {@code null} after construction.
   */
  public LANGUAGE getSelectedLanguage() {
    return this.lang;
  }

  /**
   * Determine whether a key has an explicit override for the selected language.
   *
   * @param key Key to check (case-sensitive).
   * @return {@code true} if an override exists; {@code false} otherwise.
   */
  public boolean isOverridden(String key) {
    if (this.translationOverride == null) {
      return false;
    }
    return this.translationOverride.get(key) != null;
  }

  /**
   * Write or remove an on-disk override for a key in the selected language.
   *
   * <p>Whitespace surrounding the key and value is trimmed. When the value is empty, or equals the
   * bundled translation for the current language, the override is removed. Otherwise, the value is
   * normalized by stripping CR/LF/TAB characters and then saved.
   *
   * <p>Persists changes immediately by writing the override file.
   *
   * @param key Key to override.
   * @param value New value for the key.
   */
  public void setOverride(String key, String value) {
    key = key.trim();
    value = value.trim();
    // If no override exists yet, create the container.
    if (this.translationOverride == null) {
      this.translationOverride = new SimpleFieldSet(false);
    }

    // Remove the override when empty or redundant with the bundled translation.
    if (value.isEmpty()
        || (currentTranslation != null && value.equals(this.currentTranslation.get(key)))) {
      this.translationOverride.removeValue(key);
    } else {
      value = value.replaceAll("[\r\n\t]+", "");

      // Set the override value.
      this.translationOverride.putOverwrite(key, value);
      LOG.info("Got a new translation key: set the Override!");
    }

    // Persist overrides to disk.
    saveTranslationFile();
  }

  /**
   * Persist overrides to disk using a temporary file and atomic move.
   *
   * <p>Writes {@code <final>.bak} in the same directory and then moves it into place. If the save
   * fails, the temporary file remains as a backup.
   */
  private void saveTranslationFile() {
    File finalFile = new File(this.getL10nOverrideFileName(this.lang));

    try {
      // We don't set deleteOnExit on it : if the save operation fails, we want a backup
      File tempFile = File.createTempFile(finalFile.getName(), ".bak", finalFile.getParentFile());
      LOG.debug("The temporary filename is : {}", tempFile);

      try (FileOutputStream fos = new FileOutputStream(tempFile)) {
        this.translationOverride.writeToBigBuffer(fos);
      }

      FileUtil.moveTo(tempFile, finalFile);
      LOG.info("Override file saved successfully!");
    } catch (IOException e) {
      LOG.error("Error while saving the translation override: {}", e.getMessage(), e);
    }
  }

  /**
   * Return a defensive copy of the current language's translation set.
   *
   * @return Copy of the current translation, or {@code null} if none is loaded.
   */
  public SimpleFieldSet getCurrentLanguageTranslation() {
    return (this.currentTranslation == null ? null : new SimpleFieldSet(currentTranslation));
  }

  /**
   * Return a defensive copy of the on-disk overrides for the current language.
   *
   * @return Copy of the overrides, or {@code null} if no overrides exist.
   */
  public SimpleFieldSet getOverrideForCurrentLanguageTranslation() {
    return (this.translationOverride == null ? null : new SimpleFieldSet(translationOverride));
  }

  /**
   * Return a defensive copy of the fallback language translation set (default: English).
   *
   * @return Copy of the fallback translation; never {@code null}.
   */
  public SimpleFieldSet getDefaultLanguageTranslation() {
    this.loadFallback();

    return new SimpleFieldSet(this.fallbackTranslation);
  }

  /**
   * Look up a localized string using the resolution order described at the class level.
   *
   * @param key Key to search for.
   * @return The resolved string; if no translation exists, returns the key itself.
   */
  public String getString(String key) {
    return getStrings(key).iterator().next();
  }

  /**
   * Look up a localized string and replace each occurrence of {@code ${...}} with a single
   * replacement value.
   *
   * @param key Key to search for.
   * @param replacementValue Replacement value for all patterns of the form {@code ${...}}.
   * @return The resolved and substituted string; if no translation exists, returns the key with
   *     substitutions applied.
   */
  public String getString(String key, String replacementValue) {
    String string = getStrings(key).iterator().next();
    return string.replaceAll("\\$\\{.*}", replacementValue);
  }

  /**
   * Look up a localized string with optional {@code null} when not found.
   *
   * @param key Key to search for.
   * @param returnNullIfNotFound When {@code true}, returns {@code null} if no translation exists in
   *     either the selected or fallback language; when {@code false}, behaves like {@link
   *     #getString(String)} and returns the key as a last resort.
   * @return The resolved string, or {@code null} depending on {@code returnNullIfNotFound}.
   */
  public String getString(String key, boolean returnNullIfNotFound) {
    if (!returnNullIfNotFound) {
      return getString(key);
    }

    String result = null;
    if (this.translationOverride != null) {
      result = this.translationOverride.get(key);
    }

    if (result != null) {
      return result;
    }

    if (this.currentTranslation != null) {
      result = this.currentTranslation.get(key);
    }

    if (result == null) {
      LOG.info(
          "The translation for {} hasn't been found ({})! please tell the maintainer.",
          key,
          this.getSelectedLanguage());
    }
    return result;
  }

  /** Enumerate strings associated with a key in order of preference. */
  private Iterable<String> getStrings(final String key) {
    return getStrings(key, FallbackState.CURRENT_LANG);
  }

  /**
   * Enumerate strings associated with a key in order of preference, starting with a specified one.
   */
  private Iterable<String> getStrings(final String key, final FallbackState initialState) {
    return () -> new L10nStringIterator(key, initialState);
  }

  /**
   * Wrap a localized string in an {@link HTMLNode} for display on the translation page.
   *
   * @param key Key to search for.
   * @return Text node with the resolved value; if the key is missing, returns a node prompting
   *     translation with a link to {@link TranslationToadlet}.
   */
  public HTMLNode getHTMLNode(String key) {
    return getHTMLNode(key, null, null);
  }

  /**
   * Wrap a localized string in an {@link HTMLNode}, optionally performing pattern substitution.
   *
   * @param key Key to search for.
   * @param patterns Patterns to replace. May be {@code null}; if so, {@code values} must also be
   *     {@code null}.
   * @param values Values to replace patterns with; aligned by index with {@code patterns}.
   * @return Text node with substitutions, or a prompt-to-translate node when the key is missing.
   */
  public HTMLNode getHTMLNode(String key, String[] patterns, String[] values) {
    String value = this.getString(key, true);
    if (value != null) {
      if (patterns != null) return new HTMLNode("#", getString(key, patterns, values));
      else return new HTMLNode("#", value);
    }
    HTMLNode translationField = new HTMLNode("span", "class", "translate_it");
    if (patterns != null) translationField.addChild("#", getDefaultString(key, patterns, values));
    else translationField.addChild("#", getDefaultString(key));
    translationField
        .addChild("a", "href", TranslationToadlet.TOADLET_URL + "?translate=" + key)
        .addChild("small", " (translate it in your native language!)");

    return translationField;
  }

  /**
   * Resolve a key strictly in the fallback language.
   *
   * @param key Key to search for.
   * @return The matching string in the fallback language (English); the raw key if absent there as
   *     well.
   */
  public String getDefaultString(String key) {
    return getStrings(key, FallbackState.FALLBACK_LANG).iterator().next();
  }

  /**
   * Resolve a key in the fallback language and perform pattern substitution.
   *
   * @param key Key to search for.
   * @return Fallback string with substitutions applied; the raw key if absent in the fallback
   *     language.
   */
  public String getDefaultString(String key, String[] patterns, String[] values) {
    if (patterns.length != values.length) {
      throw new IllegalArgumentException("patterns and values must have same length");
    }
    String result = getDefaultString(key);

    for (int i = 0; i < patterns.length; i++) {
      String pattern = patterns[i];
      if (pattern == null) {
        continue;
      }
      result =
          result.replaceAll(
              L10N_VAR_PREFIX + Pattern.quote(pattern) + L10N_VAR_SUFFIX,
              quoteReplacement(values[i]));
    }

    return result;
  }

  /**
   * Resolve a key and perform pattern substitution using {@code ${name}} placeholders.
   *
   * @param key Key to search for.
   * @param patterns Patterns to replace; do not include the {@code ${}} delimiters.
   * @param values Replacement values aligned by index with {@code patterns}.
   * @return Resolved and substituted string.
   */
  public String getString(String key, String[] patterns, String[] values) {
    if (patterns.length != values.length) {
      throw new IllegalArgumentException("patterns and values must have same length");
    }
    String result = getString(key);

    for (int i = 0; i < patterns.length; i++) {
      String pattern = patterns[i];
      if (pattern == null) {
        continue;
      }
      result =
          result.replaceAll(
              L10N_VAR_PREFIX + Pattern.quote(pattern) + L10N_VAR_SUFFIX,
              quoteReplacement(values[i]));
    }

    return result;
  }

  /**
   * Resolve a key and replace a single {@code ${name}} pattern.
   *
   * @param key Key to search for.
   * @param pattern Pattern to replace; do not include the {@code ${}} delimiters.
   * @param value Replacement value.
   * @return Resolved and substituted string.
   */
  public String getString(String key, String pattern, String value) {
    String base = getString(key);
    if (pattern == null) {
      return base;
    }
    return base.replaceAll(
        L10N_VAR_PREFIX + Pattern.quote(pattern) + L10N_VAR_SUFFIX, quoteReplacement(value));
  }

  /**
   * Escape null, $ and \.
   *
   * @param s Replacement string.
   * @return Escaped replacement string.
   */
  private String quoteReplacement(String s) {
    if (s == null) {
      return "(null)";
    }
    if ((s.indexOf('\\') == -1) && (s.indexOf('$') == -1)) {
      return s;
    }
    StringBuilder sb = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '\\') {
        sb.append('\\');
        sb.append('\\');
      } else if (c == '$') {
        sb.append('\\');
        sb.append('$');
      } else {
        sb.append(c);
      }
    }
    return sb.toString();
  }

  /**
   * Load a l10n string, replace variables such as {@code ${link}} or {@code ${bold}} with {@link
   * HTMLNode}s, and append the result to {@code node}.
   *
   * <p>This avoids unencoded string concatenation by requiring callers to provide structured nodes.
   * For each {@code ${name}} we search for {@code ${/name}}. If found, the created node will
   * enclose the content between them; otherwise a standalone node is added. Closing tags cannot be
   * represented directly as {@link HTMLNode}s.
   *
   * <p><b>Examples</b>:
   *
   * <p>TranslationLookup.string=This is a {@code ${link}}link{@code ${/link}} about {@code
   * ${text}}.
   *
   * <p><code>addL10nSubstitution(html, "TranslationLookup.string",
   *   new String[] { "link", "text" },
   *   new HTMLNode[] { HTMLNode.link("/KSK@gpl.txt"), HTMLNode.text("blah") });</code>
   *
   * <p>TranslationLookup.string={@code ${bold}}This{@code ${/bold}} is a bold text.
   *
   * <p><code>addL10nSubstitution(html, "TranslationLookup.string",
   *   new String[] { "bold" }, new HTMLNode[] { HTMLNode.STRONG });</code>
   *
   * @param node Destination container to receive text and nodes.
   * @param key Key of the l10n string to use.
   * @param patterns Placeholders (e.g., {@code link}) to replace.
   * @param values Replacement nodes aligned by index with {@code patterns}.
   */
  public void addL10nSubstitution(HTMLNode node, String key, String[] patterns, HTMLNode[] values) {
    List<HTMLNode> newContent = getHTMLWithSubstitutions(key, patterns, values);
    node.addChildren(newContent);
  }

  /** Attempt to parse all substitution variables in a l10n string (test utility). */
  void attemptParse(String value) throws L10nParseException {
    String[] patterns = new String[0];
    HTMLNode[] values = new HTMLNode[0];
    performHTMLSubstitutions(value, patterns, values);
  }

  /** Look up a l10n string and produce a list of {@link HTMLNode}s with substitutions applied. */
  private List<HTMLNode> getHTMLWithSubstitutions(
      String key, String[] patterns, HTMLNode[] values) {
    for (String value : getStrings(key)) {
      // catch errors caused by bad translation strings
      try {
        return performHTMLSubstitutions(value, patterns, values);
      } catch (L10nParseException e) {
        LOG.error("Error in l10n value \"{}\" for {}", value, key, e);
      }
    }
    // this should never happen, because the last item from getStrings() will be the key itself
    return Collections.singletonList(new HTMLNode("#"));
  }

  /**
   * Convert a string to a list of {@link HTMLNode}s, replacing placeholders with nodes.
   *
   * @throws L10nParseException If the placeholder syntax is malformed.
   */
  private List<HTMLNode> performHTMLSubstitutions(
      String value, String[] patterns, HTMLNode[] values) throws L10nParseException {
    HTMLNode tempNode = new HTMLNode("#");
    addHTMLSubstitutions(tempNode, value, patterns, values);
    return tempNode.getChildren();
  }

  /**
   * Append text to {@code node}, replacing placeholders with nodes and handling nested ranges.
   *
   * @throws L10nParseException If the placeholder syntax is malformed.
   */
  private void addHTMLSubstitutions(
      HTMLNode node, String value, String[] patterns, HTMLNode[] values) throws L10nParseException {
    int start;
    while (!value.isEmpty() && (start = value.indexOf("${")) != -1) {
      String before = value.substring(0, start);
      if (!before.isEmpty()) {
        node.addChild("#", before);
      }
      value = value.substring(start);

      VarInfo parsed = parseVar(value);
      String lookup = parsed.name;
      value = value.substring(parsed.endIndex + 1);

      HTMLNode subnode = findSubstitutionNode(lookup, patterns, values);
      int closeIdx = findClosingIndex(value, lookup);

      if (closeIdx == -1) {
        addCopyIfNotNull(node, subnode);
        continue;
      }

      value = processWithClosing(node, value, lookup, closeIdx, subnode, patterns, values);
    }
    if (!value.isEmpty()) {
      node.addChild("#", value);
    }
  }

  private void addCopyIfNotNull(HTMLNode node, HTMLNode candidate) {
    if (candidate != null) {
      node.addChild(candidate.copy());
    }
  }

  private String processWithClosing(
      HTMLNode node,
      String value,
      String lookup,
      int closeIdx,
      HTMLNode subnode,
      String[] patterns,
      HTMLNode[] values)
      throws L10nParseException {
    String inner = value.substring(0, closeIdx);
    String rest = value.substring(closeIdx + (4 + lookup.length()));

    if (subnode != null) {
      subnode = subnode.copy();
      node.addChild(subnode);
    } else {
      subnode = node;
    }
    addHTMLSubstitutions(subnode, inner, patterns, values);
    return rest;
  }

  /**
   * @param endIndex index of closing '}' within the input slice starting at "${"
   */
  private record VarInfo(String name, int endIndex) {}

  /** Parse a {@code ${name}} opening token at the start of {@code value}. */
  private VarInfo parseVar(String value) throws L10nParseException {
    int end = value.indexOf('}');
    if (end == -1) {
      throw new L10nParseException("Unclosed braces");
    }
    String lookup = value.substring(2, end);
    if (lookup.startsWith("/")) {
      throw new L10nParseException("Starts with /");
    }
    return new VarInfo(lookup, end);
  }

  private HTMLNode findSubstitutionNode(String lookup, String[] patterns, HTMLNode[] values) {
    for (int i = 0; i < patterns.length; i++) {
      if (patterns[i].equals(lookup)) {
        return values[i];
      }
    }
    return null;
  }

  private int findClosingIndex(String value, String lookup) {
    String searchFor = "${/" + lookup + "}";
    return value.indexOf(searchFor);
  }

  /**
   * Return all keys in the fallback translation that start with {@code prefix}.
   *
   * @param prefix Key prefix to match.
   * @return Array of matching keys; empty when the fallback set is not loaded or no match exists.
   */
  public String[] getAllNamesWithPrefix(String prefix) {
    if (fallbackTranslation == null) {
      return new String[] {};
    }
    List<String> toReturn = new ArrayList<>();
    Iterator<String> it = fallbackTranslation.keyIterator();
    while (it.hasNext()) {
      String key = it.next();
      if (key.startsWith(prefix)) {
        toReturn.add(key);
      }
    }
    return toReturn.toArray(new String[0]);
  }
}
