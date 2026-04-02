package network.crypta.clients.http.wizardsteps;

import javax.naming.OperationNotSupportedException;
import network.crypta.l10n.NodeL10n;

/**
 * Localization helper for the first-time wizard HTTP UI.
 *
 * <p>This class centralizes the localization key prefixes used by the wizard steps and delegates
 * lookups to {@link NodeL10n#getBase()}. Wizard templates and step implementations typically have
 * only the suffix portion of the message key (for example, {@code "SomeLabel"}), while the actual
 * bundles are organized under stable, shared prefixes. Using this helper avoids duplicating those
 * prefixes throughout the wizard code and makes call sites more uniform and less error-prone.
 *
 * <p>The class is intentionally stateless: it performs simple string concatenation to construct the
 * fully-qualified key and then calls through to the underlying localization system. The helper
 * itself has no mutable state; any concurrency guarantees beyond this class are provided by {@link
 * NodeL10n}.
 *
 * <ul>
 *   <li>Builds keys under {@code FirstTimeWizardToadlet.} for general wizard strings.
 *   <li>Builds keys under {@code SecurityLevels.} for security-level related strings.
 *   <li>Provides overloads for simple and templated message lookups.
 * </ul>
 */
public final class WizardL10n {

  private static final String FIRST_TIME_WIZARD_TOADLET_PREFIX = "FirstTimeWizardToadlet.";
  private static final String SECURITY_LEVELS_PREFIX = "SecurityLevels.";

  /**
   * Cannot be instantiated.
   *
   * @throws OperationNotSupportedException if called, because this class is a pure static utility.
   */
  private WizardL10n() throws OperationNotSupportedException {
    throw new OperationNotSupportedException(
        "Cannot instantiate WizardL10n; it is a utility class.");
  }

  /**
   * Returns a localized wizard string for the provided key suffix.
   *
   * <p>This method constructs a full localization key by prepending the wizard bundle prefix
   * ({@code FirstTimeWizardToadlet.}) to the supplied {@code key} and delegates the lookup to
   * {@link NodeL10n#getBase()}. The exact handling of missing keys, fallback locales, and escaping
   * behavior is defined by the underlying localization implementation.
   *
   * <p>This helper does not mutate any state in this class; it only performs a lookup via {@link
   * NodeL10n}.
   *
   * @param key the wizard message key suffix appended to {@code FirstTimeWizardToadlet.}.
   * @return the localized string produced by the underlying localization system.
   */
  public static String l10n(String key) {
    return NodeL10n.getBase().getString(FIRST_TIME_WIZARD_TOADLET_PREFIX + key);
  }

  /**
   * Returns a localized wizard string and applies a single named substitution.
   *
   * <p>This is the convenience overload for templates that expect exactly one substitution. The
   * {@code pattern} and {@code value} are forwarded to {@link NodeL10n#getBase()} as-is, which
   * performs the substitution according to the message format used by the localization bundles.
   *
   * <p>Callers should ensure the key resolves to a message that actually references the provided
   * pattern name; otherwise the underlying implementation decides how to handle unused or missing
   * substitutions.
   *
   * @param key the wizard message key suffix appended to {@code FirstTimeWizardToadlet.}.
   * @param pattern the substitution placeholder name expected by the message template.
   * @param value the replacement text to associate with the given placeholder name.
   * @return the localized and substituted message string.
   */
  public static String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString(FIRST_TIME_WIZARD_TOADLET_PREFIX + key, pattern, value);
  }

  /**
   * Returns a localized wizard string and applies a set of named substitutions.
   *
   * <p>This overload is used when a message template needs multiple substitutions. The {@code
   * patterns} and {@code values} arrays are passed directly to the underlying localization call,
   * which interprets them as paired entries. Callers typically provide arrays of equal length, with
   * each pattern name aligned to the corresponding replacement value at the same index.
   *
   * <p>No copying or validation is performed here; any validation, error reporting, or fallback
   * behavior is owned by {@link NodeL10n}.
   *
   * @param key the wizard message key suffix appended to {@code FirstTimeWizardToadlet.}.
   * @param patterns the placeholder names to substitute, usually aligned by array index.
   * @param values the replacement texts corresponding to {@code patterns}, aligned by index.
   * @return the localized and substituted message string.
   */
  public static String l10n(String key, String[] patterns, String[] values) {
    return NodeL10n.getBase().getString(FIRST_TIME_WIZARD_TOADLET_PREFIX + key, patterns, values);
  }

  /**
   * Returns a localized string from the security-level message bundle.
   *
   * <p>This method prepends {@code SecurityLevels.} to the supplied key suffix and delegates the
   * lookup to {@link NodeL10n#getBase()}. It exists to keep security-level related wizard text
   * consistent with the rest of the UI while avoiding hard-coded prefixes at call sites.
   *
   * @param key the security-level message key suffix appended to {@code SecurityLevels.}.
   * @return the localized string produced by the underlying localization system.
   */
  public static String l10nSec(String key) {
    return NodeL10n.getBase().getString(SECURITY_LEVELS_PREFIX + key);
  }
}
