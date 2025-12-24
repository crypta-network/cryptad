package org.spaceroots.mantissa;

import java.io.Serial;
import java.text.MessageFormat;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

/**
 * Base class for all Mantissa package-specific checked exceptions.
 *
 * <p>This exception type provides a single, consistent root for error conditions that are
 * meaningful within the Mantissa library, especially where callers may want to catch and handle
 * Mantissa-related failures as a group. Subclasses typically represent more specialized failure
 * modes and follow the same pattern of constructing messages via the package resource bundle.
 *
 * <p>Whenever an error is already well described by the standard Java runtime (for example, {@link
 * IllegalArgumentException} for precondition violations or {@link ArrayIndexOutOfBoundsException}
 * for invalid indexing), Mantissa code prefers throwing those standard exceptions instead of
 * wrapping them in a Mantissa-specific type. This keeps MantissaException focused on domain-level
 * problems and avoids obscuring the semantics of universally understood Java exceptions. Instances
 * are immutable and thread-safe once created.
 *
 * <ul>
 *   <li>Acts as the checked-exception root for Mantissa-specific failure cases.
 *   <li>Supports localized messages through {@link #translate(String)} helpers.
 *   <li>May be subclassed by Mantissa components to convey precise context.
 * </ul>
 *
 * @version $Id: MantissaException.java 1686 2005-12-16 12:59:51Z luc $
 * @author L. Maisonobe
 */
public class MantissaException extends Exception {

  @Serial private static final long serialVersionUID = 1L;
  private static final ResourceBundle resources =
      ResourceBundle.getBundle("org.spaceroots.mantissa.MessagesResources");

  /**
   * Translate a message key using the Mantissa resource bundle.
   *
   * <p>This method looks up the provided key in the package-level {@code MessagesResources} bundle.
   * If the key is present, the localized value is returned. If it is missing, the method returns
   * the original key unchanged rather than failing, allowing callers to safely use the untranslated
   * key as a fallback message. This behavior is intentionally lightweight and has no side effects.
   *
   * @param s resource-bundle key to translate into a localized message, typically non-null.
   * @return the localized message if available, or {@code s} unchanged when no translation exists.
   */
  public static String translate(String s) {
    try {
      return resources.getString(s);
    } catch (MissingResourceException _) {
      return s;
    }
  }

  /**
   * Translate and format a message key using {@link MessageFormat}.
   *
   * <p>The {@code specifier} is first translated through {@link #translate(String)}. The resulting
   * pattern is then formatted with the supplied {@code parts} array using {@link
   * MessageFormat#format(Object)}. The parts are inserted verbatim and are not translated. If the
   * key is missing from the bundle, the untranslated {@code specifier} is treated as the format
   * pattern, which typically yields a readable fallback string.
   *
   * @param specifier resource-bundle key that also serves as a {@link MessageFormat} pattern after
   *     translation, typically non-null.
   * @param parts values to insert into the translated format pattern, without further translation.
   * @return a fully formatted, localized message derived from the specifier and parts.
   */
  public static String translate(String specifier, String[] parts) {
    return new MessageFormat(translate(specifier)).format(parts);
  }

  /**
   * Create an exception with no detail message and no cause.
   *
   * <p>This constructor is useful when the failure context will be provided by a subclass or when a
   * generic MantissaException is sufficient. The resulting instance has a {@code null} message,
   * matching the behavior of {@link Exception#Exception()}.
   */
  public MantissaException() {
    super();
  }

  /**
   * Create an exception with a localized detail message.
   *
   * <p>The provided {@code message} is treated as a resource-bundle key and passed through {@link
   * #translate(String)} before being stored as the exception's detail message. If no translation is
   * available, the key itself becomes the message.
   *
   * @param message resource-bundle key describing the failure, translated if possible.
   */
  public MantissaException(String message) {
    super(translate(message));
  }

  /**
   * Create an exception with a localized, formatted detail message.
   *
   * <p>This constructor first translates {@code specifier} as a resource-bundle key, then formats
   * the resulting pattern with {@code parts} using {@link MessageFormat}. The parts are inserted
   * without translation. If the specifier is not found in the bundle, it is used directly as the
   * format pattern.
   *
   * @param specifier resource-bundle key that becomes a {@link MessageFormat} pattern after
   *     translation.
   * @param parts values to interpolate into the translated format pattern, not translated.
   */
  public MantissaException(String specifier, String[] parts) {
    super(translate(specifier, parts));
  }

  /**
   * Create an exception that wraps an underlying cause.
   *
   * <p>The detail message is left {@code null}. This is appropriate when the causal exception
   * already carries a meaningful message or when the MantissaException acts only as a domain-level
   * wrapper.
   *
   * @param cause underlying throwable that triggered this failure, may be {@code null}.
   */
  public MantissaException(Throwable cause) {
    super(cause);
  }

  /**
   * Create an exception with a localized message and an underlying cause.
   *
   * <p>The {@code message} is translated as a resource-bundle key via {@link #translate(String)}.
   * The {@code cause} is attached so that stack traces and causal chains retain the original
   * failure context.
   *
   * @param message resource-bundle key describing the failure, translated if possible.
   * @param cause underlying throwable that triggered this failure, may be {@code null}.
   */
  public MantissaException(String message, Throwable cause) {
    super(translate(message), cause);
  }

  /**
   * Create an exception with a localized, formatted message and an underlying cause.
   *
   * <p>This constructor combines translation and formatting of the detail message with causal
   * chaining. The {@code specifier} is translated and used as a {@link MessageFormat} pattern, the
   * {@code parts} are interpolated verbatim, and the {@code cause} is recorded as the underlying
   * reason for the failure.
   *
   * @param specifier resource-bundle key that becomes a {@link MessageFormat} pattern after
   *     translation.
   * @param parts values to interpolate into the translated format pattern, not translated.
   * @param cause underlying throwable that triggered this failure, may be {@code null}.
   */
  public MantissaException(String specifier, String[] parts, Throwable cause) {
    super(translate(specifier, parts), cause);
  }
}
