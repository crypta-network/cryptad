package network.crypta.client.filter;

import java.io.Serial;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLEncoder;

/**
 * Signals that a fetched resource exposes an unknown or unsupported content type.
 *
 * <p>This exception is raised by client-side content-type validation code when the MIME type
 * provided by an upstream source (for example, an HTTP server or plugin) cannot be mapped to a type
 * that Crypta considers safe or recognizable. The instance carries both the raw type string and a
 * pre-encoded, HTML-safe variant to simplify downstream UI rendering without duplicating escaping
 * logic. Title and message strings are produced lazily via the node localization layer ({@link
 * network.crypta.l10n.NodeL10n}) so that translations remain centralized and consistent across the
 * application.
 *
 * <p>Typical usage is to construct the exception with the original content-type value and allow the
 * higher layers to surface a localized, human-readable explanation. The object is immutable and
 * thread-safe after construction; its state never changes, and it performs no I/O. Consumers may
 * use {@link #getHTMLEncodedTitle()} when rendering into an HTML context, and {@link
 * #getRawTitle()} or {@link #getMessage()} for plain-text logs or non-HTML surfaces.
 *
 * <ul>
 *   <li>Provides raw and HTML-escaped variants of the type string.
 *   <li>Defers wording to the localization bundle for consistent phrasing.
 *   <li>Class is immutable; safe to share across threads without synchronization.
 * </ul>
 */
public class UnknownContentTypeException extends UnsafeContentTypeException {
  @Serial private static final long serialVersionUID = -1;

  /**
   * The original content type string as received from an external source. The value is not
   * HTML-escaped and is intended for plain-text contexts such as logs or console output. It is
   * assigned at construction time and remains constant for the lifetime of the instance.
   */
  final String type;

  /**
   * The content type string pre-escaped for safe inclusion in HTML. This value is derived from
   * {@link #type} using a simple encoder and is suitable for UI titles or messages rendered in
   * HTML-capable widgets. It is computed once during construction and never changes thereafter.
   */
  final String encodedType;

  /**
   * Create an exception for the given content type name.
   *
   * <p>The provided string is stored verbatim for plain-text access and is also HTML-escaped to
   * populate {@link #encodedType} for safe rendering in user interfaces. The constructor does not
   * validate the syntax beyond accepting any non-null string that represents a type as reported by
   * an upstream component.
   *
   * @param typeName raw content-type name as observed (for example, {@code
   *     "application/x-unknown"}); must be the exact value received from the source; callers should
   *     avoid passing {@code null}.
   */
  public UnknownContentTypeException(String typeName) {
    this.type = typeName;
    encodedType = HTMLEncoder.encode(type);
  }

  /**
   * Return the raw, unescaped content type string that triggered this exception.
   *
   * <p>The returned value is the exact content-type string supplied at construction. It is not
   * sanitized for HTML and is intended for plain-text outputs such as logs, metrics labels, or
   * debugging messages. Use {@link #getHTMLEncodedTitle()} if you need a localized, HTML-safe title
   * for display in a browser or rich text widget.
   *
   * @return the original content type string, unchanged and suitable for plain-text contexts
   */
  public String getType() {
    return type;
  }

  /**
   * {@inheritDoc}
   *
   * <p>This variant is safe to embed in HTML and is localized using the node's resource bundles.
   * The message focuses on user-facing clarity rather than raw diagnostic detail.
   *
   * @return a localized, HTML-escaped title that references the unknown content type
   */
  @Override
  public String getHTMLEncodedTitle() {
    return l10n("title", encodedType);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Provides a localized title appropriate for logs or plain-text user interfaces. The content
   * type is included without HTML escaping so the string remains human-readable in non-HTML
   * environments.
   *
   * @return a localized plain-text title that references the unknown content type
   */
  @Override
  public String getRawTitle() {
    return l10n("title", type);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The explanation expands on why the content type is not accepted and may include actionable
   * guidance. The phrasing is defined in localization resources to remain consistent across
   * languages and builds.
   *
   * @return a localized, plain-text explanation suitable for logs or UI messages
   */
  @Override
  public String getMessage() {
    return l10n("explanation", type);
  }

  /**
   * Localize a message for this exception, substituting the {@code type} placeholder.
   *
   * @param key resource key suffix (e.g., "title", "explanation")
   * @param value value to substitute for the {@code type} pattern
   * @return localized string
   */
  private static String l10n(String key, String value) {
    return NodeL10n.getBase().getString("UnknownContentTypeException." + key, "type", value);
  }

  /**
   * Return the standardized fetch error code that classifies this failure.
   *
   * <p>The code can be used by higher layers to group errors, drive metrics, or select recovery
   * behavior. It is stable across releases for the same semantic condition.
   *
   * @return the {@code CONTENT_VALIDATION_UNKNOWN_MIME} classification for unknown content types
   */
  @Override
  public FetchExceptionMode getFetchErrorCode() {
    return FetchExceptionMode.CONTENT_VALIDATION_UNKNOWN_MIME;
  }
}
