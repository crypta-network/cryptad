package network.crypta.client.filter;

import java.io.Serial;
import java.util.LinkedList;
import java.util.List;
import network.crypta.client.FetchException.FetchExceptionMode;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.HTMLEncoder;

/**
 * Exception indicating that a request produced a MIME type that is known to be unsafe and is not
 * processed by a built‑in content filter.
 *
 * <p>This exception is raised by the content filtering layer when a {@link FilterMIMEType} has been
 * recognized as inherently dangerous to render or otherwise handle directly (for example, it may
 * execute scripts or load external resources) and there is no applicable filter that can safely
 * sanitize the response. Callers typically catch this exception at boundaries that translate errors
 * to client‑visible responses (for example, HTTP handlers) and present a descriptive error message
 * that explains the risks and recommended next steps.
 *
 * <p>The instance carries the {@code FilterMIMEType} that triggered the decision. The exception is
 * immutable and thread‑safe for read‑only use after construction. There is no retry semantics: the
 * condition is deterministic for the given content type. The message and details are localized
 * through the node’s localization bundle to provide end‑user friendly output.
 *
 * <ul>
 *   <li>Represents a validation failure for a specific MIME type.
 *   <li>Intended for presentation to end users with clear, localized guidance.
 *   <li>Does not attempt recovery; upstream components should avoid rendering unsafe content.
 * </ul>
 *
 * @see UnsafeContentTypeException
 * @see FilterMIMEType
 */
public class KnownUnsafeContentTypeException extends UnsafeContentTypeException {
  @Serial private static final long serialVersionUID = -1;

  /**
   * The MIME type classification that triggered this exception.
   *
   * <p>This value originates from the content filtering subsystem and is treated as immutable while
   * the exception instance is in use. Callers should consider it read‑only and use it only for
   * generating user‑facing messages and diagnostics; it does not grant permission to bypass safety
   * checks or to render the associated content.
   */
  @SuppressWarnings("java:S1948")
  final FilterMIMEType type;

  /**
   * Creates a new exception for the provided dangerous MIME type.
   *
   * <p>The given {@link FilterMIMEType} is retained for later reporting in titles and details. The
   * argument is not defensively copied and should be considered read‑only by callers after it is
   * passed here.
   *
   * @param type the recognized MIME type considered unsafe to render; must not be {@code null} and
   *     is used to generate titles and explanatory details for the user interface.
   */
  public KnownUnsafeContentTypeException(FilterMIMEType type) {
    this.type = type;
  }

  /**
   * {@inheritDoc}
   *
   * <p>The returned text is localized and intended for direct display to end users. It concisely
   * explains that the content type is dangerous and that no built‑in filter is available to
   * mitigate the risk.
   *
   * @return a localized summary message suitable for UI display; never {@code null} though it may
   *     be an empty string if localization data is unavailable.
   */
  @Override
  public String getMessage() {
    return l10n("knownUnsafe") + l10n("noFilter");
  }

  /**
   * Provides a list of localized detail strings explaining specific risks for the MIME type.
   *
   * <p>Entries are suitable for bullet‑style presentation in a UI and reflect the properties of the
   * underlying {@link FilterMIMEType}. The list may be empty when no specific risk flags are set.
   * The returned list is a new instance for each call and can be freely modified by the caller
   * without affecting this exception.
   *
   * @return a newly allocated list of human‑readable, localized risk descriptions; never {@code
   *     null} though it may be empty when no risks are identified.
   */
  @Override
  public List<String> details() {
    List<String> details = new LinkedList<>();
    if (type.dangerousInlines)
      details.add(l10n("dangerousInlinesLabel") + l10n("dangerousInlines"));
    if (type.dangerousLinks) details.add(l10n("dangerousLinksLabel") + l10n("dangerousLinks"));
    if (type.dangerousScripting)
      details.add(l10n("dangerousScriptsLabel") + l10n("dangerousScripts"));
    if (type.dangerousScripting)
      details.add(l10n("dangerousMetadataLabel") + l10n("dangerousMetadata"));
    return details;
  }

  /**
   * Returns a localized title that contains the MIME type, HTML‑encoded for safe embedding.
   *
   * <p>This method is convenient for UI layers that render HTML and must avoid introducing markup
   * from the {@code primaryMimeType} value. For plain‑text contexts, prefer {@link #getRawTitle()}.
   *
   * @return a localized, HTML‑encoded title string that includes the MIME type; never {@code null}
   *     though it may be empty if localization resources are missing.
   */
  @Override
  public String getHTMLEncodedTitle() {
    return l10nTitle(HTMLEncoder.encode(type.primaryMimeType));
  }

  /**
   * Returns a localized title that contains the raw, unencoded MIME type.
   *
   * <p>Use this in plain‑text contexts or logging where HTML encoding is unnecessary. For HTML
   * rendering, use {@link #getHTMLEncodedTitle()} to prevent accidental markup injection.
   *
   * @return a localized title with the unencoded MIME type; never {@code null} though it may be an
   *     empty string if localization resources are unavailable.
   */
  @Override
  public String getRawTitle() {
    return l10nTitle(type.primaryMimeType);
  }

  /**
   * Looks up a localized string in this class's resource bundle using the provided key.
   *
   * @param key a bundle key relative to this class's namespace; must not be {@code null}.
   * @return the localized string for the key or the key itself when not found; never {@code null}.
   */
  private static String l10n(String key) {
    return NodeL10n.getBase().getString("KnownUnsafeContentTypeException." + key);
  }

  /**
   * Formats the localized title for this exception with a single {@code type} substitution.
   *
   * @param value the MIME type value to substitute for the {@code type} token; may be {@code null}
   *     which is treated as an empty string by the underlying localization.
   * @return the formatted title string in the current locale; never {@code null}.
   */
  private static String l10nTitle(String value) {
    return NodeL10n.getBase().getString("KnownUnsafeContentTypeException.title", "type", value);
  }

  /**
   * Returns the fetch error code representing this validation outcome.
   *
   * <p>Callers can map this value to protocol‑level error handling (for example, HTTP status
   * translation or FCP error codes) without inspecting localized strings.
   *
   * @return a stable {@link FetchExceptionMode} identifying a content‑validation failure due to an
   *     unsafe MIME type.
   */
  @Override
  public FetchExceptionMode getFetchErrorCode() {
    return FetchExceptionMode.CONTENT_VALIDATION_BAD_MIME;
  }
}
