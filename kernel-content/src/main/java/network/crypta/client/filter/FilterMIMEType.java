package network.crypta.client.filter;

/**
 * Describes how the content filter handles a particular media (MIME) type.
 *
 * <p>Each instance represents one primary MIME type together with optional alternative MIME strings
 * and common filename extensions. The filter framework uses this metadata to decide whether a
 * resource can be delivered as-is, must be transformed through a {@link ContentDataFilter}, or
 * should be rejected with an informative, localized warning. The class captures several safety
 * aspects (for example, whether links, inlines, scripting, or metadata are considered potentially
 * dangerous) so that callers can take appropriate precautions when relaying or storing content.
 *
 * <p>Typical usage is read-mostly: a registry declares known types and their properties at startup
 * and later consults those definitions to determine read/write safety and to get the appropriate
 * filtering component. Instances are immutable and therefore thread-safe. They carry hints about
 * charset handling for text-based formats, including whether a type accepts a charset parameter and
 * how to infer a charset when no definitive declaration is present.
 *
 * <ul>
 *   <li>Identifies a MIME type and common extensions.
 *   <li>States whether bytes are safe to read or write as-is.
 *   <li>Provides a {@link ContentDataFilter} to sanitize untrusted input when required.
 *   <li>Records risk flags for links, inlines, scripting, and metadata exposure.
 * </ul>
 *
 * @see network.crypta.support.MediaType MediaType represents an individual parsed MIME type string
 *     such as {@code "text/plain; charset=ISO-8859-1"}.
 * @see ContentDataFilter
 * @see CharsetExtractor
 * @see KnownUnsafeContentTypeException
 */
public class FilterMIMEType {

  /**
   * Canonical MIME type this handler describes.
   *
   * <p>Examples include {@code "text/html"} or {@code "image/png"}. The value is used for lookups
   * and for generating user-facing diagnostics. It should be a lower-case, standard name as it
   * would appear in a {@code Content-Type} header without parameters. The field is immutable and
   * safe to access concurrently.
   */
  public final String primaryMimeType;

  /**
   * Alternative MIME type strings recognized for this handler.
   *
   * <p>Some formats have historical or vendor-specific aliases. These entries allow matching such
   * variants while treating them as equivalent to {@link #primaryMimeType}. The array may be empty
   * when no aliases are known. Elements should be normalized as plain type/subtype tokens.
   */
  public final String[] alternateMimeTypes;

  /**
   * Primary filename extension commonly associated with this type.
   *
   * <p>The value is used only as a hint in diagnostics or when suggesting filenames; it does not
   * participate in content sniffing. The dot is omitted (for example, {@code "html"}). The field is
   * read-only after construction.
   */
  public final String primaryExtension;

  /**
   * Additional filename extensions associated with this type.
   *
   * <p>Contains secondary extensions that are sometimes used for the same format. The array may be
   * empty when no alternatives are meaningful. Extensions are provided without the leading dot and
   * are intended for informational use only.
   */
  public final String[] alternateExtensions;

  /**
   * Indicates whether bytes of this type may be delivered to clients without transformation.
   *
   * <p>A value of {@code true} means the content is considered safe to forward as-is on the read
   * path (for example, {@code text/plain}). Callers may still enforce size limits or apply
   * additional policies, but no structural sanitization is required for safety. When {@code false},
   * callers should consult {@link #readFilter} to get a stream-based sanitizer before emitting any
   * data to user agents.
   */
  public final boolean safeToRead;

  /**
   * Indicates whether data of this type may be stored or produced without transformation.
   *
   * <p>When {@code true}, writing content of this type back to disk or to downstream systems is not
   * expected to introduce active-content or metadata risks beyond the format’s normal semantics.
   * When {@code false}, even sanitized content may require additional handling; consult the {@code
   * dangerous*} flags and surrounding policy before persisting or re-emitting the data.
   */
  public final boolean safeToWrite;

  /**
   * Stream-oriented filter that validates and sanitizes untrusted input for this type.
   *
   * <p>When present, callers should pass potentially unsafe bytes through this filter before
   * delivering them to clients. The filter is responsible for removing or neutralizing dangerous
   * constructs and for enforcing structural correctness. Callers should treat the reference as
   * immutable and check for {@code null} when {@link #safeToRead} is {@code true}.
   */
  public final ContentDataFilter readFilter;

  // Detail. Not necessarily an exhaustive list.

  /**
   * Indicates that hyperlinks embedded in the content may pose a risk.
   *
   * <p>When {@code true}, callers should treat link-bearing constructs (for example, anchors or
   * redirects) with care, even after filtering. Some contexts may choose to strip or neutralize
   * link targets, depending on policy and user preferences. This flag is a conservative hint rather
   * than a strict guarantee.
   */
  public final boolean dangerousLinks;

  /**
   * Indicates that inline content (for example, images or styles) may pose a risk.
   *
   * <p>Set to {@code true} for types where inlining external resources can leak information or
   * trigger unintended fetches. Downstream components may block external references or convert them
   * to safe, local representations as part of sanitization.
   */
  public final boolean dangerousInlines;

  /**
   * Indicates that scripting or active content is considered dangerous.
   *
   * <p>When {@code true}, embedded scripts, active event handlers, or similar executable elements
   * must be removed or disabled by the filter. Callers should not assume that post-filter output is
   * executable; the intent is to prevent script execution entirely for this type.
   */
  public final boolean dangerousScripting;

  /**
   * Indicates that reading metadata may expose sensitive information.
   *
   * <p>Some formats carry authoring details, location data, or other metadata that should not be
   * revealed to untrusted parties. When this flag is {@code true}, the filter or caller may redact
   * or omit metadata fields from user-visible output.
   */
  public final boolean dangerousReadMetadata;

  /**
   * Indicates that writing metadata back to disk can be dangerous.
   *
   * <p>Set to {@code true} if persisting metadata could embed active content or privacy-sensitive
   * details. Callers may avoid writing such data or restrict persistence to sanitized, known-safe
   * fields only.
   */
  public final boolean dangerousWriteMetadata;

  /**
   * Indicates that writing this type is unsafe even after filtering.
   *
   * <p>When {@code true}, generating or storing data of this type is discouraged because residual
   * risks remain that the filter cannot fully eliminate. Systems handling user uploads may reject
   * writes regardless of the read-side sanitization outcome.
   */
  public final boolean dangerousToWriteEvenWithFilter;

  // These are in addition to the above

  /**
   * Human-readable description of read-side handling and residual risks.
   *
   * <p>The string is suitable for inclusion in warning pages or logs. It may name the format,
   * outline what the filter validates, and describe limitations or edge cases. The value is
   * provided by the registry at construction time and is immutable.
   */
  public final String readDescription;

  /**
   * Whether this MIME type accepts a {@code charset} parameter.
   *
   * <p>For text-based formats, {@code true} indicates that a charset parameter in {@code
   * Content-Type} is recognized and may influence decoding. Binary formats typically set this to
   * {@code false}. The flag is an advisory to callers and filters.
   */
  public final boolean takesACharset;

  /**
   * Default character set to assume when no definitive declaration exists.
   *
   * <p>Used as a fallback for text-based formats if neither a byte-order mark nor an authoritative
   * in-band or header declaration is available. Callers should prefer explicit declarations when
   * present. The value may be {@code null} for binary types or when no default is defined.
   */
  public final String defaultCharset;

  /**
   * Type-specific helper that infers a charset from an initial byte prefix.
   *
   * <p>Filters can consult this extractor to combine BOM detection with in-band declarations and
   * caller-provided hints. The reference is immutable, and implementations are typically stateless
   * and thread-safe.
   */
  public final CharsetExtractor charsetExtractor;

  /**
   * If true, if we cannot detect the charset from a definite declaration or BOM, we will use the
   * charset passed in from the referring document. So far CSS only uses this.
   */
  public final boolean useMaybeCharset;

  FilterMIMEType(
      FilterMIMETypeNames names,
      FilterMIMETypeSafety safety,
      FilterMIMETypeDangerousFlags dangerousFlags,
      FilterMIMETypeCharsetPolicy charsetPolicy) {
    this.primaryMimeType = names.primaryMimeType();
    this.primaryExtension = names.primaryExtension();
    this.alternateMimeTypes = names.alternateMimeTypes();
    this.alternateExtensions = names.alternateExtensions();
    this.safeToRead = safety.safeToRead();
    this.safeToWrite = safety.safeToWrite();
    this.readFilter = safety.readFilter();
    this.dangerousLinks = dangerousFlags.dangerousLinks();
    this.dangerousInlines = dangerousFlags.dangerousInlines();
    this.dangerousScripting = dangerousFlags.dangerousScripting();
    this.dangerousReadMetadata = dangerousFlags.dangerousReadMetadata();
    this.dangerousWriteMetadata = dangerousFlags.dangerousWriteMetadata();
    this.dangerousToWriteEvenWithFilter = dangerousFlags.dangerousToWriteEvenWithFilter();
    this.readDescription = safety.readDescription();
    this.takesACharset = charsetPolicy.takesACharset();
    this.defaultCharset = charsetPolicy.defaultCharset();
    this.charsetExtractor = charsetPolicy.charsetExtractor();
    this.useMaybeCharset = charsetPolicy.useMaybeCharset();
  }

  /**
   * Signals that the current MIME type is known to be unsafe for direct handling.
   *
   * <p>Callers invoke this helper when a policy decision mandates rejection rather than
   * sanitization or pass-through. The method always throws and does not return. The thrown
   * exception contains this {@link FilterMIMEType} instance so that error handlers can present a
   * detailed, localized explanation to users or logs. This method is idempotent with respect to
   * state; it has no side effects beyond throwing.
   *
   * @throws KnownUnsafeContentTypeException always thrown to indicate that the MIME type is
   *     considered unsafe and must not be processed or emitted without explicit overrides.
   */
  public void throwUnsafeContentTypeException() throws KnownUnsafeContentTypeException {
    throw new KnownUnsafeContentTypeException(this);
  }
}
