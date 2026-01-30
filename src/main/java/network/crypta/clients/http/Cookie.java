package network.crypta.clients.http;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Date;
import java.util.Locale;
import java.util.Set;
import network.crypta.support.TimeUtil;

/**
 * Represents an outbound HTTP cookie created by Crypta toadlets and serialized into response
 * headers.
 *
 * <p>This class encapsulates the state required to emit standards-compliant {@code Set-Cookie2}
 * headers for the web interface. Callers typically construct an instance with {@link #Cookie(URI,
 * String, String, Date)} and pass it to {@link ToadletContext#setCookie(Cookie)} to attach it to a
 * response. Validation routines enforce a conservative subset of RFC2965/RFC2616 so malformed or
 * potentially dangerous values are rejected early. Instances are mutable only by subclasses (all
 * fields are {@code protected}); typical callers treat them as single-use values assembled on a
 * per-response basis.
 *
 * <p>Cookies produced here use version {@code 1}, default to discard-on-close, and expect absolute
 * paths with optional domains limited to HTTP(S) schemes. Date handling uses {@link
 * TimeUtil#makeHTTPDate(long)} to format expiration timestamps in HTTP-date format. This class is
 * not thread-safe; create and use instances on the request-handling thread. It deliberately avoids
 * client-side storage concerns and focuses solely on producing outbound header strings suitable for
 * the embedded HTTP server.
 *
 * <ul>
 *   <li>Responsibilities: validate attributes, retain canonicalized values, and render header
 *       payloads.
 *   <li>Notable behaviors: rejects non-US-ASCII characters, control characters, and reserved token
 *       names; preserves case-sensitive paths.
 *   <li>Lifecycle: construct → validate → encode via {@link #encodeToHeaderValue()} → hand to
 *       {@link ToadletContext#setCookie(Cookie)}.
 * </ul>
 *
 * @author xor (xor@freenetproject.org)
 */
@SuppressWarnings("JavaUtilDate")
public class Cookie {
  /** Characters that must not appear unquoted in cookie values (based on RFC2616 separators). */
  private static final Set<Character> INVALID_VALUE_CHARACTERS =
      Set.of('(', ')', '[', ']', '{', '}', '=', ',', '\"', '/', '\\', '?', '@', ':', ';');

  /**
   * Taken from this discussion: <TheSeeker> CTL = <any US-ASCII control character <TheSeeker>
   * (octets 0 - 31) and DEL (127)> <TheSeeker> CHAR = <any US-ASCII character (octets 0 - 127)>
   * <TheSeeker> token = 1*<any CHAR except CTLs or separators> <TheSeeker> separators = "(" | ")" |
   * "<" | ">" | "@" | "," | ";" | ":" | "\" | <"> | "/" | "[" | "]" | "?" | "=" | "{" | "}" | SP |
   * HT <TheSeeker> so, anything from 32-126 that isn't in that list of seperators is valid. <p0s>
   * TheSeeker: where did you copy that from? <TheSeeker> <a
   * href="http://www.ietf.org/rfc/rfc2616.txt">http://www.ietf.org/rfc/rfc2616.txt</a>
   */
  private static final Set<Character> HTTP_SEPARATOR_CHARACTERS =
      Set.of(
          '(', ')', '<', '>', '@', ',', ';', ':', '\\', '\"', '/', '[', ']', '?', '=', '{', '}',
          ' ', '\t');

  /**
   * Cookie specification version sent in headers; defaults to {@code 1} to match RFC2965 semantics.
   */
  protected int version;

  /**
   * Optional domain scope for the cookie. When present it must use the {@code http} or {@code
   * https} scheme and omit path segments.
   */
  protected URI domain;

  /**
   * Path restriction for the cookie. Must begin with {@code /}, is case-sensitive, and must be a
   * relative URI as defined by {@link #validatePath(URI)}.
   */
  protected URI path;

  /**
   * Lowercase token identifying the cookie. Restricted to US-ASCII printable characters that are
   * not separators or reserved names defined by RFC2965.
   */
  protected String name;

  /**
   * Canonicalized cookie payload. Stored as a trimmed US-ASCII string without forbidden separator
   * characters to ensure safe header emission.
   */
  protected String value;

  /**
   * Expiration timestamp interpreted in the GMT HTTP-date format during header serialization;
   * callers provide an absolute {@link Date} in the future.
   */
  protected Date expirationDate;

  /**
   * Indicates whether the cookie should be discarded when the user agent session ends; defaults to
   * {@code true} for Crypta browser interactions.
   */
  protected boolean discard;

  /**
   * Builds a {@link Cookie} ready for delivery via {@link ToadletContext#setCookie(Cookie)} after
   * applying strict validation and normalization rules.
   *
   * <p>The constructor trims and lowercases the name, normalizes the path, rejects invalid ASCII
   * ranges, and converts a {@code null} value to an empty string for compatibility with browsers
   * that treat absent values as empty. The expiration date must be in the future; the cookie is
   * marked as discardable so that user agents drop it when the browsing session closes. No network
   * I/O occurs during construction, making it safe to call from request handlers before headers are
   * written.
   *
   * @param myPath The cookie path; must be relative, start with {@code /}, and represent the scope
   *     under which the cookie will be sent back.
   * @param myName Token identifying the cookie; trimmed, lowercased, US-ASCII, and free of reserved
   *     names such as {@code domain} or {@code secure}.
   * @param myValue Payload to send to the client; may be {@code null} to request an empty cookie
   *     value and must avoid control characters and separator tokens.
   * @param myExpirationDate Absolute expiration moment in the future; dates in the past cause an
   *     {@link IllegalArgumentException} during validation.
   * @throws IllegalArgumentException If any attribute violates RFC-inspired validation rules or the
   *     expiration time is not in the future.
   */
  public Cookie(URI myPath, String myName, String myValue, Date myExpirationDate) {
    version = 1;

    domain = null;
    path = validatePath(myPath);
    name = validateName(myName);
    value = myValue != null ? validateValue(myValue) : "";
    expirationDate = validateExpirationDate(myExpirationDate);
    discard = true; // Freenet cookies are intended to be discarded when the browser is closed.
  }

  /**
   * Protected no-arg constructor for subclass frameworks that populate fields manually before
   * calling {@link #encodeToHeaderValue()}; regular callers should prefer the public constructor.
   */
  protected Cookie() {}

  /** Returns true if two Cookies have equal domain, path and name. Does not check the value! */
  @Override
  public boolean equals(Object obj) {
    if (obj == this) return true;

    if (!(obj instanceof Cookie other)) return false;

    // RFC2965: Two cookies are equal if name and domain are equal with case-insensitive comparison
    // and path is equal with case-sensitive comparison.
    // We don't have to do anything about the case here though because getName() / getDomain()
    // returns lowercase and getPath() returns the original path.

    URI myDomain = getDomain();
    URI otherDomain = other.getDomain();

    if (myDomain != null) {
      if (otherDomain == null || !otherDomain.toString().equals(myDomain.toString())) return false;
    } else if (otherDomain != null) return false;

    if (!getPath().toString().equals(other.getPath().toString())) return false;

    return getName().equals(other.getName());
  }

  @Override
  public int hashCode() {
    return domain.hashCode() + path.hashCode() + name.hashCode();
  }

  /**
   * Parses and validates a domain attribute supplied as a string before attaching it to a cookie.
   *
   * <p>The domain is lowercased, converted to a {@link URI}, and then checked to ensure it uses the
   * {@code http} or {@code https} scheme without any path component. Callers typically pass host
   * names or origin URLs supplied by user agents and should catch {@link URISyntaxException} for
   * malformed input.
   *
   * @param domainString Host or origin provided as text; must parse as a URI with no path segments.
   * @return A normalized {@link URI} suitable for {@link Cookie#domain} and downstream equality
   *     comparisons; never {@code null}.
   * @throws URISyntaxException If the string cannot be parsed into a URI prior to validation.
   * @throws IllegalArgumentException If the resulting URI uses an unsupported scheme or embeds a
   *     path component.
   */
  public static URI validateDomain(String domainString) throws URISyntaxException {
    return validateDomain(new URI(domainString.toLowerCase(Locale.ROOT)));
  }

  /**
   * Validates a pre-parsed domain URI for cookie use, enforcing scheme and path constraints.
   *
   * <p>The method accepts only {@code http} or {@code https} schemes and forbids any non-root path
   * component. It returns the URI unchanged so callers may preserve host and port information while
   * guaranteeing compatibility with {@link #encodeToHeaderValue()}.
   *
   * @param domain Candidate domain URI, typically derived from the request host; must not be {@code
   *     null}.
   * @return The same {@link URI} instance when validation succeeds, enabling fluent assignment.
   * @throws IllegalArgumentException If the scheme is not HTTP(S) or the URI includes a path
   *     segment other than {@code /}.
   */
  public static URI validateDomain(URI domain) {
    String scheme = domain.getScheme().toLowerCase(Locale.ROOT);

    if (!"http".equals(scheme) && !"https".equals(scheme))
      throw new IllegalArgumentException("Illegal cookie domain, must be http or https: " + domain);

    String path = domain.getPath();

    if (!"".equals(path) && !"/".equals(path))
      throw new IllegalArgumentException("Illegal cookie domain, contains a path: " + domain);

    return domain;
  }

  /**
   * Parses and validates a cookie path supplied as text, ensuring it is a relative, slash-prefixed
   * URI per RFC2965 guidance.
   *
   * <p>Unlike domain validation, this routine accepts only relative paths (no scheme) and enforces
   * a leading slash while leaving the remainder unchanged. Callers can feed user-supplied paths or
   * application defaults; invalid inputs trigger exceptions immediately rather than deferring to
   * header emission.
   *
   * @param stringPath Path text expected to start with {@code /} and contain no scheme component.
   * @return A {@link URI} representing the normalized path, suitable for assignment to {@link
   *     Cookie#path}.
   * @throws URISyntaxException If the string fails URI parsing before validation occurs.
   * @throws IllegalArgumentException If the parsed URI is absolute or does not start with a forward
   *     slash.
   */
  public static URI validatePath(String stringPath) throws URISyntaxException {
    return validatePath(new URI(stringPath));
  }

  /**
   * Validates a pre-parsed cookie path, rejecting absolute URIs or relative paths that lack a
   * leading slash.
   *
   * <p>Path comparisons are case-sensitive, so the original casing is preserved. The method
   * performs minimal normalization to maintain compatibility with existing callers that rely on
   * specific path text.
   *
   * @param path Candidate path URI, expected to be relative and to begin with {@code /}; must not
   *     be {@code null}.
   * @return The input {@link URI} when it meets validation requirements; the instance is unchanged.
   * @throws IllegalArgumentException If the URI is absolute or does not start with a forward slash.
   */
  public static URI validatePath(URI path) {
    // Path validation is intentionally minimal to preserve compatibility with existing callers.

    if (path.isAbsolute())
      throw new IllegalArgumentException("Illegal cookie path, must be relative: " + path);

    if (!path.toString().startsWith("/"))
      throw new IllegalArgumentException("Illegal cookie path, must start with /: " + path);

    // RFC2965: Path is case-sensitive!

    return path;
  }

  /**
   * Validates and canonicalizes a cookie name, applying RFC2965 token rules and reserved-word
   * restrictions.
   *
   * <p>The method trims and lowercases the input, rejects whitespace, control characters, reserved
   * attribute names, and any character outside the visible US-ASCII range. It throws immediately on
   * violation to prevent constructing headers that browsers may ignore or mishandle.
   *
   * @param name Proposed cookie name before canonicalization; must be non-empty US-ASCII without
   *     whitespace or separator characters.
   * @return Lowercased, trimmed name that is safe to embed in headers; never {@code null}.
   * @throws IllegalArgumentException If the name is empty, contains forbidden characters, or uses a
   *     reserved attribute keyword such as {@code expires} or {@code secure}.
   */
  public static String validateName(String name) {
    if ("".equals(name)) throw new IllegalArgumentException("Name is empty.");

    if (!isUSASCII(name))
      throw new IllegalArgumentException("Invalid name, contains non-US-ASCII characters: " + name);

    name = name.trim().toLowerCase(Locale.ROOT); // RFC2965: Name is case-insensitive

    // RFC2616 token syntax forbids control characters and separators; this follows that guidance.

    for (int i = 0; i < name.length(); i++) {
      char c = name.charAt(i);
      if (Character.isWhitespace(c))
        throw new IllegalArgumentException("Invalid name, contains whitespace: " + name);

      // From isISOControl javadoc: A character is considered to be an ISO control character if it's
      // in the range [0,31] or [127,159]
      if (Character.isISOControl(c))
        throw new IllegalArgumentException("Invalid name, contains control characters.");

      if (HTTP_SEPARATOR_CHARACTERS.contains(c))
        throw new IllegalArgumentException(
            "Invalid name, contains one of the explicitely disallowed characters: " + name);
    }

    if (name.startsWith("$")
        || "comment".equals(name)
        || "discard".equals(name)
        || "domain".equals(name)
        || "expires".equals(name)
        || "max-age".equals(name)
        || "path".equals(name)
        || "secure".equals(name)
        || "version".equals(name)) throw new IllegalArgumentException("Name is reserved: " + name);

    return name;
  }

  @SuppressWarnings("BooleanMethodIsAlwaysInverted")
  private static boolean isUSASCII(String name) {
    for (int i = 0; i < name.length(); i++) {
      char c = name.charAt(i);
      // Java chars are Unicode. Unicode is a superset of US-ASCII.
      if (c < 32 || c > 126) return false;
    }
    return true;
  }

  /**
   * Validates and trims a cookie value, enforcing US-ASCII content and disallowing RFC2616
   * separator characters unless quoted externally by the caller.
   *
   * <p>Whitespace is permitted within the value but control characters and an explicit separator
   * set are rejected to avoid malformed header output. The returned value is safe to append to a
   * {@code name=value} pair without additional escaping.
   *
   * @param value Raw value text; must be US-ASCII and free of control characters and the explicit
   *     separator set defined by RFC2616.
   * @return Trimmed value suitable for serialization; never {@code null}.
   * @throws IllegalArgumentException If the value includes disallowed characters or non-US-ASCII
   *     code points.
   */
  public static String validateValue(String value) {
    if (!isUSASCII(value))
      throw new IllegalArgumentException(
          "Invalid value, contains non-US-ASCII characters: " + value);

    value = value.trim();

    // RFC2616 allows quoted-string values to include most characters; here we apply a stricter set.

    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      // We allow whitespace in the value because quotation is allowed and supported by the parser
      // in ReceivedCookie

      if (Character.isISOControl(c))
        throw new IllegalArgumentException("Invalid value, contains control characters.");

      // The invalid character list mirrors the separator set used by RFC2616 token rules.
      if (INVALID_VALUE_CHARACTERS.contains(c))
        throw new IllegalArgumentException(
            "Invalid value, contains one of the explicitely disallowed characters: " + value);
    }

    return value;
  }

  /**
   * Ensures the provided expiration date is in the future so that user agents accept the cookie.
   *
   * <p>This helper is intentionally strict: any date at or before the current moment triggers an
   * {@link IllegalArgumentException}. Callers should compute the desired lifetime before invoking
   * this method to avoid partially constructed cookies.
   *
   * @param expirationDate Absolute expiration {@link Date}; must represent a time after the current
   *     system clock value.
   * @return The same {@link Date} instance when valid; callers retain ownership of the mutable
   *     object.
   * @throws IllegalArgumentException If the supplied date is in the past or exactly now.
   */
  public static Date validateExpirationDate(Date expirationDate) {
    if (new Date().after(expirationDate))
      throw new IllegalArgumentException("Illegal expiration date, is in past: " + expirationDate);

    return expirationDate;
  }

  /**
   * Returns the domain associated with this cookie, or {@code null} if no domain attribute was
   * specified.
   *
   * @return Domain URI used for scoping by user agents; may be {@code null} when the cookie is host
   *     only.
   */
  public URI getDomain() {
    return domain;
  }

  /**
   * Returns the path scope for this cookie, preserving the original casing provided at construction
   * time.
   *
   * @return Relative path beginning with {@code /} that limits when the cookie is sent back to the
   *     server; never {@code null}.
   */
  public URI getPath() {
    return path;
  }

  /**
   * Returns the validated, lowercased cookie name.
   *
   * @return Token identifying the cookie; guaranteed to be US-ASCII and free of reserved names.
   */
  public String getName() {
    return name;
  }

  /**
   * Returns the sanitized value payload for this cookie.
   *
   * @return Trimmed US-ASCII cookie value safe for header emission; never {@code null} (empty when
   *     constructed with {@code null}).
   */
  public String getValue() {
    return value;
  }

  /**
   * Encodes this cookie into a {@code Set-Cookie2} header value following RFC2965 field ordering
   * and Crypta compatibility rules.
   *
   * <p>The method emits attributes in a deterministic order (name/value, version, domain, path,
   * expires, discard) without quoting values, mirroring Firefox 4 behavior and the HTTP State draft
   * cited in the original implementation. Callers generally invoke this from {@link
   * ToadletContext#setCookie(Cookie)}; the returned string omits the {@code set-cookie2:} prefix so
   * it can be placed directly into header collections.
   *
   * @return Serialized header payload representing the cookie; suitable for immediate inclusion in
   *     HTTP responses.
   */
  protected String encodeToHeaderValue() {
    StringBuilder sb =
        new StringBuilder(
            512); // Capacity chosen for current Freetalk usage; adjust if headers grow.

    // RFC2965: Name MUST be first.
    sb.append(name);
    sb.append("=");
    sb.append(value);
    sb.append(';');

    sb.append("version=");
    sb.append(version);
    sb.append(';');

    if (domain != null) {
      sb.append("domain=");
      sb.append(domain);
      sb.append(';');
    }

    sb.append("path=");
    sb.append(path);
    sb.append(';');

    sb.append("expires=");
    sb.append(TimeUtil.makeHTTPDate(expirationDate.getTime()));
    sb.append(';');

    if (discard) {
      sb.append("discard=");
      sb.append(true);
      sb.append(';');
    }

    return sb.toString();
  }
}
