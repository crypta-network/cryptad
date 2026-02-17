package network.crypta.clients.http;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Instant;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import network.crypta.support.TimeUtil;

/**
 * Represents an outbound HTTP cookie created by Crypta toadlets and serialized into response
 * headers.
 *
 * <p>This class encapsulates the state required to emit standards-compliant {@code Set-Cookie2}
 * headers for the web interface. Callers typically build an instance with {@link #create(URI,
 * String, String, Instant)} and pass it to {@link ToadletContext#setCookie(Cookie)} to attach it to
 * a response. Validation routines enforce a conservative subset of RFC2965/RFC2616 so malformed or
 * potentially dangerous values are rejected early. Typical callers treat instances as single-use
 * values assembled on a per-response basis.
 *
 * <p>Cookies produced here use version {@code 1}, default to discard-on-close, and expect absolute
 * paths with optional domains limited to HTTP(S) schemes. Timestamp handling uses {@link
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
  private final int version;

  /**
   * Optional domain scope for the cookie. When present it must use the {@code http} or {@code
   * https} scheme and omit path segments.
   */
  private final URI domain;

  /**
   * Path restriction for the cookie. Must begin with {@code /}, is case-sensitive, and must be a
   * relative URI as defined by {@link #validatePath(URI)}.
   */
  private final URI path;

  /**
   * Lowercase token identifying the cookie. Restricted to US-ASCII printable characters that are
   * not separators or reserved names defined by RFC2965.
   */
  private final String name;

  /**
   * Canonicalized cookie payload. Stored as a trimmed US-ASCII string without forbidden separator
   * characters to ensure safe header emission.
   */
  private final String value;

  /**
   * Expiration timestamp interpreted in the GMT HTTP-date format during header serialization;
   * callers provide an absolute {@link Instant} in the future.
   */
  private final Instant expirationDate;

  /**
   * Indicates whether the cookie should be discarded when the user agent session ends; defaults to
   * {@code true} for Crypta browser interactions.
   */
  private final boolean discard;

  /** Immutable validated state used to construct a cookie without throwing from constructors. */
  private record CookieState(
      URI domain, URI path, String name, String value, Instant expirationDate) {}

  /**
   * Internal constructor for validated cookie state. Callers should use {@link #create(URI, String,
   * String, Instant)} or {@link #create(URI, URI, String, String, Instant)}.
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
   * @param myExpirationDate Absolute expiration moment in the future; instants in the past cause an
   *     {@link IllegalArgumentException} during validation.
   */
  protected Cookie(URI myPath, String myName, String myValue, Instant myExpirationDate) {
    this(validateState(null, myPath, myName, myValue, myExpirationDate));
  }

  /**
   * Builds a {@link Cookie} with an optional explicit domain attribute.
   *
   * <p>When {@code myDomain} is {@code null}, the cookie remains host-only. When provided, the
   * domain must pass {@link #validateDomain(URI)} and is emitted in {@link #encodeToHeaderValue()}.
   * All other validation and normalization rules are identical to {@link #Cookie(URI, String,
   * String, Instant)}.
   *
   * @param myDomain Optional domain scope; must be {@code http} or {@code https} and omit path
   *     segments when non-null.
   * @param myPath The cookie path; must be relative, start with {@code /}, and represent the scope
   *     under which the cookie will be sent back.
   * @param myName Token identifying the cookie; trimmed, lowercased, US-ASCII, and free of reserved
   *     names such as {@code domain} or {@code secure}.
   * @param myValue Payload to send to the client; may be {@code null} to request an empty cookie
   *     value and must avoid control characters and separator tokens.
   * @param myExpirationDate Absolute expiration moment in the future; instants in the past cause an
   *     {@link IllegalArgumentException} during validation.
   */
  protected Cookie(
      URI myDomain, URI myPath, String myName, String myValue, Instant myExpirationDate) {
    this(validateState(myDomain, myPath, myName, myValue, myExpirationDate));
  }

  private Cookie(CookieState state) {
    version = 1;
    domain = state.domain();
    path = state.path();
    name = state.name();
    value = state.value();
    expirationDate = state.expirationDate();
    discard = true; // Freenet cookies are intended to be discarded when the browser is closed.
  }

  /**
   * Creates and validates a host-only cookie.
   *
   * @param path cookie path
   * @param name cookie name
   * @param value cookie value
   * @param expirationDate expiration timestamp
   * @return a validated cookie
   */
  public static Cookie create(URI path, String name, String value, Instant expirationDate) {
    return create(null, path, name, value, expirationDate);
  }

  /**
   * Creates and validates a cookie with optional domain scope.
   *
   * @param domain optional domain scope
   * @param path cookie path
   * @param name cookie name
   * @param value cookie value
   * @param expirationDate expiration timestamp
   * @return a validated cookie
   */
  public static Cookie create(
      URI domain, URI path, String name, String value, Instant expirationDate) {
    return new Cookie(validateState(domain, path, name, value, expirationDate));
  }

  private static CookieState validateState(
      URI domain, URI path, String name, String value, Instant expirationDate) {
    URI validatedDomain = domain != null ? validateDomain(domain) : null;
    URI validatedPath = validatePath(path);
    String validatedName = validateName(name);
    String validatedValue = value != null ? validateValue(value) : "";
    Instant validatedExpiration = validateExpirationDate(expirationDate);
    return new CookieState(
        validatedDomain, validatedPath, validatedName, validatedValue, validatedExpiration);
  }

  /** Returns true if two Cookies have equal domain, path, and name. Does not check the value! */
  @Override
  public boolean equals(Object obj) {
    if (obj == this) return true;

    if (!(obj instanceof Cookie other)) return false;

    // RFC2965: Two cookies are equal if name and domain are equal with case-insensitive comparison
    // and the path is equal with case-sensitive comparison.
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
    return Objects.hash(domain == null ? null : domain.toString(), path.toString(), name);
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
    return validateDomain(new URI(domainString));
  }

  /**
   * Validates a pre-parsed domain URI for cookie use, enforcing scheme and path constraints.
   *
   * <p>The method accepts only {@code http} or {@code https} schemes and forbids any non-root path
   * component. On success, it returns a lowercased URI representation, so cookie identity
   * comparisons remain case-insensitive for domain text.
   *
   * @param domain Candidate domain URI, typically derived from the request host; must not be {@code
   *     null}.
   * @return A lowercased {@link URI} suitable for stable cookie identity comparisons.
   * @throws IllegalArgumentException If the scheme is not HTTP(S), or the URI includes a path
   *     segment other than {@code /}, query, fragment, or user-info.
   */
  public static URI validateDomain(URI domain) {
    String scheme = domain.getScheme();

    if (scheme == null)
      throw new IllegalArgumentException("Illegal cookie domain, must include scheme: " + domain);

    scheme = scheme.toLowerCase(Locale.ROOT);

    if (!"http".equals(scheme) && !"https".equals(scheme))
      throw new IllegalArgumentException("Illegal cookie domain, must be http or https: " + domain);

    String path = domain.getPath();

    if (!"".equals(path) && !"/".equals(path))
      throw new IllegalArgumentException("Illegal cookie domain, contains a path: " + domain);

    if (domain.getQuery() != null)
      throw new IllegalArgumentException("Illegal cookie domain, contains a query: " + domain);

    if (domain.getFragment() != null)
      throw new IllegalArgumentException("Illegal cookie domain, contains a fragment: " + domain);

    if (domain.getUserInfo() != null)
      throw new IllegalArgumentException("Illegal cookie domain, contains user info: " + domain);

    return URI.create(domain.toString().toLowerCase(Locale.ROOT));
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
   * @throws URISyntaxException If the string fails, URI parsing before validation occurs.
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

      // From isISOControl Javadoc: A character is considered to be an ISO control character if it's
      // in the range [0,31] or [127,159]
      if (Character.isISOControl(c))
        throw new IllegalArgumentException("Invalid name, contains control characters.");

      if (HTTP_SEPARATOR_CHARACTERS.contains(c))
        throw new IllegalArgumentException(
            "Invalid name, contains one of the explicitly disallowed characters: " + name);
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
   * <p>Whitespace is permitted within the value, but control characters and an explicit separator
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
            "Invalid value, contains one of the explicitly disallowed characters: " + value);
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
   * @param expirationDate Absolute expiration {@link Instant}; must represent a time after the
   *     current system clock value.
   * @return The same {@link Instant} instance when valid; callers retain ownership of the value.
   * @throws IllegalArgumentException If the supplied date is in the past or exactly now.
   */
  public static Instant validateExpirationDate(Instant expirationDate) {
    if (Instant.now().isAfter(expirationDate))
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
  String encodeToHeaderValue() {
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
    sb.append(TimeUtil.makeHTTPDate(expirationDate.toEpochMilli()));
    sb.append(';');

    if (discard) {
      sb.append("discard=");
      sb.append(true);
      sb.append(';');
    }

    return sb.toString();
  }
}
