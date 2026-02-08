package network.crypta.clients.http;

import static java.util.concurrent.TimeUnit.DAYS;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.StringJoiner;
import java.util.TimeZone;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.clients.http.FProxyFetchInProgress.REFILTER_POLICY;
import network.crypta.clients.http.bookmark.BookmarkManager;
import network.crypta.crypt.SSL;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.TimeUtil;
import network.crypta.support.URIPreEncoder;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.LineReadingInputStream;
import network.crypta.support.io.NoFreeBucket;
import network.crypta.support.io.TooLongException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Concrete {@link ToadletContext} that encapsulates a single HTTP request lifecycle and the
 * response tools exposed to toadlets. The instance is created once the request line and headers
 * have been parsed and stays bound to that socket conversation until the handler decides whether to
 * keep the connection alive.
 *
 * <p>Typical usage flows from {@link #handle(Socket, ToadletRequestServices)}: the container builds
 * a {@code ToadletContextImpl}, passes it to the selected toadlet, and the toadlet invokes
 * convenience helpers such as {@link #sendReplyHeaders(int, String, MultiValueTable, String, long)}
 * or {@link #writeData(Bucket)}. The context tracks cookies, form-password validation, CSP/HSTS
 * headers, and other protocol details so individual toadlets can focus on rendering content.
 *
 * <p>The object is not thread-safe and is intended for single-request, single-thread use. Once
 * {@link #close()} or {@link #forceDisconnect()} flips the internal state, further writes throw
 * {@link ToadletContextClosedException}. Callers should treat instances as short-lived and avoid
 * retaining references beyond the handling path.
 *
 * <ul>
 *   <li>Responsibilities: header parsing, policy enforcement, cookie parsing/setting, and reply
 *       header generation.
 *   <li>Networking: wraps a single socket output stream; connection reuse obeys HTTP/1.0 and
 *       keep-alive hints.
 *   <li>Security: injects strict CSP/HSTS headers and enforces form-password checks when required
 *       by toadlets.
 * </ul>
 *
 * @author root
 * @see ToadletContext
 */
public class ToadletContextImpl implements ToadletContext {
  private static final Logger LOG = LoggerFactory.getLogger(ToadletContextImpl.class);
  private static final String HTML_TITLE_PREFIX = "<html><head><title>";
  private static final String BAD_REQUEST = "Bad Request";
  private static final String CONNECTION_HEADER = "connection";

  private static final Class<?>[] HANDLE_PARAMETERS =
      new Class<?>[] {URI.class, HTTPRequest.class, ToadletContext.class};

  /* methods listed here are *not* configurable with
   * AllowData annotation
   */
  private static final String METHODS_MUST_HAVE_DATA = "POST";
  private static final String METHODS_CANNOT_HAVE_DATA = "GET";
  private static final String METHODS_RESTRICTED_MODE = "GET POST";

  private final MultiValueTable<String, String> headers;
  private ArrayList<ReceivedCookie>
      cookies; // Null until the first time the user queries us for a ReceivedCookie.
  private ArrayList<Cookie> replyCookies; // Null until the first time the user sets a Cookie.
  private final OutputStream sockOutputStream;
  private final PageMaker pagemaker;
  private final BucketFactory bf;
  private final ToadletContainer container;
  private final UserAlertManager userAlertManager;
  private final BookmarkManager bookmarkManager;
  private final InetAddress remoteAddr;
  private Exception firstReplySendingException;
  private final AtomicReference<Toadlet> activeToadlet = new AtomicReference<>();

  /** The unique id of the request */
  private final String uniqueId;

  private final URI uri;

  // Legacy Logger threshold callbacks removed; use LOG.isDebugEnabled()/isTraceEnabled().

  /**
   * Is the context closed? If so, don't allow writes anymore. This is because there may be later
   * requests.
   */
  private volatile boolean closed;

  private volatile boolean shouldDisconnect;

  /**
   * Builds a per-request context wrapping the client socket, parsed headers, and supporting
   * collaborators. The context owns the socket output stream and carries helpers for cookie
   * handling, form-password validation, and reply generation. Instances are expected to be
   * short-lived; callers should create one per request and avoid reuse across threads or
   * connections. The constructor does not validate the supplied headers or URI beyond storing them;
   * those are assumed to be pre-parsed by the caller.
   *
   * @param sock Client socket already accepted by the server loop and ready for I/O on the current
   *     thread.
   * @param headers Parsed HTTP request headers in a multi-value table, preserving repeated fields
   *     as delivered by the client.
   * @param bf Bucket factory used for request bodies and outgoing payload buffering during this
   *     context's lifetime.
   * @param services Shared request-handling services bundled by the HTTP listener.
   * @param uri Fully parsed and normalized request URI associated with the incoming HTTP request
   *     line.
   * @param uniqueId Monotonic identifier supplied by the container to correlate logs and responses
   *     across asynchronous callbacks.
   * @throws IOException If the socket output stream cannot be obtained for later replies.
   */
  public ToadletContextImpl(
      Socket sock,
      MultiValueTable<String, String> headers,
      BucketFactory bf,
      ToadletRequestServices services,
      URI uri,
      long uniqueId)
      throws IOException {
    this.headers = headers;
    this.cookies = null;
    this.replyCookies = null;
    this.closed = false;
    this.uri = uri;
    sockOutputStream = sock.getOutputStream();
    remoteAddr = sock.getInetAddress();
    if (LOG.isTraceEnabled()) LOG.trace("Connection from {}", remoteAddr);
    this.bf = bf;
    this.pagemaker = services.pageMaker();
    this.container = services.container();
    this.userAlertManager = services.userAlertManager();
    this.bookmarkManager = services.bookmarkManager();
    // Generate a unique id
    this.uniqueId = String.valueOf(uniqueId);
  }

  private void close() {
    closed = true;
  }

  private void sendMethodNotAllowed(String method, boolean shouldDisconnect)
      throws ToadletContextClosedException, IOException {
    if (closed) throw new ToadletContextClosedException();
    if (LOG.isDebugEnabled()) {
      LOG.debug("Method not allowed: {}", method);
    }
    MultiValueTable<String, String> mvt = MultiValueTable.from("Allow", "GET, PUT");
    sendError(
        sockOutputStream,
        405,
        "Method Not Allowed",
        l10n("methodNotAllowed"),
        shouldDisconnect,
        mvt);
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("ToadletContextImpl." + key);
  }

  private static String l10nParseError(String value) {
    return NodeL10n.getBase()
        .getString(
            "ToadletContextImpl.parseErrorWithError", new String[] {"error"}, new String[] {value});
  }

  /**
   * Send an error message. Caller provides the HTTP code, reason string, and a message, which will
   * become the title and the h1'ed contents of the error page.
   */
  private static void sendError(
      OutputStream os,
      int code,
      String httpReason,
      String message,
      boolean shouldDisconnect,
      MultiValueTable<String, String> mvt)
      throws IOException {
    sendHTMLError(
        os,
        code,
        httpReason,
        HTML_TITLE_PREFIX + message + "</title></head><body><h1>" + message + "</h1></body>",
        shouldDisconnect,
        mvt);
  }

  /**
   * Send an error message containing full HTML from a String.
   *
   * @param os The OutputStream to send the message to.
   * @param code The HTTP status code.
   * @param httpReason The HTTP reason string for the HTTP status code. Do not make stuff up, use
   *     the official reason string, or some browsers may break.
   * @param htmlMessage The HTML string to send.
   * @param disconnect Whether to disconnect from the client afterward.
   * @param mvt Any additional headers.
   * @throws IOException If we could not send the error message.
   */
  private static void sendHTMLError(
      OutputStream os,
      int code,
      String httpReason,
      String htmlMessage,
      boolean disconnect,
      MultiValueTable<String, String> mvt)
      throws IOException {
    if (mvt == null) mvt = new MultiValueTable<>();
    byte[] messageBytes = htmlMessage.getBytes(StandardCharsets.UTF_8);
    ReplyHeaders replyHeaders = ReplyHeaders.of(code, httpReason, "text/html; charset=UTF-8", mvt);
    ReplyHeaderOptions options =
        new ReplyHeaderOptions(messageBytes.length, null, disconnect, false, false);
    sendReplyHeaders(os, replyHeaders, options);
    os.write(messageBytes);
  }

  private void sendNoToadletError(boolean shouldDisconnect)
      throws ToadletContextClosedException, IOException {
    if (closed) throw new ToadletContextClosedException();
    sendError(sockOutputStream, 404, "Not Found", l10n("noSuchToadlet"), shouldDisconnect, null);
  }

  private static void sendURIParseError(OutputStream os, Throwable e) throws IOException {
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    e.printStackTrace(pw);
    pw.close();
    String message =
        HTML_TITLE_PREFIX
            + l10n("uriParseErrorTitle")
            + "</title></head><body><p>"
            + HTMLEncoder.encode(e.getMessage())
            + "</p><pre>\n"
            + sw;
    sendHTMLError(os, 400, BAD_REQUEST, message, true, null);
  }

  /**
   * Sends HTTP response headers for a reply with a known payload length. This convenience overload
   * keeps scripting enabled according to container policy and assumes no modification time for
   * caching. Callers typically use it when streaming simple bodies where chunking is unnecessary
   * and connection reuse is allowed. The method must be called before writing any response bytes
   * and only once per context instance; later attempts raise an error to prevent malformed
   * responses.
   *
   * @param code HTTP status code to emit toward the client connection.
   * @param desc Human-readable reason phrase paired with the status code for logging and clients.
   * @param mvt Additional headers to merge into the response; may be {@code null} for none.
   * @param mimeType MIME type string; {@code null} sends no content-type header.
   * @param length Exact number of response bytes that will follow; {@code -1} omits the header.
   * @throws ToadletContextClosedException If the context has already been closed for further
   *     output.
   * @throws IOException If writing to the underlying socket output stream fails.
   */
  @Override
  public void sendReplyHeaders(
      int code, String desc, MultiValueTable<String, String> mvt, String mimeType, long length)
      throws ToadletContextClosedException, IOException {
    ReplyHeaders replyHeaders = ReplyHeaders.of(code, desc, mimeType, mvt);
    ReplyHeaderOptions options =
        new ReplyHeaderOptions(
            length, null, shouldDisconnect, container.isFProxyJavascriptEnabled(), false);
    sendReplyHeaders(replyHeaders, options);
  }

  /**
   * Sends HTTP response headers with optional suppression of inline JavaScript. Use this overload
   * when a caller wants to ensure a hardened response (e.g., error pages) even if global JavaScript
   * support is enabled in the container. The method computes CSP and connection headers based on
   * the provided arguments and the container configuration, deferring to keep-alive if permitted.
   *
   * @param code HTTP status code to emit toward the client connection.
   * @param desc Human-readable reason phrase paired with the status code for logging and clients.
   * @param mvt Additional headers to merge into the response; may be {@code null} for none.
   * @param mimeType MIME type string; {@code null} sends no content-type header.
   * @param length Exact number of response bytes that will follow; {@code -1} omits the header.
   * @param forceDisableJavascript When {@code true}, disables script allowances regardless of
   *     container settings.
   * @throws ToadletContextClosedException If the context has already been closed for further
   *     output.
   * @throws IOException If writing to the underlying socket output stream fails.
   */
  @Override
  public void sendReplyHeaders(
      int code,
      String desc,
      MultiValueTable<String, String> mvt,
      String mimeType,
      long length,
      boolean forceDisableJavascript)
      throws ToadletContextClosedException, IOException {
    ReplyHeaders replyHeaders = ReplyHeaders.of(code, desc, mimeType, mvt, forceDisableJavascript);
    boolean enableJavascript = !forceDisableJavascript && container.isFProxyJavascriptEnabled();
    ReplyHeaderOptions options =
        new ReplyHeaderOptions(length, null, shouldDisconnect, enableJavascript, false);
    sendReplyHeaders(replyHeaders, options);
  }

  /**
   * Sends response headers for static content with a known last-modified timestamp. Unlike the
   * streaming variant, this method always enables cache-related headers based on {@code mTime} so
   * user agents can perform conditional requests and reuse cached assets. It leaves scripting and
   * framing disabled to align with typical static resource expectations.
   *
   * @param replyCode HTTP status code to emit for the static response payload.
   * @param replyDescription Reason phrase to go with the status code for client readability.
   * @param mvt Additional headers to merge into the response; may be {@code null} for none.
   * @param mimeType MIME type string; {@code null} sends no content-type header.
   * @param contentLength Exact number of bytes that will be written after the headers.
   * @param mTime Last-modified timestamp used to set caching headers; must be non-null.
   * @throws ToadletContextClosedException If the context is already closed and cannot send data.
   * @throws IOException If the socket output stream rejects the header bytes.
   */
  @Override
  public void sendReplyHeadersStatic(
      int replyCode,
      String replyDescription,
      MultiValueTable<String, String> mvt,
      String mimeType,
      long contentLength,
      Instant mTime)
      throws ToadletContextClosedException, IOException {
    if (mTime == null) throw new IllegalArgumentException();
    ReplyHeaders replyHeaders = ReplyHeaders.of(replyCode, replyDescription, mimeType, mvt);
    ReplyHeaderOptions options =
        new ReplyHeaderOptions(contentLength, mTime, shouldDisconnect, false, false);
    sendReplyHeaders(replyHeaders, options);
  }

  /**
   * Sends response headers for FProxy pages, enabling script support when both web pushing and
   * JavaScript are permitted by the container. The method is intended for HTML responses rendered
   * by the gateway UI, where richer interactivity is required and framing may be allowed based on
   * the container's CSP policy. It mirrors {@link #sendReplyHeaders(int, String, MultiValueTable,
   * String, long)} but narrows semantics to the FProxy context for clarity and auditing.
   *
   * @param replyCode HTTP status code to emit toward the client connection.
   * @param replyDescription Human-readable reason phrase paired with the status code for logging
   *     and clients.
   * @param mvt Additional headers to merge into the response; may be {@code null} for none.
   * @param mimeType MIME type string; {@code null} sends no content-type header.
   * @param contentLength Exact number of response bytes that will follow the header block.
   * @throws ToadletContextClosedException If the context has already been closed for further
   *     output.
   * @throws IOException If writing to the underlying socket output stream fails.
   */
  @Override
  public void sendReplyHeadersFProxy(
      int replyCode,
      String replyDescription,
      MultiValueTable<String, String> mvt,
      String mimeType,
      long contentLength)
      throws ToadletContextClosedException, IOException {
    boolean enableJavascript =
        container.isFProxyWebPushingEnabled() && container.isFProxyJavascriptEnabled();
    ReplyHeaders replyHeaders = ReplyHeaders.of(replyCode, replyDescription, mimeType, mvt);
    ReplyHeaderOptions options =
        new ReplyHeaderOptions(contentLength, null, shouldDisconnect, enableJavascript, true);
    sendReplyHeaders(replyHeaders, options);
  }

  private void sendReplyHeaders(ReplyHeaders replyHeaders, ReplyHeaderOptions options)
      throws ToadletContextClosedException, IOException {
    if (closed) throw new ToadletContextClosedException();
    if (firstReplySendingException != null) {
      throw new IllegalStateException("Already sent headers!", firstReplySendingException);
    }
    firstReplySendingException = new Exception();

    MultiValueTable<String, String> mvt = replyHeaders.headers();
    if (mvt == null) {
      mvt = new MultiValueTable<>();
    }
    if (replyCookies != null) {
      // We do NOT use "set-cookie2" even though we should, according though RFC2965 - Firefox
      // 3.0.14
      // ignores it for me!

      for (Cookie cookie : replyCookies) {
        final String cookieHeader = cookie.encodeToHeaderValue();
        mvt.put("set-cookie", cookieHeader);
        if (LOG.isDebugEnabled()) LOG.debug("set-cookie: {}", cookieHeader);
      }
    }

    if (container.isSSL()) {
      String hsts = SSL.getHSTSHeader();
      if (!hsts.isEmpty() && !mvt.containsKey("strict-transport-security")) {
        // SSL enabled, set strict-transport-security so that the user agent upgrades future
        // requests
        // to SSL.
        mvt.put("strict-transport-security", hsts);
      }
    }
    ReplyHeaders resolvedHeaders =
        new ReplyHeaders(
            replyHeaders.code(),
            replyHeaders.description(),
            replyHeaders.mimeType(),
            mvt,
            replyHeaders.forceDisableJavascript());
    sendReplyHeaders(sockOutputStream, resolvedHeaders, options);
  }

  /**
   * Returns the page maker responsible for rendering localized HTML responses. Callers typically
   * use it to assemble templated UI fragments after access checks have passed. The reference is
   * shared with other contexts but should be treated as read-mostly; heavy mutations belong in the
   * container wiring. It also centralizes consistent branding and error layout so individual
   * toadlets can remain lightweight and focus on data retrieval and validation.
   *
   * @return PageMaker instance configured for the current node environment and localization
   *     settings.
   */
  @Override
  public PageMaker getPageMaker() {
    return pagemaker;
  }

  /**
   * Retrieves the configured form password string used to protect POST endpoints from CSRF and
   * cross-user invocation. The value is opaque to callers and should be compared using
   * constant-time checks, as implemented by {@link #hasFormPassword(HTTPRequest)}. Do not expose it
   * to logs. The password may be rotated between requests by container policy, so callers must
   * fetch it anew for each validation rather than caching it across contexts.
   *
   * @return Form password for this node; never {@code null} but may be empty in permissive modes.
   */
  @Override
  public String getFormPassword() {
    return container.getFormPassword();
  }

  /**
   * Validates that the supplied request carries the correct form password, redirecting to the root
   * path on failure. This helper centralizes CSRF enforcement for POST handlers and ensures callers
   * do not accidentally leak response bodies before verifying credentials. When validation fails,
   * the caller should stop processing and rely on the redirect that was already emitted.
   *
   * @param request HTTP request object containing parsed parameters and body parts for validation.
   * @return {@code true} when the form password matches the configured value; {@code false} after a
   *     redirect has been sent to the client.
   * @throws ToadletContextClosedException If the context is already closed before the redirect is
   *     written.
   * @throws IOException If the header transmission fails while issuing the redirect response.
   */
  @Override
  public boolean checkFormPassword(HTTPRequest request)
      throws ToadletContextClosedException, IOException {
    return checkFormPassword(request, "/");
  }

  /**
   * Validates that the supplied request carries the correct form password, redirecting to a caller
   * provided location on failure. This variant is useful when a toadlet wants to return the user to
   * a specific page rather than the root. The method does not throw when authentication fails; it
   * simply returns {@code false} after writing headers.
   *
   * @param request HTTP request object containing parsed parameters and body parts for validation.
   * @param redirectTo Absolute or relative path where unauthenticated clients should be redirected.
   * @return {@code true} when the form password matches the configured value; {@code false} after a
   *     redirect has been sent to the target location.
   * @throws ToadletContextClosedException If the context is already closed before the redirect is
   *     written.
   * @throws IOException If the header transmission fails while issuing the redirect response.
   */
  @Override
  public boolean checkFormPassword(HTTPRequest request, String redirectTo)
      throws ToadletContextClosedException, IOException {
    if (!hasFormPassword(request)) {
      MultiValueTable<String, String> redirectHeaders =
          MultiValueTable.from("Location", redirectTo);
      sendReplyHeaders(302, "Found", redirectHeaders, null, 0);
      return false;
    } else {
      return true;
    }
  }

  /**
   * Checks whether the current client holds full-access permissions for the requested resource. If
   * access is denied, the target toadlet is asked to emit its unauthorized page and processing
   * stops. Use this early in request handling to prevent partially rendered responses that might
   * leak privileged information.
   *
   * @param toadlet Target toadlet that can render an unauthorized response when access fails.
   * @return {@code true} when full access is permitted by the container policy; {@code false} after
   *     the toadlet has produced an unauthorized page.
   * @throws ToadletContextClosedException If the context has already been closed during handling.
   * @throws IOException If the unauthorized page cannot be written to the client socket.
   * @see ToadletContext#checkFullAccess(Toadlet)
   */
  @Override
  public boolean checkFullAccess(Toadlet toadlet)
      throws ToadletContextClosedException, IOException {
    if (isAllowedFullAccess()) {
      return true;
    } else {
      toadlet.sendUnauthorizedPage(this);
      return false;
    }
  }

  /**
   * Performs a constant-time comparison between the supplied {@code formPassword} parameter and the
   * node's configured secret. Logging remains conservative to avoid exposing mismatched values.
   * This method does not send responses and can be used by callers that want to enforce their own
   * error handling flow.
   *
   * @param request HTTP request containing a potential {@code formPassword} parameter to verify.
   * @return {@code true} when the provided parameter matches exactly; {@code false} otherwise.
   */
  @Override
  public boolean hasFormPassword(HTTPRequest request) {
    String pass = request.getPartAsStringFailsafe("formPassword", 32);
    byte[] inputBytes = pass.getBytes(StandardCharsets.UTF_8);
    byte[] compareBytes = getFormPassword().getBytes(StandardCharsets.UTF_8);
    if (!MessageDigest.isEqual(inputBytes, compareBytes)) {
      if (LOG.isDebugEnabled()) LOG.debug("Bad formPassword: {}", pass);
      return false;
    } else return true;
  }

  /**
   * Returns the alert manager that can surface user-facing notifications triggered during this
   * request. Handlers can publish warnings or informational alerts without re-creating alert
   * infrastructure, ensuring consistent presentation across the web UI. The manager handles
   * queuing, deduplication, and localization concerns so individual toadlets can raise alerts
   * without worrying about display semantics or thread confinement.
   *
   * @return Shared {@link UserAlertManager} instance used by the container for UI alerts.
   */
  @Override
  public UserAlertManager getAlertManager() {
    return userAlertManager;
  }

  /**
   * Provides access to the bookmark subsystem so toadlets can read or modify stored bookmarks while
   * servicing this request. The returned manager is shared across requests and should be treated as
   * a service dependency rather than a per-request object. It offers persistence, validation, and
   * localization support so individual handlers can focus on user flows rather than storage
   * details.
   *
   * @return Bookmark manager configured for the running node; never {@code null}.
   */
  @Override
  public BookmarkManager getBookmarkManager() {
    return bookmarkManager;
  }

  /**
   * Returns a view of the request headers as a multi-value table. Callers can inspect fields such
   * as {@code user-agent}, cookies, or conditional headers to tailor responses. The table reflects
   * the parsed input and should not be mutated unless the caller intends to shadow values during
   * response generation. Iteration preserves all repeated fields, enabling accurate parsing of
   * headers such as {@code cookie} or {@code accept-language} that legitimately appear multiple
   * times.
   *
   * @return Request headers keyed by lower-cased field names with all received values preserved.
   */
  @Override
  public MultiValueTable<String, String> getHeaders() {
    return headers;
  }

  private void parseCookies() throws ParseException {
    if (cookies != null) return;

    int cookieAmount = headers.countAll("cookie");

    if (cookieAmount == 0) return;

    cookies = new ArrayList<>(cookieAmount + 1);

    for (String cookieHeader : headers.iterateAll("cookie")) {
      List<ReceivedCookie> parsedCookies = ReceivedCookie.parseHeader(cookieHeader);
      cookies.addAll(parsedCookies);
    }
  }

  /**
   * It looks up a previously received cookie by name after parsing all {@code Cookie} headers.
   * Domain and path arguments are currently unused but retained for interface compatibility.
   * Invalid cookies are skipped with logging, so a malformed entry does not prevent other cookies
   * from being resolved.
   *
   * @param domain The ignored domain hint; callers should pass the request host for future use.
   * @param path Ignored path hint; callers should pass the request path for future use.
   * @param name Case-insensitive cookie name to retrieve from the parsed collection.
   * @return Matching {@link ReceivedCookie} or {@code null} when absent or parsing produced no
   *     cookies.
   * @throws ParseException If cookie headers cannot be parsed into structured values.
   */
  @Override
  public ReceivedCookie getCookie(URI domain, URI path, String name) throws ParseException {
    parseCookies();

    if (cookies == null) { // There are no cookies.
      return null;
    }

    name = name.toLowerCase(Locale.ROOT);

    for (ReceivedCookie cookie : cookies) {
      try {
        if (cookie.getName().equals(name)) return cookie;
      } catch (RuntimeException e) {
        LOG.error("Error in cookie", e);
      }
    }

    return null;
  }

  /**
   * Registers a cookie to be sent with the response. Added cookies are encoded during header
   * emission; callers may invoke this multiple times to queue several {@code Set-Cookie} fields. A
   * cookie added here remains pending until the next call to one of the {@code sendReplyHeaders*}
   * helpers, which serializes the collection in insertion order. Because the context is tied to a
   * single request and not thread-safe, callers should add cookies before handing control to any
   * asynchronous writers. Modifications after headers have been emitted are ignored because the
   * response state is then fixed by HTTP semantics.
   *
   * @param newCookie Cookie instance to serialize into the outbound headers; must not be {@code
   *     null}.
   */
  @Override
  public void setCookie(Cookie newCookie) {
    if (replyCookies == null) replyCookies = new ArrayList<>(4);

    replyCookies.add(newCookie);
  }

  static void sendReplyHeaders(
      OutputStream sockOutputStream, ReplyHeaders replyHeaders, ReplyHeaderOptions options)
      throws IOException {

    MultiValueTable<String, String> mvt = replyHeaders.headers();
    if (mvt == null) {
      mvt = new MultiValueTable<>();
    }
    // Construct headers
    addContentTypeHeader(mvt, replyHeaders.mimeType());
    if (options.contentLength() >= 0) {
      mvt.put("content-length", Long.toString(options.contentLength()));
    }

    addCachingHeaders(mvt, options.modifiedTime());

    String nowString = TimeUtil.makeHTTPDate(System.currentTimeMillis());
    String lastModString =
        options.modifiedTime() == null
            ? nowString
            : TimeUtil.makeHTTPDate(options.modifiedTime().toEpochMilli());

    mvt.put("last-modified", lastModString);
    mvt.put("date", nowString);
    if (options.disconnect()) {
      mvt.put(CONNECTION_HEADER, "close");
    } else {
      mvt.put(CONNECTION_HEADER, "keep-alive");
    }
    mvt.put("cross-origin-embedder-policy", "require-corp");
    mvt.put("cross-origin-opener-policy", "same-origin");
    String contentSecurityPolicy = generateCSP(options.allowScripts(), options.allowFrames());
    mvt.put("content-security-policy", contentSecurityPolicy);
    mvt.put("x-content-security-policy", contentSecurityPolicy);
    mvt.put("x-webkit-csp", contentSecurityPolicy);
    mvt.put("x-frame-options", options.allowFrames() ? "SAMEORIGIN" : "DENY");
    StringBuilder buf = new StringBuilder(1024);
    buf.append("HTTP/1.1 ");
    buf.append(replyHeaders.code());
    buf.append(' ');
    buf.append(replyHeaders.description());
    buf.append("\r\n");
    for (Map.Entry<String, List<String>> entry : mvt.entrySet()) {
      String key = entry.getKey();
      List<String> list = entry.getValue();
      for (String s : list) {
        buf.append(key);
        buf.append(": ");
        buf.append(s);
        buf.append("\r\n");
      }
    }
    buf.append("\r\n");
    sockOutputStream.write(buf.toString().getBytes(StandardCharsets.US_ASCII));
  }

  private static void addCachingHeaders(MultiValueTable<String, String> mvt, Instant mTime) {
    boolean allowCaching = mTime != null;
    String expiresTime;
    String cacheControl;
    if (allowCaching) {
      expiresTime = TimeUtil.makeHTTPDate(System.currentTimeMillis() + DAYS.toMillis(30));
      cacheControl = "public, max-age=" + 3600 * 24 * 30;
    } else {
      expiresTime = "Thu, 01 Jan 1970 00:00:00 GMT";
      cacheControl =
          "private, max-age=0, must-revalidate, no-cache, no-store, post-check=0, pre-check=0";
      mvt.put("pragma", "no-cache");
    }
    mvt.put("expires", expiresTime);
    mvt.put("cache-control", cacheControl);
  }

  private static void addContentTypeHeader(MultiValueTable<String, String> mvt, String mimeType) {
    if (mimeType == null) {
      return;
    }
    if (mimeType.equalsIgnoreCase("text/html")) {
      mvt.put("content-type", mimeType + "; charset=UTF-8");
    } else {
      mvt.put("content-type", mimeType);
    }
  }

  private static String generateCSP(boolean allowScripts, boolean allowFrames) {
    // allow access to blobs, because these are purely local
    // Use modern CSP tokens; remove deprecated "options inline-script".
    return "default-src 'self' blob:; script-src "
        + (allowScripts ? "'self' 'unsafe-inline' 'unsafe-eval'" : generateRestrictedScriptSrc())
        + "; frame-src "
        + (allowFrames ? "'self'" : "'none'")
        + "; object-src 'none'"
        +
        // Always send unsafe-inline for CSS. This is safe given it can't use external stuff
        // anyway, and we only use it for our own UI.
        "; style-src 'self' 'unsafe-inline'";
  }

  private static String generateRestrictedScriptSrc() {
    // Note: auto-generate these hashes from the path to the source file
    String[] allowedScriptHashes =
        new String[] {
          "sha256-RY9OjosvFxocXEmcUqBJ2v1KByDRdUgnGHYSL3Qx/t8=" // freenet/clients/http/staticfiles/js/m3u-player.js
        };
    StringJoiner stringJoiner = new StringJoiner("' '", "'", "'");
    stringJoiner.setEmptyValue("'none'");
    for (String source : allowedScriptHashes) {
      stringJoiner.add(source);
    }
    return stringJoiner.toString();
  }

  private static final TimeZone UTC_TIME_ZONE = TimeZone.getTimeZone("UTC");

  /**
   * Parses an RFC 7231/RFC 1123 HTTP date string into a {@link Date} in UTC. The parser is strict
   * with respect to the {@code EEE, dd MMM yyyy HH:mm:ss 'GMT'} pattern and locale, matching the
   * formatting used by {@link TimeUtil#makeHTTPDate(long)}. Callers can rely on this utility when
   * interpreting headers such as {@code If-Modified-Since} or {@code Last-Modified}. Invalid input
   * results in a {@link ParseException}, allowing callers to surface clear client errors without
   * silently accepting malformed dates.
   *
   * @param httpDate Raw HTTP date string, usually sourced from client request headers.
   * @return Parsed {@link Date} instance in UTC representing the provided timestamp.
   * @throws ParseException If the supplied string does not conform to the expected HTTP date
   *     format.
   */
  public static Date parseHTTPDate(String httpDate) throws ParseException {
    SimpleDateFormat sdf = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US);
    sdf.setTimeZone(UTC_TIME_ZONE);
    return sdf.parse(httpDate);
  }

  /**
   * Handles an incoming socket connection by reading the request line, headers, and optional body
   * before dispatching to the appropriate toadlet. The loop continues to process pipelined requests
   * while the client and container allow persistent connections. Errors are translated into HTTP
   * responses where possible, with parsing and length violations mapped to {@code 400 Bad Request}
   * and unexpected exceptions mapped to {@code 500 Internal Failure}. This method blocks on I/O and
   * should be invoked from a dedicated worker thread per connection.
   *
   * @param sock Open the client socket carrying the HTTP conversation for this handler thread.
   * @param services Shared container services required for request handling.
   */
  public static void handle(Socket sock, ToadletRequestServices services) {
    try (InputStream is = new BufferedInputStream(sock.getInputStream(), 4096);
        LineReadingInputStream lis = new LineReadingInputStream(is)) {
      boolean keepProcessing = processRequest(sock, services, is, lis);
      while (keepProcessing) {
        keepProcessing = processRequest(sock, services, is, lis);
      }
    } catch (ParseException e) {
      try {
        sendError(
            sock.getOutputStream(), 400, BAD_REQUEST, l10nParseError(e.getMessage()), true, null);
      } catch (IOException _) {
        // Ignore
      }
    } catch (TooLongException _) {
      try {
        sendError(sock.getOutputStream(), 400, BAD_REQUEST, l10n("headersLineTooLong"), true, null);
      } catch (IOException _) {
        // Ignore
      }
    } catch (IOException _) {
      // ignore and return
    } catch (ToadletContextClosedException _) {
      LOG.error("ToadletContextClosedException while handling connection!");
    } catch (Exception t) {
      LOG.error("Caught error: {} handling socket", t, t);
      try {
        String msg =
            HTML_TITLE_PREFIX
                + NodeL10n.getBase().getString("Toadlet.internalErrorTitle")
                + "</title></head><body><h1>"
                + NodeL10n.getBase().getString("Toadlet.internalErrorPleaseReport")
                + "</h1><pre>";
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);
        t.printStackTrace(pw);
        pw.flush();
        msg = msg + sw + "</pre></body></html>";
        byte[] messageBytes = msg.getBytes(StandardCharsets.UTF_8);
        ReplyHeaders replyHeaders =
            ReplyHeaders.of(500, "Internal failure", "text/html; charset=UTF-8");
        ReplyHeaderOptions options =
            new ReplyHeaderOptions(messageBytes.length, null, true, false, false);
        sendReplyHeaders(sock.getOutputStream(), replyHeaders, options);
        sock.getOutputStream().write(messageBytes);
      } catch (IOException _) {
        // ignore and return
      }
    }
  }

  private static boolean processRequest(
      Socket sock, ToadletRequestServices services, InputStream is, LineReadingInputStream lis)
      throws IOException,
          ParseException,
          ToadletContextClosedException,
          NoSuchMethodException,
          IllegalAccessException,
          ToadletInvocationException {
    ToadletContainer container = services.container();
    String firstLine = lis.readLine(32768, 128, false); // ISO-8859-1 or US-ASCII, _not_ UTF-8
    if (firstLine == null) {
      sock.close();
      return false;
    }
    if (firstLine.isEmpty()) {
      return true;
    }
    RequestLine requestLine = parseRequestLine(firstLine, sock);
    if (requestLine == null) {
      return false;
    }

    MultiValueTable<String, String> requestHeaders = readHeaders(lis, sock);
    if (requestHeaders == null) {
      return false;
    }

    boolean disconnect =
        shouldDisconnectAfterHandled(requestLine.isHTTP10(), requestHeaders)
            || !container.enablePersistentConnections();

    BucketFactory bf = container.getBucketFactory();

    ToadletContextImpl ctx =
        new ToadletContextImpl(
            sock, requestHeaders, bf, services, requestLine.uri, container.generateUniqueID());
    ctx.shouldDisconnect = disconnect;

    DataReadResult dataResult =
        readRequestData(
            requestLine.method,
            requestHeaders.getFirst("content-length"),
            container.allowPosts(),
            container,
            ctx,
            bf,
            is);

    if (!dataResult.continueProcessing) {
      return false;
    }

    Bucket data = dataResult.data;
    try {
      if (!container.enableExtendedMethodHandling()
          && !METHODS_RESTRICTED_MODE.contains(requestLine.method)) {
        sendError(
            sock.getOutputStream(),
            403,
            "Forbidden",
            "Method not allowed in this configuration",
            true,
            null);
        return false;
      }

      handleToadletRequests(container, requestLine.method, requestLine.uri, data, ctx, sock);
      if (ctx.shouldDisconnect) {
        sock.close();
        return false;
      }
      return true;
    } finally {
      if (data != null) data.free();
    }
  }

  private static RequestLine parseRequestLine(String firstLine, Socket sock)
      throws IOException, ParseException {
    if (LOG.isDebugEnabled()) LOG.debug("first line: {}", firstLine);

    int firstSpace = firstLine.indexOf(' ');
    int secondSpace = firstLine.indexOf(' ', firstSpace + 1);
    if (firstSpace <= 0 || secondSpace <= firstSpace || secondSpace == firstLine.length() - 1) {
      throw new ParseException("Could not parse request line: " + firstLine, -1);
    }
    if (firstLine.indexOf(' ', secondSpace + 1) != -1) {
      throw new ParseException("Could not parse request line (too many parts): " + firstLine, -1);
    }

    String method = firstLine.substring(0, firstSpace);
    String rawUri = firstLine.substring(firstSpace + 1, secondSpace);
    String protocol = firstLine.substring(secondSpace + 1);

    if (!protocol.startsWith("HTTP/1."))
      throw new ParseException("Unrecognized protocol " + protocol, -1);

    try {
      URI uri = URIPreEncoder.encodeURI(rawUri).normalize();
      if (LOG.isDebugEnabled())
        LOG.debug(
            "URI: {} path {} host {} frag {} port {} query {} scheme {}",
            uri,
            uri.getPath(),
            uri.getHost(),
            uri.getFragment(),
            uri.getPort(),
            uri.getQuery(),
            uri.getScheme());
      return new RequestLine(method, uri, protocol);
    } catch (URISyntaxException e) {
      sendURIParseError(sock.getOutputStream(), e);
      return null;
    }
  }

  private static MultiValueTable<String, String> readHeaders(
      LineReadingInputStream lis, Socket sock) throws IOException, ParseException {
    MultiValueTable<String, String> headers = new MultiValueTable<>();
    while (true) {
      String line = lis.readLine(32768, 128, false); // ISO-8859 or US-ASCII, not UTF-8
      if (line == null) {
        sock.close();
        return null;
      }
      if (line.isEmpty()) {
        return headers;
      }
      int index = line.indexOf(':');
      if (index < 0) {
        throw new ParseException("Missing ':' in request header field", -1);
      }
      String before = line.substring(0, index).toLowerCase(Locale.ROOT);
      String after = line.substring(index + 1).trim();
      headers.put(before, after);
    }
  }

  private static DataReadResult readRequestData(
      String method,
      String contentLengthHeader,
      boolean allowPost,
      ToadletContainer container,
      ToadletContextImpl ctx,
      BucketFactory bf,
      InputStream is)
      throws IOException, ToadletContextClosedException {
    boolean missingRequiredData =
        METHODS_MUST_HAVE_DATA.contains(method) && contentLengthHeader == null;
    boolean unexpectedData =
        METHODS_CANNOT_HAVE_DATA.contains(method) && contentLengthHeader != null;
    if (missingRequiredData || unexpectedData) {
      ctx.shouldDisconnect = true;
      ctx.sendReplyHeaders(400, BAD_REQUEST, null, null, -1);
      return DataReadResult.stop();
    }

    if (contentLengthHeader == null) {
      return DataReadResult.success(null);
    }

    long length;
    try {
      length = Integer.parseInt(contentLengthHeader);
      if (length < 0) throw new NumberFormatException("content-length less than 0");
    } catch (NumberFormatException _) {
      ctx.shouldDisconnect = true;
      ctx.sendReplyHeaders(400, BAD_REQUEST, null, null, -1);
      return DataReadResult.stop();
    }

    if (allowPost && (!container.publicGatewayMode() || ctx.isAllowedFullAccess())) {
      Bucket data = bf.makeBucket(length);
      BucketTools.copyFrom(data, is, length);
      return DataReadResult.success(data);
    }

    FileUtil.skipFully(is, length);
    if ("POST".equals(method)) {
      ctx.sendMethodNotAllowed("POST", true);
    } else {
      sendError(
          ctx.sockOutputStream,
          403,
          "Forbidden",
          "Content not allowed in this configuration",
          true,
          null);
    }
    ctx.close();
    return DataReadResult.stop();
  }

  private static void handleToadletRequests(
      ToadletContainer container,
      String method,
      URI uri,
      Bucket data,
      ToadletContextImpl ctx,
      Socket sock)
      throws IOException,
          ToadletContextClosedException,
          NoSuchMethodException,
          IllegalAccessException,
          ToadletInvocationException {
    URI currentUri = uri;
    boolean redirect;
    do {
      redirect = false;
      FindToadletResult toadletResult = findToadlet(container, ctx, currentUri);
      if (toadletResult.handled) {
        return;
      }
      Toadlet toadlet = toadletResult.toadlet;
      if (toadlet == null) {
        ctx.sendNoToadletError(ctx.shouldDisconnect);
        return;
      }

      if (!toadlet.findSupportedMethods().contains(method)) {
        ctx.sendMethodNotAllowed(method, ctx.shouldDisconnect);
        return;
      }

      HTTPRequestImpl req = new HTTPRequestImpl(currentUri, data, ctx, method);
      try {
        if (method.equals("POST")
            && !toadlet.allowPOSTWithoutPassword()
            && !ctx.checkFormPassword(req, toadlet.path())) {
          return;
        }

        if (ctx.isAllowedFullAccess()) {
          ctx.getPageMaker().parseMode(req, container);
        }

        try {
          callToadletMethod(toadlet, method, currentUri, req, ctx, data, sock);
        } catch (RedirectException re) {
          currentUri = re.newuri;
          redirect = true;
        }
      } finally {
        req.freeParts();
      }
    } while (redirect);
  }

  private static FindToadletResult findToadlet(
      ToadletContainer container, ToadletContextImpl ctx, URI uri)
      throws IOException, ToadletContextClosedException {
    try {
      Toadlet toadlet = container.findToadlet(uri);
      return new FindToadletResult(toadlet, false);
    } catch (PermanentRedirectException e) {
      Toadlet.writePermanentRedirect(ctx, "Found elsewhere", e.newuri.toASCIIString());
      return new FindToadletResult(null, true);
    }
  }

  private record DataReadResult(Bucket data, boolean continueProcessing) {
    static DataReadResult success(Bucket data) {
      return new DataReadResult(data, true);
    }

    static DataReadResult stop() {
      return new DataReadResult(null, false);
    }
  }

  private record RequestLine(String method, URI uri, String protocol) {
    boolean isHTTP10() {
      return "HTTP/1.0".equals(protocol);
    }
  }

  private record FindToadletResult(Toadlet toadlet, boolean handled) {}

  private static final class ToadletInvocationException extends Exception {
    ToadletInvocationException(Throwable cause) {
      super(cause);
    }
  }

  private static void callToadletMethod(
      Toadlet t,
      String method,
      URI uri,
      HTTPRequestImpl req,
      ToadletContextImpl ctx,
      Bucket data,
      Socket sock)
      throws IOException,
          RedirectException,
          ToadletContextClosedException,
          NoSuchMethodException,
          IllegalAccessException,
          ToadletInvocationException {
    if ("GET".equals(method)) {
      handleGetRequest(t, uri, req, ctx, data, sock);
      return;
    }

    Method reflectedMethod = resolveHandleMethod(t, method);
    invokeToadletMethod(t, reflectedMethod, uri, req, ctx);
  }

  private static void invokeToadletMethod(
      Toadlet toadlet, Method reflectedMethod, URI uri, HTTPRequestImpl req, ToadletContextImpl ctx)
      throws IOException,
          RedirectException,
          ToadletContextClosedException,
          ToadletInvocationException,
          IllegalAccessException {
    ctx.setActiveToadlet(toadlet);
    try {
      reflectedMethod.invoke(toadlet, uri, req, ctx);
    } catch (InvocationTargetException ite) {
      handleInvocationCause(ite.getCause());
    }
  }

  private static void handleInvocationCause(Throwable cause)
      throws IOException,
          RedirectException,
          ToadletContextClosedException,
          ToadletInvocationException {
    if (cause instanceof IOException io) {
      throw io;
    }
    if (cause instanceof RedirectException redirect) {
      throw redirect;
    }
    if (cause instanceof ToadletContextClosedException closed) {
      throw closed;
    }
    if (cause instanceof RuntimeException runtime) {
      throw runtime;
    }
    if (cause instanceof Error error) {
      throw error;
    }
    throw new ToadletInvocationException(cause);
  }

  private static Method resolveHandleMethod(Toadlet toadlet, String method)
      throws NoSuchMethodException {
    Class<? extends Toadlet> clazz = toadlet.getClass();
    String methodName = Toadlet.HANDLE_METHOD_PREFIX + method;
    return clazz.getMethod(methodName, HANDLE_PARAMETERS);
  }

  private static void handleGetRequest(
      Toadlet toadlet,
      URI uri,
      HTTPRequestImpl req,
      ToadletContextImpl ctx,
      Bucket data,
      Socket sock)
      throws IOException, ToadletContextClosedException, RedirectException {
    if (data != null) {
      sendError(sock.getOutputStream(), 400, BAD_REQUEST, "Content not allowed", true, null);
      ctx.close();
      return;
    }
    ctx.setActiveToadlet(toadlet);
    toadlet.handleMethodGET(uri, req, ctx);
  }

  private void setActiveToadlet(Toadlet t) {
    this.activeToadlet.set(t);
  }

  /**
   * Returns the toadlet currently handling this context, or {@code null} when none is active. The
   * value is updated before invoking handler methods and can be used by logging or error handling
   * code to attribute messages to the correct component. It reflects a best-effort reference and is
   * not intended for long-term storage.
   *
   * @return Active {@link Toadlet} assigned to this context, or {@code null} before dispatch.
   */
  @Override
  public Toadlet activeToadlet() {
    return activeToadlet.get();
  }

  /**
   * Should the connection be closed after handling this request?
   *
   * @param isHTTP10 Did the client specify HTTP/1.0?
   * @param headers Client headers.
   * @return True if the connection should be closed.
   */
  private static boolean shouldDisconnectAfterHandled(
      boolean isHTTP10, MultiValueTable<String, String> headers) {
    String connection = headers.getFirst(CONNECTION_HEADER);
    if (connection != null) {
      if (connection.equalsIgnoreCase("close")) return true;

      if (connection.equalsIgnoreCase("keep-alive")) return false;
    }
    // HTTP 1.1
    return isHTTP10;
  }

  /**
   * Writes a portion of a byte array to the client, preserving any previously sent headers. Call
   * this after emitting response headers and before finalizing the connection. The method performs
   * no buffering beyond the socket stream, so callers may wish to chunk large payloads externally
   * for back-pressure handling.
   *
   * @param data Byte array containing the content to transmit to the client.
   * @param offset Offset within the array where the payload to send begins.
   * @param length Number of bytes to write starting at {@code offset}; must not exceed array size.
   * @throws ToadletContextClosedException If the context has been closed and cannot accept output.
   * @throws IOException If the socket writing fails or the connection drops mid-transfer.
   */
  @Override
  public void writeData(byte[] data, int offset, int length)
      throws ToadletContextClosedException, IOException {
    if (closed) throw new ToadletContextClosedException();
    sockOutputStream.write(data, offset, length);
  }

  /**
   * Writes an entire byte array as the response body following any previously sent headers. This is
   * a thin convenience wrapper over the offset-based variant and does not perform additional
   * validation beyond the closed-context check. Use it for small payloads that are already fully
   * materialized in memory.
   *
   * @param data Byte array to write to the socket; must not be {@code null}.
   * @throws ToadletContextClosedException If the context has been closed and cannot accept output.
   * @throws IOException If the socket writing fails or the connection drops mid-transfer.
   */
  @Override
  public void writeData(byte[] data) throws ToadletContextClosedException, IOException {
    writeData(data, 0, data.length);
  }

  /**
   * Streams the contents of the supplied {@link Bucket} to the client and then frees the bucket.
   * Callers transfer ownership to the context; if the data must remain available afterward, wrap it
   * in a {@link NoFreeBucket} before calling. The method copies until the bucket reports end-of-
   * stream or the socket writing fails, making it suitable for large payloads without loading the
   * entire content into memory at once. It keeps the order of writes unchanged, allowing response
   * bodies generated earlier to be piped directly.
   *
   * @param data Bucket containing the reply data to transfer; ownership passes to the context.
   * @throws ToadletContextClosedException If the context has been closed and cannot accept output.
   * @throws IOException If reading from the bucket or writing to the socket fails.
   * @see NoFreeBucket
   */
  @Override
  public void writeData(Bucket data) throws ToadletContextClosedException, IOException {
    if (closed) throw new ToadletContextClosedException();
    BucketTools.copyTo(data, sockOutputStream, Long.MAX_VALUE);
    data.free();
  }

  /**
   * Provides the bucket factory configured for this node, enabling handlers to allocate temporary
   * storage for request bodies or generated responses. The factory selection may incorporate
   * quota-handling and disk preferences, so callers should prefer this accessor over creating
   * buckets directly. Using the shared factory keeps allocation consistent with node-level storage
   * policies such as maximum size limits or memory/disk balancing.
   *
   * @return {@link BucketFactory} suitable for allocating storage during request processing.
   */
  @Override
  public BucketFactory getBucketFactory() {
    return bf;
  }

  /**
   * Adds a form element to the given parent node using container defaults. This is a pass-through
   * to {@link ToadletContainer#addFormChild(HTMLNode, String, String)} and keeps form creation
   * logic centralized. Callers should use it when emitting forms that need the container's action
   * paths and hidden fields. It ensures consistent CSRF protection and localization across all
   * request handlers.
   *
   * @param parentNode Parent HTML node to which the form child will be appended.
   * @param target Target URL or path for form submission generated by the container.
   * @param name Form name used for identification within the page.
   * @return Newly created {@link HTMLNode} representing the form child.
   */
  @Override
  public HTMLNode addFormChild(HTMLNode parentNode, String target, String name) {
    return container.addFormChild(parentNode, target, name);
  }

  /**
   * Determines whether the request originates from a client granted full access. The decision is
   * delegated to the container and usually involves IP-based checks or session state. Use it to
   * gate expensive operations or privileged views before processing user input. The result can vary
   * between requests, so callers should check per-request rather than caching the answer globally.
   *
   * @return {@code true} when the container reports that the remote address has full access.
   */
  @Override
  public boolean isAllowedFullAccess() {
    return container.isAllowedFullAccess(remoteAddr);
  }

  /**
   * Indicates whether the node is operating in advanced mode, which typically unlocks additional UI
   * controls and diagnostic information. Toadlets can use this flag to tailor responses without
   * duplicating configuration reads. Advanced mode often exposes extra logging hooks, expert forms,
   * or maintenance endpoints that are hidden in the default mode for safety.
   *
   * @return {@code true} when advanced mode features should be enabled in responses.
   */
  @Override
  public boolean isAdvancedModeEnabled() {
    return container.isAdvancedModeEnabled();
  }

  /**
   * Reports whether the server should expose a robots.txt response. This allows toadlets to
   * suppress crawler-facing endpoints in deployments where indexing is undesirable. Use it to
   * decide whether to inject robot tags or return 404/403 responses for robot probes.
   *
   * @return {@code true} when robots directives should be served for this node.
   */
  @Override
  public boolean doRobots() {
    return container.doRobots();
  }

  /**
   * Requests that the underlying connection be closed after the current response. Callers can set
   * this when they know further reuse is unsafe or when protocol errors have occurred. The flag is
   * honored when headers are emitted next and complements automatic close behavior driven by {@code
   * Connection: close} requests or HTTP/1.0 clients.
   */
  @Override
  public void forceDisconnect() {
    this.shouldDisconnect = true;
  }

  /**
   * Returns the parent container that owns this context and governs policy decisions. Toadlets can
   * consult it for configuration or helper methods beyond what the context exposes directly. The
   * container is long-lived and centralizes shared services such as bucket factories, security
   * checks, and localization helpers.
   *
   * @return Non-null {@link ToadletContainer} instance associated with this request.
   */
  @Override
  public ToadletContainer getContainer() {
    return container;
  }

  /**
   * Indicates whether the progress page should be suppressed for this request. The container uses
   * this to allow plugin-provided UIs to opt out of the standard progress feedback. Handlers can
   * consult this flag when deciding whether to stream incremental progress updates or present a
   * minimalist response.
   *
   * @return {@code true} when progress pages must be disabled for the caller.
   */
  @Override
  public boolean disableProgressPage() {
    return container.disableProgressPage();
  }

  /**
   * Returns the unique identifier assigned to this request. The ID is a stringified long used for
   * logging, correlation, and client-visible debugging. It remains stable for the lifetime of the
   * context and is safe to include in client-visible diagnostics because it contains no sensitive
   * data by itself.
   *
   * @return Unique request identifier supplied by the container at creation time.
   */
  @Override
  public String getUniqueId() {
    return uniqueId;
  }

  /**
   * Returns the normalized request URI associated with this context. Callers should treat it as
   * immutable and prefer cloning when modifications are required for redirects. The URI contains
   * any query string provided by the client; callers should parse query parameters before mutation
   * to avoid losing fidelity.
   *
   * @return Request {@link URI} as parsed from the incoming request line.
   */
  @Override
  public URI getUri() {
    return uri;
  }

  /**
   * Exposes the current refilter policy chosen by FProxy for this request. Handlers can use the
   * policy to decide whether to re-run content filters on cached data or forwarded responses. The
   * value reflects container configuration and any per-request overrides captured when the context
   * was created.
   *
   * @return {@link REFILTER_POLICY} indicating how the proxy should treat filtering behavior.
   */
  @Override
  public REFILTER_POLICY getReFilterPolicy() {
    return container.getReFilterPolicy();
  }
}

/**
 * Bundle of response header options used when emitting reply metadata.
 *
 * @param contentLength length of the response body, or {@code -1} to omit the header
 * @param modifiedTime optional last-modified timestamp for cache handling
 * @param disconnect whether to close the socket after the response
 * @param allowScripts whether scripts are permitted by the CSP
 * @param allowFrames whether framing is permitted by the CSP
 */
record ReplyHeaderOptions(
    long contentLength,
    Instant modifiedTime,
    boolean disconnect,
    boolean allowScripts,
    boolean allowFrames) {}
