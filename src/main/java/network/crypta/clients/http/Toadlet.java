package network.crypta.clients.http;

import com.onionnetworks.util.Buffer;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import network.crypta.client.FetchContext;
import network.crypta.client.FetchException;
import network.crypta.client.FetchResult;
import network.crypta.client.FetchWaiter;
import network.crypta.client.HighLevelSimpleClient;
import network.crypta.client.InsertBlock;
import network.crypta.client.InsertException;
import network.crypta.client.async.ClientGetter;
import network.crypta.keys.FreenetURI;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.RequestClient;
import network.crypta.support.HTMLEncoder;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.NoFreeBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract base for HTTP "toadlets" served by Crypta's browser interface. Each subclass maps to a
 * controller that renders pages or performs actions over FProxy-style endpoints without relying on
 * a servlet container. The type orchestrates reflection-based dispatch to {@code handleMethod*}
 * handlers, keeps the node-specific client helper available, and exposes helpers for common reply
 * and error patterns so subclasses stay focused on domain logic.
 *
 * <p>Typical usage creates a concrete toadlet, registers it with a {@link ToadletContainer}, and
 * lets the container invoke {@link #handleMethodGET(URI, HTTPRequest, ToadletContext)} or the
 * corresponding POST/PUT equivalents. Toadlets are expected to be stateless per request; any
 * mutable state should be confined to the {@link ToadletContext} or external services. The class is
 * not thread-safe in itself but relies on the container to provide one instance per request or to
 * enforce appropriate synchronization.
 *
 * <ul>
 *   <li>Reflective dispatch uses {@link #HANDLE_METHOD_PREFIX} to locate verb-specific handlers.
 *   <li>{@link #showAsToadlet(ToadletContext)} cooperates with menu rendering for navigation
 *       highlights.
 *   <li>Utility writers produce consistent headers, character encodings, and redirect pages.
 * </ul>
 *
 * @see ToadletContext
 * @see ToadletContainer
 * @see PageMaker
 */
public abstract class Toadlet {
  private static final Logger LOG = LoggerFactory.getLogger(Toadlet.class);
  private static final String HTML_TITLE_OPEN = "<html><head><title>";
  private static final String HTML_TITLE_CLOSE_H1_OPEN = "</title></head><body><h1>";
  private static final String REASON_PATTERN = "reason";
  private static final ThreadLocal<Boolean> LEGACY_SHOW_AS_TOADLET_GUARD =
      ThreadLocal.withInitial(() -> Boolean.FALSE);

  /**
   * Prefix used when reflecting verb-specific handler methods such as {@code handleMethodGET}. The
   * container scans public/protected methods for names beginning with this token to advertise and
   * dispatch supported HTTP verbs. Changing it would break routing and capability detection for all
   * toadlets.
   */
  public static final String HANDLE_METHOD_PREFIX = "handleMethod";

  final HighLevelSimpleClient client;
  ToadletContainer container;
  private String supportedMethodsCache;

  /**
   * Creates a toadlet bound to the high-level client helper used for fetch and insert operations.
   * The client is typically shared across multiple toadlets, so connection pooling, throttling, and
   * authentication remain consistent. Implementations should store configuration on the client
   * rather than subclass fields so that instances stay lightweight and easy to construct.
   *
   * @param client Non-null helper that performs network requests on behalf of this toadlet.
   */
  protected Toadlet(HighLevelSimpleClient client) {
    this.client = client;
  }

  private static String l10nWithReason(String key, String value) {
    return NodeL10n.getBase()
        .getString("Toadlet." + key, new String[] {REASON_PATTERN}, new String[] {value});
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString("Toadlet." + key);
  }

  /**
   * Do a permanent redirect (HTTP Status 301).
   *
   * <p>This will write rudimentary HTML, but typically browsers will follow the Location header.
   * Consider refactoring with writeTemporaryRedirect.
   *
   * @param ctx Request context used to send headers and body for the redirect response.
   * @param msg Optional message rendered into the HTML body after encoding; may be {@code null}.
   * @param location Absolute or relative URL to place in the {@code Location} header and anchor
   *     tag.
   * @throws ToadletContextClosedException If the client disconnects before the redirect is written.
   * @throws IOException If writing headers or the small HTML body fails.
   */
  static void writePermanentRedirect(ToadletContext ctx, String msg, String location)
      throws ToadletContextClosedException, IOException {
    if (msg == null) msg = "";
    else msg = HTMLEncoder.encode(msg);
    String redirDoc =
        HTML_TITLE_OPEN
            + msg
            + HTML_TITLE_CLOSE_H1_OPEN
            + l10nWithReason("permRedirectWithReason", msg)
            + "</h1><a href=\""
            + HTMLEncoder.encode(location)
            + "\">"
            + l10n("clickHere")
            + "</a></body></html>";
    byte[] buf = redirDoc.getBytes(StandardCharsets.UTF_8);
    MultiValueTable<String, String> headers = MultiValueTable.from("Location", location);
    ctx.sendReplyHeaders(301, "Moved Permanently", headers, "text/html; charset=UTF-8", buf.length);
    ctx.writeData(buf, 0, buf.length);
  }

  /**
   * Adds a navigation link back to the node homepage into the supplied content node. This is used
   * by many error pages to give users a predictable escape hatch. The method mutates the provided
   * {@link HTMLNode} by appending an anchor element configured with localized text and the root
   * relative URL.
   *
   * @param content Container node that will receive the appended link; must not be {@code null}.
   */
  protected static void addHomepageLink(HTMLNode content) {
    content.addChild(
        "a",
        new String[] {"href", "title"},
        new String[] {"/", l10n("homepage")},
        l10n("returnToNodeHomepage"));
  }

  /**
   * Handles the canonical HTTP GET for this toadlet. The container reflects to this method for each
   * GET request whose path resolves to the instance; POST/PUT handlers follow the same naming
   * convention. Implementations should inspect the {@link HTTPRequest}, generate a reply via the
   * supplied {@link ToadletContext}, and either return normally or throw a controlled redirect. The
   * method is invoked per-request and should avoid storing per-request data on the instance to
   * remain thread-safe.
   *
   * @param uri Fully parsed request URI, already validated by the container for basic structure.
   * @param request Mutable HTTP request wrapper containing query parameters and headers; never
   *     null.
   * @param ctx Execution context for writing replies, acquiring page builders, and tracking session
   *     state; guaranteed open when the method is entered.
   * @throws ToadletContextClosedException If the client disconnects before the response is written.
   * @throws IOException If streaming, the response fails or backing storage cannot be read.
   * @throws RedirectException If the handler deliberately triggers an HTTP redirect for navigation.
   */
  public abstract void handleMethodGET(URI uri, HTTPRequest request, ToadletContext ctx)
      throws ToadletContextClosedException, IOException, RedirectException;

  /**
   * Returns the canonical mount path for this toadlet within the HTTP namespace. The container uses
   * the value to route incoming requests and to build menu entries. Paths should start with a slash
   * and remain stable, so bookmarks and inter-toadlet links stay valid across releases.
   *
   * @return Absolute path fragment (e.g., {@code "/welcome/"}) that uniquely identifies the
   *     toadlet.
   */
  public abstract String path();

  /**
   * The primary purpose of this function is being overridden in your Toadlet implementations - for
   * the following purpose:
   *
   * <p>When displaying this Toadlet, the web interface should show the menu from which it was
   * selected as opened and mark the appropriate entry as selected in the menu. This function may
   * return the Toadlet whose menu shall be opened and whose entry shall be marked as selected in
   * the menu.
   *
   * <p>It is necessary to have this function instead of just marking <code>Toadlet.this</code> as
   * selected: Some Toadlets won't be added to a menu. They will be only accessible through other
   * Toadlets. For example, a Toadlet for deleting a single download might only be accessible
   * through the Toadlet, which shows all downloads. For still being able to figure out the menu
   * entry through which those so-called invisible Toadlets where accessed, this function is
   * necessary.
   *
   * @param context Can be used to decide the return value, for example, to check session cookies
   *     using {@link SessionManager}.
   * @return The result of {@link #showAsToadlet()}, which is <code>this</code> by default.<br>
   *     This behavior is for backwards compatibility with existing code which overrides that
   *     function.<br>
   *     <br>
   *     <p>Override this function to return something else for invisible Toadlets as explained
   *     above.
   */
  public Toadlet showAsToadlet(ToadletContext context) {
    return resolveLegacyShowAsToadlet();
  }

  /**
   * Legacy compatibility hook; prefer {@link #showAsToadlet(ToadletContext)}. Internally, fred will
   * always call that function, which delegates to this legacy method by default, so the existing
   * code continues to work. When removing this legacy function, change {@link
   * #showAsToadlet(ToadletContext)} to return <code>this</code> by default, as already specified in
   * its Javadoc.
   *
   * @return <code>this</code>
   */
  public Toadlet showAsToadlet() {
    // DO NOT CHANGE THIS ANYMORE: Otherwise showAsToadlet(ToadletContext) will not follow the
    // contract of its Javadoc.
    return resolveLegacyShowAsToadlet();
  }

  private Toadlet resolveLegacyShowAsToadlet() {
    if (Boolean.TRUE.equals(LEGACY_SHOW_AS_TOADLET_GUARD.get())) {
      return this;
    }
    LEGACY_SHOW_AS_TOADLET_GUARD.set(Boolean.TRUE);
    try {
      Method legacyMethod = getClass().getMethod("showAsToadlet");
      if (legacyMethod.getDeclaringClass() != Toadlet.class) {
        return invokeLegacyShowAsToadlet(legacyMethod);
      }
      return this;
    } catch (InvocationTargetException e) {
      throw propagateLegacyShowAsToadletFailure(e.getCause());
    } catch (IllegalAccessException e) {
      throw new IllegalStateException("Cannot access legacy showAsToadlet()", e);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException("Legacy showAsToadlet() method missing", e);
    } finally {
      LEGACY_SHOW_AS_TOADLET_GUARD.remove();
    }
  }

  private Toadlet invokeLegacyShowAsToadlet(Method legacyMethod)
      throws IllegalAccessException, InvocationTargetException {
    return (Toadlet) legacyMethod.invoke(this);
  }

  private RuntimeException propagateLegacyShowAsToadletFailure(Throwable cause) {
    if (cause instanceof RuntimeException runtimeException) {
      throw runtimeException;
    }
    if (cause instanceof Error error) {
      throw error;
    }
    throw new IllegalStateException("Legacy showAsToadlet() threw a checked exception", cause);
  }

  /**
   * Indicates whether this toadlet accepts POST requests that lack the configured form password.
   * Returning {@code true} lets the container bypass its default protection and deliver
   * unauthenticated POST bodies to the handler. Most toadlets should keep the strict default unless
   * they explicitly manage authentication or only expose non-sensitive operations.
   *
   * @return {@code true} to allow unauthenticated POSTs; {@code false} to enforce the password
   *     gate.
   */
  public boolean allowPOSTWithoutPassword() {
    return false;
  }

  /**
   * Discovers the HTTP verbs implemented by this toadlet by scanning for methods whose names begin
   * with {@link #HANDLE_METHOD_PREFIX}. The result informs capability headers and tooling that
   * lists available operations. Because reflection inspects inherited methods, subclasses can
   * override this method to intentionally hide a parent implementation.
   *
   * @return Comma-separated list of supported verbs (e.g., {@code "GET, POST"}), cached per
   *     instance for performance.
   */
  public final String findSupportedMethods() {
    if (supportedMethodsCache == null) {
      Method[] methlist = this.getClass().getMethods();
      StringBuilder sb = new StringBuilder();
      for (Method m : methlist) {
        String name = m.getName();
        if (name.startsWith(HANDLE_METHOD_PREFIX)) {
          sb.append(name.substring(HANDLE_METHOD_PREFIX.length()));
          sb.append(", ");
        }
      }
      if (sb.length() >= 2) {
        // remove last ", "
        sb.deleteCharAt(sb.length() - 1);
        sb.deleteCharAt(sb.length() - 1);
      }
      supportedMethodsCache = sb.toString();
    }
    return supportedMethodsCache;
  }

  /**
   * Client calls from the above messages to run a Freenet request. This method may block (or
   * suspend).
   *
   * @param maxSize Maximum length of returned content.
   * @param clientContext Client context object. This should be the same for any group of related
   *     requests, but different for any two unrelated requests. Request selection round-robin's
   *     over these, within any priority and retry count class, and above the level of individual
   *     block fetches.
   */
  FetchResult fetch(FreenetURI uri, long maxSize, RequestClient clientContext, FetchContext fctx)
      throws FetchException {
    // Honor the provided maxSize for this request.
    if (maxSize > 0) {
      fctx.setMaxOutputLength(maxSize);
      fctx.setMaxTempLength(maxSize);
    }
    FetchWaiter fw = new FetchWaiter(clientContext);
    @SuppressWarnings("unused")
    ClientGetter getter = getClientImpl().fetch(uri, fw, fctx);
    return fw.waitForCompletion();
  }

  /**
   * Returns a default FetchContext
   *
   * @param maxSize The maximum allowable size of the fetch's result
   * @return A default FetchContext
   */
  FetchContext getFetchContext(long maxSize, String schemeHostAndPort) {
    // We want to retrieve a FetchContext we may override
    return getClientImpl().getFetchContext(maxSize, schemeHostAndPort);
  }

  FreenetURI insert(InsertBlock insert, String filenameHint) throws InsertException {
    // For now, just run it blocking.
    FreenetURI desiredURI = Objects.requireNonNull(insert.desiredURI, "InsertBlock.desiredURI");
    desiredURI.checkInsertURI();
    return getClientImpl().insert(insert, false, filenameHint);
  }

  /**
   * Writes a complete HTTP response from an in-memory byte array. This helper streams the specified
   * slice directly to the {@link ToadletContext} with minimal buffering and no extra headers,
   * making it suitable for generated pages, small binary assets, or error payloads. Callers retain
   * ownership of the {@code data} buffer and should ensure it already contains encoded UTF-8 text
   * when used for HTML or plain text bodies.
   *
   * @param ctx Request context that identifies the client connection receiving the payload.
   * @param replyHeaders Status, MIME type, and header metadata for the response.
   * @param data Buffer slice containing the bytes to transmit; ownership is not transferred.
   * @throws ToadletContextClosedException If the client disconnects before headers or body are
   *     sent.
   * @throws IOException If the underlying output stream fails during header or body transmission.
   */
  protected void writeReply(ToadletContext ctx, ReplyHeaders replyHeaders, Buffer data)
      throws ToadletContextClosedException, IOException {
    if (replyHeaders.forceDisableJavascript()) {
      ctx.sendReplyHeaders(
          replyHeaders.code(),
          replyHeaders.description(),
          replyHeaders.headers(),
          replyHeaders.mimeType(),
          data.len,
          true);
    } else {
      ctx.sendReplyHeaders(
          replyHeaders.code(),
          replyHeaders.description(),
          replyHeaders.headers(),
          replyHeaders.mimeType(),
          data.len);
    }
    ctx.writeData(data.b, data.off, data.len);
  }

  /**
   * Writes a response whose body is provided as a {@link Bucket}. Buckets allow streaming large or
   * file-backed content without loading it all into memory. The method assumes ownership of the
   * bucket lifecycle and will free it after the response is transmitted; callers that need to
   * retain the bucket should wrap it in {@link NoFreeBucket} first.
   *
   * @param context HTTP exchange context used to emit headers and stream the bucket data.
   * @param replyHeaders Status, MIME type, and header metadata for the response.
   * @param data Bucket containing the response body; ownership is transferred and will be freed.
   * @throws ToadletContextClosedException If the client disconnects while headers or body are sent.
   * @throws IOException If reading from the bucket or writing to the output stream fails.
   * @see NoFreeBucket
   */
  protected void writeReply(ToadletContext context, ReplyHeaders replyHeaders, Bucket data)
      throws ToadletContextClosedException, IOException {
    if (replyHeaders.forceDisableJavascript()) {
      context.sendReplyHeaders(
          replyHeaders.code(),
          replyHeaders.description(),
          replyHeaders.headers(),
          replyHeaders.mimeType(),
          data.size(),
          true);
    } else {
      context.sendReplyHeaders(
          replyHeaders.code(),
          replyHeaders.description(),
          replyHeaders.headers(),
          replyHeaders.mimeType(),
          data.size());
    }
    context.writeData(data);
  }

  /**
   * Writes a text response using a {@link String} body and no extra headers. The body is encoded as
   * UTF-8 before transmission, making this suitable for HTML, JSON, or plaintext replies that are
   * generated on the fly and fit comfortably in memory. For larger payloads, prefer the {@link
   * Bucket}-based overload.
   *
   * @param ctx Context representing the request whose response is being written.
   * @param replyHeaders Status, MIME type, and header metadata for the response.
   * @param reply Textual body content to encode as UTF-8 before streaming.
   * @throws ToadletContextClosedException If the client closes the connection during the writing.
   * @throws IOException If writing headers or encoding/streaming, the body fails.
   */
  protected void writeReply(ToadletContext ctx, ReplyHeaders replyHeaders, String reply)
      throws ToadletContextClosedException, IOException {
    byte[] buffer = reply.getBytes(StandardCharsets.UTF_8);
    writeReply(ctx, replyHeaders, new Buffer(buffer));
  }

  /**
   * Sends a simple HTML response using UTF-8 encoding and no extra headers. This convenience
   * overload keeps common success and error pages concise by setting the MIME type to {@code
   * text/html; charset=utf-8} and delegating to the string-based reply writer.
   *
   * @param ctx Context for the request being serviced; must be open when invoked.
   * @param code HTTP status code to associate with the HTML payload.
   * @param desc Short reason phrase corresponding to {@code code}; appears in some browsers.
   * @param reply HTML markup to transmit; callers are responsible for ensuring it is well-formed.
   * @throws ToadletContextClosedException If the connection closes before headers or body finish.
   * @throws IOException If writing headers or streaming, the body fails.
   */
  protected void writeHTMLReply(ToadletContext ctx, int code, String desc, String reply)
      throws ToadletContextClosedException, IOException {
    writeHTMLReply(ctx, ReplyHeaders.of(code, desc, "text/html; charset=utf-8"), reply);
  }

  /**
   * Writes a UTF-8 plain-text response without any additional headers. Intended for human-readable
   * diagnostics or lightweight API messages where HTML wrapping is unnecessary. The body is encoded
   * from the supplied string and streamed directly to the client.
   *
   * @param ctx Context representing the active HTTP exchange for the response.
   * @param code HTTP status code to return alongside the text body.
   * @param desc Reason phrase paired with {@code code} for logging and browsers.
   * @param reply Plain-text body content to encode as UTF-8.
   * @throws ToadletContextClosedException If the client disconnects during transmission.
   * @throws IOException If header or body writes fail.
   */
  protected void writeTextReply(ToadletContext ctx, int code, String desc, String reply)
      throws ToadletContextClosedException, IOException {
    writeTextReply(
        ctx, ReplyHeaders.of(code, desc, "text/plain; charset=utf-8", null, true), reply);
  }

  /**
   * Sends an HTML response while allowing callers to supply extra headers and optional JavaScript
   * suppression. The body is encoded as UTF-8 and streamed after the supplied headers have been
   * merged with the default ones produced by the context.
   *
   * @param ctx Request context that handles header emission and output buffering.
   * @param replyHeaders Status, MIME type, and header metadata for the response.
   * @param reply HTML markup to encode as UTF-8 and stream to the client.
   * @throws ToadletContextClosedException If the connection closes before the response completes.
   * @throws IOException If writing headers or body data fails.
   */
  protected void writeHTMLReply(ToadletContext ctx, ReplyHeaders replyHeaders, String reply)
      throws ToadletContextClosedException, IOException {
    writeReply(ctx, replyHeaders, reply);
  }

  /**
   * Streams a plain-text response while allowing custom headers. This is useful for API responses
   * or diagnostic endpoints that need to control cache headers or content disposition but still
   * return a lightweight textual payload.
   *
   * @param ctx Context identifying the in-progress HTTP request/response exchange.
   * @param replyHeaders Status, MIME type, and header metadata for the response.
   * @param reply Plain-text body content to encode as UTF-8.
   * @throws ToadletContextClosedException If the client disconnects before the transmission
   *     completes.
   * @throws IOException If writing headers or streaming, the body fails.
   */
  protected void writeTextReply(ToadletContext ctx, ReplyHeaders replyHeaders, String reply)
      throws ToadletContextClosedException, IOException {
    writeReply(ctx, replyHeaders, reply);
  }

  /**
   * Issues an HTTP 302 redirect with a minimal HTML body that references the new location. Browsers
   * typically follow the {@code Location} header immediately, but the generated body offers a
   * fallback for manual navigation or clients without automatic redirect handling. Use this when
   * the redirect target is transient; prefer {@link #writePermanentRedirect(ToadletContext, String,
   * String)} for durable moves.
   *
   * @param ctx Request context used to send headers and body for the redirect response.
   * @param msg Optional message rendered into the HTML body after encoding; may be {@code null}.
   * @param location Absolute or relative URL to place in the {@code Location} header and anchor
   *     tag.
   * @throws ToadletContextClosedException If the client disconnects before the redirect is written.
   * @throws IOException If writing headers or the small HTML body fails.
   */
  protected void writeTemporaryRedirect(ToadletContext ctx, String msg, String location)
      throws ToadletContextClosedException, IOException {
    if (msg == null) msg = "";
    else msg = HTMLEncoder.encode(msg);
    String redirDoc =
        HTML_TITLE_OPEN
            + msg
            + HTML_TITLE_CLOSE_H1_OPEN
            + l10nWithReason("tempRedirectWithReason", msg)
            + "</h1><a href=\""
            + HTMLEncoder.encode(location)
            + "\">"
            + l10n("clickHere")
            + "</a></body></html>";
    byte[] buf = redirDoc.getBytes(StandardCharsets.UTF_8);
    MultiValueTable<String, String> mvt = MultiValueTable.from("Location", location);
    ctx.sendReplyHeaders(302, "Found", mvt, "text/html; charset=UTF-8", buf.length);
    ctx.writeData(buf, 0, buf.length);
  }

  /**
   * Renders a localized error page with a plain-text message. This helper constructs a basic {@link
   * HTMLNode} wrapper around the message, delegates to the richer HTML overload, and then streams
   * the page using the standard page maker so the output matches the rest of the UI chrome.
   *
   * @param ctx Active request context used to render and send the error response.
   * @param code HTTP status code that describes the failure condition.
   * @param desc Short description placed in the page title and status line.
   * @param message Human-readable explanation shown inside the error infobox; not HTML-escaped
   *     here.
   * @throws ToadletContextClosedException If the client disconnects before the page is delivered.
   * @throws IOException If building or streaming, the error page fails.
   */
  protected void sendErrorPage(ToadletContext ctx, int code, String desc, String message)
      throws ToadletContextClosedException, IOException {
    sendErrorPage(ctx, code, desc, new HTMLNode("#", message));
  }

  /**
   * Renders a full error page using a pre-built {@link HTMLNode} fragment. The fragment is inserted
   * into a standard infobox, augmented with navigation links, and then streamed with the supplied
   * HTTP status code. Callers can pass rich markup to tailor the user experience while keeping the
   * layout consistent.
   *
   * @param ctx Active request context used for rendering and output.
   * @param code HTTP status code that goes with the error page.
   * @param desc Title for the page and infobox heading.
   * @param message Markup describing the error details; ownership remains with the caller.
   * @throws ToadletContextClosedException If the client disconnects before the output completes.
   * @throws IOException If writing the generated page to the client fails.
   */
  protected void sendErrorPage(ToadletContext ctx, int code, String desc, HTMLNode message)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(desc, ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode infoboxContent =
        ctx.getPageMaker().getInfobox("infobox-error", desc, contentNode, null, true);
    infoboxContent.addChild(message);
    infoboxContent.addChild("br");
    infoboxContent.addChild("a", "href", ".", l10n("returnToPrevPage"));
    infoboxContent.addChild("br");
    addHomepageLink(infoboxContent);

    writeHTMLReply(ctx, code, desc, page.generate());
  }

  /**
   * Send an error page from an exception.
   *
   * @param ctx The context object for this request.
   * @param desc The title of the error page
   * @param message The message to be sent to the user. The stack trace will follow.
   * @param t The Throwable which caused the error.
   * @throws IOException If there is an error writing the reply.
   * @throws ToadletContextClosedException If the context has already been closed.
   */
  protected void sendErrorPage(ToadletContext ctx, String desc, String message, Throwable t)
      throws ToadletContextClosedException, IOException {
    PageNode page = ctx.getPageMaker().getPageNode(desc, ctx);
    HTMLNode contentNode = page.getContentNode();

    HTMLNode infoboxContent =
        ctx.getPageMaker().getInfobox("infobox-error", desc, contentNode, null, true);
    infoboxContent.addChild("#", message);
    infoboxContent.addChild("br");
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    pw.println(t);
    t.printStackTrace(pw);
    pw.close();
    // Consider replacing <pre> with CSS-based styling when modernizing the markup.
    infoboxContent.addChild("pre", sw.toString());
    infoboxContent.addChild("br");
    infoboxContent.addChild("a", "href", ".", l10n("returnToPrevPage"));
    addHomepageLink(infoboxContent);

    writeHTMLReply(ctx, 500, desc, page.generate());
  }

  /**
   * @throws IOException See {@link #sendErrorPage(ToadletContext, int, String, String)}
   * @throws ToadletContextClosedException See {@link #sendErrorPage(ToadletContext, int, String,
   *     String)}
   */
  void sendUnauthorizedPage(ToadletContext ctx) throws ToadletContextClosedException, IOException {
    sendErrorPage(
        ctx,
        403,
        NodeL10n.getBase().getString("Toadlet.unauthorizedTitle"),
        NodeL10n.getBase().getString("Toadlet.unauthorized"));
  }

  /**
   * Logs and renders an internal-error page that includes the full exception stack. This is
   * intended for unexpected failures inside a toadlet; it emits a 500 status, mirrors the throwable
   * chain into a {@code <pre>} block, and asks the user to report the problem. The method is
   * best-effort and may itself fail if the context is already closed.
   *
   * @param t Root throwable that triggered the error response; may include nested causes.
   * @param ctx Context used to send the diagnostic page back to the caller.
   * @throws ToadletContextClosedException If the client disconnects before the error page is sent.
   * @throws IOException If writing the generated page or headers fails.
   */
  protected void writeInternalError(Throwable t, ToadletContext ctx)
      throws ToadletContextClosedException, IOException {
    LOG.error("Caught {}", t, t);
    String msg =
        HTML_TITLE_OPEN
            + NodeL10n.getBase().getString("Toadlet.internalErrorTitle")
            + HTML_TITLE_CLOSE_H1_OPEN
            + NodeL10n.getBase().getString("Toadlet.internalErrorPleaseReport")
            + "</h1><pre>";
    StringWriter sw = new StringWriter();
    PrintWriter pw = new PrintWriter(sw);
    while (t != null) {
      t.printStackTrace(pw);
      t = t.getCause();
    }
    pw.flush();
    msg = msg + sw + "</pre></body></html>";
    writeHTMLReply(ctx, 500, "Internal Error", msg);
  }

  /**
   * Exposes the underlying high-level client used for network operations. Callers may tweak shared
   * settings or initiate fetch/insert requests, but should respect the container's threading model
   * and avoid blocking calls on UI threads.
   *
   * @return The reusable {@link HighLevelSimpleClient} instance backing this toadlet.
   */
  protected HighLevelSimpleClient getClientImpl() {
    return client;
  }
}
