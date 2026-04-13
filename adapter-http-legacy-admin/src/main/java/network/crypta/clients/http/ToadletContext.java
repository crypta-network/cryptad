package network.crypta.clients.http;

import java.io.IOException;
import java.net.URI;
import java.text.ParseException;
import java.time.Instant;
import network.crypta.runtime.alerts.UserAlertSurface;
import network.crypta.support.HTMLNode;
import network.crypta.support.MultiValueTable;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.BucketFactory;
import network.crypta.support.api.HTTPRequest;
import network.crypta.support.io.NoFreeBucket;

/**
 * Context object describing a single incoming HTTP request processed by the web interface layer.
 * Implementations provide utilities for building responses, querying request-scoped metadata, and
 * enforcing security policies such as form-password validation and access level checks. A {@code
 * ToadletContext} is typically created by the request dispatcher and passed into a {@link Toadlet}
 * handler; the handler uses it to send headers and body data, inspect cookies, manage response
 * cookies, and get helpers like {@link PageMaker}. Instances are short-lived and not thread-safe:
 * they represent one connection/request pair and should not be shared across threads without
 * external synchronization. Typical call flow is: validate permissions, send reply headers tailored
 * to the content type (static, FProxy, or dynamic), write the body via {@link #writeData(byte[],
 * int, int)}, and optionally adjust connection behavior with {@link #forceDisconnect()}.
 * Implementers must track connection state to prevent writes after closure.
 *
 * <p><strong>Responsibilities</strong>
 *
 * <ul>
 *   <li>Expose request headers, cookies, and URI for business logic.
 *   <li>Send correctly formed HTTP response headers for various content classes.
 *   <li>Provide helper factories ({@link BucketFactory}, {@link PageMaker}) for response bodies.
 *   <li>Enforce security levers: form passwords, advanced-mode gates, full-access checks.
 * </ul>
 *
 * @see Toadlet
 * @see ToadletContainer
 * @see PageMaker
 */
@SuppressWarnings("TypeParameterUnusedInFormals")
public interface ToadletContext {

  /**
   * Write reply headers for dynamically generated responses such as HTML pages, JSON payloads, or
   * redirects.
   *
   * @param code HTTP status code to send (e.g., 200, 302); must be a valid numeric code.
   * @param desc Human-readable status text matching {@code code}; non-null and short.
   * @param mvt Additional headers to include; may be {@code null} for none.
   * @param mimeType MIME type of the response body; {@code null} when no content follows.
   * @param length Declared content length in bytes, or a negative value when unknown/streaming.
   * @throws ToadletContextClosedException if the underlying connection has already been closed.
   * @throws IOException if writing to the client socket fails or is interrupted.
   */
  void sendReplyHeaders(
      int code, String desc, MultiValueTable<String, String> mvt, String mimeType, long length)
      throws ToadletContextClosedException, IOException;

  /**
   * Write reply headers for dynamic content while optionally disabling client-side JavaScript even
   * when the global setting allows it.
   *
   * @param code HTTP status code to emit; must be positive and standards-compliant.
   * @param desc Descriptive phrase paired with {@code code}; should reflect the status semantics.
   * @param mvt Additional headers keyed by lowercase names; {@code null} means no extra headers.
   * @param mimeType MIME type for the response body; {@code null} allowed when no body is sent.
   * @param length Length in bytes to advertise in {@code Content-Length}; negative to omit header.
   * @param forceDisableJavascript When {@code true}, adds headers that disallow script execution in
   *     the rendered page.
   * @throws ToadletContextClosedException if the context is closed before headers are written.
   * @throws IOException if the output stream cannot be written.
   */
  void sendReplyHeaders(
      int code,
      String desc,
      MultiValueTable<String, String> mvt,
      String mimeType,
      long length,
      boolean forceDisableJavascript)
      throws ToadletContextClosedException, IOException;

  /**
   * Write reply headers for static resources while supplying an explicit last-modified timestamp to
   * support cache validation.
   *
   * @param code HTTP status code such as 200 or 304, must align with the cache semantics desired.
   * @param desc Status description paired with {@code code}; required and non-empty.
   * @param mvt Extra headers to include; {@code null} permitted when no additional headers are
   *     needed.
   * @param mimeType MIME type for the static payload; may be {@code null} when no body follows.
   * @param length Content length in bytes; negative values suppress the {@code Content-Length}
   *     header.
   * @param mTime Modification time used for {@code Last-Modified}; must be non-null to avoid
   *     ambiguous cache hints.
   * @throws ToadletContextClosedException if the connection is already closed before writing.
   * @throws IOException if socket output fails while sending headers.
   */
  void sendReplyHeadersStatic(
      int code,
      String desc,
      MultiValueTable<String, String> mvt,
      String mimeType,
      long length,
      Instant mTime)
      throws ToadletContextClosedException, IOException;

  /**
   * Write reply headers tailored for content fetched from Freenet where JavaScript must always be
   * disabled to prevent injected scripts from executing.
   *
   * @param code HTTP status code to return for the proxied content; commonly 200 or 302.
   * @param desc Textual description of {@code code}; must match the status meaning.
   * @param mvt Additional headers; may be {@code null} when no overrides are required.
   * @param mimeType MIME type of the fetched object; {@code null} acceptable for header-only
   *     responses.
   * @param length Byte length of the body; negative when unknown or streaming.
   * @throws ToadletContextClosedException if headers cannot be written because the context is
   *     closed.
   * @throws IOException if low-level I/O fails while emitting the header block.
   */
  void sendReplyHeadersFProxy(
      int code, String desc, MultiValueTable<String, String> mvt, String mimeType, long length)
      throws ToadletContextClosedException, IOException;

  /**
   * Write a contiguous slice of bytes to the response body. Callers must send headers beforehand
   * using one of the {@code sendReplyHeaders*} methods.
   *
   * @param data Buffer containing response bytes; must not be {@code null}.
   * @param offset Starting index within {@code data} to write; zero or greater.
   * @param length Number of bytes to send from {@code data}; zero allowed for empty writes.
   * @throws ToadletContextClosedException if the context is closed before or during the writing.
   * @throws IOException if writing to the underlying stream fails.
   */
  void writeData(byte[] data, int offset, int length)
      throws ToadletContextClosedException, IOException;

  /**
   * Force a disconnection after handling this request. Used only when a throwable was thrown, and
   * we don't know what the state of the connection is. Callers use this when header/body state may
   * be inconsistent and a clean close is safer than attempting further writes.
   */
  void forceDisconnect();

  /**
   * Convenience method that writes an entire buffer to the client without specifying an offset or
   * length.
   *
   * @param data Complete response payload to send; must not be {@code null}.
   * @throws ToadletContextClosedException if the context was closed before the writing begins.
   * @throws IOException if the stream cannot be written due to network or socket errors.
   */
  void writeData(byte[] data) throws ToadletContextClosedException, IOException;

  /**
   * Write the contents of a {@link Bucket} to the client. Ownership of the bucket transfers to the
   * context, which frees it after transmission unless wrapped in a {@link NoFreeBucket}.
   *
   * @param data Bucket containing the response body; must be non-null and readable for its length.
   * @throws ToadletContextClosedException if the connection has already been closed.
   * @throws IOException if streaming the bucket to the socket fails.
   */
  void writeData(Bucket data) throws ToadletContextClosedException, IOException;

  /**
   * Obtain the {@link PageMaker} helper for generating HTML scaffolding and infoboxes.
   *
   * @return PageMaker bound to this request; never {@code null}.
   */
  PageMaker getPageMaker();

  /**
   * Retrieve the CSRF-style form password required for sensitive operations in the web interface.
   *
   * @return Non-null secret string that must match the user's submitted value.
   */
  String getFormPassword();

  /**
   * Validate a form password present in the request and emit an error or redirect when it is
   * missing or invalid.
   *
   * @param request Incoming request to inspect; must not be {@code null}.
   * @param redirectTo Location to redirect the client when validation fails; may be {@code null} to
   *     send an inline error page instead.
   * @return {@code true} when the supplied password matches; {@code false} when an error page or
   *     redirect has been sent.
   * @throws ToadletContextClosedException if the context is already closed during the response.
   * @throws IOException if writing the failure response cannot complete.
   */
  boolean checkFormPassword(HTTPRequest request, String redirectTo)
      throws ToadletContextClosedException, IOException;

  /**
   * Validate the form password in the request, sending an error response on failure.
   *
   * @param request Request containing form fields or cookies; must not be {@code null}.
   * @return {@code true} when validation succeeds; {@code false} after an error response is sent.
   * @throws ToadletContextClosedException if the connection is closed while handling the error.
   * @throws IOException if writing the validation error fails.
   */
  boolean checkFormPassword(HTTPRequest request) throws ToadletContextClosedException, IOException;

  /**
   * Check whether the request provides a form password without sending a response, allowing callers
   * to defer how they handle the absence (for example, by showing a confirmation page).
   *
   * @param request Request to inspect for form password presence; non-null required.
   * @return {@code true} when a password is present and valid; {@code false} otherwise.
   * @throws IOException if parsing or inspecting the request fails.
   */
  boolean hasFormPassword(HTTPRequest request) throws IOException;

  /**
   * Check a context for whether {@link #isAllowedFullAccess()} is true.
   *
   * <p>If it is false, an error page is sent to the client, and the false is returned. You can then
   * abort processing of the request.
   *
   * @return The return value of {@link #isAllowedFullAccess()}.
   * @param toadlet The toadlet requesting access; used for context in unauthorized responses.
   * @throws IOException See {@link Toadlet#sendUnauthorizedPage(ToadletContext)}
   * @throws ToadletContextClosedException See {@link Toadlet#sendUnauthorizedPage(ToadletContext)}
   */
  boolean checkFullAccess(Toadlet toadlet) throws ToadletContextClosedException, IOException;

  /**
   * Access the detached {@link UserAlertSurface} that accumulates alerts for the current node.
   *
   * @return non-null alert surface tied to this context.
   */
  UserAlertSurface getAlertManager();

  /**
   * Access the {@link BookmarkManagerHandle} used to read or update bookmarks within this request.
   *
   * @return non-null bookmark handle instance.
   */
  <T extends BookmarkManagerHandle> T getBookmarkManager();

  /**
   * Obtain the {@link BucketFactory} used to create buckets for reading request bodies or composing
   * responses.
   *
   * @return Bucket factory for this context; never {@code null}.
   */
  BucketFactory getBucketFactory();

  /**
   * Retrieve the request headers captured from the client.
   *
   * @return Mutable multivalue table of header names to values; never {@code null}.
   */
  MultiValueTable<String, String> getHeaders();

  /**
   * Look up an existing {@link Cookie} provided by the client that matches the supplied scope.
   *
   * @param domain Domain to match against the cookie's domain attribute; must not be {@code null}.
   * @param path Path to compare with the cookie path attribute; must not be {@code null}.
   * @param name Cookie name to search for; must not be {@code null} or empty.
   * @return Matching cookie instance, or {@code null} when no cookie satisfies the criteria.
   * @throws ParseException if cookie headers cannot be parsed into structured data.
   */
  ReceivedCookie getCookie(URI domain, URI path, String name) throws ParseException;

  /**
   * Register a {@link Cookie} to be emitted with the response headers. Replaces any existing cookie
   * with the same name, domain, and path.
   *
   * @param newCookie Cookie to send back to the client; must be non-null and fully specified.
   */
  void setCookie(Cookie newCookie);

  /**
   * Add a form node to an HTMLNode under construction. This will have the correct enctype and
   * formPassword set already, so all the caller needs to do is add its specific fields.
   *
   * @param parentNode The parent HTMLNode.
   * @param target Where the form should be POSTed to.
   * @param id HTML name for the form for stylesheet/script access. Will be added as both id and
   *     name.
   * @return The newly created form node attached under {@code parentNode}; never {@code null}.
   */
  HTMLNode addFormChild(HTMLNode parentNode, String target, String id);

  /**
   * Is this Toadlet allowed full access to the node, including the ability to reconfigure it,
   * restart it, etc.?
   *
   * @return {@code true} when the current request is authorized for full administrative access;
   *     {@code false} otherwise.
   */
  boolean isAllowedFullAccess();

  /**
   * Determine whether the web interface is operating in advanced mode, enabling additional
   * settings.
   *
   * @return {@code true} when advanced mode is enabled for this request; otherwise {@code false}.
   */
  boolean isAdvancedModeEnabled();

  /**
   * Indicate whether this context should return a restrictive {@code robots.txt} that blocks
   * crawlers.
   *
   * @return {@code true} if robots should be disallowed; {@code false} to allow default behavior.
   */
  boolean doRobots();

  /**
   * Provide the container managing this context, enabling access to shared configuration and
   * resource factories.
   *
   * @return Owning {@link ToadletContainer}; never {@code null}.
   */
  ToadletContainer getContainer();

  /**
   * Signal whether the standard progress page should be disabled for this request, typically for
   * lightweight or background responses.
   *
   * @return {@code true} when progress pages are suppressed; {@code false} otherwise.
   */
  boolean disableProgressPage();

  /**
   * Return the currently active {@link Toadlet} handling this context.
   *
   * @return Active toadlet instance; may be {@code null} if none is registered yet.
   */
  Toadlet activeToadlet();

  /**
   * Returns the unique id of this request
   *
   * @return The unique id
   */
  String getUniqueId();

  /**
   * Retrieve the {@link URI} of the inbound request after parsing and normalization.
   *
   * @return Normalized absolute or relative {@code URI} representing the request target.
   */
  URI getUri();

  /**
   * What to do when we find cached data on the global queue, but it's already been filtered, and we
   * want a filtered copy.
   *
   * @return Policy describing whether to refilter, reuse, or skip cached filtered data.
   */
  RefilterPolicy getReFilterPolicy();
}
