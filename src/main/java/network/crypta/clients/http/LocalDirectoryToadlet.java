package network.crypta.clients.http;

import network.crypta.client.HighLevelSimpleClient;
import network.crypta.node.NodeClientCore;
import network.crypta.support.HTMLNode;

/**
 * Base toadlet for browsing directories exposed through the local HTTP UI.
 *
 * <p>This abstract helper wires the generic file browser capabilities from {@link
 * LocalFileBrowserToadlet} to flows that specifically operate on directories rather than files.
 * Subclasses provide concrete behaviors such as filtering allowable targets, persisting form state,
 * and rendering action buttons appropriate to their use case (for example choosing a download
 * destination or configuring a data directory). The instance is immutable after construction and is
 * intended to be reused by the HTTP server for multiple requests without additional
 * synchronization; no internal state is mutated across calls. Methods are structured to allow
 * subclasses to override only the pieces they need—such as the starting directory or which query
 * parameters should survive navigation—while retaining common path handling. Callers should expect
 * URL paths to be rooted beneath {@link #BASE_PATH} and treat returned fragments as relative URL
 * components suitable for composing hyperlinks or form actions.
 *
 * <ul>
 *   <li>Responsibilities: provide stable path prefixes and delegate subclass-specific behaviors.
 *   <li>Thread-safety: stateless and safe for concurrent request handling.
 *   <li>Usage: extend and implement directory selection helpers; the HTTP layer will invoke {@link
 *       #path()} and {@link #postTo()} to assemble endpoints.
 * </ul>
 */
public abstract class LocalDirectoryToadlet extends LocalFileBrowserToadlet {

  /**
   * URL suffix appended to {@link #BASE_PATH} to form the concrete endpoint for this toadlet; never
   * mutated after construction and treated as a relative path component.
   */
  protected final String postToPath;

  /**
   * Shared HTTP base path under which all local directory browser endpoints are exposed; immutable
   * and constant for the application lifetime.
   */
  protected static final String BASE_PATH = "/directory-browser";

  /**
   * Creates a directory-focused toadlet bound to a specific post target path.
   *
   * <p>The constructor only wires dependencies and stores the relative path segment used to
   * assemble request URLs; it does not perform any I/O. Subclasses can rely on the provided core
   * components being non-null and ready for immediate use. Instances are typically created once and
   * held by the HTTP server to serve repeated requests.
   *
   * @param core node client core providing access to validation, permissions, and node services;
   *     must be initialized and non-null.
   * @param highLevelSimpleClient client helper used for higher-level operations triggered by user
   *     actions; expected to be thread-safe and non-null.
   * @param postTo relative URL suffix appended to {@link #BASE_PATH} when building form actions;
   *     must not be null and should start with a leading slash for correct concatenation.
   */
  protected LocalDirectoryToadlet(
      NodeClientCore core, HighLevelSimpleClient highLevelSimpleClient, String postTo) {
    super(core, highLevelSimpleClient);
    this.postToPath = postTo;
  }

  /**
   * Computes the request path used to reach this toadlet, combining the shared base with the
   * subclass-defined suffix.
   *
   * <p>The value is deterministic for the life of the instance and involves no filesystem access or
   * network I/O. It is primarily used by the HTTP server when registering handlers and by view
   * templates when constructing form actions or links. Because the result is produced by simple
   * string concatenation, callers should perform any needed URL encoding for user-supplied segments
   * that might be appended later.
   *
   * @return full path, starting with a slash, that uniquely identifies this directory browsing
   *     endpoint within the local HTTP UI; never null.
   */
  @Override
  public String path() {
    return BASE_PATH + postToPath;
  }

  /**
   * Returns the immutable HTTP base path shared by all directory browser toadlets.
   *
   * <p>This is the stable root segment that precedes every directory-browsing endpoint exposed by
   * the local HTTP server. Callers can safely concatenate additional path elements or query
   * parameters without needing to inspect subclass details, because subclasses only append their
   * own relative suffixes through {@link #postTo()}. The value never changes during runtime and is
   * suitable for reuse across multiple request handlers.
   *
   * @return constant path segment beginning with a forward slash that serves as the common
   *     namespace root for directory browsing endpoints.
   */
  public static String basePath() {
    return BASE_PATH;
  }

  /**
   * Builds the full URL path that this toadlet responds to by combining {@link #BASE_PATH} with the
   * subclass-provided suffix.
   *
   * <p>The returned value is intended for routing and hyperlink generation within the local UI. It
   * is always a simple string concatenation and contains no URL encoding; callers should apply
   * additional encoding if user-controlled input is appended later. The method performs no I/O and
   * is safe for frequent repeated invocation across threads.
   *
   * @return absolute path (from the HTTP server root) that identifies this directory browser
   *     endpoint; never null and stable for the life of the instance.
   */
  @Override
  protected String postTo() {
    return postToPath;
  }

  /**
   * Directory selection is not used for this toadlet; subclasses handling file selection override
   * the relevant hook instead. The method is intentionally empty to avoid adding unused form
   * controls to directory-only views.
   *
   * @param fileRow HTML table row representing the current file entry; ignored in this
   *     implementation.
   * @param filename name of the file associated with the row; ignored because directory selection
   *     does not require per-file submission controls.
   * @param persist node containing hidden fields that preserve navigation state between requests;
   *     not modified here.
   */
  @Override
  protected void createSelectFileButton(HTMLNode fileRow, String filename, HTMLNode persist) {}
}
