package network.crypta.clients.http;

import java.io.File;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.HTMLNode;

/**
 * Serves the local file browser specifically for node-to-node messaging uploads.
 *
 * <p>This toadlet exposes a narrow surface that mirrors {@link LocalFileBrowserToadlet} but tailors
 * the navigation and form posting targets to the N2NM workflow. It renders a directory listing
 * rooted at the default upload directory and refuses to expose a directory picker, so the browser
 * remains scoped to administrator-approved paths. Each request is handled without a shared mutable
 * state; thread safety therefore matches the servlet container model provided by the underlying
 * toadlet infrastructure.
 *
 * <p>Typical usage registers {@link #BROWSE_PATH} with the toadlet registrar and routes POST
 * submissions to {@link #POST_TARGET}. The handler preserves message and node-selection form fields
 * via {@link #persistenceFields(Map)} so that form reloads keep user intent intact even after
 * validation errors. Clients should favor this toadlet when embedding N2NM attachments because it
 * enforces the same directory allowlist that governs general uploads while keeping the UI minimal.
 *
 * <ul>
 *   <li>Provides a browse endpoint for N2NM attachments.
 *   <li>Uses the core upload policy to guard filesystem access.
 *   <li>Intentionally omits directory selection controls to reduce misuse.
 * </ul>
 */
public class LocalFileN2NMToadlet extends LocalFileBrowserToadlet {

  private static final String PATH_SEPARATOR = "/";
  private static final String BROWSE_SEGMENT = "n2nm-browse";
  private static final String POST_SEGMENT = "send_n2ntm";

  /**
   * HTTP path segment (with leading and trailing slashes) for browsing local files in the N2NM UI.
   * The trailing slash ensures relative links resolve correctly when the registrar mounts the
   * toadlet under the root namespace.
   */
  public static final String BROWSE_PATH = PATH_SEPARATOR + BROWSE_SEGMENT + PATH_SEPARATOR;

  /**
   * HTTP path segment (with leading and trailing slashes) that accepts POST submissions of N2NM
   * attachment forms. The value aligns with the form action emitted by the browse page to keep
   * navigation and upload handling consistent.
   */
  public static final String POST_TARGET = PATH_SEPARATOR + POST_SEGMENT + PATH_SEPARATOR;

  /**
   * Builds a toadlet bound to the provided node client core and high-level client helpers.
   *
   * <p>The constructor performs no I/O or validation beyond delegating the collaborators to the
   * superclass. Callers should provide the same instances used for other toadlets so upload policy
   * and session handling remain consistent across the HTTP interface.
   *
   * @param transferAccess transfer-access runtime port that supplies configuration and upload
   *     permission checks; must not be {@code null}.
   */
  public LocalFileN2NMToadlet(TransferAccessPort transferAccess) {
    super(transferAccess);
  }

  /**
   * Returns the browse path segment used to register this toadlet with the HTTP router.
   *
   * <p>The path contains leading and trailing slashes so that relative links on the generated page
   * remain stable even when the servlet container mounts the application under a prefix. The value
   * is static and safe to reuse across requests.
   *
   * @return canonical browse URL path for N2NM local file selection, including trailing slash.
   */
  @Override
  public String path() {
    return BROWSE_PATH;
  }

  /**
   * Provides the target path for POST submissions from the N2NM browse page.
   *
   * <p>Handlers rely on this path to bind multipart form uploads. The returned value matches {@link
   * #POST_TARGET} exactly and includes leading and trailing slashes so client-generated links do
   * not require additional normalization.
   *
   * @return absolute path segment that should receive N2NM upload POST requests.
   */
  @Override
  protected String postTo() {
    return POST_TARGET;
  }

  /**
   * Resolves the starting directory displayed to users when the browse page first loads.
   *
   * <p>The implementation defers to {@link #defaultUploadDir()} from the superclass, ensuring the
   * same initial folder as other upload toadlets. The directory should already respect the node's
   * configured upload policy, but later checks still run through {@link #allowedDir(File)} to guard
   * against policy changes after initialization.
   *
   * @return absolute path of the initial directory shown to the user, never {@code null}.
   */
  @Override
  protected String startingDir() {
    return defaultUploadDir();
  }

  /**
   * Verifies that a requested directory is eligible for browsing and upload in the N2NM context.
   *
   * <p>The method delegates to {@link TransferAccessPort#allowUploadFrom(File)} to honor the global
   * upload allowlist. Callers should supply canonicalized paths to avoid duplicate traversals; the
   * method itself does not resolve symlinks. Null inputs are treated as disallowed by the runtime
   * policy helper.
   *
   * @param path candidate directory to expose in the browser; expected to exist and be readable.
   * @return {@code true} when the core permits uploads from the directory, {@code false} otherwise.
   */
  @Override
  protected boolean allowedDir(File path) {
    return transferAccess.allowUploadFrom(path);
  }

  /**
   * Skips rendering of a directory selection button for N2NM uploads.
   *
   * <p>N2NM flows intentionally constrain users to the default upload directory to reduce
   * accidental disclosure of unrelated files. By overriding this hook with a no-op, the UI omits
   * the button that would normally allow choosing alternative directories while still participating
   * in the rendering pipeline of the parent class.
   *
   * @param fileRow HTML row element representing the current file entry; untouched by this method.
   * @param path path string associated with the row; retained for interface parity.
   * @param persistence persistence container used by the parent renderer; left unmodified here.
   */
  @Override
  protected void createSelectDirectoryButton(HTMLNode fileRow, String path, HTMLNode persistence) {
    // Directory selection is intentionally disabled for N2N message uploads.
  }

  /**
   * Extracts form fields that must persist across page reloads for the N2NM upload form.
   *
   * <p>The method copies the free-form {@code message} field verbatim when present and marks any
   * {@code node_*} checkbox selections with a fixed value of {@code "1"}. Other fields are ignored
   * to keep the persisted payload minimal. The returned map is detached from the input and may be
   * safely mutated by callers.
   *
   * @param set original submitted parameters keyed by form field name; may include null values.
   * @return a new map containing only message content and node-selection flags suitable for reuse.
   */
  @Override
  protected Map<String, String> persistenceFields(Map<String, String> set) {
    Map<String, String> fieldPairs = new HashMap<>();
    String message = set.get("message");
    if (message != null) fieldPairs.put("message", message);
    Set<String> keys = set.keySet();
    for (String key : keys) {
      if (key.startsWith("node_")) {
        fieldPairs.put(key, "1");
      }
    }
    return fieldPairs;
  }
}
