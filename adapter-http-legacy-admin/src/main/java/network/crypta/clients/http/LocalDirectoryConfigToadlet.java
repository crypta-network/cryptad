package network.crypta.clients.http;

import java.io.File;
import java.util.Map;
import network.crypta.l10n.NodeL10n;
import network.crypta.runtime.spi.TransferAccessPort;
import network.crypta.support.HTMLNode;

/**
 * Directory selector used by configuration pages in the local HTTP UI.
 *
 * <p>This toadlet specializes {@link LocalDirectoryToadlet} for configuration flows where the
 * operator must choose any directory on the host without the normal safety restrictions applied to
 * uploads or downloads. It always starts in the current user's home directory, permits navigation
 * into every path presented by the filesystem, and renders a concise form that posts the chosen
 * directory back to a calling toadlet. Instances are stateless after construction and rely on the
 * base class to manage navigation state such as the last successful selection.
 *
 * <p>Typical usage is to register a single instance with the HTTP server and reuse it across
 * requests. The caller supplies a {@code postTo} path identifying the handler that will receive the
 * selected directory. Because the instance does not cache filesystem data, it reflects the current
 * filesystem state on each request and is safe for concurrent access by multiple request threads.
 *
 * <ul>
 *   <li>Starts in the JVM user's home directory for familiarity.
 *   <li>Allows browsing and selection of any readable directory without additional policy checks.
 *   <li>Strips sensitive navigation fields before persisting parameters across page views.
 * </ul>
 *
 * @see LocalDirectoryToadlet
 * @see LocalFileBrowserToadlet
 */
public class LocalDirectoryConfigToadlet extends LocalDirectoryToadlet {

  /**
   * Constructs a configuration directory browser that posts selections to the provided path.
   *
   * <p>The constructor performs no I/O and stores the collaborators for later use by the base
   * class. The {@code postTo} value is appended to {@link LocalDirectoryToadlet#basePath()} to form
   * the public URL for this toadlet and is also used as the redirect target when a directory is
   * chosen.
   *
   * @param transferAccess initialized transfer-access runtime port carried by the shared local
   *     browser base; must be non-null and remain reachable for the lifetime of the instance.
   * @param postTo relative URL segment (beginning with a slash) that identifies the handler to
   *     receive selected directories; the value is concatenated with {@link #path()} and reused for
   *     redirects.
   */
  public LocalDirectoryConfigToadlet(TransferAccessPort transferAccess, String postTo) {
    super(transferAccess, postTo);
  }

  /**
   * Returns the initial directory shown to the user.
   *
   * <p>This implementation always yields the JVM's {@code user.home} property so operators begin in
   * a familiar location. The value is resolved at call time, allowing tests or embedded runtimes to
   * substitute a different home directory via system properties without recreating the toadlet.
   *
   * @return absolute path of the home directory from {@code System.getProperty("user.home")}; never
   *     {@code null} unless the system property itself is unset.
   */
  @Override
  protected String startingDir() {
    // Start out in the user home directory.
    return System.getProperty("user.home");
  }

  /**
   * Indicates that all directories are eligible for selection.
   *
   * <p>Configuration flows intentionally allow unrestricted browsing so operators can point the
   * node at any desired path. The method therefore ignores the supplied {@code path} and returns
   * {@code true} for every call. Callers relying on stricter policies should implement their own
   * subclass with custom validation logic.
   *
   * @param path directory candidate being considered; the value is not inspected and may be any
   *     readable or unreadable {@link File} instance.
   * @return {@code true} for all inputs, enabling the UI to render navigation controls everywhere.
   */
  @Override
  protected boolean allowedDir(File path) {
    // When configuring, can select any directory.
    return true;
  }

  /**
   * Renders a submission control that posts the currently browsed directory to the caller.
   *
   * <p>The method appends three children to {@code formNode}: a Submit button with the localized
   * label from {@code ConfigToadlet.selectDirectory}, a hidden field holding the absolute directory
   * path, and the provided {@code persist} node containing additional hidden fields. The structure
   * matches the expectations of {@link LocalFileBrowserToadlet#SELECT_DIR} so the base class can
   * detect the selection and perform a redirect.
   *
   * @param formNode parent form container to which controls are added; must be mutable and
   *     non-null.
   * @param path absolute directory path to insert into the hidden filename field; callers should
   *     pass the canonical path used for navigation to avoid ambiguity.
   * @param persist pre-rendered hidden fields that preserve request context (for example, CSRF
   *     tokens or previous query parameters); the node is appended unmodified.
   */
  @Override
  protected void createSelectDirectoryButton(HTMLNode formNode, String path, HTMLNode persist) {
    formNode.addChild(
        "input",
        new String[] {"type", "name", "value"},
        new String[] {
          "submit", SELECT_DIR, NodeL10n.getBase().getString("ConfigToadlet.selectDirectory")
        });
    formNode.addChild(
        "input",
        new String[] {"type", "name", "value"},
        new String[] {"hidden", filenameField(), path});
    formNode.addChild(persist);
  }

  /**
   * Filters persisted request fields before rendering hidden inputs.
   *
   * <p>Configuration browsing does not retain the current {@code path} or {@code formPassword}
   * fields between views to avoid leaking navigation state or password material into the following
   * posts. All other entries in the supplied map are left intact and returned to the caller for
   * serialization.
   *
   * @param set mutable map of request parameters collected from the current HTTP request; expected
   *     to contain simple string key/value pairs and remain non-null.
   * @return the same map instance with {@code path} and {@code formPassword} keys removed; callers
   *     may mutate or serialize the returned map as needed.
   */
  @Override
  protected Map<String, String> persistenceFields(Map<String, String> set) {
    set.remove("path");
    set.remove("formPassword");
    return set;
  }
}
