package network.crypta.platform.webshell.bootstrap;

import java.net.URI;
import java.util.List;
import java.util.Objects;
import network.crypta.platform.webshell.routes.WebShellPaths;

/**
 * Browser bootstrapping data for the node-management shell.
 *
 * <p>The bootstrap keeps the browser contract stable and transport-neutral.
 *
 * <p>The legacy HTTP bridge can inject the JSON form of this record into the shell template.
 * Browser-side code can then discover the Platform API root, the shell root, and the legacy deep
 * links without hardcoded knowledge of the adapter layer.
 *
 * @param shellTitle visible title shown in the shell hero area
 * @param shellDescription short description of the shell purpose
 * @param shellRoot canonical mount path for the shell page
 * @param assetRoot canonical mount path for shell-owned static assets
 * @param platformApiRoot read-only Platform API v1 root used by the browser-side fetches
 * @param legacyRoot legacy HTTP root used for deep links back to existing pages
 * @param legacyLinks user-visible deep links back to the legacy admin pages
 */
public record WebShellBootstrap(
    String shellTitle,
    String shellDescription,
    String shellRoot,
    String assetRoot,
    String platformApiRoot,
    String legacyRoot,
    List<LegacyLink> legacyLinks) {
  /** Default shell title used by the node-management UI. */
  public static final String DEFAULT_SHELL_TITLE = "Cryptad Web Shell";

  /** Default shell description used by the node-management UI. */
  public static final String DEFAULT_SHELL_DESCRIPTION =
      "Read-only node management powered by Platform API v1.";

  /** Default read-only Platform API v1 root. */
  public static final String DEFAULT_PLATFORM_API_ROOT = "/api/v1/";

  /** Default root for legacy deep links. */
  public static final String DEFAULT_LEGACY_ROOT = "/";

  /**
   * Creates the current shell bootstrap payload with the default node-management layout.
   *
   * @param legacyLinks user-visible deep links back to the legacy admin pages
   * @return bootstrap payload suitable for the first-party shell
   */
  public static WebShellBootstrap nodeManagement(List<LegacyLink> legacyLinks) {
    return new WebShellBootstrap(
        DEFAULT_SHELL_TITLE,
        DEFAULT_SHELL_DESCRIPTION,
        WebShellPaths.SHELL_ROOT,
        WebShellPaths.ASSET_ROOT,
        DEFAULT_PLATFORM_API_ROOT,
        DEFAULT_LEGACY_ROOT,
        legacyLinks);
  }

  /**
   * Requires one non-blank text field in the bootstrap payload.
   *
   * @param value field value to validate
   * @param label logical field name used in validation messages
   * @throws NullPointerException if {@code value} is {@code null}
   * @throws IllegalArgumentException if {@code value} is blank
   */
  private static void requireText(String value, String label) {
    Objects.requireNonNull(value, label);
    if (value.isBlank()) {
      throw new IllegalArgumentException(label + " must not be blank");
    }
  }

  /**
   * Requires one canonical root path for shell routes and API endpoints.
   *
   * @param value root path to validate
   * @param label logical field name used in validation messages
   * @throws NullPointerException if {@code value} is {@code null}
   * @throws IllegalArgumentException if the path is blank or is not wrapped in leading and trailing
   *     slashes
   */
  private static void requireRootPath(String value, String label) {
    requireText(value, label);
    if (value.charAt(0) != '/' || value.startsWith("//")) {
      throw new IllegalArgumentException(label + " must start with a single leading '/'");
    }
    try {
      URI uri = URI.create("http://localhost" + value);
      if (!value.equals(uri.getRawPath())
          || uri.getRawQuery() != null
          || uri.getRawFragment() != null
          || !value.endsWith("/")) {
        throw new IllegalArgumentException(label + " must be a valid absolute root path");
      }
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(label + " must be a valid absolute root path", e);
    }
  }

  /**
   * Creates an immutable shell bootstrap payload.
   *
   * <p>The constructor keeps the data deliberately narrow: route roots, a short descriptive title,
   * and an adapter-supplied list of deep links back into the legacy UI. That is enough for the
   * first shell while keeping the adapter bridge free to remain a thin transport layer.
   *
   * @throws NullPointerException if any required field is {@code null}
   * @throws IllegalArgumentException if any root path is blank, does not start with {@code /}, or
   *     does not end with {@code /}
   */
  public WebShellBootstrap {
    requireText(shellTitle, "shellTitle");
    requireText(shellDescription, "shellDescription");
    requireRootPath(shellRoot, "shellRoot");
    requireRootPath(assetRoot, "assetRoot");
    requireRootPath(platformApiRoot, "platformApiRoot");
    requireRootPath(legacyRoot, "legacyRoot");
    legacyLinks = List.copyOf(Objects.requireNonNull(legacyLinks, "legacyLinks"));
    if (legacyLinks.isEmpty()) {
      throw new IllegalArgumentException("legacyLinks must not be empty");
    }
  }

  /**
   * One user-visible deep link back into the legacy admin UI.
   *
   * @param path absolute path to the legacy page
   * @param label visible link label used by the shell
   */
  public record LegacyLink(String path, String label) {
    /**
     * Creates one deep link definition.
     *
     * @throws NullPointerException if either field is {@code null}
     * @throws IllegalArgumentException if the path is blank or does not start and end with {@code
     *     /}
     */
    public LegacyLink {
      requireRootPath(path, "path");
      requireText(label, "label");
    }
  }
}
