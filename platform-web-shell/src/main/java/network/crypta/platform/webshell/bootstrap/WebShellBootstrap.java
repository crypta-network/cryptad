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
 * @param platformApiRoot Platform API v1 root used by the browser-side fetches
 * @param formPassword legacy mutation token used by the current Platform API bridge, or {@code
 *     null} when the shell should stay read-only
 * @param legacyRoot legacy HTTP root used for deep links back to existing pages
 * @param legacySecurityLevelsPath legacy security page path used for explicit fallback flows
 * @param legacyDiagnosticPath legacy diagnostic export path used for explicit fallback flows
 * @param legacyLinks user-visible deep links back to the legacy admin pages
 */
public record WebShellBootstrap(
    String shellTitle,
    String shellDescription,
    String shellRoot,
    String assetRoot,
    String platformApiRoot,
    String formPassword,
    String legacyRoot,
    String legacySecurityLevelsPath,
    String legacyDiagnosticPath,
    List<LegacyLink> legacyLinks) {
  /** Default shell title used by the node-management UI. */
  public static final String DEFAULT_SHELL_TITLE = "Cryptad Web Shell";

  /** Default shell description used by the node-management UI. */
  public static final String DEFAULT_SHELL_DESCRIPTION =
      "Node management and queue control powered by Platform API v1.";

  /** Default Platform API v1 root used by the shell bootstrap payload. */
  public static final String DEFAULT_PLATFORM_API_ROOT = "/api/v1/";

  /** Default root for legacy deep links. */
  public static final String DEFAULT_LEGACY_ROOT = "/";

  /**
   * Creates the current shell bootstrap payload with adapter-resolved legacy fallback paths.
   *
   * <p>The platform shell does not own the legacy security-levels route. The serving adapter must
   * pass the routes it registered for the legacy security and diagnostic toadlets, including
   * deployments that customize those paths through local configuration. Keeping the values as
   * explicit parameters prevents the browser bootstrap from drifting away from the route map that
   * actually handles the fallback forms and exports.
   *
   * @param legacySecurityLevelsPath configured path for the legacy security-levels page
   * @param legacyDiagnosticPath configured path for the legacy diagnostic export
   * @param legacyLinks user-visible deep links back to the legacy admin pages
   * @return bootstrap payload suitable for the first-party shell
   */
  public static WebShellBootstrap nodeManagement(
      String legacySecurityLevelsPath, String legacyDiagnosticPath, List<LegacyLink> legacyLinks) {
    return new WebShellBootstrap(
        DEFAULT_SHELL_TITLE,
        DEFAULT_SHELL_DESCRIPTION,
        WebShellPaths.SHELL_ROOT,
        WebShellPaths.ASSET_ROOT,
        DEFAULT_PLATFORM_API_ROOT,
        null,
        DEFAULT_LEGACY_ROOT,
        legacySecurityLevelsPath,
        legacyDiagnosticPath,
        legacyLinks);
  }

  /**
   * Returns a copy of this bootstrap payload with one explicit mutation token.
   *
   * @param formPassword legacy mutation token injected by the serving bridge
   * @return bootstrap payload carrying the supplied mutation token
   */
  public WebShellBootstrap withFormPassword(String formPassword) {
    String normalizedFormPassword =
        formPassword == null || formPassword.isBlank() ? null : formPassword;
    return new WebShellBootstrap(
        shellTitle,
        shellDescription,
        shellRoot,
        assetRoot,
        platformApiRoot,
        normalizedFormPassword,
        legacyRoot,
        legacySecurityLevelsPath,
        legacyDiagnosticPath,
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
   * @throws IllegalArgumentException if the path is blank, does not start with {@code /}, or does
   *     not end with {@code /}
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
   * Requires one same-origin absolute path for a legacy route that may be registered slashless.
   *
   * <p>Most Web Shell fields are route roots and therefore require a trailing slash. The legacy
   * fallback routes are different: they mirror configured legacy toadlet paths exactly, including
   * installations that set a fallback route to a slashless path. The value is still constrained to
   * a local path with no query or fragment so browser bootstrap data cannot become an open redirect
   * or leak request metadata.
   *
   * @param value path value to validate
   * @param label logical field name used in validation messages
   * @throws NullPointerException if {@code value} is {@code null}
   * @throws IllegalArgumentException if the path is blank, is not a single-leading-slash local
   *     path, or contains query/fragment data
   */
  private static void requireLegacyLocalPath(String value, String label) {
    requireText(value, label);
    if (value.charAt(0) != '/' || value.startsWith("//")) {
      throw new IllegalArgumentException(label + " must start with a single leading '/'");
    }
    try {
      URI uri = URI.create("http://localhost" + value);
      if (!value.equals(uri.getRawPath())
          || uri.getRawQuery() != null
          || uri.getRawFragment() != null) {
        throw new IllegalArgumentException(label + " must be a valid absolute local path");
      }
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(label + " must be a valid absolute local path", e);
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
   * @throws IllegalArgumentException if any route path is blank, is not local, or contains query or
   *     fragment data
   */
  public WebShellBootstrap {
    requireText(shellTitle, "shellTitle");
    requireText(shellDescription, "shellDescription");
    requireRootPath(shellRoot, "shellRoot");
    requireRootPath(assetRoot, "assetRoot");
    requireRootPath(platformApiRoot, "platformApiRoot");
    if (formPassword != null) {
      requireText(formPassword, "formPassword");
    }
    requireRootPath(legacyRoot, "legacyRoot");
    requireLegacyLocalPath(legacySecurityLevelsPath, "legacySecurityLevelsPath");
    requireLegacyLocalPath(legacyDiagnosticPath, "legacyDiagnosticPath");
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
