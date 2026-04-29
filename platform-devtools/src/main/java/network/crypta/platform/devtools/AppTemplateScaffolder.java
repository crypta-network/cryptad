package network.crypta.platform.devtools;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppDistributionException;

/**
 * Creates standalone staged app-bundle skeletons for third-party developers.
 *
 * <p>The scaffolder writes ordinary bundle files, not a Gradle subproject. Generated manifests are
 * parsed with the production appdist parser before they are written so command-line input follows
 * the same syntax and value rules as signed bundles. A static template also copies the canonical
 * browser SDK resource into the staged bundle so the new app can load the same client API that
 * first-party static apps use.
 *
 * <p>The generated bundle is intentionally conservative: it uses no sandbox, zero quota defaults,
 * and a launcher script that tells developers to replace it before publishing. The class is
 * stateless; all filesystem state is captured by {@link ScaffoldRequest}, and each scaffold
 * operation validates the target directory before writing files.
 */
final class AppTemplateScaffolder {
  /** Classpath resource that contains the canonical browser SDK copied into static templates. */
  private static final String SDK_RESOURCE = "/network/crypta/platform/sdk/js/crypta-platform.js";

  /** Manifest UI mode value and asset directory name used by static app templates. */
  private static final String STATIC_TEMPLATE_NAME = "static";

  /** Placeholder token replaced with the normalized app identifier in generated template files. */
  private static final String APP_ID_PLACEHOLDER = "${APP_ID}";

  /** Stylesheet content written to {@code static/app.css} for the static scaffold. */
  private static final String STATIC_CSS =
      """
      :root {
        color-scheme: light dark;
        font-family: system-ui, sans-serif;
      }

      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
      }

      main {
        width: min(42rem, calc(100vw - 2rem));
      }
      """;

  /** Utility class; template generation is exposed through {@link #scaffold(ScaffoldRequest)}. */
  private AppTemplateScaffolder() {}

  /**
   * Creates or overwrites a staged bundle skeleton from a normalized scaffold request.
   *
   * <p>The method validates the destination policy, creates the bundle directory layout, renders
   * the manifest and static assets, parses the generated manifest with appdist rules, and returns
   * the absolute directory that was written. Existing non-empty directories are accepted only when
   * the request enables overwrite.
   *
   * @param request scaffold parameters supplied by the command-line init flow
   * @return normalized bundle directory that now contains the scaffolded files
   * @throws IOException if the destination cannot be inspected or written
   */
  static Path scaffold(ScaffoldRequest request) throws IOException {
    ScaffoldRequest checked = Objects.requireNonNull(request, "request").normalize();
    ensureWritableTarget(checked.directory(), checked.overwrite());
    createTemplateDirectory(checked.directory(), "target directory");
    createTemplateDirectory(checked.directory().resolve("bin"), "launcher directory");
    if (checked.uiMode() == UiMode.STATIC) {
      createTemplateDirectory(
          checked.directory().resolve(STATIC_TEMPLATE_NAME), "static template directory");
    }

    String manifest = checked.manifestContent();
    AppBundleManifestParser.parseContent(manifest);
    writeTemplateFile(
        checked.directory().resolve(AppBundleManifestParser.MANIFEST_FILE_NAME), manifest);
    writeTemplateFile(
        checked.directory().resolve("bin").resolve("start.sh"), launcherScript(checked.appId()));
    if (checked.uiMode() == UiMode.STATIC) {
      writeStaticTemplate(checked);
    }
    writeTemplateFile(checked.directory().resolve("README.md"), readme(checked));
    return checked.directory();
  }

  /**
   * Verifies that the scaffold target can be used for this init operation.
   *
   * @param directory target directory after request normalization
   * @param overwrite whether a non-empty existing directory is allowed
   * @throws IOException if the directory cannot be inspected
   */
  private static void ensureWritableTarget(Path directory, boolean overwrite) throws IOException {
    if (!Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
      ensureExistingParentIsDirectory(directory);
      return;
    }
    if (Files.isSymbolicLink(directory)) {
      throw new AppDistributionException(
          "target directory must not be a symbolic link: " + directory);
    }
    if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("target path is not a directory: " + directory);
    }
    if (overwrite || directoryIsEmpty(directory)) {
      return;
    }
    throw new AppDistributionException("target directory is not empty: " + directory);
  }

  /**
   * Ensures that the nearest existing parent for a new scaffold target is a real directory.
   *
   * @param directory target directory that does not yet exist
   * @throws IOException if parent inspection fails or finds an unsafe parent path
   */
  private static void ensureExistingParentIsDirectory(Path directory) throws IOException {
    Path existingParent = directory.getParent();
    while (existingParent != null && !Files.exists(existingParent, LinkOption.NOFOLLOW_LINKS)) {
      existingParent = existingParent.getParent();
    }
    if (existingParent == null) {
      return;
    }
    if (Files.isSymbolicLink(existingParent)
        || !Files.isDirectory(existingParent, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException(
          "target directory parent must be a real directory: " + existingParent);
    }
  }

  /**
   * Creates a scaffold-managed directory without accepting a symbolic-link replacement.
   *
   * @param directory directory to create or reuse
   * @param description directory role used in diagnostics
   * @throws IOException if the path is unsafe or cannot be created
   */
  private static void createTemplateDirectory(Path directory, String description)
      throws IOException {
    if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
      requireRealDirectory(directory, description);
      return;
    }
    Files.createDirectories(directory);
    requireRealDirectory(directory, description);
  }

  private static void requireRealDirectory(Path directory, String description) throws IOException {
    if (Files.isSymbolicLink(directory)) {
      throw new AppDistributionException(
          description + " must not be a symbolic link: " + directory);
    }
    if (!Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException(description + " must be a directory: " + directory);
    }
  }

  /**
   * Writes a scaffold-managed UTF-8 file while refusing symbolic-link destinations.
   *
   * @param file target file under the scaffold directory
   * @param content UTF-8 text to write
   * @throws IOException if the file path is unsafe or cannot be written
   */
  private static void writeTemplateFile(Path file, String content) throws IOException {
    requireWritableTemplateFile(file);
    Files.writeString(
        file,
        content,
        StandardCharsets.UTF_8,
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE,
        LinkOption.NOFOLLOW_LINKS);
  }

  private static void requireWritableTemplateFile(Path file) throws IOException {
    Path parent = file.getParent();
    if (parent == null) {
      throw new AppDistributionException("template file must have a parent directory: " + file);
    }
    requireRealDirectory(parent, "template file parent");
    if (!Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    if (Files.isSymbolicLink(file)) {
      throw new AppDistributionException("template file must not be a symbolic link: " + file);
    }
    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("template file path must be a regular file: " + file);
    }
  }

  /**
   * Checks whether an existing directory contains no entries.
   *
   * @param directory directory to inspect without recursively reading contents
   * @return {@code true} when the directory has no direct children
   * @throws IOException if the directory stream cannot be opened
   */
  private static boolean directoryIsEmpty(Path directory) throws IOException {
    try (DirectoryStream<Path> stream = Files.newDirectoryStream(directory)) {
      return !stream.iterator().hasNext();
    }
  }

  /**
   * Writes the static UI template and browser SDK into the scaffold directory.
   *
   * @param request normalized scaffold request used for names and app identifiers
   * @throws IOException if any static template file cannot be written
   */
  private static void writeStaticTemplate(ScaffoldRequest request) throws IOException {
    Path staticDir = request.directory().resolve(STATIC_TEMPLATE_NAME);
    writeTemplateFile(staticDir.resolve("index.html"), staticIndex(request));
    writeTemplateFile(staticDir.resolve("app.js"), staticJavaScript(request));
    writeTemplateFile(staticDir.resolve("app.css"), STATIC_CSS);
    copySdk(staticDir.resolve("crypta-platform.js"));
  }

  /**
   * Copies the canonical browser SDK resource into a generated static UI.
   *
   * @param target destination file path inside the scaffolded {@code static} directory
   * @throws IOException if the resource cannot be read or the target cannot be written
   */
  private static void copySdk(Path target) throws IOException {
    try (InputStream input = AppTemplateScaffolder.class.getResourceAsStream(SDK_RESOURCE)) {
      if (input == null) {
        throw new AppDistributionException("Crypta browser SDK resource is not on the classpath");
      }
      requireWritableTemplateFile(target);
      try (OutputStream output =
          Files.newOutputStream(
              target,
              StandardOpenOption.CREATE,
              StandardOpenOption.TRUNCATE_EXISTING,
              StandardOpenOption.WRITE,
              LinkOption.NOFOLLOW_LINKS)) {
        input.transferTo(output);
      }
    }
  }

  /**
   * Renders the placeholder process launcher for a scaffolded bundle.
   *
   * @param appId normalized app identifier used in the launcher message
   * @return shell script content that developers must replace for production distribution
   */
  private static String launcherScript(String appId) {
    return """
    #!/bin/sh
    set -eu

    echo "This is the scaffolded launcher for ${APP_ID}."
    echo "Replace bin/start.sh with the production launcher before publishing this app."
    """
        .replace(APP_ID_PLACEHOLDER, appId);
  }

  /**
   * Renders the minimal static HTML entry point.
   *
   * @param request normalized scaffold request that supplies display text
   * @return HTML document content for {@code static/index.html}
   */
  private static String staticIndex(ScaffoldRequest request) {
    String escapedName = escapeHtml(request.name());
    return """
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>${APP_NAME}</title>
        <link rel="stylesheet" href="./app.css">
      </head>
      <body>
        <main>
          <h1>${APP_NAME}</h1>
          <p id="status">Connecting to Crypta...</p>
        </main>
        <script src="./crypta-platform.js"></script>
        <script type="module" src="./app.js"></script>
      </body>
    </html>
    """
        .replace("${APP_NAME}", escapedName);
  }

  /**
   * Renders the static UI JavaScript bootstrap example.
   *
   * @param request normalized scaffold request that supplies the app identifier
   * @return module script content for {@code static/app.js}
   */
  private static String staticJavaScript(ScaffoldRequest request) {
    return """
    const status = document.querySelector("#status");

    async function main() {
      const platform = window.CryptaPlatform;
      const bootstrap = await platform.bootstrap.load({ appId: "${APP_ID}" });
      status.textContent = `${bootstrap.appName} is connected.`;
    }

    main().catch((error) => {
      status.textContent = error instanceof Error ? error.message : String(error);
    });
    """
        .replace(APP_ID_PLACEHOLDER, request.appId());
  }

  /**
   * Renders the README that explains the local developer workflow.
   *
   * @param request normalized scaffold request that supplies app name, id, and version
   * @return Markdown content for the scaffolded {@code README.md}
   */
  private static String readme(ScaffoldRequest request) {
    return """
    # ${APP_NAME}

    This directory is a standalone Crypta staged app bundle. It is not a Gradle subproject.

    ## Local workflow

    ```bash
    crypta-app validate --bundle-dir .
    crypta-app sign --bundle-dir . --key-id dev-local --private-key-file /path/to/private.pem
    crypta-app pack --bundle-dir . --output ../${APP_ID}-${APP_VERSION}.zip --overwrite
    crypta-app verify --bundle-dir . --trusted-key-id dev-local --trusted-public-key-file /path/to/public.pem
    ```

    Replace `bin/start.sh` with the production launcher before distributing the app.
    """
        .replace("${APP_NAME}", request.name())
        .replace(APP_ID_PLACEHOLDER, request.appId())
        .replace("${APP_VERSION}", request.version());
  }

  /**
   * Escapes display text inserted into the generated HTML template.
   *
   * @param value raw display value supplied by the scaffold request
   * @return value escaped for HTML text and attribute contexts used by the template
   */
  private static String escapeHtml(String value) {
    return value
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;");
  }

  /**
   * Supported UI template modes for scaffolded manifests.
   *
   * <p>The enum values map directly to manifest {@code app.ui.mode} literals. Static mode writes
   * local HTML, JavaScript, CSS, and SDK files. Shell-panel mode emits a manifest entry that points
   * at the app-owned shell panel route but does not generate UI files. None mode creates a bundle
   * without a UI entry.
   */
  enum UiMode {
    /** Static app-owned browser UI served from files inside the bundle. */
    STATIC(STATIC_TEMPLATE_NAME),
    /** Shell-panel app UI that relies on an external app-owned route. */
    SHELL_PANEL("shell-panel"),
    /** No browser UI is declared in the generated manifest. */
    NONE("none");

    /** Manifest literal written for this UI mode. */
    private final String value;

    /**
     * Stores the manifest literal for one UI mode.
     *
     * @param value exact {@code app.ui.mode} value written to the scaffolded manifest
     */
    UiMode(String value) {
      this.value = value;
    }

    /**
     * Parses a command-line UI mode value.
     *
     * <p>Input is trimmed and lowercased before matching so developer CLI invocations do not depend
     * on enum naming. Unsupported values fail early before any scaffold files are written.
     *
     * @param rawValue user-supplied UI mode value from the init command
     * @return matching scaffold UI mode
     * @throws IllegalArgumentException if the value is not one of the supported manifest modes
     */
    static UiMode parse(String rawValue) {
      String normalized = rawValue.trim().toLowerCase(Locale.ROOT);
      for (UiMode mode : values()) {
        if (mode.value.equals(normalized)) {
          return mode;
        }
      }
      throw new IllegalArgumentException("unsupported UI mode: " + rawValue);
    }
  }

  /**
   * Immutable input used to render one scaffolded staged bundle.
   *
   * <p>The request stores the developer-facing values accepted by the CLI and applies normalization
   * in a separate step so command parsing can stay simple. Permission values are copied as
   * supplied; the manifest parser validates their syntax once {@link #manifestContent()} has
   * rendered the generated properties.
   *
   * @param directory target bundle directory to create or overwrite
   * @param appId manifest app identifier supplied by the developer
   * @param name human-readable app name written into the manifest and template UI
   * @param version app version string written into the manifest
   * @param uiMode requested UI template mode, defaulting to static when omitted
   * @param permissions manifest permissions requested for the generated app
   * @param overwrite whether an existing non-empty target directory may be reused
   */
  record ScaffoldRequest(
      Path directory,
      String appId,
      String name,
      String version,
      UiMode uiMode,
      List<String> permissions,
      boolean overwrite) {
    /**
     * Creates a scaffold request and copies collection state into immutable storage.
     *
     * <p>The constructor performs only null handling and defaulting. Use {@link #normalize()}
     * before writing files so paths, app identifiers, names, and versions are in manifest-ready
     * form.
     */
    ScaffoldRequest {
      Objects.requireNonNull(directory, "directory");
      Objects.requireNonNull(appId, "appId");
      Objects.requireNonNull(name, "name");
      Objects.requireNonNull(version, "version");
      uiMode = Objects.requireNonNullElse(uiMode, UiMode.STATIC);
      permissions = List.copyOf(Objects.requireNonNull(permissions, "permissions"));
    }

    /**
     * Returns a request with filesystem and manifest values normalized for rendering.
     *
     * <p>The directory becomes absolute and normalized, the app identifier is passed through the
     * production manifest normalizer, and name/version strings are trimmed. Permission values are
     * left in their original order so the generated manifest reflects the CLI input order.
     *
     * @return normalized request ready for scaffold file generation
     */
    ScaffoldRequest normalize() {
      return new ScaffoldRequest(
          directory.toAbsolutePath().normalize(),
          AppBundleManifest.normalizeAppId(appId),
          name.trim(),
          version.trim(),
          uiMode,
          permissions,
          overwrite);
    }

    /**
     * Renders the staged bundle manifest properties for this request.
     *
     * <p>The output contains conservative sandbox, quota, and restart defaults. The {@code
     * app.permissions} property is omitted when no permissions were requested, which avoids writing
     * a blank permission value that production manifest parsing would reject.
     *
     * @return UTF-8 compatible manifest properties content for {@code cryptad-app.properties}
     */
    String manifestContent() {
      StringBuilder builder = new StringBuilder();
      builder
          .append("manifest.version=1\n")
          .append("app.id=")
          .append(appId)
          .append('\n')
          .append("app.name=")
          .append(name)
          .append('\n')
          .append("app.version=")
          .append(version)
          .append('\n')
          .append("app.exec=bin/start.sh\n")
          .append("app.ui.mode=")
          .append(uiMode.value)
          .append('\n');
      if (uiMode == UiMode.STATIC) {
        builder.append("app.ui.entry=static/index.html\n");
      } else if (uiMode == UiMode.SHELL_PANEL) {
        builder.append("app.ui.entry=/app/node/#").append(appId).append('\n');
      }
      builder
          .append("sandbox.mode=none\n")
          .append("sandbox.required=false\n")
          .append("quota.data.bytes=0\n")
          .append("quota.cache.bytes=0\n")
          .append("app.restart.policy=never\n")
          .append("app.restart.maxAttempts=0\n")
          .append("app.restart.backoff.ms=0\n");
      if (!permissions.isEmpty()) {
        builder.append("app.permissions=").append(String.join(",", permissions)).append('\n');
      }
      return builder.toString();
    }
  }
}
