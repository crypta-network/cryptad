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
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import network.crypta.platform.api.PlatformApiCapabilityDescriptor;
import network.crypta.platform.api.PlatformApiContract;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppDistributionException;
import network.crypta.platform.designsystem.DesignSystemAssets;

/**
 * Creates standalone staged app-bundle skeletons for third-party developers.
 *
 * <p>The scaffolder writes ordinary bundle files, not a Gradle subproject. Generated manifests are
 * parsed with the production appdist parser before they are written so command-line input follows
 * the same syntax and value rules as signed bundles. A static template also copies the canonical
 * browser SDK and app UI design-system resources into the staged bundle so the new app can load the
 * same client API and platform UI vocabulary that first-party static apps use.
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

  /** Placeholder token replaced with the app display name in generated template files. */
  private static final String APP_NAME_PLACEHOLDER = "${APP_NAME}";

  /** Placeholder token replaced with the app version in generated template files. */
  private static final String APP_VERSION_PLACEHOLDER = "${APP_VERSION}";

  /** Platform API permission for reading app-owned durable records. */
  private static final String APP_DATA_READ_PERMISSION = "app.data.read";

  /** Platform API permission for writing app-owned durable records. */
  private static final String APP_DATA_WRITE_PERMISSION = "app.data.write";

  /** App-data permissions that require generated schema and backup review notes. */
  private static final Set<String> APP_DATA_PERMISSIONS =
      Set.of(APP_DATA_READ_PERMISSION, APP_DATA_WRITE_PERMISSION);

  /** Stylesheet content written to {@code static/app.css} for the static scaffold. */
  private static final String STATIC_CSS =
      """
      .sample-layout {
        display: grid;
        gap: var(--cr-space-4);
      }

      .sample-status {
        margin-top: var(--cr-space-3);
      }

      .sample-grid {
        display: grid;
        gap: var(--cr-space-3);
        grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr));
      }

      .sample-actions {
        display: flex;
        flex-wrap: wrap;
        gap: var(--cr-space-2);
      }

      .sample-list {
        display: grid;
        gap: var(--cr-space-2);
        margin: 0;
        padding: 0;
      }

      .sample-list li {
        display: flex;
        justify-content: space-between;
        gap: var(--cr-space-3);
      }

      .sample-preview {
        margin: 0;
        overflow: auto;
        white-space: pre-wrap;
      }
      """;

  /** Review-note scaffold explaining the template's default sandbox posture. */
  private static final String HELLO_STABLE_SANDBOX_RATIONALE =
      """
      # Sandbox rationale

      This scaffold uses a static UI and a placeholder launcher. It declares `sandbox.mode=none`
      because it has no background runtime behavior in the local beta fixture. A production
      third-party app must document the sandbox provider it needs and why.
      """;

  /** Review-note scaffold used for deterministic local reviewer decisions. */
  private static final String HELLO_STABLE_DECISION_REASON =
      """
      # Review decision reason

      Non-production reviewed decision for the local Hello Stable beta fixture. Use only with
      deterministic test reviewer material and `--allow-non-production`.
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
    if (checked.templateKind() != AppTemplateKind.STATIC_BASIC
        && checked.uiMode() != UiMode.STATIC) {
      throw new AppDistributionException(
          "template " + checked.templateKind().cliName() + " requires --ui-mode static");
    }
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
    if (checked.templateKind() == AppTemplateKind.HELLO_STABLE) {
      writeHelloStableReviewNotes(checked);
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
    DesignSystemAssets.copyIntoBundle(request.directory());
  }

  private static void writeHelloStableReviewNotes(ScaffoldRequest request) throws IOException {
    Path reviewDir = request.directory().resolve("review");
    createTemplateDirectory(reviewDir, "review notes directory");
    Map<String, String> notes = new LinkedHashMap<>();
    notes.put("permission-rationale.md", helloStablePermissionRationale(request));
    notes.put("sandbox-rationale.md", HELLO_STABLE_SANDBOX_RATIONALE);
    notes.put("data-schema.md", helloStableDataSchema(request));
    notes.put("backup-restore.md", helloStableBackupRestore(request));
    notes.put("security-notes.md", helloStableSecurityNotes(request));
    notes.put("changelog.md", helloStableChangelog(request));
    notes.put("decision-reason.md", HELLO_STABLE_DECISION_REASON);
    for (Map.Entry<String, String> note : notes.entrySet()) {
      writeTemplateFile(reviewDir.resolve(note.getKey()), note.getValue());
    }
  }

  private static String helloStablePermissionRationale(ScaffoldRequest request) {
    return """
    # Permission rationale

    The generated manifest requests these permissions:

    ${PERMISSION_RATIONALES}
    No capabilities outside this list are requested. Known internal and operator-only capabilities
    are rejected before this scaffold is written. Replace any placeholder rationale with the exact
    user-facing workflow before submission.
    """
        .replace(
            "${PERMISSION_RATIONALES}",
            permissionRationales(request.permissions(), request.name()));
  }

  private static String permissionRationales(List<String> permissions, String appName) {
    if (permissions.isEmpty()) {
      return "- No Platform API permissions are requested.\n";
    }
    StringBuilder builder = new StringBuilder();
    for (String permission : permissions) {
      builder
          .append("- `")
          .append(permission)
          .append("`: ")
          .append(permissionRationale(permission, appName))
          .append('\n');
    }
    return builder.toString();
  }

  private static String permissionRationale(String permission, String appName) {
    return switch (permission) {
      case "platform.contract.read" ->
          "Allows "
              + appName
              + " to display the local Platform API contract version and stable baseline metadata.";
      case "queue.read" ->
          "Allows the app to display user-visible queue status and item summaries.";
      case "queue.write" -> "Allows the app to update queue items after an explicit user action.";
      case "content.fetch" ->
          "Allows bounded foreground fetches for user-supplied Crypta or Freenet content keys.";
      case "content.insert" ->
          "Allows local insert requests for user-selected files or directories.";
      case "content.insert.app-document" ->
          "Allows publishing bounded app-generated documents after user action.";
      case "content.subscribe" -> "Allows app-owned subscriptions for user-approved USK sources.";
      case APP_DATA_READ_PERMISSION ->
          "Allows reading app-owned durable records for this app only.";
      case APP_DATA_WRITE_PERMISSION ->
          "Allows writing app-owned durable records for this app only.";
      case "app.services.read" ->
          "Allows discovery of local app-service descriptors and active grant metadata.";
      case "app.services.call" ->
          "Allows invocation of operator-approved local app-service grants.";
      case "trust.read" -> "Allows reading local Trust Graph preview data exposed to this app.";
      case "trust.write" ->
          "Allows importing Trust Graph statements and managing local anchors after user action.";
      case "vault.identities.read" -> "Allows reading identity metadata granted to this app.";
      case "vault.identities.create" ->
          "Allows creating app-owned identities after explicit user action.";
      case "vault.identities.use" ->
          "Allows using granted identities for bounded app document signing workflows.";
      default ->
          "Replace this scaffold line with the exact user-facing reason "
              + appName
              + " needs this capability before submission.";
    };
  }

  private static String helloStableDataSchema(ScaffoldRequest request) {
    if (hasAnyAppDataPermission(request.permissions())) {
      return """
      # App-data schema

      ${APP_NAME} declares ${APP_DATA_PERMISSIONS}. Replace this scaffold note with the exact
      app-data namespaces, record shapes, size bounds, and migration behavior before submission. Do
      not paste raw app-data values.
      """
          .replace(APP_NAME_PLACEHOLDER, request.name())
          .replace("${APP_DATA_PERMISSIONS}", inlineAppDataPermissions(request.permissions()));
    }
    return """
    # App-data schema

    ${APP_NAME} does not use durable app data and does not create app-owned records. There is no
    schema to migrate for version `${APP_VERSION}`.
    """
        .replace(APP_NAME_PLACEHOLDER, request.name())
        .replace(APP_VERSION_PLACEHOLDER, request.version());
  }

  private static String helloStableBackupRestore(ScaffoldRequest request) {
    if (hasAnyAppDataPermission(request.permissions())) {
      return """
      # Backup and restore

      ${APP_NAME} declares ${APP_DATA_PERMISSIONS}. Replace this scaffold note with the app-owned
      namespaces that participate in backup/restore, restore prerequisites, unsupported restore
      cases, and any beta data-discard policy before submission.
      """
          .replace(APP_NAME_PLACEHOLDER, request.name())
          .replace("${APP_DATA_PERMISSIONS}", inlineAppDataPermissions(request.permissions()));
    }
    return """
    # Backup and restore

    ${APP_NAME} has no app-data namespaces, cache state, or background runtime state to include in
    app-data backup/restore. A future version that writes durable app data must declare namespaces,
    restore behavior, and migration expectations before submission.
    """
        .replace(APP_NAME_PLACEHOLDER, request.name());
  }

  private static String helloStableSecurityNotes(ScaffoldRequest request) {
    StringBuilder builder =
        new StringBuilder(
            """
            # Security notes

            This non-production scaffold loads only local static assets and avoids remote scripts,
            authorization headers, bearer tokens, private keys, private insert URIs, fetched
            payload bodies, app-owned record values, and local filesystem paths.
            """);
    if (hasAnyPermission(request.permissions(), "content.fetch")) {
      builder.append(
          """

          If `content.fetch` remains, keep fetches bounded to user-supplied Crypta/Freenet keys \
          and do not log retrieved payload bodies.
          """);
    }
    if (hasAnyAppDataPermission(request.permissions())) {
      builder.append(
          """

          If app-data permissions remain, keep records app-owned and avoid raw values in logs, \
          review notes, support bundles, and issue reports.
          """);
    }
    if (hasAnyPermission(request.permissions(), "app.services.read", "app.services.call")) {
      builder.append(
          """

          If app-service permissions remain, document grant context and do not log service \
          request bodies, subject URIs, provider app data, or grant tokens.
          """);
    }
    if (hasAnyPermission(
        request.permissions(),
        "vault.identities.read",
        "vault.identities.create",
        "vault.identities.use")) {
      builder.append(
          """

          If vault identity permissions remain, document consent scope and do not log raw \
          signatures, private keys, or identity secret material.
          """);
    }
    return builder.toString();
  }

  private static boolean hasAnyPermission(List<String> permissions, String... names) {
    Set<String> expected = Set.of(names);
    for (String permission : permissions) {
      if (expected.contains(permission)) {
        return true;
      }
    }
    return false;
  }

  private static boolean hasAnyAppDataPermission(List<String> permissions) {
    return hasAnyPermission(permissions, APP_DATA_READ_PERMISSION, APP_DATA_WRITE_PERMISSION);
  }

  private static String inlineAppDataPermissions(List<String> permissions) {
    StringBuilder builder = new StringBuilder();
    for (String permission : permissions) {
      if (!APP_DATA_PERMISSIONS.contains(permission)) {
        continue;
      }
      if (!builder.isEmpty()) {
        builder.append(", ");
      }
      builder.append('`').append(permission).append('`');
    }
    return builder.isEmpty() ? "`none`" : builder.toString();
  }

  private static String helloStableChangelog(ScaffoldRequest request) {
    return """
    # Changelog

    ## ${APP_VERSION}

    Initial non-production third-party beta scaffold.
    """
        .replace(APP_VERSION_PLACEHOLDER, request.version());
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
        <link rel="stylesheet" href="./crypta-ui/crypta-ui-tokens.css">
        <link rel="stylesheet" href="./crypta-ui/crypta-ui.css">
        <link rel="stylesheet" href="./app.css">
      </head>
      <body class="cr-app">
        <main class="cr-shell sample-layout">
          <header class="cr-header">
            <div>
              <p class="cr-label">Crypta app</p>
              <h1>${APP_NAME}</h1>
            </div>
          </header>
          ${PERMISSION_SUMMARY}
          <section class="cr-card" aria-labelledby="status-heading">
            <h2 id="status-heading">Connection</h2>
            <p class="cr-status cr-status--info sample-status" id="status" role="status" aria-live="polite">
              Connecting to Crypta...
            </p>
          </section>
          ${TEMPLATE_BODY}
        </main>
        <script src="./crypta-platform.js"></script>
        <script type="module" src="./app.js"></script>
      </body>
    </html>
    """
        .replace(APP_NAME_PLACEHOLDER, escapedName)
        .replace("${PERMISSION_SUMMARY}", permissionSummary(request.permissions()))
        .replace("${TEMPLATE_BODY}", templateBody(request.templateKind()));
  }

  private static String templateBody(AppTemplateKind templateKind) {
    return switch (templateKind) {
      case STATIC_BASIC -> "";
      case HELLO_STABLE ->
          """
          <section class="cr-card" aria-labelledby="contract-heading">
            <h2 id="contract-heading">Platform API</h2>
            <div class="sample-grid">
              <div>
                <p class="cr-label">Current contract</p>
                <p id="contract-version">Waiting for mock API...</p>
              </div>
              <div>
                <p class="cr-label">Stable baseline</p>
                <p id="stable-baseline">Waiting for mock API...</p>
              </div>
              <div>
                <p class="cr-label">Stable capabilities</p>
                <p id="capability-count">Waiting for mock API...</p>
              </div>
            </div>
          </section>
          """;
      case QUEUE_DASHBOARD ->
          """
          <section class="cr-card" aria-labelledby="queue-heading">
            <div class="cr-card__header">
              <h2 id="queue-heading">Queue</h2>
              <button class="cr-button cr-button--secondary" type="button" id="refresh-queue">Refresh</button>
            </div>
            <ul class="sample-list" id="queue-list" aria-live="polite"></ul>
            <div class="sample-actions">
              <button class="cr-button" type="button" id="restart-first">Restart first</button>
              <button class="cr-button cr-button--secondary" type="button" id="raise-priority">Raise priority</button>
            </div>
          </section>
          """;
      case PUBLISHER ->
          """
          <section class="cr-card" aria-labelledby="publisher-heading">
            <h2 id="publisher-heading">Publisher</h2>
            <form class="sample-layout" id="publish-form">
              <label class="cr-field">
                <span class="cr-label">Source path</span>
                <input class="cr-input" name="sourcePath" required autocomplete="off">
              </label>
              <label class="cr-field">
                <span class="cr-label">Insert URI</span>
                <input class="cr-input" name="insertUri" required autocomplete="off">
              </label>
              <label class="cr-field">
                <span class="cr-label">Queue identifier</span>
                <input class="cr-input" name="identifier" value="sample-insert">
              </label>
              <label class="cr-field">
                <span class="cr-label">Target filename</span>
                <input class="cr-input" name="targetFilename" value="welcome.txt">
              </label>
              <button class="cr-button" type="submit">Queue insert</button>
            </form>
            <ul class="sample-list" id="publish-list" aria-live="polite"></ul>
          </section>
          """;
      case VAULT_PROFILE ->
          """
          <section class="cr-card" aria-labelledby="vault-heading">
            <div class="cr-card__header">
              <h2 id="vault-heading">Vault profile</h2>
              <div class="sample-actions">
                <button class="cr-button" type="button" id="create-identity">Create identity</button>
                <button class="cr-button cr-button--secondary" type="button" id="preview-profile">Preview document</button>
              </div>
            </div>
            <div class="sample-grid">
              <div>
                <p class="cr-label">Identities</p>
                <ul class="sample-list" id="identity-list" aria-live="polite"></ul>
              </div>
              <div>
                <p class="cr-label">Profile document</p>
                <pre class="sample-preview" id="profile-document" aria-live="polite">{}</pre>
              </div>
            </div>
          </section>
          """;
    };
  }

  /**
   * Renders the static UI JavaScript bootstrap example.
   *
   * @param request normalized scaffold request that supplies the app identifier
   * @return module script content for {@code static/app.js}
   */
  private static String staticJavaScript(ScaffoldRequest request) {
    return switch (request.templateKind()) {
      case STATIC_BASIC ->
          """
          const status = document.querySelector("#status");

          async function main() {
            const platform = window.CryptaPlatform;
            const bootstrap = await platform.bootstrap.load({ appId: "${APP_ID}" });
            status.textContent = `${bootstrap.name} is connected.`;
            status.className = "cr-status cr-status--success sample-status";
          }

          main().catch((error) => {
            status.textContent = error instanceof Error ? error.message : String(error);
            status.className = "cr-status cr-status--danger sample-status";
          });
          """
              .replace(APP_ID_PLACEHOLDER, request.appId());
      case HELLO_STABLE -> helloStableJavaScript(request.appId());
      case QUEUE_DASHBOARD -> queueDashboardJavaScript(request.appId());
      case PUBLISHER -> publisherJavaScript(request.appId());
      case VAULT_PROFILE -> vaultProfileJavaScript(request.appId());
    };
  }

  private static String helloStableJavaScript(String appId) {
    return """
    const status = document.querySelector("#status");
    const contractVersion = document.querySelector("#contract-version");
    const stableBaseline = document.querySelector("#stable-baseline");
    const capabilityCount = document.querySelector("#capability-count");

    async function main() {
      const platform = window.CryptaPlatform;
      const bootstrap = await platform.bootstrap.load({ appId: "${APP_ID}" });
      const response = await platform.api.get("platform/contract");
      const contract = response.contract || response;
      const baseline = contract.stableBaseline || {};
      const capabilities = Array.isArray(baseline.capabilities) ? baseline.capabilities : [];

      contractVersion.textContent = String(contract.contractVersion || "unknown");
      stableBaseline.textContent = baseline.name || "1.0";
      capabilityCount.textContent =
        capabilities.length > 0 ? String(capabilities.length) : String(baseline.capabilityCount || "unknown");
      status.textContent = `${bootstrap.name} loaded stable Platform API metadata.`;
      status.className = "cr-status cr-status--success sample-status";
    }

    function showError(error) {
      status.textContent = window.CryptaPlatform.api.errorMessage(error);
      status.className = "cr-status cr-status--danger sample-status";
    }

    main().catch(showError);
    """
        .replace(APP_ID_PLACEHOLDER, appId);
  }

  private static String queueDashboardJavaScript(String appId) {
    return """
    const status = document.querySelector("#status");
    const queueList = document.querySelector("#queue-list");
    const refreshButton = document.querySelector("#refresh-queue");
    const restartButton = document.querySelector("#restart-first");
    const priorityButton = document.querySelector("#raise-priority");

    let firstRequestId = "";

    async function loadQueue() {
      const platform = window.CryptaPlatform;
      const bootstrap = await platform.bootstrap.load({ appId: "${APP_ID}" });
      const snapshot = await platform.queue.snapshot({ page: "downloads" });
      const requests = Array.isArray(snapshot.requests) ? snapshot.requests : [];
      firstRequestId = requests.length > 0 ? String(requests[0].id || "") : "";
      queueList.replaceChildren(...requests.map(renderRequest));
      status.textContent = `${bootstrap.name} loaded ${requests.length} queue item(s).`;
      status.className = "cr-status cr-status--success sample-status";
    }

    function renderRequest(request) {
      const item = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = request.name || request.uri || request.id || "Queued request";
      const state = document.createElement("strong");
      state.textContent = request.state || "mocked";
      item.append(label, state);
      return item;
    }

    async function mutateFirst(action) {
      if (!firstRequestId) {
        status.textContent = "No queue item is available in the mock data.";
        return;
      }
      const form = new URLSearchParams();
      form.set("identifier", firstRequestId);
      if (action === "queue/requests/priority") {
        form.set("priority", "2");
      }
      await window.CryptaPlatform.queue.mutate(action, form);
      await loadQueue();
    }

    refreshButton.addEventListener("click", () => loadQueue().catch(showError));
    restartButton.addEventListener("click", () => mutateFirst("queue/requests/restart").catch(showError));
    priorityButton.addEventListener("click", () => mutateFirst("queue/requests/priority").catch(showError));

    function showError(error) {
      status.textContent = window.CryptaPlatform.api.errorMessage(error);
      status.className = "cr-status cr-status--danger sample-status";
    }

    loadQueue().catch(showError);
    """
        .replace(APP_ID_PLACEHOLDER, appId);
  }

  private static String publisherJavaScript(String appId) {
    return """
    const status = document.querySelector("#status");
    const form = document.querySelector("#publish-form");
    const publishList = document.querySelector("#publish-list");

    async function main() {
      const platform = window.CryptaPlatform;
      const bootstrap = await platform.bootstrap.load({ appId: "${APP_ID}" });
      const snapshot = await platform.queue.snapshot({ page: "uploads" });
      renderQueue(snapshot);
      status.textContent = `${bootstrap.name} is ready to queue inserts.`;
      status.className = "cr-status cr-status--success sample-status";
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const data = new FormData(form);
      const params = new URLSearchParams();
      const identifier = String(data.get("identifier") || "").trim() || `sample-insert-${Date.now()}`;
      params.set("sourcePath", String(data.get("sourcePath") || "").trim());
      params.set("insertUri", String(data.get("insertUri") || "").trim());
      params.set("identifier", identifier);
      const targetFilename = String(data.get("targetFilename") || "").trim();
      if (targetFilename) {
        params.set("targetFilename", targetFilename);
      }
      const result = await window.CryptaPlatform.content.insertFile(params);
      status.textContent = result.message || "Insert request queued in the mock API.";
      await main();
    });

    function renderQueue(snapshot) {
      const requests = Array.isArray(snapshot.requests) ? snapshot.requests : [];
      publishList.replaceChildren(...requests.map((request) => {
        const item = document.createElement("li");
        const label = document.createElement("span");
        label.textContent = request.name || request.id || "Insert request";
        const state = document.createElement("strong");
        state.textContent = request.state || "queued";
        item.append(label, state);
        return item;
      }));
    }

    main().catch((error) => {
      status.textContent = window.CryptaPlatform.api.errorMessage(error);
      status.className = "cr-status cr-status--danger sample-status";
    });
    """
        .replace(APP_ID_PLACEHOLDER, appId);
  }

  private static String vaultProfileJavaScript(String appId) {
    return """
    const status = document.querySelector("#status");
    const identityList = document.querySelector("#identity-list");
    const profileDocument = document.querySelector("#profile-document");
    const createButton = document.querySelector("#create-identity");
    const previewButton = document.querySelector("#preview-profile");

    let currentIdentityId = "local-profile";

    async function main() {
      const platform = window.CryptaPlatform;
      const bootstrap = await platform.bootstrap.load({ appId: "${APP_ID}" });
      const identities = await platform.vault.identities.list();
      const identityValues = Array.isArray(identities.identities) ? identities.identities : [];
      currentIdentityId = currentIdentityId || firstIdentityId(identityValues);
      render(identityList, identityValues, "identity");
      status.textContent = `${bootstrap.name} loaded ${identityValues.length} mock identity item(s).`;
      status.className = "cr-status cr-status--success sample-status";
    }

    createButton.addEventListener("click", () => createIdentity().catch(showError));
    previewButton.addEventListener("click", () => previewProfileDocument().catch(showError));

    async function createIdentity() {
      const result = await window.CryptaPlatform.vault.identities.create({
        label: "Local Profile",
        scopes: ["metadata.read", "sign.domain-separated"],
      });
      currentIdentityId = identityId(result.identity) || currentIdentityId;
      await main();
    }

    async function previewProfileDocument() {
      const result = await window.CryptaPlatform.vault.identities.createProfileDocument(
        currentIdentityId,
        {
          displayName: "Local Profile",
          bio: "Mock profile preview",
          tags: ["local", "mock"],
        }
      );
      profileDocument.textContent = JSON.stringify(result.profileDocument || result, null, 2);
      status.textContent = `Prepared profile document for ${currentIdentityId}.`;
      status.className = "cr-status cr-status--success sample-status";
    }

    function render(target, values, fallback) {
      target.replaceChildren(...values.map((value) => {
        const item = document.createElement("li");
        const label = document.createElement("span");
        label.textContent = value.displayName || value.label || identityId(value) || fallback;
        const state = document.createElement("strong");
        state.textContent = value.status || value.kind || "mock";
        item.append(label, state);
        return item;
      }));
    }

    function firstIdentityId(values) {
      const first = values.find((value) => identityId(value));
      return first ? identityId(first) : "";
    }

    function identityId(value) {
      if (!value || typeof value !== "object") {
        return "";
      }
      return String(value.identityId || value.id || "").trim();
    }

    function showError(error) {
      status.textContent = window.CryptaPlatform.api.errorMessage(error);
      status.className = "cr-status cr-status--danger sample-status";
    }

    main().catch(showError);
    """
        .replace(APP_ID_PLACEHOLDER, appId);
  }

  private static String permissionSummary(List<String> permissions) {
    if (permissions.isEmpty()) {
      return "";
    }
    StringBuilder builder = new StringBuilder();
    builder
        .append("<section class=\"cr-permission-summary\" data-crypta-permission-summary>")
        .append('\n')
        .append("            <p><strong>Declared permissions</strong></p>")
        .append('\n')
        .append("            <ul>")
        .append('\n');
    for (String permission : permissions) {
      builder
          .append("              <li><code>")
          .append(escapeHtml(permission))
          .append("</code></li>")
          .append('\n');
    }
    builder.append("            </ul>").append('\n').append("          </section>");
    return builder.toString();
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
    crypta-app dev --bundle-dir . --port 0
    crypta-app test --bundle-dir . --strict
    crypta-app keys generate --key-id dev-local --private-key-file ../keys/dev-local-private.der --public-key-file ../keys/dev-local-public.der --trusted-keys-file ../keys/trusted-app-keys.properties
    crypta-app sign --bundle-dir . --key-id dev-local --private-key-file ../keys/dev-local-private.der
    crypta-app pack --bundle-dir . --output ../${APP_ID}-${APP_VERSION}.zip --overwrite
    crypta-app verify --bundle-dir . --trusted-keys-file ../keys/trusted-app-keys.properties
    ```

    Template: `${TEMPLATE}`.

    Third-party beta submissions should follow
    `docs/third-party-developer-beta-program.md` and
    `docs/third-party-app-submission-checklist.md` from the Crypta source tree before packaging.
    Keep permission rationales, sandbox notes, app-data schema notes, backup/restore notes, and
    security notes beside the bundle so `crypta-app submission create` can include their digests.

    Replace `bin/start.sh` with the production launcher before distributing the app.
    """
        .replace(APP_NAME_PLACEHOLDER, request.name())
        .replace(APP_ID_PLACEHOLDER, request.appId())
        .replace(APP_VERSION_PLACEHOLDER, request.version())
        .replace("${TEMPLATE}", request.templateKind().cliName());
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
   * in a separate step so command parsing can stay simple. Permission values are normalized to the
   * same lower-case form as the manifest parser; the parser still validates their syntax once
   * {@link #manifestContent()} has rendered the generated properties.
   *
   * @param directory target bundle directory to create or overwrite
   * @param appId manifest app identifier supplied by the developer
   * @param name human-readable app name written into the manifest and template UI
   * @param version app version string written into the manifest
   * @param uiMode requested UI template mode, defaulting to static when omitted
   * @param templateKind named static beta template to render
   * @param permissions manifest permissions requested for the generated app
   * @param overwrite whether an existing non-empty target directory may be reused
   */
  record ScaffoldRequest(
      Path directory,
      String appId,
      String name,
      String version,
      UiMode uiMode,
      AppTemplateKind templateKind,
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
      templateKind = Objects.requireNonNullElse(templateKind, AppTemplateKind.STATIC_BASIC);
      permissions = List.copyOf(Objects.requireNonNull(permissions, "permissions"));
    }

    /**
     * Returns a request with filesystem and manifest values normalized for rendering.
     *
     * <p>The directory becomes absolute and normalized, the app identifier is passed through the
     * production manifest normalizer, and name/version strings are trimmed. Permission values are
     * lower-cased, trimmed, and deduplicated in first-seen order so the generated manifest and
     * static disclosure use the same canonical identifiers.
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
          templateKind,
          normalizePermissions(templatePermissions(templateKind, permissions)),
          overwrite);
    }

    private static List<String> templatePermissions(
        AppTemplateKind templateKind, List<String> permissions) {
      LinkedHashSet<String> combined = new LinkedHashSet<>(templateKind.defaultPermissions());
      combined.addAll(permissions);
      return List.copyOf(combined);
    }

    /**
     * Normalizes permission spellings to the manifest parser's canonical comparison form.
     *
     * <p>The parser accepts case-insensitive permission identifiers and stores them lower-case.
     * Rendering the same normalized values into both {@code app.permissions} and the static
     * disclosure keeps a freshly scaffolded app strict-lint clean even when the CLI input used
     * mixed case. Invalid or blank values are intentionally preserved after trimming/lower-casing
     * so the production manifest parser still reports the canonical validation error for the
     * generated manifest.
     *
     * @param permissions CLI-supplied permission strings in request order
     * @return immutable normalized permission strings with duplicates removed in first-seen order
     */
    private static List<String> normalizePermissions(List<String> permissions) {
      LinkedHashSet<String> normalized = new LinkedHashSet<>();
      for (String permission : permissions) {
        normalized.add(permission.trim().toLowerCase(Locale.ROOT));
      }
      return List.copyOf(normalized);
    }

    private static ApiMetadataDefaults apiMetadataDefaults(List<String> permissions)
        throws AppDistributionException {
      PlatformApiContract contract = DevtoolsCapabilityVocabulary.currentValidationContract();
      Set<String> stableBaselineCapabilities = Set.copyOf(contract.stableBaseline().capabilities());
      Map<String, PlatformApiCapabilityDescriptor> capabilitiesByName =
          capabilitiesByName(contract);
      boolean usesNonBaselineAppFacingApi = false;
      for (String permission : permissions) {
        PlatformApiCapabilityDescriptor descriptor = capabilitiesByName.get(permission);
        if (descriptor == null) {
          continue;
        }
        if (descriptor.stability().isRestrictedAudience()) {
          throw new AppDistributionException(
              "permission "
                  + permission
                  + " is "
                  + descriptor.stability().jsonValue()
                  + " and cannot be used by third-party app scaffolds");
        }
        if (!stableBaselineCapabilities.contains(descriptor.name())) {
          usesNonBaselineAppFacingApi = true;
        }
      }
      return usesNonBaselineAppFacingApi
          ? new ApiMetadataDefaults("experimental", true)
          : new ApiMetadataDefaults("stable", false);
    }

    private static Map<String, PlatformApiCapabilityDescriptor> capabilitiesByName(
        PlatformApiContract contract) {
      LinkedHashMap<String, PlatformApiCapabilityDescriptor> byName = new LinkedHashMap<>();
      for (PlatformApiCapabilityDescriptor descriptor : contract.capabilities()) {
        byName.put(descriptor.name(), descriptor);
      }
      return Map.copyOf(byName);
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
    String manifestContent() throws AppDistributionException {
      StringBuilder builder = new StringBuilder();
      int currentContractVersion = PlatformApiContract.current().contractVersion();
      ApiMetadataDefaults apiMetadataDefaults = apiMetadataDefaults(permissions);
      int minimumContractVersion =
          apiMetadataDefaults.experimentalCapabilitiesAccepted()
              ? currentContractVersion
              : PlatformApiContract.current().stableBaseline().contractVersion();
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
          .append("api.minimumVersion=")
          .append(minimumContractVersion)
          .append('\n')
          .append("api.maximumTestedVersion=")
          .append(currentContractVersion)
          .append('\n')
          .append("api.targetStability=")
          .append(apiMetadataDefaults.targetStability())
          .append('\n');
      if ("stable".equals(apiMetadataDefaults.targetStability())) {
        builder
            .append("api.targetBaseline=")
            .append(AppApiCompatibilityMetadata.DEFAULT_STABLE_TARGET_BASELINE)
            .append('\n');
      }
      builder
          .append("api.experimentalCapabilitiesAccepted=")
          .append(apiMetadataDefaults.experimentalCapabilitiesAccepted())
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

  private record ApiMetadataDefaults(
      String targetStability, boolean experimentalCapabilitiesAccepted) {}
}
