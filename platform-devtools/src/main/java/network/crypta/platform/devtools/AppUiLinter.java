package network.crypta.platform.devtools;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;
import network.crypta.platform.appdist.AppBundleManifest;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppUiMode;
import network.crypta.platform.appui.AppUiContentTypes;
import network.crypta.platform.designsystem.DesignSystemAsset;
import network.crypta.platform.designsystem.DesignSystemAssets;

/**
 * Offline linter for staged static app-owned browser UI bundles.
 *
 * <p>The linter validates the parts of an app UI bundle that can be checked without a running
 * Crypta node or a browser automation dependency. It reads the bundle manifest, resolves the
 * manifest-declared static UI entry, inspects the HTML entry point, and scans local text files that
 * are either in the entry directory or referenced by the entry. The checks focus on high-value
 * failures: local-resource CSP compatibility, SDK bootstrap ordering, obvious credential naming,
 * design-system adoption, permission disclosure, and basic accessibility.
 *
 * <p>The implementation is intentionally conservative. It is a developer-facing safety net, not a
 * full HTML, CSS, or JavaScript parser. Findings use bundle-relative paths and stable ids so
 * command output, JSON reports, and release-certification evidence stay deterministic and do not
 * disclose absolute host paths or runtime secrets.
 */
final class AppUiLinter {
  /** Finding category for CSP and local-resource compatibility findings. */
  static final String CATEGORY_CSP = "csp";

  /** File extensions whose contents are safe and useful for lightweight text scanning. */
  private static final Set<String> TEXT_EXTENSIONS =
      Set.of("css", "html", "htm", "js", "json", "mjs", "svg", "txt");

  /** Finding category for canonical design-system adoption and integrity checks. */
  private static final String CATEGORY_DESIGN_SYSTEM = "design-system";

  /** Finding category for UI safety checks that protect app/session credential boundaries. */
  private static final String CATEGORY_SAFETY = "safety";

  /** Finding category for permission-disclosure consistency checks. */
  private static final String CATEGORY_PERMISSIONS = "permissions";

  /** Percent-encoding marker used by app-owned UI route paths. */
  private static final char PERCENT = '%';

  /** Pattern for direct Platform API calls that should normally go through the browser SDK. */
  private static final Pattern DIRECT_API_REFERENCE =
      Pattern.compile("(?s)(fetch\\s*\\(\\s*['\"]/?api/v1/|['\"]/?api/v1/)");

  /** Credential and launch-token spellings that should not appear in browser-owned UI files. */
  private static final List<String> FORBIDDEN_TEXT =
      List.of(
          "CRYPTAD_APP_TOKEN",
          "formPassword",
          "X-Crypta-Form-Password",
          "launchToken",
          "launch-token");

  /** Prevents construction because the linter exposes only stateless static helpers. */
  private AppUiLinter() {}

  /**
   * Runs offline UI lint checks for a staged app bundle.
   *
   * <p>Static bundles are inspected from their manifest-declared UI entry. Non-static UI modes are
   * returned as not applicable with a note instead of failing, which keeps explicit {@code ui lint}
   * and strict validation compatible with apps that intentionally have no app-owned static UI. When
   * {@code strict} is true, selected consistency and accessibility findings are promoted from
   * warnings to errors before they are returned.
   *
   * @param bundleDir staged app bundle directory containing {@code cryptad-app.properties}
   * @param strict whether strict-mode advisory findings should be reported as errors
   * @return deterministic lint result with bundle identity, applicability, and findings
   * @throws IOException if the manifest, static entry, canonical assets, or scanned files cannot be
   *     read
   */
  static AppUiLintResult lint(Path bundleDir, boolean strict) throws IOException {
    Path bundleRoot = bundleDir.toAbsolutePath().normalize();
    AppBundleManifest manifest =
        AppBundleManifestParser.parse(
            bundleRoot.resolve(AppBundleManifestParser.MANIFEST_FILE_NAME));
    List<AppUiLintFinding> findings = new ArrayList<>();
    if (manifest.uiMode() != AppUiMode.STATIC) {
      findings.add(
          finding(
              "ui-not-applicable",
              "ui",
              AppUiLintSeverity.NOTE,
              "UI lint applies only to app.ui.mode=static bundles.",
              ""));
      return new AppUiLintResult(
          manifest.appId(), manifest.uiMode().manifestValue(), false, findings);
    }

    Path entryRelativePath = manifest.staticUiEntryPath();
    String entryBundlePath = bundlePath(entryRelativePath);
    Path entry = bundleRoot.resolve(entryRelativePath).normalize();
    if (!entry.startsWith(bundleRoot) || !Files.isRegularFile(entry, LinkOption.NOFOLLOW_LINKS)) {
      findings.add(
          error(
              "static-entry-missing",
              "structure",
              "app.ui.entry does not resolve to a readable static UI file: " + manifest.uiEntry(),
              entryBundlePath));
      return new AppUiLintResult(manifest.appId(), "static", true, findings);
    }

    String indexHtml = Files.readString(entry, StandardCharsets.UTF_8);
    Path entryDirectory =
        entryRelativePath.getParent() == null ? Path.of("") : entryRelativePath.getParent();
    StaticHtmlInspector html =
        StaticHtmlInspector.inspect(indexHtml, entryBundlePath, entryDirectory);
    List<String> scriptSources = html.normalizedScriptSources();
    List<String> stylesheetHrefs = html.normalizedStylesheetHrefs();
    addDesignSystemFindings(bundleRoot, html, entryBundlePath, strict, findings);
    findings.addAll(html.safetyFindings());
    findings.addAll(html.accessibilityFindings(strict, designSystemCssPresent(bundleRoot)));
    findings.addAll(html.sdkFindings(strict));
    addLocalReferenceFindings(bundleRoot, scriptSources, "script", "text/javascript", findings);
    addLocalReferenceFindings(bundleRoot, stylesheetHrefs, "stylesheet", "text/css", findings);
    addPermissionFindings(manifest, html, entryBundlePath, strict, findings);
    Path scanRoot =
        entryDirectory.toString().isBlank() ? bundleRoot : bundleRoot.resolve(entryDirectory);
    addTextFileFindings(bundleRoot, scanRoot, scriptSources, strict, findings);
    addCssFindings(bundleRoot, scanRoot, stylesheetHrefs, strict, findings);
    return new AppUiLintResult(manifest.appId(), "static", true, findings);
  }

  /**
   * Adds findings for canonical design-system presence, integrity, load order, and class usage.
   *
   * <p>Asset byte checks compare staged files to the canonical resources published by {@link
   * DesignSystemAssets}. HTML link checks use already-normalized bundle-relative stylesheet paths,
   * so a manifest entry can live outside {@code static/index.html} while still loading the
   * canonical files from {@code static/crypta-ui/}.
   *
   * @param bundleRoot normalized absolute bundle root used for file reads
   * @param html inspected static UI entry point
   * @param entryBundlePath bundle-relative path to the inspected entry file
   * @param strict whether advisory design-system findings should become errors
   * @param findings mutable finding list that receives design-system findings
   * @throws IOException if canonical asset metadata or staged asset bytes cannot be read
   */
  private static void addDesignSystemFindings(
      Path bundleRoot,
      StaticHtmlInspector html,
      String entryBundlePath,
      boolean strict,
      List<AppUiLintFinding> findings)
      throws IOException {
    for (DesignSystemAsset asset : DesignSystemAssets.list()) {
      Path target = bundleRoot.resolve(asset.bundlePath());
      if (!Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS)) {
        findings.add(
            strictFinding(
                strict,
                "design-system-asset-missing",
                CATEGORY_DESIGN_SYSTEM,
                "Canonical design-system asset is missing: " + asset.bundlePath(),
                asset.bundlePath()));
        continue;
      }
      String actualDigest = sha256Hex(Files.readAllBytes(target));
      if (!actualDigest.equals(asset.sha256Hex())) {
        findings.add(
            strictFinding(
                strict,
                "design-system-asset-modified",
                CATEGORY_DESIGN_SYSTEM,
                "Canonical design-system asset bytes differ from the platform resource.",
                asset.bundlePath()));
      }
    }
    List<String> stylesheets = html.normalizedStylesheetHrefs();
    int tokensIndex = stylesheets.indexOf("static/crypta-ui/crypta-ui-tokens.css");
    int uiIndex = stylesheets.indexOf("static/crypta-ui/crypta-ui.css");
    int firstAppCss = firstAppStylesheet(stylesheets);
    if (tokensIndex < 0) {
      findings.add(
          strictFinding(
              strict,
              "design-system-tokens-not-linked",
              CATEGORY_DESIGN_SYSTEM,
              "index.html does not link crypta-ui-tokens.css.",
              entryBundlePath));
    }
    if (uiIndex < 0) {
      findings.add(
          strictFinding(
              strict,
              "design-system-css-not-linked",
              CATEGORY_DESIGN_SYSTEM,
              "index.html does not link crypta-ui.css.",
              entryBundlePath));
    }
    if (firstAppCss >= 0
        && ((tokensIndex >= 0 && tokensIndex > firstAppCss)
            || (uiIndex >= 0 && uiIndex > firstAppCss))) {
      findings.add(
          strictFinding(
              strict,
              "design-system-css-order",
              CATEGORY_DESIGN_SYSTEM,
              "Design-system stylesheets must load before app-specific stylesheets.",
              entryBundlePath));
    }
    if (!html.usesDesignSystemClass()) {
      findings.add(
          strictFinding(
              strict,
              "design-system-classes-unused",
              CATEGORY_DESIGN_SYSTEM,
              "App UI does not use stable cr-* design-system classes.",
              entryBundlePath));
    }
  }

  /**
   * Finds the first stylesheet that is not part of the canonical design system.
   *
   * @param stylesheets bundle-relative stylesheet paths in document load order
   * @return zero-based index of the first app-specific stylesheet, or {@code -1} when absent
   */
  private static int firstAppStylesheet(List<String> stylesheets) {
    for (int index = 0; index < stylesheets.size(); index++) {
      if (!stylesheets.get(index).startsWith("static/crypta-ui/")) {
        return index;
      }
    }
    return -1;
  }

  /**
   * Checks whether the canonical design-system CSS file exists in the bundle.
   *
   * <p>The accessibility pass uses this as a proxy for inherited focus-visible styling. It does not
   * validate asset bytes; integrity findings are produced separately by the design-system check.
   *
   * @param bundleRoot normalized absolute bundle root used for file reads
   * @return {@code true} when the canonical CSS path is a real regular file
   */
  private static boolean designSystemCssPresent(Path bundleRoot) {
    return Files.isRegularFile(
        bundleRoot.resolve("static/crypta-ui/crypta-ui.css"), LinkOption.NOFOLLOW_LINKS);
  }

  /**
   * Adds findings for permission disclosure consistency.
   *
   * <p>The check is intentionally offline. It compares the static HTML disclosure surface with the
   * manifest permission list and does not require Platform API access, live app state, or catalog
   * descriptor metadata.
   *
   * @param manifest parsed bundle manifest that provides declared permissions
   * @param html inspected static UI entry point
   * @param entryBundlePath bundle-relative path to the inspected entry file
   * @param strict whether advisory permission findings should become errors
   * @param findings mutable finding list that receives permission findings
   */
  private static void addPermissionFindings(
      AppBundleManifest manifest,
      StaticHtmlInspector html,
      String entryBundlePath,
      boolean strict,
      List<AppUiLintFinding> findings) {
    if (!manifest.permissions().isEmpty() && !html.hasPermissionDisclosure()) {
      findings.add(
          strictFinding(
              strict,
              "permission-disclosure-missing",
              CATEGORY_PERMISSIONS,
              "App declares permissions but the UI has no visible permission disclosure section.",
              entryBundlePath));
    }
    Set<String> mentionedPermissions = html.mentionedPermissionsInDisclosure();
    if (!manifest.permissions().isEmpty() && html.hasPermissionDisclosure()) {
      for (String declaredPermission : manifest.permissions()) {
        if (!mentionedPermissions.contains(declaredPermission)) {
          findings.add(
              strictFinding(
                  strict,
                  "permission-disclosure-missing-permission",
                  CATEGORY_PERMISSIONS,
                  "Permission disclosure omits declared permission: " + declaredPermission,
                  entryBundlePath));
        }
      }
    }
    for (String mentionedPermission : mentionedPermissions) {
      if (!manifest.permissions().contains(mentionedPermission)) {
        findings.add(
            strictFinding(
                strict,
                "permission-disclosure-undeclared-permission",
                CATEGORY_PERMISSIONS,
                "Permission disclosure mentions undeclared permission: " + mentionedPermission,
                entryBundlePath));
      }
    }
  }

  /**
   * Scans local UI text files for forbidden token names, storage writes, and JavaScript hazards.
   *
   * <p>The scan covers regular text files under the static entry directory and local files
   * referenced by loaded script tags. Bootstrap usage is counted only for loaded local app scripts,
   * which prevents unrelated helper files or the browser SDK itself from satisfying the SDK
   * bootstrap requirement.
   *
   * @param bundleRoot normalized absolute bundle root used to relativize findings
   * @param scanRoot directory that contains the manifest-declared static entry
   * @param loadedScripts bundle-relative script references loaded by the static entry
   * @param strict whether advisory JavaScript findings should become errors
   * @param findings mutable finding list that receives text and JavaScript findings
   * @throws IOException if a candidate text file cannot be read
   */
  private static void addTextFileFindings(
      Path bundleRoot,
      Path scanRoot,
      List<String> loadedScripts,
      boolean strict,
      List<AppUiLintFinding> findings)
      throws IOException {
    List<String> loadedScriptAssetPaths = localRouteAssetPaths(loadedScripts);
    ScriptScanResult scriptScan = ScriptScanResult.NONE;
    for (Path file : uiTextFiles(bundleRoot, scanRoot, loadedScripts)) {
      scriptScan =
          scriptScan.merge(
              scanTextFile(bundleRoot, loadedScriptAssetPaths, strict, findings, file));
    }
    addBootstrapMissingFindingIfNeeded(loadedScriptAssetPaths, strict, findings, scriptScan);
  }

  /**
   * Scans one local UI text file and reports any loaded app-script state it contributes.
   *
   * @param bundleRoot normalized absolute bundle root used to relativize findings
   * @param loadedScripts decoded bundle-relative script asset paths loaded by the static entry
   * @param strict whether advisory JavaScript findings should become errors
   * @param findings mutable finding list that receives text and JavaScript findings
   * @param file candidate regular file found during UI scanning
   * @return app-script and bootstrap observations from this file
   * @throws IOException if the candidate text file cannot be read
   */
  private static ScriptScanResult scanTextFile(
      Path bundleRoot,
      List<String> loadedScripts,
      boolean strict,
      List<AppUiLintFinding> findings,
      Path file)
      throws IOException {
    if (!isTextFile(file)) {
      return ScriptScanResult.NONE;
    }
    String path = relativePath(bundleRoot, file);
    String text = Files.readString(file, StandardCharsets.UTF_8);
    addForbiddenTextFindings(findings, path, text);
    addPersistentStorageFinding(findings, path, text);
    if (!isJavaScript(file)) {
      return ScriptScanResult.NONE;
    }
    return scanJavaScriptFile(bundleRoot, loadedScripts, strict, findings, file, path, text);
  }

  /**
   * Adds findings for forbidden token and form-password spellings in browser UI files.
   *
   * @param findings mutable finding list that receives forbidden-text findings
   * @param path bundle-relative path to the file being scanned
   * @param text file contents decoded as UTF-8 text
   */
  private static void addForbiddenTextFindings(
      List<AppUiLintFinding> findings, String path, String text) {
    for (String forbidden : FORBIDDEN_TEXT) {
      if (text.contains(forbidden)) {
        findings.add(
            error(
                "forbidden-token-text",
                CATEGORY_SAFETY,
                "App UI files must not reference " + forbidden + ".",
                path));
      }
    }
  }

  /**
   * Adds a finding when browser storage writes may persist credential material.
   *
   * @param findings mutable finding list that receives storage findings
   * @param path bundle-relative path to the file being scanned
   * @param text file contents decoded as UTF-8 text
   */
  private static void addPersistentStorageFinding(
      List<AppUiLintFinding> findings, String path, String text) {
    if (text.contains("localStorage.setItem") || text.contains("sessionStorage.setItem")) {
      findings.add(
          error(
              "persistent-browser-storage",
              CATEGORY_SAFETY,
              "App UI must not persist app or session credential material in browser storage.",
              path));
    }
  }

  /**
   * Scans one JavaScript file and reports whether it is a loaded app script with SDK bootstrap.
   *
   * @param bundleRoot normalized absolute bundle root used to classify loaded scripts
   * @param loadedScripts decoded bundle-relative script asset paths loaded by the static entry
   * @param strict whether advisory JavaScript findings should become errors
   * @param findings mutable finding list that receives JavaScript findings
   * @param file candidate JavaScript file
   * @param path bundle-relative path to the file being scanned
   * @param text script contents decoded as UTF-8 text
   * @return app-script and bootstrap observations from this script
   */
  private static ScriptScanResult scanJavaScriptFile(
      Path bundleRoot,
      List<String> loadedScripts,
      boolean strict,
      List<AppUiLintFinding> findings,
      Path file,
      String path,
      String text) {
    String bundlePath = relativePath(bundleRoot, file);
    boolean loadedAppScript = loadedScripts.contains(bundlePath) && isAppScript(bundlePath);
    addJavaScriptFindings(strict, findings, path, text);
    return new ScriptScanResult(
        loadedAppScript, loadedAppScript && text.contains(".bootstrap.load"));
  }

  /**
   * Adds the SDK bootstrap finding after all local app scripts have been scanned.
   *
   * @param loadedScripts decoded bundle-relative script asset paths loaded by the static entry
   * @param strict whether the bootstrap finding should be warning or error severity
   * @param findings mutable finding list that receives the bootstrap finding
   * @param scriptScan aggregate app-script and bootstrap observations
   */
  private static void addBootstrapMissingFindingIfNeeded(
      List<String> loadedScripts,
      boolean strict,
      List<AppUiLintFinding> findings,
      ScriptScanResult scriptScan) {
    if (scriptScan.appJavaScriptFound() && !scriptScan.bootstrapUsageFound()) {
      String findingPath =
          loadedScripts.stream().filter(AppUiLinter::isAppScript).findFirst().orElse("");
      findings.add(
          strictFinding(
              strict,
              "sdk-bootstrap-missing",
              "sdk",
              "Local app JavaScript does not call CryptaPlatform.bootstrap.load(...).",
              findingPath));
    }
  }

  /**
   * Converts loaded HTML references to route-decoded bundle asset paths.
   *
   * <p>HTML inspection keeps reference text in URL form so local-reference findings can point at
   * the source attribute. JavaScript scanning compares against filesystem paths discovered during
   * the bundle walk, so it needs the route-decoded asset path that the runtime resolver would use.
   *
   * @param referencedPaths bundle-relative URL references loaded by the static entry
   * @return decoded route-safe asset paths in first-seen order
   */
  private static List<String> localRouteAssetPaths(Collection<String> referencedPaths) {
    LinkedHashSet<String> assetPaths = new LinkedHashSet<>();
    for (String referencedPath : referencedPaths) {
      String assetPath = localRouteAssetPath(referencedPath);
      if (!assetPath.isBlank()) {
        assetPaths.add(assetPath);
      }
    }
    return List.copyOf(assetPaths);
  }

  /**
   * Adds JavaScript-specific findings for one local script file.
   *
   * <p>The scanner looks for simple high-signal patterns rather than attempting to parse
   * JavaScript. Direct API references are strict-mode configurable because the browser SDK remains
   * the preferred path for app browser sessions, while dynamic evaluation is always an error under
   * app-owned UI CSP expectations.
   *
   * @param strict whether direct Platform API references should be warnings or errors
   * @param findings mutable finding list that receives JavaScript findings
   * @param path bundle-relative path to the script being scanned
   * @param text script contents decoded as UTF-8 text
   */
  private static void addJavaScriptFindings(
      boolean strict, List<AppUiLintFinding> findings, String path, String text) {
    if (text.contains("eval(") || text.contains("new Function(")) {
      findings.add(
          error(
              "dynamic-code-evaluation",
              CATEGORY_SAFETY,
              "Local JavaScript must not use eval() or new Function().",
              path));
    }
    if (!isSdkScript(path) && DIRECT_API_REFERENCE.matcher(text).find()) {
      findings.add(
          strictFinding(
              strict,
              "direct-platform-api-reference",
              "sdk",
              "Local app JavaScript references /api/v1/ directly; use the browser SDK helpers.",
              path));
    }
  }

  /**
   * Adds errors for local script and stylesheet references that cannot load at runtime.
   *
   * <p>HTML inspection already reports remote, absolute, and traversal-shaped resource references
   * as CSP/safety findings. This check handles the remaining local-resource contract: every local
   * entry-point script or stylesheet that the browser will try to load must resolve to a regular
   * file inside the staged bundle and must use the same executable/applicable MIME mapping as the
   * app-owned UI server. Missing files and unsupported content types are reported before the
   * JavaScript and CSS scans so strict validation cannot pass an app UI whose SDK, app script, or
   * stylesheet was omitted or will be served as opaque bytes under {@code nosniff}.
   *
   * @param bundleRoot normalized absolute bundle root
   * @param referencedPaths normalized bundle-relative paths referenced by the static entry
   * @param referenceKind human-readable resource kind for the finding message
   * @param requiredContentTypePrefix content-type prefix required for this reference kind
   * @param findings mutable finding list that receives local-reference errors
   */
  private static void addLocalReferenceFindings(
      Path bundleRoot,
      Collection<String> referencedPaths,
      String referenceKind,
      String requiredContentTypePrefix,
      List<AppUiLintFinding> findings) {
    LinkedHashSet<String> checkedPaths = new LinkedHashSet<>();
    for (String referencedPath : referencedPaths) {
      if (isLocalReferenceCandidate(referencedPath) && checkedPaths.add(referencedPath)) {
        String routeAssetPath = localRouteAssetPath(referencedPath);
        if (routeAssetPath.isBlank()) {
          findings.add(
              error(
                  "local-ui-reference-route-invalid",
                  CATEGORY_CSP,
                  "Local "
                      + referenceKind
                      + " reference is not a valid app UI route asset path: "
                      + referencedPath,
                  referencedPath));
        } else {
          Path file = bundleRoot.resolve(routeAssetPath).normalize();
          if (!file.startsWith(bundleRoot)
              || !Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
            findings.add(
                error(
                    "local-ui-reference-missing",
                    CATEGORY_CSP,
                    "Local "
                        + referenceKind
                        + " reference does not resolve to a regular file: "
                        + routeAssetPath,
                    referencedPath));
          } else {
            addUnsupportedLocalReferenceFindingIfNeeded(
                routeAssetPath, referenceKind, requiredContentTypePrefix, findings);
          }
        }
      }
    }
  }

  /**
   * Resolves one local HTML reference using the app-owned UI route segment rules.
   *
   * <p>The linter starts from bundle-relative paths after HTML URL resolution, then applies the
   * same asset-segment contract as the installed app UI route: percent-decoding happens before
   * segment validation, and decoded traversal, embedded separators, drive-letter syntax, blank
   * segments, control characters, and malformed percent escapes are rejected. The returned path is
   * the decoded bundle asset path that the runtime resolver would receive.
   *
   * @param referencedPath normalized bundle-relative reference from the static entry
   * @return the route-safe asset path, or an empty string when the route parser would reject it
   */
  private static String localRouteAssetPath(String referencedPath) {
    if (referencedPath.isBlank() || referencedPath.startsWith("/")) {
      return "";
    }
    String[] rawSegments = referencedPath.split("/", -1);
    boolean trailingSlash = rawSegments.length > 1 && rawSegments[rawSegments.length - 1].isEmpty();
    int segmentCount = trailingSlash ? rawSegments.length - 1 : rawSegments.length;
    List<String> decodedSegments = new ArrayList<>(segmentCount);
    for (int index = 0; index < segmentCount; index++) {
      String segment = decodedRouteSegment(rawSegments[index]);
      if (!isRouteSafeAssetSegment(segment)) {
        return "";
      }
      decodedSegments.add(segment);
    }
    return String.join("/", decodedSegments);
  }

  /**
   * Decodes one raw route segment using the app UI route's percent-encoding rules.
   *
   * @param rawSegment raw segment from a browser URL path
   * @return decoded UTF-8 segment, or an empty string when the encoding is malformed
   */
  private static String decodedRouteSegment(String rawSegment) {
    if (rawSegment.isEmpty()) {
      return "";
    }
    ByteArrayOutputStream bytes = new ByteArrayOutputStream(rawSegment.length());
    int index = 0;
    while (index < rawSegment.length()) {
      char character = rawSegment.charAt(index);
      if (character == PERCENT) {
        int high = hexDigit(rawSegment, index + 1);
        int low = hexDigit(rawSegment, index + 2);
        if (high < 0 || low < 0) {
          return "";
        }
        bytes.write((high << 4) + low);
        index += 3;
      } else if (character > 0x7F) {
        bytes.writeBytes(Character.toString(character).getBytes(StandardCharsets.UTF_8));
        index++;
      } else {
        bytes.write((byte) character);
        index++;
      }
    }
    return bytes.toString(StandardCharsets.UTF_8);
  }

  /**
   * Reads one hexadecimal percent-escape digit.
   *
   * @param rawSegment raw segment that contains the percent escape
   * @param index character index to read
   * @return decoded digit value, or {@code -1} when the escape is incomplete or invalid
   */
  private static int hexDigit(String rawSegment, int index) {
    return index >= rawSegment.length() ? -1 : Character.digit(rawSegment.charAt(index), 16);
  }

  /**
   * Checks one decoded app UI asset path segment against the runtime route denylist.
   *
   * @param segment decoded path segment
   * @return {@code true} when the segment is safe to pass to bundle-relative resolution
   */
  private static boolean isRouteSafeAssetSegment(String segment) {
    if (segment.isBlank()
        || segment.equals(".")
        || segment.equals("..")
        || segment.indexOf('/') >= 0
        || segment.indexOf('\\') >= 0
        || segment.indexOf(':') >= 0
        || segment.indexOf('\0') >= 0) {
      return false;
    }
    for (int index = 0; index < segment.length(); index++) {
      if (Character.isISOControl(segment.charAt(index))) {
        return false;
      }
    }
    return true;
  }

  /**
   * Adds an error when a local entry reference resolves but will be served with the wrong MIME
   * type.
   *
   * <p>The app UI runtime sends {@code X-Content-Type-Options: nosniff}; a script or stylesheet
   * that maps to {@link AppUiContentTypes#OCTET_STREAM} exists on disk but still will not execute
   * or apply in the browser. Keeping this check tied to {@link AppUiContentTypes} avoids a linter
   * allowlist that drifts from the server-side static asset behavior.
   *
   * @param referencedPath normalized bundle-relative path referenced by the static entry
   * @param referenceKind human-readable resource kind for the finding message
   * @param requiredContentTypePrefix content-type prefix required for this reference kind
   * @param findings mutable finding list that receives unsupported-type errors
   */
  private static void addUnsupportedLocalReferenceFindingIfNeeded(
      String referencedPath,
      String referenceKind,
      String requiredContentTypePrefix,
      List<AppUiLintFinding> findings) {
    String contentType = AppUiContentTypes.forPath(referencedPath);
    if (!contentType.startsWith(requiredContentTypePrefix)) {
      findings.add(
          error(
              "local-ui-reference-unsupported-type",
              CATEGORY_CSP,
              "Local "
                  + referenceKind
                  + " reference uses unsupported app UI content type "
                  + contentType
                  + ": "
                  + referencedPath,
              referencedPath));
    }
  }

  /**
   * Scans local CSS files for import patterns that are incompatible with app-owned UI CSP.
   *
   * <p>The scan includes files in the entry directory and local stylesheets referenced by the
   * entry. Remote imports are always fatal; non-normalized local imports follow the current
   * strict-mode policy implemented by {@link StaticCssInspector}.
   *
   * @param bundleRoot normalized absolute bundle root used to relativize findings
   * @param scanRoot directory that contains the manifest-declared static entry
   * @param stylesheetHrefs bundle-relative stylesheet paths loaded by the static entry
   * @param strict whether advisory CSS findings should become errors
   * @param findings mutable finding list that receives CSS findings
   * @throws IOException if a candidate CSS file cannot be read
   */
  private static void addCssFindings(
      Path bundleRoot,
      Path scanRoot,
      List<String> stylesheetHrefs,
      boolean strict,
      List<AppUiLintFinding> findings)
      throws IOException {
    for (Path file : uiTextFiles(bundleRoot, scanRoot, stylesheetHrefs)) {
      if (!extension(file).equals("css")) {
        continue;
      }
      findings.addAll(
          StaticCssInspector.inspect(
              Files.readString(file, StandardCharsets.UTF_8),
              relativePath(bundleRoot, file),
              strict));
    }
  }

  /**
   * Builds the deterministic set of local text files considered by a static UI scan.
   *
   * <p>The entry directory walk catches app-owned HTML, CSS, and JavaScript next to the manifest
   * entry. The referenced-path pass adds local assets loaded from elsewhere in the bundle, such as
   * the SDK under {@code static/crypta-platform.js} when the entry lives under {@code ui/}. Remote,
   * absolute, and traversal-shaped references are ignored because they are handled by HTML/CSP
   * checks and must not be resolved against the host filesystem.
   *
   * @param bundleRoot normalized absolute bundle root
   * @param scanRoot directory walked for local UI text files
   * @param referencedPaths normalized bundle-relative paths referenced by the entry
   * @return immutable list of regular files in deterministic scan order
   * @throws IOException if the entry-directory walk cannot be completed
   */
  private static List<Path> uiTextFiles(
      Path bundleRoot, Path scanRoot, Collection<String> referencedPaths) throws IOException {
    LinkedHashSet<Path> files = new LinkedHashSet<>();
    if (Files.isDirectory(scanRoot, LinkOption.NOFOLLOW_LINKS)) {
      try (var stream = Files.walk(scanRoot)) {
        stream
            .filter(file -> Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
            .sorted()
            .forEach(files::add);
      }
    }
    for (String referencedPath : referencedPaths) {
      String routeAssetPath = localRouteAssetPath(referencedPath);
      if (!routeAssetPath.isBlank()) {
        Path file = bundleRoot.resolve(routeAssetPath).normalize();
        if (file.startsWith(bundleRoot) && Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS)) {
          files.add(file);
        }
      }
    }
    return List.copyOf(files);
  }

  /**
   * Checks whether a file extension is part of the lightweight text scan allow-list.
   *
   * @param file candidate regular file found during UI scanning
   * @return {@code true} when the file extension is scanned as UTF-8 text
   */
  private static boolean isTextFile(Path file) {
    return TEXT_EXTENSIONS.contains(extension(file));
  }

  /**
   * Checks whether a file extension represents local JavaScript.
   *
   * @param file candidate regular file found during UI scanning
   * @return {@code true} for {@code .js} and {@code .mjs} files
   */
  private static boolean isJavaScript(Path file) {
    String extension = extension(file);
    return extension.equals("js") || extension.equals("mjs");
  }

  /**
   * Classifies a loaded script path as app-owned JavaScript.
   *
   * <p>The SDK and design-system support files are excluded because they should not satisfy app
   * bootstrap requirements or trigger direct app-script ordering checks. The input must already be
   * normalized to a bundle-relative path.
   *
   * @param scriptPath normalized script path from the static entry
   * @return {@code true} when the path refers to a local app script
   */
  static boolean isAppScript(String scriptPath) {
    String routeAssetPath = localRouteAssetPath(scriptPath);
    return !routeAssetPath.isBlank()
        && !isSdkAssetPath(routeAssetPath)
        && !routeAssetPath.startsWith("static/crypta-ui/");
  }

  /**
   * Classifies a loaded script path as the browser SDK.
   *
   * @param scriptPath normalized script path from the static entry
   * @return {@code true} when the local bundle path ends in {@code crypta-platform.js}
   */
  static boolean isSdkScript(String scriptPath) {
    return isSdkAssetPath(localRouteAssetPath(scriptPath));
  }

  /**
   * Checks whether a route-normalized script path names the browser SDK.
   *
   * @param assetPath decoded bundle-relative asset path produced by {@link #localRouteAssetPath}
   * @return {@code true} when the final path segment is {@code crypta-platform.js}
   */
  private static boolean isSdkAssetPath(String assetPath) {
    return !assetPath.isBlank() && fileName(assetPath).equals("crypta-platform.js");
  }

  /**
   * Checks whether a normalized reference should be resolved against the app bundle.
   *
   * @param path candidate bundle-relative reference
   * @return {@code true} for references that are not remote, absolute, or JavaScript URLs
   */
  private static boolean isLocalReferenceCandidate(String path) {
    String normalized = path.toLowerCase(Locale.ROOT);
    return !normalized.isBlank()
        && !normalized.startsWith("http://")
        && !normalized.startsWith("https://")
        && !normalized.startsWith("//")
        && !normalized.startsWith("/")
        && !normalized.startsWith("javascript:");
  }

  /**
   * Extracts the last path segment from a normalized bundle path.
   *
   * @param bundlePath normalized bundle-relative path using either slash style
   * @return file name portion after the last slash, or the full value when no slash is present
   */
  private static String fileName(String bundlePath) {
    String normalized = bundlePath.replace('\\', '/');
    int separator = normalized.lastIndexOf('/');
    return separator < 0 ? normalized : normalized.substring(separator + 1);
  }

  /**
   * Extracts a lowercase filename extension.
   *
   * @param file candidate file path
   * @return extension without the dot, or an empty string when the filename has no extension
   */
  private static String extension(Path file) {
    String name = file.getFileName().toString();
    int index = name.lastIndexOf('.');
    return index < 0 ? "" : name.substring(index + 1).toLowerCase(Locale.ROOT);
  }

  /**
   * Creates a fatal lint finding.
   *
   * @param id stable finding id
   * @param category finding category used by CLI and JSON output
   * @param message human-readable diagnostic text
   * @param relativePath bundle-relative path associated with the finding
   * @return immutable error-severity finding
   */
  private static AppUiLintFinding error(
      String id, String category, String message, String relativePath) {
    return finding(id, category, AppUiLintSeverity.ERROR, message, relativePath);
  }

  /**
   * Creates a finding whose severity depends on strict mode.
   *
   * @param strict whether the finding should be promoted to error severity
   * @param id stable finding id
   * @param category finding category used by CLI and JSON output
   * @param message human-readable diagnostic text
   * @param relativePath bundle-relative path associated with the finding
   * @return immutable finding with warning or error severity
   */
  static AppUiLintFinding strictFinding(
      boolean strict, String id, String category, String message, String relativePath) {
    return finding(
        id,
        category,
        strict ? AppUiLintSeverity.ERROR : AppUiLintSeverity.WARNING,
        message,
        relativePath);
  }

  /**
   * Creates an advisory CSP lint finding.
   *
   * @param id stable finding id
   * @param message human-readable diagnostic text
   * @param relativePath bundle-relative path associated with the finding
   * @return immutable warning-severity finding
   */
  static AppUiLintFinding cspWarning(String id, String message, String relativePath) {
    return finding(id, CATEGORY_CSP, AppUiLintSeverity.WARNING, message, relativePath);
  }

  /**
   * Creates a lint finding with an explicit effective severity.
   *
   * @param id stable finding id
   * @param category finding category used by CLI and JSON output
   * @param severity effective finding severity for the current command mode
   * @param message human-readable diagnostic text
   * @param relativePath bundle-relative path associated with the finding
   * @return immutable lint finding
   */
  private static AppUiLintFinding finding(
      String id, String category, AppUiLintSeverity severity, String message, String relativePath) {
    return new AppUiLintFinding(id, category, severity, message, relativePath);
  }

  /**
   * Converts a filesystem path to a report-safe bundle-relative path when possible.
   *
   * @param bundleRoot normalized absolute bundle root
   * @param file file path being reported
   * @return forward-slash relative path under the bundle, or the filename for out-of-tree paths
   */
  private static String relativePath(Path bundleRoot, Path file) {
    Path normalizedRoot = bundleRoot.toAbsolutePath().normalize();
    Path normalizedFile = file.toAbsolutePath().normalize();
    if (normalizedFile.startsWith(normalizedRoot)) {
      return normalizedRoot.relativize(normalizedFile).toString().replace('\\', '/');
    }
    return file.getFileName().toString();
  }

  /**
   * Converts a manifest-relative path to a forward-slash bundle path.
   *
   * @param relativePath manifest-provided relative path after appdist normalization
   * @return normalized bundle-relative path suitable for reports
   */
  private static String bundlePath(Path relativePath) {
    return relativePath.normalize().toString().replace('\\', '/');
  }

  /**
   * Computes a lowercase SHA-256 digest for canonical asset comparison.
   *
   * @param bytes bytes read from a staged or classpath asset
   * @return lowercase hexadecimal SHA-256 digest
   */
  private static String sha256Hex(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is not available", exception);
    }
  }

  /**
   * Aggregated app-script observations from the local text-file scan.
   *
   * @param appJavaScriptFound whether a loaded local app script was found
   * @param bootstrapUsageFound whether such a script calls {@code CryptaPlatform.bootstrap.load}
   */
  private record ScriptScanResult(boolean appJavaScriptFound, boolean bootstrapUsageFound) {
    /** Empty scan result used for non-text and non-JavaScript files. */
    private static final ScriptScanResult NONE = new ScriptScanResult(false, false);

    /**
     * Merges this result with another file's observations.
     *
     * @param other observations from another scanned file
     * @return combined observations across both inputs
     */
    private ScriptScanResult merge(ScriptScanResult other) {
      return new ScriptScanResult(
          appJavaScriptFound || other.appJavaScriptFound,
          bootstrapUsageFound || other.bootstrapUsageFound);
    }
  }
}
