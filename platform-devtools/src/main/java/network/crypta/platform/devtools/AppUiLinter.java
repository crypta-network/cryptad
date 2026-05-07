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
 * failures: local-resource CSP compatibility, SDK bootstrap ordering, route-safe local references,
 * obvious credential naming, design-system adoption, permission disclosure, and basic
 * accessibility.
 *
 * <p>The implementation is intentionally conservative. It is a developer-facing safety net, not a
 * full HTML, CSS, or JavaScript parser. Findings use bundle-relative paths and stable ids so
 * command output, JSON reports, and release-certification evidence stay deterministic and do not
 * disclose absolute host paths or runtime secrets.
 *
 * <p>The scan follows the same security boundary as app-owned static UI routes: files must stay
 * under the staged bundle, symlinked parents are not trusted, local scripts and stylesheets must
 * map to content types the app UI server will actually serve, and remote code is never treated as a
 * fallback for missing local assets. Those checks make strict validation useful before signing or
 * cataloging a bundle while keeping non-static app modes explicitly not applicable.
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

  /** Content-type prefix required for the manifest-declared static UI document. */
  private static final String HTML_CONTENT_TYPE_PREFIX = "text/html";

  /** Manifest value for app-owned static UI mode in result summaries. */
  private static final String STATIC_UI_MODE = "static";

  /** Canonical design-system token stylesheet path inside static app bundles. */
  private static final String DESIGN_SYSTEM_TOKENS_CSS =
      DesignSystemAssets.BUNDLE_DIRECTORY + "/crypta-ui-tokens.css";

  /** Canonical design-system base stylesheet path inside static app bundles. */
  private static final String DESIGN_SYSTEM_CSS =
      DesignSystemAssets.BUNDLE_DIRECTORY + "/crypta-ui.css";

  /** Optional canonical design-system progressive-enhancement script path. */
  private static final String DESIGN_SYSTEM_COMPONENTS_JS =
      DesignSystemAssets.BUNDLE_DIRECTORY + "/crypta-ui-components.js";

  /** Canonical design-system stylesheet paths that are exempt from app-CSS ordering checks. */
  private static final Set<String> CANONICAL_DESIGN_SYSTEM_STYLESHEETS =
      Set.of(DESIGN_SYSTEM_TOKENS_CSS, DESIGN_SYSTEM_CSS);

  /** Canonical design-system script paths that are not considered app bootstrap scripts. */
  private static final Set<String> CANONICAL_DESIGN_SYSTEM_SCRIPTS =
      Set.of(DESIGN_SYSTEM_COMPONENTS_JS);

  /** Common prefix for local script and stylesheet reference diagnostics. */
  private static final String LOCAL_REFERENCE_MESSAGE_PREFIX = "Local ";

  /** Percent-encoding marker used by app-owned UI route paths. */
  private static final char PERCENT = '%';

  /** Pattern for direct Platform API calls that should normally go through the browser SDK. */
  private static final Pattern DIRECT_API_REFERENCE =
      Pattern.compile("(?s)(fetch\\s*\\(\\s*['\"]/?api/v1/|['\"]/?api/v1/)");

  /** JavaScript property name for the SDK bootstrap namespace. */
  private static final String BOOTSTRAP_PROPERTY = "bootstrap";

  /** JavaScript method name for the SDK bootstrap loader. */
  private static final String LOAD_METHOD = "load";

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
   * <p>The method performs all checks against staged bundle files and canonical classpath
   * resources. It does not fetch remote URLs, execute scripts, open a browser, or inspect live
   * Platform API state. If a referenced local resource is missing or route-invalid, the linter
   * reports that failure and avoids resolving the value through host filesystem semantics.
   *
   * @param bundleDir staged app bundle directory containing {@code cryptad-app.properties} and any
   *     app-owned UI files
   * @param strict whether strict-mode advisory findings should be promoted to error severity before
   *     reporting
   * @return deterministic lint result with bundle identity, applicability, and sanitized findings
   * @throws IOException if the manifest, static entry, canonical assets, or scanned bundle-local
   *     files cannot be read
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
    if (!isBundleLocalRegularFile(bundleRoot, entry)) {
      findings.add(
          error(
              "static-entry-missing",
              "structure",
              "app.ui.entry does not resolve to a readable static UI file: " + manifest.uiEntry(),
              entryBundlePath));
      return new AppUiLintResult(manifest.appId(), STATIC_UI_MODE, true, findings);
    }
    String entryContentType = AppUiContentTypes.forPath(entryBundlePath);
    if (!entryContentType.startsWith(HTML_CONTENT_TYPE_PREFIX)) {
      findings.add(
          error(
              "static-entry-non-html",
              "structure",
              "app.ui.entry must resolve to an HTML document served as text/html, but maps to "
                  + entryContentType
                  + ": "
                  + manifest.uiEntry(),
              entryBundlePath));
      return new AppUiLintResult(manifest.appId(), STATIC_UI_MODE, true, findings);
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
    return new AppUiLintResult(manifest.appId(), STATIC_UI_MODE, true, findings);
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
      if (!isBundleLocalRegularFile(bundleRoot, target)) {
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
    int tokensIndex = stylesheets.indexOf(DESIGN_SYSTEM_TOKENS_CSS);
    int uiIndex = stylesheets.indexOf(DESIGN_SYSTEM_CSS);
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
    if ((firstAppCss >= 0 && (tokensIndex > firstAppCss || uiIndex > firstAppCss))
        || (uiIndex >= 0 && tokensIndex > uiIndex)) {
      findings.add(
          strictFinding(
              strict,
              "design-system-css-order",
              CATEGORY_DESIGN_SYSTEM,
              "Design-system tokens must load before base styles, and both before app-specific"
                  + " stylesheets.",
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
      if (!CANONICAL_DESIGN_SYSTEM_STYLESHEETS.contains(stylesheets.get(index))) {
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
    return isBundleLocalRegularFile(bundleRoot, bundleRoot.resolve(DESIGN_SYSTEM_CSS));
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
        loadedAppScript, loadedAppScript && containsBootstrapLoadCall(text));
  }

  /**
   * Checks loaded app JavaScript for a real SDK bootstrap member call.
   *
   * <p>Comments and string literals are blanked before matching so notes such as {@code TODO
   * .bootstrap.load} or examples embedded in strings do not satisfy strict UI lint. The matcher
   * still accepts common aliases such as {@code platform.bootstrap.load(...)} because the generated
   * scaffold stores {@code window.CryptaPlatform} in a local variable before loading bootstrap
   * data. The member-chain check is implemented as a linear scan instead of a regular expression so
   * very large generated scripts cannot trigger regex recursion or backtracking limits.
   *
   * @param text JavaScript source decoded as UTF-8
   * @return {@code true} when executable-looking code calls a {@code bootstrap.load(...)} member
   */
  private static boolean containsBootstrapLoadCall(String text) {
    String stripped = stripJavaScriptCommentsAndStrings(text);
    int bootstrapIndex = stripped.indexOf(BOOTSTRAP_PROPERTY);
    while (bootstrapIndex >= 0) {
      if (isBootstrapLoadCallAt(stripped, bootstrapIndex)) {
        return true;
      }
      bootstrapIndex = stripped.indexOf(BOOTSTRAP_PROPERTY, bootstrapIndex + 1);
    }
    return false;
  }

  /**
   * Checks one {@code bootstrap} token candidate for a receiver-backed {@code .load(...)} call.
   *
   * @param text JavaScript source with comments and strings already blanked
   * @param bootstrapIndex offset of a candidate {@code bootstrap} token
   * @return {@code true} when the candidate is part of {@code receiver.bootstrap.load(...)}
   */
  private static boolean isBootstrapLoadCallAt(String text, int bootstrapIndex) {
    return hasIdentifierBoundaries(text, bootstrapIndex, BOOTSTRAP_PROPERTY.length())
        && hasReceiverMemberAccessBefore(text, bootstrapIndex)
        && hasLoadCallAfterBootstrap(text, bootstrapIndex + BOOTSTRAP_PROPERTY.length());
  }

  /**
   * Checks whether a token is bounded by non-identifier characters.
   *
   * @param text JavaScript source being scanned
   * @param start token start offset
   * @param length token length in characters
   * @return {@code true} when adjacent characters cannot extend the identifier token
   */
  private static boolean hasIdentifierBoundaries(String text, int start, int length) {
    int end = start + length;
    return (start == 0 || !isJavaScriptIdentifierPart(text.charAt(start - 1)))
        && (end >= text.length() || !isJavaScriptIdentifierPart(text.charAt(end)));
  }

  /**
   * Checks whether the {@code bootstrap} token is reached through a member receiver.
   *
   * @param text JavaScript source being scanned
   * @param bootstrapIndex offset of the candidate {@code bootstrap} token
   * @return {@code true} for shapes like {@code platform.bootstrap}
   */
  private static boolean hasReceiverMemberAccessBefore(String text, int bootstrapIndex) {
    int dotIndex = skipJavaScriptWhitespaceBackward(text, bootstrapIndex - 1);
    if (dotIndex < 0 || text.charAt(dotIndex) != '.') {
      return false;
    }
    int receiverEnd = skipJavaScriptWhitespaceBackward(text, dotIndex - 1);
    return receiverEnd >= 0 && isJavaScriptIdentifierPart(text.charAt(receiverEnd));
  }

  /**
   * Checks whether {@code bootstrap} is followed by a {@code .load(} member call.
   *
   * @param text JavaScript source being scanned
   * @param afterBootstrap first offset after the candidate {@code bootstrap} token
   * @return {@code true} when a load call follows
   */
  private static boolean hasLoadCallAfterBootstrap(String text, int afterBootstrap) {
    int dotIndex = skipJavaScriptWhitespace(text, afterBootstrap);
    if (dotIndex >= text.length() || text.charAt(dotIndex) != '.') {
      return false;
    }
    int loadIndex = skipJavaScriptWhitespace(text, dotIndex + 1);
    if (!text.startsWith(LOAD_METHOD, loadIndex)) {
      return false;
    }
    int afterLoad = loadIndex + LOAD_METHOD.length();
    if (afterLoad < text.length() && isJavaScriptIdentifierPart(text.charAt(afterLoad))) {
      return false;
    }
    int callIndex = skipJavaScriptWhitespace(text, afterLoad);
    return callIndex < text.length() && text.charAt(callIndex) == '(';
  }

  /**
   * Skips JavaScript whitespace moving forward.
   *
   * @param text JavaScript source being scanned
   * @param index first offset to inspect
   * @return first non-whitespace offset, or {@code text.length()}
   */
  private static int skipJavaScriptWhitespace(String text, int index) {
    int position = Math.max(0, index);
    while (position < text.length() && Character.isWhitespace(text.charAt(position))) {
      position++;
    }
    return position;
  }

  /**
   * Skips JavaScript whitespace moving backward.
   *
   * @param text JavaScript source being scanned
   * @param index first offset to inspect
   * @return first non-whitespace offset, or {@code -1}
   */
  private static int skipJavaScriptWhitespaceBackward(String text, int index) {
    int position = Math.min(index, text.length() - 1);
    while (position >= 0 && Character.isWhitespace(text.charAt(position))) {
      position--;
    }
    return position;
  }

  /**
   * Checks whether a character is part of the ASCII JavaScript identifier subset used by the lint
   * scanner.
   *
   * @param character character to classify
   * @return {@code true} for letters, digits, underscore, or dollar sign
   */
  private static boolean isJavaScriptIdentifierPart(char character) {
    return (character >= 'A' && character <= 'Z')
        || (character >= 'a' && character <= 'z')
        || (character >= '0' && character <= '9')
        || character == '_'
        || character == '$';
  }

  /**
   * Replaces JavaScript comments and string/template literals with spaces while preserving offsets.
   *
   * @param text JavaScript source to sanitize for pattern checks
   * @return source text with comments and strings removed from token matching
   */
  private static String stripJavaScriptCommentsAndStrings(String text) {
    StringBuilder stripped = new StringBuilder(text);
    int index = 0;
    while (index < text.length()) {
      int ignoredStart = nextJavaScriptIgnoredRangeStart(text, index);
      if (ignoredStart < 0) {
        return stripped.toString();
      }
      int ignoredEnd = javaScriptIgnoredRangeEnd(text, ignoredStart);
      blankRangeExceptLineBreaks(stripped, ignoredStart, ignoredEnd);
      index = ignoredEnd;
    }
    return stripped.toString();
  }

  /**
   * Finds the next JavaScript comment or string/template literal opener.
   *
   * @param text JavaScript source to scan
   * @param fromIndex first character position to inspect
   * @return opener offset, or {@code -1} when no ignored range remains
   */
  private static int nextJavaScriptIgnoredRangeStart(String text, int fromIndex) {
    for (int index = Math.max(0, fromIndex); index < text.length(); index++) {
      char character = text.charAt(index);
      if (isJavaScriptQuote(character) || startsJavaScriptComment(text, index)) {
        return index;
      }
    }
    return -1;
  }

  /**
   * Computes the exclusive end offset for one JavaScript ignored range.
   *
   * @param text JavaScript source being scanned
   * @param start offset of a quote, line comment, or block comment opener
   * @return exclusive end offset for the ignored range
   */
  private static int javaScriptIgnoredRangeEnd(String text, int start) {
    if (startsLineComment(text, start)) {
      return lineCommentEnd(text, start + 2);
    }
    if (startsBlockComment(text, start)) {
      return blockCommentEnd(text, start + 2);
    }
    return quotedJavaScriptEnd(text, start, text.charAt(start));
  }

  /**
   * Checks whether a character opens a JavaScript string or template literal.
   *
   * @param character character to classify
   * @return {@code true} for single quotes, double quotes, and template backticks
   */
  private static boolean isJavaScriptQuote(char character) {
    return character == '\'' || character == '"' || character == '`';
  }

  /**
   * Checks whether a JavaScript comment starts at an offset.
   *
   * @param text JavaScript source being scanned
   * @param index candidate comment opener position
   * @return {@code true} for line and block comments
   */
  private static boolean startsJavaScriptComment(String text, int index) {
    return startsLineComment(text, index) || startsBlockComment(text, index);
  }

  /**
   * Checks whether {@code //} starts at an offset.
   *
   * @param text text being scanned
   * @param index candidate offset
   * @return {@code true} when a line comment starts here
   */
  private static boolean startsLineComment(String text, int index) {
    return index + 1 < text.length() && text.charAt(index) == '/' && text.charAt(index + 1) == '/';
  }

  /**
   * Checks whether {@code /*} starts at an offset.
   *
   * @param text text being scanned
   * @param index candidate offset
   * @return {@code true} when a block comment starts here
   */
  private static boolean startsBlockComment(String text, int index) {
    return index + 1 < text.length() && text.charAt(index) == '/' && text.charAt(index + 1) == '*';
  }

  /**
   * Finds the exclusive end of a JavaScript line comment body.
   *
   * @param text JavaScript source being scanned
   * @param index first character after the {@code //} opener
   * @return offset of the line break or source end
   */
  private static int lineCommentEnd(String text, int index) {
    int end = index;
    while (end < text.length() && text.charAt(end) != '\n' && text.charAt(end) != '\r') {
      end++;
    }
    return end;
  }

  /**
   * Finds the exclusive end of a JavaScript block comment body.
   *
   * @param text JavaScript source being scanned
   * @param index first character after the {@code /*} opener
   * @return first offset after the block-comment terminator, or source end for an unterminated
   *     comment
   */
  private static int blockCommentEnd(String text, int index) {
    int close = text.indexOf("*/", index);
    return close < 0 ? text.length() : close + 2;
  }

  /**
   * Finds the exclusive end of a quoted JavaScript string or template literal.
   *
   * @param text JavaScript source being scanned
   * @param quoteIndex offset of the opening quote or backtick
   * @param quote quote character that closes the literal
   * @return first offset after the closing quote, or source end when unterminated
   */
  private static int quotedJavaScriptEnd(String text, int quoteIndex, char quote) {
    int index = quoteIndex + 1;
    while (index < text.length()) {
      char character = text.charAt(index);
      if (character == '\\') {
        index += 2;
      } else if (character == quote) {
        return index + 1;
      } else {
        index++;
      }
    }
    return text.length();
  }

  /**
   * Blanks a source range while preserving line breaks for stable diagnostic offsets.
   *
   * @param text mutable source text
   * @param start first offset to blank
   * @param end exclusive end offset
   */
  private static void blankRangeExceptLineBreaks(StringBuilder text, int start, int end) {
    for (int index = start; index < end; index++) {
      char character = text.charAt(index);
      if (character != '\n' && character != '\r') {
        text.setCharAt(index, ' ');
      }
    }
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
   * <p>HTML inspection already reports remote and JavaScript URL resource references as CSP/safety
   * findings. This check handles the remaining local-resource contract: every entry-point script or
   * stylesheet that the browser will try to load from the app UI origin must be route-safe, resolve
   * to a regular file inside the staged bundle, and use the same executable/applicable MIME mapping
   * as the app-owned UI server. Invalid absolute paths, traversal-shaped paths, missing files, and
   * unsupported content types are reported before the JavaScript and CSS scans so strict validation
   * cannot pass an app UI whose SDK, app script, or stylesheet was omitted or will be served as
   * opaque bytes under {@code nosniff}.
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
                  LOCAL_REFERENCE_MESSAGE_PREFIX
                      + referenceKind
                      + " reference is not a valid app UI route asset path: "
                      + referencedPath,
                  referencedPath));
        } else {
          Path file = bundleRoot.resolve(routeAssetPath).normalize();
          if (!isBundleLocalRegularFile(bundleRoot, file)) {
            findings.add(
                error(
                    "local-ui-reference-missing",
                    CATEGORY_CSP,
                    LOCAL_REFERENCE_MESSAGE_PREFIX
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
              LOCAL_REFERENCE_MESSAGE_PREFIX
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
    if (isBundleLocalDirectory(bundleRoot, scanRoot)) {
      try (var stream = Files.walk(scanRoot)) {
        stream
            .filter(file -> isBundleLocalRegularFile(bundleRoot, file))
            .sorted()
            .forEach(files::add);
      }
    }
    for (String referencedPath : referencedPaths) {
      String routeAssetPath = localRouteAssetPath(referencedPath);
      if (!routeAssetPath.isBlank()) {
        Path file = bundleRoot.resolve(routeAssetPath).normalize();
        if (isBundleLocalRegularFile(bundleRoot, file)) {
          files.add(file);
        }
      }
    }
    return List.copyOf(files);
  }

  /**
   * Checks whether a candidate file is a regular file reached without leaving the staged bundle.
   *
   * <p>{@link LinkOption#NOFOLLOW_LINKS} on {@link Files#isRegularFile(Path, LinkOption...)}
   * protects only the final component. UI lint also refuses symlinked parent directories so a
   * staged bundle cannot point {@code static/} or an asset subdirectory at host files outside the
   * bundle and have those external bytes linted as if they were app-owned UI resources.
   *
   * @param bundleRoot normalized absolute bundle root
   * @param file candidate file path
   * @return {@code true} when the file is regular and every path component under the bundle root is
   *     not a symbolic link
   */
  private static boolean isBundleLocalRegularFile(Path bundleRoot, Path file) {
    return hasNoSymbolicLinkInPath(bundleRoot, file)
        && Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS);
  }

  /**
   * Checks whether a candidate directory can be walked as part of the staged bundle.
   *
   * @param bundleRoot normalized absolute bundle root
   * @param directory candidate directory path
   * @return {@code true} when the directory exists under the bundle root without symlink components
   */
  private static boolean isBundleLocalDirectory(Path bundleRoot, Path directory) {
    return hasNoSymbolicLinkInPath(bundleRoot, directory)
        && Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS);
  }

  /**
   * Rejects paths outside the bundle or paths that traverse symbolic links under the bundle root.
   *
   * @param bundleRoot normalized absolute bundle root
   * @param candidate candidate file or directory path
   * @return {@code true} when every candidate component from the root through the final path
   *     element is lexical-bundle-local and not a symbolic link
   */
  private static boolean hasNoSymbolicLinkInPath(Path bundleRoot, Path candidate) {
    Path normalizedRoot = bundleRoot.toAbsolutePath().normalize();
    Path normalizedCandidate = candidate.toAbsolutePath().normalize();
    if (!normalizedCandidate.startsWith(normalizedRoot) || Files.isSymbolicLink(normalizedRoot)) {
      return false;
    }
    Path current = normalizedRoot;
    for (Path segment : normalizedRoot.relativize(normalizedCandidate)) {
      current = current.resolve(segment);
      if (Files.isSymbolicLink(current)) {
        return false;
      }
    }
    return true;
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
   * <p>The SDK and canonical design-system support files are excluded because they should not
   * satisfy app bootstrap requirements or trigger direct app-script ordering checks. Other scripts
   * remain app-owned even if an author places them beside the vendored design-system assets. The
   * input must already be normalized to a bundle-relative path.
   *
   * @param scriptPath normalized script path from the static entry
   * @return {@code true} when the path refers to a local app script
   */
  static boolean isAppScript(String scriptPath) {
    String routeAssetPath = localRouteAssetPath(scriptPath);
    return !routeAssetPath.isBlank()
        && !isSdkAssetPath(routeAssetPath)
        && !CANONICAL_DESIGN_SYSTEM_SCRIPTS.contains(routeAssetPath);
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
   * Checks whether a normalized reference should be validated against the app UI route contract.
   *
   * @param path candidate bundle-relative reference
   * @return {@code true} for references that are not remote, protocol-relative, or JavaScript URLs
   */
  private static boolean isLocalReferenceCandidate(String path) {
    String normalized = path.toLowerCase(Locale.ROOT);
    return !normalized.isBlank()
        && !normalized.startsWith("http://")
        && !normalized.startsWith("https://")
        && !normalized.startsWith("//")
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
