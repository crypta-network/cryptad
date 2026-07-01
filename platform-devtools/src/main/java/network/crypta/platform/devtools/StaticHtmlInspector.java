package network.crypta.platform.devtools;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Conservative scanner for static app HTML files.
 *
 * <p>This inspector provides the HTML-facing half of {@code crypta-app ui lint}. It extracts a
 * small set of tags and attributes, then reports high-value CSP, SDK bootstrap, accessibility,
 * permission-disclosure, and design-system signals. The scanner is not a browser parser and does
 * not attempt to execute JavaScript, compute styles, or validate every possible HTML edge case.
 * That trade-off keeps the developer CLI offline and dependency-free while still catching mistakes
 * that would break app-owned UI under Crypta's local-resource CSP.
 *
 * <p>Paths returned by this class are normalized relative to the manifest-declared entry directory.
 * A bundle can therefore use {@code ui/index.html}, {@code index.html}, or the first-party {@code
 * static/index.html} layout and still get deterministic bundle-relative findings. Comments are
 * blanked before tag scanning, duplicate attributes preserve the first browser-visible value, and
 * URL-bearing attributes are decoded for the character references that affect schemes. Those
 * details keep the linter aligned with common browser behavior without adding a full HTML parser
 * dependency.
 */
final class StaticHtmlInspector {
  /** Pattern that captures start tags and their raw attribute text. */
  private static final Pattern TAG_PATTERN =
      Pattern.compile("<\\s*([a-zA-Z][a-zA-Z0-9:-]*)\\b([^>]*)>", Pattern.DOTALL);

  /** Pattern that locates a script end tag after an inline script start tag. */
  private static final Pattern END_SCRIPT_PATTERN =
      Pattern.compile("</\\s*script\\s*>", Pattern.CASE_INSENSITIVE);

  /** Pattern that captures one HTML attribute name token. */
  private static final Pattern ATTRIBUTE_NAME_PATTERN =
      Pattern.compile("[A-Za-z_:][-A-Za-z0-9_:.]*");

  /** Pattern that extracts heading contents for visible-heading checks. */
  private static final Pattern HEADING_PATTERN =
      Pattern.compile("<h[1-6]\\b[^>]*>(.*?)</h[1-6]>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  /** Pattern that extracts title contents for non-empty title checks. */
  private static final Pattern TITLE_PATTERN =
      Pattern.compile("<title\\b[^>]*>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  /** Pattern that captures button attributes and contents for accessible-name checks. */
  private static final Pattern BUTTON_PATTERN =
      Pattern.compile(
          "<button\\b([^>]*)>(.*?)</button>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  /** Pattern that captures input attributes for label association checks. */
  private static final Pattern INPUT_TAG_PATTERN =
      Pattern.compile("<input\\b([^>]*)>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  /** Pattern that captures label attributes for {@code for=} association checks. */
  private static final Pattern LABEL_FOR_PATTERN =
      Pattern.compile("<label\\b([^>]*)>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

  /** Pattern for manifest-style permission identifiers mentioned in disclosure markup. */
  private static final Pattern PERMISSION_PATTERN =
      Pattern.compile("\\b[a-z][a-z0-9._-]*\\.[a-z][a-z0-9._-]*\\b");

  /** Finding category for accessibility essentials in app-owned UI entries. */
  private static final String CATEGORY_ACCESSIBILITY = "accessibility";

  /** Lower-case tag name for script elements. */
  private static final String TAG_SCRIPT = "script";

  /** Attribute name for source-bearing HTML elements. */
  private static final String ATTRIBUTE_SRC = "src";

  /** Attribute name for asynchronous script execution. */
  private static final String ATTRIBUTE_ASYNC = "async";

  /** Attribute name for deferred script execution. */
  private static final String ATTRIBUTE_DEFER = "defer";

  /** Attribute name that selects JavaScript module scripts. */
  private static final String ATTRIBUTE_TYPE = "type";

  /** Design-system class that marks a first-party permission disclosure summary. */
  private static final String CLASS_PERMISSION_SUMMARY = "cr-permission-summary";

  /** Data attribute marker for permission disclosure summaries. */
  private static final String ATTRIBUTE_PERMISSION_SUMMARY = "data-crypta-permission-summary";

  /** Custom element marker for permission disclosure summaries. */
  private static final String ELEMENT_PERMISSION_SUMMARY = "<crypta-permission-summary";

  /** Stable Crypta UI class names documented for app-owned static UI. */
  private static final Set<String> DESIGN_SYSTEM_CLASSES =
      Set.of(
          "cr-app",
          "cr-shell",
          "cr-header",
          "cr-card",
          "cr-toolbar",
          "cr-button",
          "cr-button--primary",
          "cr-button--secondary",
          "cr-field",
          "cr-label",
          "cr-input",
          "cr-checkbox",
          "cr-status",
          "cr-status--success",
          "cr-status--warning",
          "cr-status--danger",
          "cr-status--info",
          "cr-empty",
          "cr-kv-list",
          "cr-kv-row",
          CLASS_PERMISSION_SUMMARY,
          "cr-sr-only");

  /** Raw HTML text from the manifest-declared static UI entry. */
  private final String html;

  /** HTML text with comments blanked out so scanners do not treat examples as live markup. */
  private final String uncommentedHtml;

  /** Bundle-relative path to the inspected entry, used in emitted findings. */
  private final String path;

  /** Bundle-relative directory that contains the inspected entry. */
  private final Path entryDirectory;

  /** Parsed start tags in source order with lower-case tag and attribute names. */
  private final List<Tag> tags;

  /**
   * Creates an inspector from raw HTML and pre-scanned tags.
   *
   * @param html raw HTML text from the static UI entry
   * @param uncommentedHtml HTML text with comments replaced by offset-preserving whitespace
   * @param path bundle-relative path to the inspected entry
   * @param entryDirectory bundle-relative directory that contains the inspected entry
   * @param tags parsed start tags in source order
   */
  private StaticHtmlInspector(
      String html, String uncommentedHtml, String path, Path entryDirectory, List<Tag> tags) {
    this.html = html;
    this.uncommentedHtml = uncommentedHtml;
    this.path = path;
    this.entryDirectory = entryDirectory;
    this.tags = tags;
  }

  /**
   * Scans an HTML entry point into a reusable inspector.
   *
   * <p>The scan records start tags and attributes only. Later checks use the raw HTML when they
   * need paired content, such as inline script bodies, title text, headings, labels, or button
   * names. Attribute values are normalized during this phase so downstream CSP and SDK checks work
   * with the value a browser would use for scheme interpretation and duplicate-attribute handling.
   *
   * @param html raw HTML text from the static UI entry, decoded from the staged bundle file
   * @param path bundle-relative path to the inspected entry for diagnostics and JSON output
   * @param entryDirectory bundle-relative directory that contains the inspected entry
   * @return inspector with parsed tag metadata, comment-stripped scanner text, and original HTML
   */
  static StaticHtmlInspector inspect(String html, String path, Path entryDirectory) {
    String uncommentedHtml = stripHtmlComments(html);
    List<Tag> tags = new ArrayList<>();
    Matcher matcher = TAG_PATTERN.matcher(uncommentedHtml);
    while (matcher.find()) {
      tags.add(
          new Tag(
              matcher.group(1).toLowerCase(Locale.ROOT),
              attributes(matcher.group(2)),
              matcher.start(),
              matcher.end()));
    }
    return new StaticHtmlInspector(html, uncommentedHtml, path, entryDirectory, tags);
  }

  /**
   * Replaces HTML comments with spaces while preserving line breaks and character offsets.
   *
   * <p>The linter uses regular-expression scanners for a small HTML subset. Blanking comment ranges
   * before those scans prevents disabled examples such as commented remote scripts from producing
   * CSP findings, while preserved offsets still let tag metadata point into the original document
   * for inline-script body checks.
   *
   * @param html raw HTML text from the static UI entry
   * @return HTML with comment contents removed from scanner visibility
   */
  private static String stripHtmlComments(String html) {
    StringBuilder stripped = new StringBuilder(html);
    int searchIndex = 0;
    while (searchIndex < html.length()) {
      int commentStart = html.indexOf("<!--", searchIndex);
      if (commentStart < 0) {
        return stripped.toString();
      }
      int commentEnd = html.indexOf("-->", commentStart + 4);
      int exclusiveEnd = commentEnd < 0 ? html.length() : commentEnd + 3;
      blankRangeExceptLineBreaks(stripped, commentStart, exclusiveEnd);
      searchIndex = exclusiveEnd;
    }
    return stripped.toString();
  }

  /**
   * Blanks a source range while preserving line breaks for stable offsets.
   *
   * @param text mutable text to update
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
   * Returns stylesheet references normalized to bundle-relative paths.
   *
   * <p>Remote, absolute, and JavaScript URLs are returned unchanged so the caller can classify them
   * as CSP findings without resolving them against the local filesystem.
   *
   * @return stylesheet hrefs in document order, normalized relative to the entry directory
   */
  List<String> normalizedStylesheetHrefs() {
    List<String> hrefs = new ArrayList<>();
    for (Tag tag : tags) {
      if (isStylesheetLink(tag)) {
        hrefs.add(normalizeLocalReference(tag.attribute("href"), entryDirectory));
      }
    }
    return hrefs;
  }

  /**
   * Checks whether the entry appears to use the stable Crypta UI class vocabulary.
   *
   * @return {@code true} when a documented {@code cr-*} class token appears in a class attribute
   */
  boolean usesDesignSystemClass() {
    for (Tag tag : tags) {
      if (usesDesignSystemClass(tag.attribute("class"))) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks one decoded class attribute for documented Crypta UI classes.
   *
   * @param classAttribute decoded class attribute value
   * @return {@code true} when any whitespace-separated class token is documented
   */
  private static boolean usesDesignSystemClass(String classAttribute) {
    int position = 0;
    while (position < classAttribute.length()) {
      position = skipHtmlWhitespace(classAttribute, position);
      int classStart = position;
      while (position < classAttribute.length()
          && !Character.isWhitespace(classAttribute.charAt(position))) {
        position++;
      }
      if (classStart < position
          && DESIGN_SYSTEM_CLASSES.contains(classAttribute.substring(classStart, position))) {
        return true;
      }
    }
    return false;
  }

  /**
   * Checks whether the entry contains an obvious permission disclosure region.
   *
   * @return {@code true} when supported class, data attribute, or custom element markers are
   *     present
   */
  boolean hasPermissionDisclosure() {
    String lower = uncommentedHtml.toLowerCase(Locale.ROOT);
    return lower.contains(CLASS_PERMISSION_SUMMARY)
        || lower.contains(ATTRIBUTE_PERMISSION_SUMMARY)
        || lower.contains(ELEMENT_PERMISSION_SUMMARY);
  }

  /**
   * Checks whether a literal marker is absent from live, uncommented HTML.
   *
   * <p>This is used for opt-in first-party readiness markers that are expressed as data attributes.
   * The method intentionally does not parse values; the surrounding linter owns policy semantics
   * and this class remains a lightweight static HTML scanner.
   *
   * @param marker case-insensitive marker text to find
   * @return {@code true} when the marker does not appear outside HTML comments
   */
  boolean lacksMarker(String marker) {
    return !uncommentedHtml.toLowerCase(Locale.ROOT).contains(marker.toLowerCase(Locale.ROOT));
  }

  /**
   * Extracts permission identifiers mentioned in the disclosure region.
   *
   * <p>The scan starts at the first supported disclosure marker and stops at the end of that
   * section or custom element when possible. It is intended to catch mismatched manifest
   * disclosures, not to parse arbitrary natural-language permission text.
   *
   * @return permission identifiers in first-seen order, lower-cased for manifest comparison
   */
  Set<String> mentionedPermissionsInDisclosure() {
    Set<String> permissions = new LinkedHashSet<>();
    String lower = uncommentedHtml.toLowerCase(Locale.ROOT);
    int start = lower.indexOf(CLASS_PERMISSION_SUMMARY);
    if (start < 0) {
      start = lower.indexOf(ATTRIBUTE_PERMISSION_SUMMARY);
    }
    if (start < 0) {
      start = lower.indexOf(ELEMENT_PERMISSION_SUMMARY);
    }
    if (start < 0) {
      return permissions;
    }
    int end = lower.indexOf("</section>", start);
    if (end < 0) {
      end = lower.indexOf("</crypta-permission-summary>", start);
    }
    String block = uncommentedHtml.substring(start, end < 0 ? uncommentedHtml.length() : end);
    Matcher matcher = PERMISSION_PATTERN.matcher(block);
    while (matcher.find()) {
      permissions.add(matcher.group().toLowerCase(Locale.ROOT));
    }
    return permissions;
  }

  /**
   * Reports CSP and local-resource safety findings from HTML tags and inline script bodies.
   *
   * @return deterministic safety findings in source order where possible
   */
  List<AppUiLintFinding> safetyFindings() {
    List<AppUiLintFinding> findings = new ArrayList<>();
    for (Tag tag : tags) {
      addTagSafetyFindings(tag, findings);
    }
    addInlineScriptFindings(findings);
    return findings;
  }

  /**
   * Reports SDK loading and ordering findings.
   *
   * <p>The first loaded local app script must not appear before the browser SDK in document order.
   * The check also rejects SDK execution attributes that make document order unreliable: an {@code
   * async} SDK can race any app script, and a deferred or module SDK can run after a later
   * parser-blocking app script. Any local script that is not the SDK or a design-system support
   * file is treated as app JavaScript, regardless of filename.
   *
   * @param strict whether SDK findings should be warnings or errors where applicable
   * @return deterministic SDK findings for the inspected entry
   */
  List<AppUiLintFinding> sdkFindings(boolean strict) {
    List<AppUiLintFinding> findings = new ArrayList<>();
    List<ScriptReference> scripts = scriptReferences();
    int sdkIndex = firstSdkScriptIndex(scripts);
    int appIndex = firstAppScriptIndex(scripts);
    if (sdkIndex < 0) {
      findings.add(
          AppUiLinter.strictFinding(
              strict,
              "sdk-script-missing",
              "sdk",
              "Static UI entry does not load crypta-platform.js.",
              path));
    }
    if (appIndex >= 0 && appIndex < sdkIndex) {
      findings.add(
          AppUiLinter.strictFinding(
              strict,
              "sdk-script-order",
              "sdk",
              "App JavaScript appears before crypta-platform.js.",
              path));
    }
    addSdkExecutionAttributeFindings(strict, scripts, sdkIndex, appIndex, findings);
    return findings;
  }

  /**
   * Returns script references normalized to bundle-relative paths.
   *
   * @return script sources in document order, normalized relative to the entry directory
   */
  List<String> normalizedScriptSources() {
    return scriptReferences().stream().map(ScriptReference::source).toList();
  }

  /**
   * Returns local and remote script references with execution-relevant attributes.
   *
   * @return script references in document order
   */
  private List<ScriptReference> scriptReferences() {
    List<ScriptReference> references = new ArrayList<>();
    for (Tag tag : tags) {
      if (tag.name().equals(TAG_SCRIPT) && !tag.attribute(ATTRIBUTE_SRC).isBlank()) {
        references.add(scriptReference(tag));
      }
    }
    return references;
  }

  /**
   * Converts a parsed script tag into the execution model used by SDK-order checks.
   *
   * @param tag parsed script tag with a non-empty {@code src}
   * @return normalized script reference and execution attributes
   */
  private ScriptReference scriptReference(Tag tag) {
    return new ScriptReference(
        normalizeLocalReference(tag.attribute(ATTRIBUTE_SRC), entryDirectory),
        tag.hasAttribute(ATTRIBUTE_ASYNC),
        tag.hasAttribute(ATTRIBUTE_DEFER),
        tag.attribute(ATTRIBUTE_TYPE).equalsIgnoreCase("module"));
  }

  /**
   * Finds the first browser SDK script in document order.
   *
   * @param scripts normalized script references from the static entry
   * @return zero-based index of the first SDK script, or {@code -1} when absent
   */
  private static int firstSdkScriptIndex(List<ScriptReference> scripts) {
    for (int index = 0; index < scripts.size(); index++) {
      if (scripts.get(index).isSdk()) {
        return index;
      }
    }
    return -1;
  }

  /**
   * Finds the first local app script in document order.
   *
   * @param scripts normalized script references from the static entry
   * @return zero-based index of the first app script, or {@code -1} when absent
   */
  private static int firstAppScriptIndex(List<ScriptReference> scripts) {
    for (int index = 0; index < scripts.size(); index++) {
      if (scripts.get(index).isApp()) {
        return index;
      }
    }
    return -1;
  }

  /**
   * Adds findings for SDK script attributes that make SDK-before-app ordering unreliable.
   *
   * @param strict whether SDK findings should be warnings or errors where applicable
   * @param scripts normalized script references from the static entry
   * @param sdkIndex zero-based SDK script index, or {@code -1} when absent
   * @param appIndex zero-based first app script index, or {@code -1} when absent
   * @param findings mutable finding list that receives SDK findings
   */
  private void addSdkExecutionAttributeFindings(
      boolean strict,
      List<ScriptReference> scripts,
      int sdkIndex,
      int appIndex,
      List<AppUiLintFinding> findings) {
    if (sdkIndex < 0 || appIndex < 0) {
      return;
    }
    ScriptReference sdk = scripts.get(sdkIndex);
    if (sdk.async()) {
      findings.add(
          AppUiLinter.strictFinding(
              strict,
              "sdk-script-async",
              "sdk",
              "crypta-platform.js must not use async because app JavaScript may execute before the"
                  + " SDK.",
              path));
    } else if (sdk.isDeferred() && hasAppScriptThatCanBeatDeferredSdk(scripts, sdkIndex)) {
      findings.add(
          AppUiLinter.strictFinding(
              strict,
              "sdk-script-defer-order",
              "sdk",
              "Deferred crypta-platform.js can run after a later parser-blocking or async app"
                  + " script.",
              path));
    }
  }

  /**
   * Checks whether a script after a deferred SDK can execute before that SDK.
   *
   * @param scripts normalized script references from the static entry
   * @param sdkIndex zero-based index of the deferred SDK script
   * @return {@code true} when a later app script is parser-blocking or async
   */
  private static boolean hasAppScriptThatCanBeatDeferredSdk(
      List<ScriptReference> scripts, int sdkIndex) {
    for (int index = sdkIndex + 1; index < scripts.size(); index++) {
      ScriptReference script = scripts.get(index);
      if (script.isApp() && script.canRunBeforeDeferredPredecessor()) {
        return true;
      }
    }
    return false;
  }

  /**
   * Reports basic accessibility findings for the static entry.
   *
   * <p>The checks intentionally cover essentials that a static scanner can detect cheaply:
   * language, viewport, title, visible heading, labels for inputs, names for icon-only buttons, and
   * focus-visible styling when the canonical design-system CSS is absent.
   *
   * @param strict whether accessibility findings should be warnings or errors
   * @param hasDesignSystemCss whether canonical design-system CSS is present in the bundle
   * @return deterministic accessibility findings for the inspected entry
   */
  List<AppUiLintFinding> accessibilityFindings(boolean strict, boolean hasDesignSystemCss) {
    List<AppUiLintFinding> findings = new ArrayList<>();
    if (!htmlTagHasLang()) {
      findings.add(accessibilityFinding(strict, "html-lang-missing", "<html> must declare lang."));
    }
    if (!hasViewportMeta()) {
      findings.add(
          accessibilityFinding(
              strict, "viewport-meta-missing", "index.html must include a viewport meta tag."));
    }
    if (!hasNonEmptyTitle()) {
      findings.add(
          accessibilityFinding(
              strict, "title-missing", "index.html must include a non-empty title."));
    }
    if (!hasVisibleHeading()) {
      findings.add(
          accessibilityFinding(
              strict, "heading-missing", "Static UI should include a visible heading."));
    }
    addInputLabelFindings(strict, findings);
    addButtonNameFindings(strict, findings);
    if (!hasDesignSystemCss && !html.contains(":focus-visible")) {
      findings.add(
          accessibilityFinding(
              strict,
              "focus-visible-style-missing",
              "App UI should provide a focus-visible style when design-system CSS is absent."));
    }
    return findings;
  }

  /**
   * Adds CSP and local-resource findings for one parsed tag.
   *
   * @param tag parsed start tag from the inspected entry
   * @param findings mutable finding list that receives tag-level safety findings
   */
  private void addTagSafetyFindings(Tag tag, List<AppUiLintFinding> findings) {
    addAttributeSafetyFindings(tag, findings);
    addElementSafetyFindings(tag, findings);
    addRemoteReferenceFindings(tag, findings);
  }

  /**
   * Adds CSP findings for inline handlers, JavaScript URLs, and inline styles.
   *
   * @param tag parsed start tag from the inspected entry
   * @param findings mutable finding list that receives attribute-level safety findings
   */
  private void addAttributeSafetyFindings(Tag tag, List<AppUiLintFinding> findings) {
    for (Map.Entry<String, String> attribute : tag.attributes().entrySet()) {
      addAttributeSafetyFinding(attribute.getKey(), attribute.getValue(), findings);
    }
  }

  /**
   * Adds a CSP finding for one attribute when it uses a prohibited browser feature.
   *
   * @param name lower-case attribute name
   * @param value unquoted attribute value
   * @param findings mutable finding list that receives attribute-level safety findings
   */
  private void addAttributeSafetyFinding(
      String name, String value, List<AppUiLintFinding> findings) {
    if (name.startsWith("on")) {
      findings.add(error("inline-event-handler", "Inline event handlers are not allowed."));
    }
    if (value.trim().toLowerCase(Locale.ROOT).startsWith("javascript:")) {
      findings.add(error("javascript-url", "javascript: URLs are not allowed."));
    }
    if (name.equals("style")) {
      findings.add(
          AppUiLinter.cspWarning("inline-style", "Inline style attributes are discouraged.", path));
    }
  }

  /**
   * Adds CSP findings for prohibited embedding and base-url elements.
   *
   * @param tag parsed start tag from the inspected entry
   * @param findings mutable finding list that receives element-level safety findings
   */
  private void addElementSafetyFindings(Tag tag, List<AppUiLintFinding> findings) {
    switch (tag.name()) {
      case "base" -> findings.add(error("base-tag", "<base> tags are not allowed."));
      case "object", "embed" ->
          findings.add(error("object-embed-tag", "<object> and <embed> tags are not allowed."));
      default -> {
        // Other tags are handled by attribute and remote-reference checks.
      }
    }
  }

  /**
   * Adds CSP findings for remote resources referenced by otherwise recognized tags.
   *
   * @param tag parsed start tag from the inspected entry
   * @param findings mutable finding list that receives remote-resource findings
   */
  private void addRemoteReferenceFindings(Tag tag, List<AppUiLintFinding> findings) {
    switch (tag.name()) {
      case TAG_SCRIPT ->
          addRemoteSourceErrorIfNeeded(
              tag, "remote-script", "Remote script sources are not allowed.", findings);
      case "link" -> addRemoteStylesheetFindingIfNeeded(tag, findings);
      case "iframe" ->
          addRemoteSourceErrorIfNeeded(
              tag, "remote-iframe", "Remote iframes are not allowed.", findings);
      case "img" -> addRemotePassiveResourceFindingIfNeeded(tag, ATTRIBUTE_SRC, findings);
      case "a" -> addRemotePassiveResourceFindingIfNeeded(tag, "href", findings);
      default -> {
        // Local-resource CSP has no tag-specific remote check for this element.
      }
    }
  }

  /**
   * Adds a remote-resource error when a tag's {@code src} points outside the app bundle.
   *
   * @param tag parsed start tag from the inspected entry
   * @param id stable finding id
   * @param message human-readable diagnostic text
   * @param findings mutable finding list that receives remote-resource findings
   */
  private void addRemoteSourceErrorIfNeeded(
      Tag tag, String id, String message, List<AppUiLintFinding> findings) {
    if (isRemoteReference(tag.attribute(ATTRIBUTE_SRC))) {
      findings.add(error(id, message));
    }
  }

  /**
   * Adds a remote-stylesheet error for stylesheet links that point outside the app bundle.
   *
   * @param tag parsed start tag from the inspected entry
   * @param findings mutable finding list that receives remote-stylesheet findings
   */
  private void addRemoteStylesheetFindingIfNeeded(Tag tag, List<AppUiLintFinding> findings) {
    if (isStylesheetLink(tag) && isRemoteReference(tag.attribute("href"))) {
      findings.add(error("remote-stylesheet", "Remote stylesheets are not allowed."));
    }
  }

  /**
   * Adds a warning for remote passive resources that current app-owned UI CSP may block.
   *
   * @param tag parsed start tag from the inspected entry
   * @param attribute attribute that contains the URL-like value
   * @param findings mutable finding list that receives passive-resource findings
   */
  private void addRemotePassiveResourceFindingIfNeeded(
      Tag tag, String attribute, List<AppUiLintFinding> findings) {
    if (isRemoteReference(tag.attribute(attribute))) {
      findings.add(
          AppUiLinter.cspWarning(
              "remote-passive-resource",
              "Remote images or links may not work under app-owned UI CSP.",
              path));
    }
  }

  /**
   * Adds findings for non-empty inline script blocks.
   *
   * <p>Script tags with a {@code src} attribute are handled by tag-level remote-source checks. This
   * method only looks for inline content between a start tag and the next script end tag.
   *
   * @param findings mutable finding list that receives inline-script findings
   */
  private void addInlineScriptFindings(List<AppUiLintFinding> findings) {
    for (Tag tag : tags) {
      if (isInlineScriptTag(tag)) {
        addInlineScriptFinding(tag, findings);
      }
    }
  }

  /**
   * Checks whether a tag is an inline script start tag.
   *
   * @param tag parsed start tag from the inspected entry
   * @return {@code true} when the tag is {@code <script>} and has no {@code src} attribute
   */
  private static boolean isInlineScriptTag(Tag tag) {
    return tag.name().equals(TAG_SCRIPT) && tag.attribute(ATTRIBUTE_SRC).isBlank();
  }

  /**
   * Adds an inline-script finding when a script tag has non-empty inline content.
   *
   * @param tag parsed inline script start tag from the inspected entry
   * @param findings mutable finding list that receives inline-script findings
   */
  private void addInlineScriptFinding(Tag tag, List<AppUiLintFinding> findings) {
    Matcher endMatcher = END_SCRIPT_PATTERN.matcher(html);
    if (endMatcher.find(tag.endOffset())) {
      String content = html.substring(tag.endOffset(), endMatcher.start()).trim();
      if (!content.isEmpty()) {
        findings.add(error("inline-script", "Inline script content is not allowed."));
      }
    }
  }

  /**
   * Checks whether the document declares a language on its root HTML element.
   *
   * @return {@code true} when an {@code html} tag has a non-empty {@code lang} attribute
   */
  private boolean htmlTagHasLang() {
    return tags.stream()
        .filter(tag -> tag.name().equals("html"))
        .findFirst()
        .map(tag -> !tag.attribute("lang").isBlank())
        .orElse(false);
  }

  /**
   * Checks whether the document declares a non-empty viewport meta tag.
   *
   * @return {@code true} when a viewport meta tag with content is present
   */
  private boolean hasViewportMeta() {
    return tags.stream()
        .anyMatch(
            tag ->
                tag.name().equals("meta")
                    && tag.attribute("name").equalsIgnoreCase("viewport")
                    && !tag.attribute("content").isBlank());
  }

  /**
   * Checks whether the document title contains visible text.
   *
   * @return {@code true} when the first title element has non-empty stripped text
   */
  private boolean hasNonEmptyTitle() {
    Matcher matcher = TITLE_PATTERN.matcher(uncommentedHtml);
    return matcher.find() && !stripTags(matcher.group(1)).isBlank();
  }

  /**
   * Checks whether the document contains a visible heading.
   *
   * @return {@code true} when any {@code h1} through {@code h6} element has non-empty stripped text
   */
  private boolean hasVisibleHeading() {
    Matcher matcher = HEADING_PATTERN.matcher(uncommentedHtml);
    while (matcher.find()) {
      if (!stripTags(matcher.group(1)).isBlank()) {
        return true;
      }
    }
    return false;
  }

  /**
   * Adds a finding when the first visible input lacks an accessible name.
   *
   * @param strict whether the finding should be warning or error severity
   * @param findings mutable finding list that receives the input-label finding
   */
  private void addInputLabelFindings(boolean strict, List<AppUiLintFinding> findings) {
    Set<String> labelledIds = labelForIds();
    Matcher matcher = INPUT_TAG_PATTERN.matcher(uncommentedHtml);
    while (matcher.find()) {
      Map<String, String> attrs = attributes(matcher.group(1));
      if (isVisibleInputWithoutAccessibleName(attrs, labelledIds, matcher.start())) {
        findings.add(
            accessibilityFinding(
                strict,
                "input-label-missing",
                "Input elements should have an associated label or ARIA label."));
        return;
      }
    }
  }

  /**
   * Checks whether an input participates in accessibility labeling checks and lacks a name.
   *
   * @param attrs lower-case attributes from the input start tag
   * @param labelledIds ids targeted by {@code label for=} elements in the document
   * @param inputOffset character offset of the input tag in the raw HTML text
   * @return {@code true} when a visible input has no label, ARIA label, or wrapping label
   */
  private boolean isVisibleInputWithoutAccessibleName(
      Map<String, String> attrs, Set<String> labelledIds, int inputOffset) {
    if (attrs.getOrDefault("type", "").equalsIgnoreCase("hidden")) {
      return false;
    }
    String id = attrs.getOrDefault("id", "");
    boolean hasAccessibleName =
        !attrs.getOrDefault("aria-label", "").isBlank()
            || !attrs.getOrDefault("aria-labelledby", "").isBlank()
            || (!id.isBlank() && labelledIds.contains(id))
            || isWrappedInLabel(inputOffset);
    return !hasAccessibleName;
  }

  /**
   * Adds findings for buttons that have no visible text or ARIA name.
   *
   * @param strict whether findings should be warning or error severity
   * @param findings mutable finding list that receives button-name findings
   */
  private void addButtonNameFindings(boolean strict, List<AppUiLintFinding> findings) {
    Matcher matcher = BUTTON_PATTERN.matcher(uncommentedHtml);
    while (matcher.find()) {
      Map<String, String> attrs = attributes(matcher.group(1));
      String text = stripTags(matcher.group(2)).trim();
      if (text.isEmpty()
          && attrs.getOrDefault("aria-label", "").isBlank()
          && attrs.getOrDefault("aria-labelledby", "").isBlank()
          && attrs.getOrDefault("title", "").isBlank()) {
        findings.add(
            accessibilityFinding(
                strict,
                "button-name-missing",
                "Icon or empty buttons should have visible text or an ARIA label."));
      }
    }
  }

  /**
   * Collects target ids from {@code label for=} attributes.
   *
   * @return input ids that are explicitly associated with labels
   */
  private Set<String> labelForIds() {
    Set<String> ids = new LinkedHashSet<>();
    Matcher matcher = LABEL_FOR_PATTERN.matcher(uncommentedHtml);
    while (matcher.find()) {
      String id = attributes(matcher.group(1)).getOrDefault("for", "");
      if (!id.isBlank()) {
        ids.add(id);
      }
    }
    return ids;
  }

  /**
   * Checks whether an input offset appears inside a label element.
   *
   * @param offset character offset of an input tag in the comment-stripped HTML text
   * @return {@code true} when the nearest preceding label closes after the input offset
   */
  private boolean isWrappedInLabel(int offset) {
    int labelStart = uncommentedHtml.lastIndexOf("<label", offset);
    if (labelStart < 0) {
      return false;
    }
    int labelEnd = uncommentedHtml.indexOf("</label>", labelStart);
    return labelEnd > offset;
  }

  /**
   * Creates a CSP-category error finding for the inspected entry.
   *
   * @param id stable finding id
   * @param message human-readable diagnostic text
   * @return immutable fatal finding associated with this entry path
   */
  private AppUiLintFinding error(String id, String message) {
    return new AppUiLintFinding(
        id, AppUiLinter.CATEGORY_CSP, AppUiLintSeverity.ERROR, message, path);
  }

  /**
   * Parses simple HTML attributes from raw tag text.
   *
   * <p>Attribute values are entity-decoded once, matching the browser's treatment of URL-bearing
   * attributes before scheme interpretation. This keeps safety checks from missing values whose
   * scheme separators are written as character references. The decoder intentionally supports the
   * numeric references and small named-reference set that affect URL schemes and separators;
   * unknown or malformed references are left intact. When a tag repeats an attribute, the first
   * value is retained because browsers ignore later duplicates for the same attribute name.
   *
   * @param attributeText raw attribute text captured from a start tag
   * @return lower-case attribute names mapped to the first entity-decoded, unquoted value seen for
   *     that name
   */
  private static Map<String, String> attributes(String attributeText) {
    java.util.LinkedHashMap<String, String> attributes = new java.util.LinkedHashMap<>();
    int position = 0;
    while (position < attributeText.length()) {
      position = skipAttributeSeparators(attributeText, position);
      Matcher matcher = ATTRIBUTE_NAME_PATTERN.matcher(attributeText);
      matcher.region(position, attributeText.length());
      if (!matcher.lookingAt()) {
        position++;
        continue;
      }
      String name = matcher.group().toLowerCase(Locale.ROOT);
      AttributeValue value = readAttributeValue(attributeText, matcher.end());
      attributes.putIfAbsent(name, decodeHtmlCharacterReferences(value.value()));
      position = value.nextIndex();
    }
    return attributes;
  }

  /**
   * Skips whitespace and self-closing slashes before the next attribute name.
   *
   * @param attributeText raw attribute text captured from a start tag
   * @param offset first character to inspect
   * @return first candidate attribute-name position
   */
  private static int skipAttributeSeparators(String attributeText, int offset) {
    int position = offset;
    while (position < attributeText.length()
        && (Character.isWhitespace(attributeText.charAt(position))
            || attributeText.charAt(position) == '/')) {
      position++;
    }
    return position;
  }

  /**
   * Reads the optional value after one parsed attribute name.
   *
   * @param attributeText raw attribute text captured from a start tag
   * @param offset first character after the attribute name
   * @return raw value text and the next parse offset
   */
  private static AttributeValue readAttributeValue(String attributeText, int offset) {
    int position = skipHtmlWhitespace(attributeText, offset);
    if (position >= attributeText.length() || attributeText.charAt(position) != '=') {
      return new AttributeValue("", position);
    }
    position = skipHtmlWhitespace(attributeText, position + 1);
    if (position >= attributeText.length()) {
      return new AttributeValue("", position);
    }
    char first = attributeText.charAt(position);
    if (first == '"' || first == '\'') {
      return readQuotedAttributeValue(attributeText, position, first);
    }
    return readUnquotedAttributeValue(attributeText, position);
  }

  /**
   * Skips HTML attribute whitespace from a starting position.
   *
   * @param text attribute text to scan
   * @param offset first character to inspect
   * @return first non-whitespace position, or the text length
   */
  private static int skipHtmlWhitespace(String text, int offset) {
    int position = offset;
    while (position < text.length() && Character.isWhitespace(text.charAt(position))) {
      position++;
    }
    return position;
  }

  /**
   * Reads a quoted attribute value.
   *
   * @param attributeText raw attribute text captured from a start tag
   * @param quotePosition position of the opening quote
   * @param quote quote character that closes the value
   * @return value without surrounding quotes and the next parse offset
   */
  private static AttributeValue readQuotedAttributeValue(
      String attributeText, int quotePosition, char quote) {
    int valueStart = quotePosition + 1;
    int valueEnd = attributeText.indexOf(quote, valueStart);
    if (valueEnd < 0) {
      return new AttributeValue(attributeText.substring(valueStart), attributeText.length());
    }
    return new AttributeValue(attributeText.substring(valueStart, valueEnd), valueEnd + 1);
  }

  /**
   * Reads an unquoted attribute value.
   *
   * @param attributeText raw attribute text captured from a start tag
   * @param offset first value character
   * @return value text and the next parse offset
   */
  private static AttributeValue readUnquotedAttributeValue(String attributeText, int offset) {
    int position = offset;
    while (position < attributeText.length()
        && !isUnquotedAttributeValueTerminator(attributeText.charAt(position))) {
      position++;
    }
    return new AttributeValue(attributeText.substring(offset, position), position);
  }

  /**
   * Checks whether a character terminates an unquoted attribute value.
   *
   * @param character character to classify
   * @return {@code true} when the unquoted value should end before this character
   */
  private static boolean isUnquotedAttributeValueTerminator(char character) {
    return Character.isWhitespace(character)
        || character == '"'
        || character == '\''
        || character == '>'
        || character == '`';
  }

  /**
   * Decodes HTML character references used in attribute values.
   *
   * @param value unquoted raw attribute value
   * @return value with supported character references decoded
   */
  private static String decodeHtmlCharacterReferences(String value) {
    int firstAmpersand = value.indexOf('&');
    if (firstAmpersand < 0) {
      return value;
    }
    StringBuilder decoded = new StringBuilder(value.length());
    decoded.append(value, 0, firstAmpersand);
    int index = firstAmpersand;
    while (index < value.length()) {
      char character = value.charAt(index);
      if (character == '&') {
        CharacterReference reference = readCharacterReference(value, index + 1);
        if (reference.decoded() != null) {
          decoded.append(reference.decoded());
          index = reference.nextIndex();
        } else {
          decoded.append(character);
          index++;
        }
      } else {
        decoded.append(character);
        index++;
      }
    }
    return decoded.toString();
  }

  /**
   * Reads one named or numeric character reference after an ampersand.
   *
   * @param value complete attribute value
   * @param offset first character after {@code &}
   * @return decoded reference, or a missing result when the reference is malformed or unsupported
   */
  private static CharacterReference readCharacterReference(String value, int offset) {
    if (offset >= value.length()) {
      return CharacterReference.missing(offset);
    }
    if (value.charAt(offset) == '#') {
      return readNumericCharacterReference(value, offset + 1);
    }
    return readNamedCharacterReference(value, offset);
  }

  /**
   * Reads a decimal or hexadecimal numeric character reference.
   *
   * <p>HTML numeric character references do not require a semicolon in attribute values when the
   * next character is not part of the selected radix. Decoding the semicolonless form keeps URL
   * scheme checks aligned with browser handling of values such as {@code javascript&#58alert(1)}.
   *
   * @param value complete attribute value
   * @param offset first character after {@code &#}
   * @return decoded reference, or a missing result when the numeric reference is invalid
   */
  private static CharacterReference readNumericCharacterReference(String value, int offset) {
    int radix = 10;
    int digitsStart = offset;
    if (offset < value.length() && isHtmlHexMarker(value.charAt(offset))) {
      radix = 16;
      digitsStart = offset + 1;
    }
    int position = digitsStart;
    while (position < value.length() && Character.digit(value.charAt(position), radix) >= 0) {
      position++;
    }
    if (position == digitsStart) {
      return CharacterReference.missing(offset);
    }
    String digits = value.substring(digitsStart, position);
    String decoded = decodeCodePoint(digits, radix);
    int nextIndex =
        position < value.length() && value.charAt(position) == ';' ? position + 1 : position;
    return decoded == null
        ? CharacterReference.missing(offset)
        : CharacterReference.found(decoded, nextIndex);
  }

  /**
   * Checks whether a numeric character reference switches to hexadecimal notation.
   *
   * @param character character after {@code &#}
   * @return {@code true} for {@code x} and {@code X}
   */
  private static boolean isHtmlHexMarker(char character) {
    return character == 'x' || character == 'X';
  }

  /**
   * Decodes one numeric character-reference code point.
   *
   * @param digits numeric digits captured from the reference
   * @param radix numeric radix, either 10 or 16
   * @return decoded code point as a string, or {@code null} when invalid
   */
  private static String decodeCodePoint(String digits, int radix) {
    try {
      int codePoint = Integer.parseInt(digits, radix);
      if (!Character.isValidCodePoint(codePoint)
          || (codePoint <= Character.MAX_VALUE && Character.isSurrogate((char) codePoint))) {
        return null;
      }
      return Character.toString(codePoint);
    } catch (NumberFormatException _) {
      return null;
    }
  }

  /**
   * Reads a small set of named character references relevant to URL attributes.
   *
   * @param value complete attribute value
   * @param offset first character after {@code &}
   * @return decoded reference, or a missing result when the name is malformed or unsupported
   */
  private static CharacterReference readNamedCharacterReference(String value, int offset) {
    int position = offset;
    while (position < value.length() && Character.isLetterOrDigit(value.charAt(position))) {
      position++;
    }
    if (position == offset || position >= value.length() || value.charAt(position) != ';') {
      return CharacterReference.missing(offset);
    }
    String decoded = decodeNamedCharacterReference(value.substring(offset, position));
    return decoded == null
        ? CharacterReference.missing(offset)
        : CharacterReference.found(decoded, position + 1);
  }

  /**
   * Decodes common named references that can affect URL safety checks.
   *
   * @param name entity name without {@code &} or {@code ;}
   * @return decoded text, or {@code null} for unsupported names
   */
  private static String decodeNamedCharacterReference(String name) {
    return switch (name) {
      case "amp" -> "&";
      case "apos" -> "'";
      case "colon" -> ":";
      case "gt" -> ">";
      case "lt" -> "<";
      case "quot" -> "\"";
      case "sol" -> "/";
      default -> null;
    };
  }

  /**
   * Checks whether a URL-like value points at a remote resource.
   *
   * @param value URL or path value from an HTML attribute
   * @return {@code true} for HTTP, HTTPS, and protocol-relative references
   */
  private static boolean isRemoteReference(String value) {
    String normalized = value.trim().toLowerCase(Locale.ROOT);
    return normalized.startsWith("http://")
        || normalized.startsWith("https://")
        || normalized.startsWith("//");
  }

  /**
   * Checks whether a parsed tag is a stylesheet link.
   *
   * @param tag parsed start tag from the inspected entry
   * @return {@code true} when the tag is a {@code link} whose {@code rel} includes stylesheet
   */
  private static boolean isStylesheetLink(Tag tag) {
    return tag.name().equals("link")
        && tag.attribute("rel").toLowerCase(Locale.ROOT).contains("stylesheet");
  }

  /**
   * Creates an accessibility finding for the inspected entry.
   *
   * @param strict whether the finding should be warning or error severity
   * @param id stable finding id
   * @param message human-readable diagnostic text
   * @return immutable accessibility finding associated with this entry path
   */
  private AppUiLintFinding accessibilityFinding(boolean strict, String id, String message) {
    return AppUiLinter.strictFinding(strict, id, CATEGORY_ACCESSIBILITY, message, path);
  }

  /**
   * Normalizes a local HTML reference relative to the static entry directory.
   *
   * <p>Query strings and fragments are removed before path normalization because lint findings need
   * bundle file paths, not request URLs. Remote, absolute, protocol-relative, and {@code
   * javascript:} references are returned unchanged so safety checks can report them without
   * resolving them locally. Relative browser paths are normalized with slash-separated string logic
   * instead of host {@link Path} parsing so route-invalid URL text such as custom schemes,
   * drive-letter-looking values, or malformed asset names is reported as a lint finding on every
   * supported operating system.
   *
   * @param value raw attribute value from {@code href} or {@code src}
   * @param entryDirectory bundle-relative directory containing the inspected entry
   * @return bundle-relative normalized path, or the original non-local reference form
   */
  private static String normalizeLocalReference(String value, Path entryDirectory) {
    String normalized = value.trim();
    int query = normalized.indexOf('?');
    if (query >= 0) {
      normalized = normalized.substring(0, query);
    }
    int fragment = normalized.indexOf('#');
    if (fragment >= 0) {
      normalized = normalized.substring(0, fragment);
    }
    if (isRemoteReference(normalized)
        || normalized.startsWith("//")
        || normalized.startsWith("/")
        || normalized.toLowerCase(Locale.ROOT).startsWith("javascript:")) {
      return normalized;
    }
    return normalizeRelativeBrowserPath(entryDirectory, normalized);
  }

  /**
   * Resolves one relative browser reference against the entry directory without host path parsing.
   *
   * @param entryDirectory bundle-relative directory that contains the inspected entry
   * @param reference query- and fragment-free browser reference
   * @return slash-separated bundle-relative path after dot-segment normalization
   */
  private static String normalizeRelativeBrowserPath(Path entryDirectory, String reference) {
    List<String> segments = new ArrayList<>();
    appendPathSegments(segments, entryDirectory.toString().replace('\\', '/'), false);
    appendPathSegments(segments, reference.replace('\\', '/'), true);
    return String.join("/", segments);
  }

  /**
   * Appends path segments while applying URL-style dot-segment normalization.
   *
   * @param segments mutable normalized segment list
   * @param path slash-separated path text
   * @param preserveEmptySegments whether embedded empty segments should remain lintable
   */
  private static void appendPathSegments(
      List<String> segments, String path, boolean preserveEmptySegments) {
    if (path.isEmpty()) {
      return;
    }
    String[] rawSegments = path.split("/", -1);
    for (int index = 0; index < rawSegments.length; index++) {
      String segment = rawSegments[index];
      if (segment.equals("..")) {
        normalizeParentSegment(segments);
      } else if (!segment.equals(".")
          && (!segment.isEmpty()
              || shouldKeepEmptySegment(rawSegments, index, preserveEmptySegments))) {
        segments.add(segment);
      }
    }
  }

  /**
   * Applies one parent-directory segment to a normalized relative path.
   *
   * @param segments mutable normalized segment list
   */
  private static void normalizeParentSegment(List<String> segments) {
    if (!segments.isEmpty() && !segments.getLast().equals("..")) {
      segments.removeLast();
    } else {
      segments.add("..");
    }
  }

  /**
   * Checks whether an empty raw segment should be preserved for route validation.
   *
   * @param rawSegments complete raw segment array
   * @param index current raw segment index
   * @param preserveEmptySegments whether reference-path empty segments should remain visible
   * @return {@code true} for embedded empty segments in relative browser references
   */
  private static boolean shouldKeepEmptySegment(
      String[] rawSegments, int index, boolean preserveEmptySegments) {
    return preserveEmptySegments && index > 0 && index < rawSegments.length - 1;
  }

  /**
   * Removes tags and collapses whitespace for text-presence checks.
   *
   * @param value raw HTML fragment
   * @return text-like content with tags removed and whitespace normalized
   */
  private static String stripTags(String value) {
    return value.replaceAll("<[^>]+>", " ").replaceAll("\\s+", " ").trim();
  }

  /**
   * Result of reading one HTML attribute value.
   *
   * @param value parsed attribute value without surrounding quotes
   * @param nextIndex next character offset after the consumed value
   */
  private record AttributeValue(String value, int nextIndex) {}

  /**
   * Result of reading one HTML character reference.
   *
   * @param decoded decoded text, or {@code null} when no supported reference was present
   * @param nextIndex next character offset after the consumed reference
   */
  private record CharacterReference(String decoded, int nextIndex) {
    /**
     * Creates a successful character-reference parse result.
     *
     * @param decoded decoded character or string inserted into the attribute value
     * @param nextIndex first offset after the consumed reference text
     * @return character-reference result carrying decoded text
     */
    private static CharacterReference found(String decoded, int nextIndex) {
      return new CharacterReference(decoded, nextIndex);
    }

    /**
     * Creates a missing or unsupported character-reference parse result.
     *
     * @param nextIndex offset where the caller should resume scanning the raw value
     * @return character-reference result with no decoded replacement
     */
    private static CharacterReference missing(int nextIndex) {
      return new CharacterReference(null, nextIndex);
    }
  }

  /**
   * Normalized script reference with the attributes that influence browser execution order.
   *
   * @param source normalized script source from the static entry
   * @param async whether the script has an {@code async} attribute
   * @param defer whether the script has a {@code defer} attribute
   * @param module whether the script is loaded with {@code type=module}
   */
  private record ScriptReference(String source, boolean async, boolean defer, boolean module) {
    /**
     * Checks whether this reference loads the browser SDK.
     *
     * @return {@code true} when the source path names {@code crypta-platform.js}
     */
    private boolean isSdk() {
      return AppUiLinter.isSdkScript(source);
    }

    /**
     * Checks whether this reference is local app-owned JavaScript.
     *
     * @return {@code true} when the source path is local and not the SDK or design-system support
     */
    private boolean isApp() {
      return AppUiLinter.isAppScript(source);
    }

    /**
     * Checks whether this script waits until document parsing completes before execution.
     *
     * @return {@code true} for deferred classic scripts and non-async module scripts
     */
    private boolean isDeferred() {
      return defer || module;
    }

    /**
     * Checks whether this script can execute before an earlier deferred script.
     *
     * @return {@code true} for async scripts and parser-blocking classic scripts
     */
    private boolean canRunBeforeDeferredPredecessor() {
      return async || !isDeferred();
    }
  }

  /**
   * Parsed start tag with normalized attribute names and source offsets.
   *
   * @param name lower-case tag name
   * @param attributes lower-case attribute names mapped to unquoted values
   * @param startOffset start offset of the tag in the raw HTML text
   * @param endOffset end offset of the start tag in the raw HTML text
   */
  private record Tag(String name, Map<String, String> attributes, int startOffset, int endOffset) {
    /**
     * Returns an attribute value by case-insensitive name.
     *
     * @param name requested attribute name
     * @return attribute value, or an empty string when the attribute is absent
     */
    private String attribute(String name) {
      return attributes.getOrDefault(name.toLowerCase(Locale.ROOT), "");
    }

    /**
     * Checks whether an attribute was present even when its value is blank.
     *
     * @param name requested attribute name
     * @return {@code true} when the parsed start tag included the attribute
     */
    private boolean hasAttribute(String name) {
      return attributes.containsKey(name.toLowerCase(Locale.ROOT));
    }
  }
}
