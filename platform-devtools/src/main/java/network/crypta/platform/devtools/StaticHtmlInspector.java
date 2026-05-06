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
 * static/index.html} layout and still get deterministic bundle-relative findings.
 */
final class StaticHtmlInspector {
  /** Pattern that captures start tags and their raw attribute text. */
  private static final Pattern TAG_PATTERN =
      Pattern.compile("<\\s*([a-zA-Z][a-zA-Z0-9:-]*)\\b([^>]*)>", Pattern.DOTALL);

  /** Pattern that locates a script end tag after an inline script start tag. */
  private static final Pattern END_SCRIPT_PATTERN =
      Pattern.compile("</\\s*script\\s*>", Pattern.CASE_INSENSITIVE);

  /** Pattern that captures simple quoted and unquoted HTML attributes. */
  private static final Pattern ATTRIBUTE_PATTERN =
      Pattern.compile(
          "([A-Za-z_:][-A-Za-z0-9_:.]*)\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s\"'>`]+)", Pattern.DOTALL);

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

  /** Raw HTML text from the manifest-declared static UI entry. */
  private final String html;

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
   * @param path bundle-relative path to the inspected entry
   * @param entryDirectory bundle-relative directory that contains the inspected entry
   * @param tags parsed start tags in source order
   */
  private StaticHtmlInspector(String html, String path, Path entryDirectory, List<Tag> tags) {
    this.html = html;
    this.path = path;
    this.entryDirectory = entryDirectory;
    this.tags = tags;
  }

  /**
   * Scans an HTML entry point into a reusable inspector.
   *
   * <p>The scan records start tags and attributes only. Later checks use the raw HTML when they
   * need paired content, such as inline script bodies, title text, headings, labels, or button
   * names.
   *
   * @param html raw HTML text from the static UI entry
   * @param path bundle-relative path to the inspected entry
   * @param entryDirectory bundle-relative directory that contains the inspected entry
   * @return inspector with parsed tag metadata and the original HTML text
   */
  static StaticHtmlInspector inspect(String html, String path, Path entryDirectory) {
    List<Tag> tags = new ArrayList<>();
    Matcher matcher = TAG_PATTERN.matcher(html);
    while (matcher.find()) {
      tags.add(
          new Tag(
              matcher.group(1).toLowerCase(Locale.ROOT),
              attributes(matcher.group(2)),
              matcher.start(),
              matcher.end()));
    }
    return new StaticHtmlInspector(html, path, entryDirectory, tags);
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
   * @return {@code true} when a known {@code cr-*} class name appears in the HTML text
   */
  boolean usesDesignSystemClass() {
    return Pattern.compile(
            "\\bcr-(?:app|shell|header|card|toolbar|button|status|field|input|empty)")
        .matcher(html)
        .find();
  }

  /**
   * Checks whether the entry contains an obvious permission disclosure region.
   *
   * @return {@code true} when supported class, data attribute, or custom element markers are
   *     present
   */
  boolean hasPermissionDisclosure() {
    String lower = html.toLowerCase(Locale.ROOT);
    return lower.contains("cr-permission-summary")
        || lower.contains("data-crypta-permission-summary")
        || lower.contains("<crypta-permission-summary");
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
    String lower = html.toLowerCase(Locale.ROOT);
    int start = lower.indexOf("cr-permission-summary");
    if (start < 0) {
      start = lower.indexOf("data-crypta-permission-summary");
    }
    if (start < 0) {
      start = lower.indexOf("<crypta-permission-summary");
    }
    if (start < 0) {
      return permissions;
    }
    int end = lower.indexOf("</section>", start);
    if (end < 0) {
      end = lower.indexOf("</crypta-permission-summary>", start);
    }
    String block = html.substring(start, end < 0 ? html.length() : end);
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
   * <p>The first loaded local app script must not appear before the browser SDK. Any local script
   * that is not the SDK or a design-system support file is treated as app JavaScript, regardless of
   * filename.
   *
   * @param strict whether SDK findings should be warnings or errors where applicable
   * @return deterministic SDK findings for the inspected entry
   */
  List<AppUiLintFinding> sdkFindings(boolean strict) {
    List<AppUiLintFinding> findings = new ArrayList<>();
    List<String> scripts = normalizedScriptSources();
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
    return findings;
  }

  /**
   * Returns script references normalized to bundle-relative paths.
   *
   * @return script sources in document order, normalized relative to the entry directory
   */
  List<String> normalizedScriptSources() {
    List<String> scripts = new ArrayList<>();
    for (Tag tag : tags) {
      if (tag.name().equals(TAG_SCRIPT) && !tag.attribute(ATTRIBUTE_SRC).isBlank()) {
        scripts.add(normalizeLocalReference(tag.attribute(ATTRIBUTE_SRC), entryDirectory));
      }
    }
    return scripts;
  }

  /**
   * Finds the first browser SDK script in document order.
   *
   * @param scripts normalized script paths from the static entry
   * @return zero-based index of the first SDK script, or {@code -1} when absent
   */
  private static int firstSdkScriptIndex(List<String> scripts) {
    for (int index = 0; index < scripts.size(); index++) {
      if (AppUiLinter.isSdkScript(scripts.get(index))) {
        return index;
      }
    }
    return -1;
  }

  /**
   * Finds the first local app script in document order.
   *
   * @param scripts normalized script paths from the static entry
   * @return zero-based index of the first app script, or {@code -1} when absent
   */
  private static int firstAppScriptIndex(List<String> scripts) {
    for (int index = 0; index < scripts.size(); index++) {
      if (AppUiLinter.isAppScript(scripts.get(index))) {
        return index;
      }
    }
    return -1;
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
    Matcher matcher = TITLE_PATTERN.matcher(html);
    return matcher.find() && !stripTags(matcher.group(1)).isBlank();
  }

  /**
   * Checks whether the document contains a visible heading.
   *
   * @return {@code true} when any {@code h1} through {@code h6} element has non-empty stripped text
   */
  private boolean hasVisibleHeading() {
    Matcher matcher = HEADING_PATTERN.matcher(html);
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
    Matcher matcher = INPUT_TAG_PATTERN.matcher(html);
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
    Matcher matcher = BUTTON_PATTERN.matcher(html);
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
    Matcher matcher = LABEL_FOR_PATTERN.matcher(html);
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
   * @param offset character offset of an input tag in the raw HTML text
   * @return {@code true} when the nearest preceding label closes after the input offset
   */
  private boolean isWrappedInLabel(int offset) {
    int labelStart = html.lastIndexOf("<label", offset);
    if (labelStart < 0) {
      return false;
    }
    int labelEnd = html.indexOf("</label>", labelStart);
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
   * @param attributeText raw attribute text captured from a start tag
   * @return lower-case attribute names mapped to unquoted values in source order
   */
  private static Map<String, String> attributes(String attributeText) {
    java.util.LinkedHashMap<String, String> attributes = new java.util.LinkedHashMap<>();
    Matcher matcher = ATTRIBUTE_PATTERN.matcher(attributeText);
    while (matcher.find()) {
      attributes.put(matcher.group(1).toLowerCase(Locale.ROOT), unquote(matcher.group(2)));
    }
    return attributes;
  }

  /**
   * Removes one matching quote pair from an attribute value.
   *
   * @param value raw attribute value captured by the attribute pattern
   * @return unquoted value when single or double quotes wrap the full value
   */
  private static String unquote(String value) {
    if ((value.startsWith("\"") && value.endsWith("\""))
        || (value.startsWith("'") && value.endsWith("'"))) {
      return value.substring(1, value.length() - 1);
    }
    return value;
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
  }
}
