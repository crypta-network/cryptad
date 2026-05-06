package network.crypta.platform.devtools;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

/**
 * Conservative scanner for app-owned CSS files.
 *
 * <p>The UI lint contract only needs a small CSS surface today: identifying remote imports and
 * discouraging path forms that are ambiguous under app-owned UI CSP. This class therefore uses a
 * small linear scanner for {@code @import} statements instead of attempting to parse full CSS. It
 * favors high-value deterministic findings and leaves layout, cascade, and token usage checks to
 * the design-system stylesheet itself.
 *
 * <p>Callers provide the bundle-relative path separately so findings never include absolute local
 * paths. Remote imports are always fatal because app-owned UI must stay local; non-normalized local
 * imports follow the strict-mode severity chosen by the CLI.
 */
final class StaticCssInspector {
  /** CSS directive that imports another stylesheet. */
  private static final String IMPORT_DIRECTIVE = "@import";

  /** Prefix for the CSS {@code url(...)} import form. */
  private static final String URL_FUNCTION_PREFIX = "url(";

  /** Prevents construction because CSS inspection is a stateless utility operation. */
  private StaticCssInspector() {}

  /**
   * Inspects CSS text for import rules that violate the app UI lint contract.
   *
   * <p>The scanner reports remote imports as errors and local imports that are not normalized as
   * strict-mode findings. It does not resolve imports or read additional files; the surrounding
   * linter decides which CSS files are local and safe to scan.
   *
   * @param css CSS text decoded from a local app UI file
   * @param path bundle-relative path used in emitted findings
   * @param strict whether non-normalized local imports should be warnings or errors
   * @return deterministic list of CSS findings in source order
   */
  static List<AppUiLintFinding> inspect(String css, String path, boolean strict) {
    List<AppUiLintFinding> findings = new ArrayList<>();
    int importIndex = indexOfImportDirective(css, 0);
    while (importIndex >= 0) {
      ImportValue importValue = readImportValue(css, importIndex + IMPORT_DIRECTIVE.length());
      importValue.value().ifPresent(value -> addImportFinding(value, path, strict, findings));
      int nextSearchIndex =
          Math.max(importIndex + IMPORT_DIRECTIVE.length(), importValue.nextIndex());
      importIndex = indexOfImportDirective(css, nextSearchIndex);
    }
    return findings;
  }

  /**
   * Adds the linter finding for one extracted import value.
   *
   * @param value extracted import token without surrounding quotes
   * @param path bundle-relative path used in emitted findings
   * @param strict whether non-normalized local imports should be warnings or errors
   * @param findings mutable finding list that receives CSS import findings
   */
  private static void addImportFinding(
      String value, String path, boolean strict, List<AppUiLintFinding> findings) {
    if (isRemoteReference(value)) {
      findings.add(
          new AppUiLintFinding(
              "remote-css-import",
              AppUiLinter.CATEGORY_CSP,
              AppUiLintSeverity.ERROR,
              "Remote CSS @import is not allowed.",
              path));
    } else if (!isNormalizedLocalImport(value)) {
      findings.add(
          AppUiLinter.strictFinding(
              strict,
              "css-import-not-normalized",
              AppUiLinter.CATEGORY_CSP,
              "CSS @import should use a normalized local relative path.",
              path));
    }
  }

  /**
   * Reads the first URL-like token after a CSS {@code @import} directive.
   *
   * <p>This method intentionally recognizes the same small grammar the previous regex handled:
   * whitespace after {@code @import}, an optional {@code url(} wrapper, optional surrounding
   * quotes, and a token terminated by quotes, whitespace, {@code ;}, or {@code )}. It advances at
   * least past the directive offset for malformed imports so callers can continue scanning in
   * linear time.
   *
   * @param css CSS text decoded from a local app UI file
   * @param offset position immediately after {@code @import}
   * @return extracted value and the next safe scan position
   */
  private static ImportValue readImportValue(String css, int offset) {
    if (!hasWhitespaceAt(css, offset)) {
      return ImportValue.missing(offset);
    }
    int position = skipWhitespace(css, offset);
    if (startsWithUrlFunction(css, position)) {
      position = skipWhitespace(css, position + URL_FUNCTION_PREFIX.length());
    }
    if (position >= css.length()) {
      return ImportValue.missing(position);
    }
    if (isQuote(css.charAt(position))) {
      position++;
    }
    int valueStart = position;
    while (position < css.length() && !isImportValueTerminator(css.charAt(position))) {
      position++;
    }
    if (position == valueStart) {
      return ImportValue.missing(position);
    }
    return ImportValue.found(css.substring(valueStart, position).trim(), position);
  }

  /**
   * Finds the next CSS import directive without regular-expression backtracking.
   *
   * @param css CSS text to scan
   * @param fromIndex first candidate index
   * @return first matching {@code @import} index, or {@code -1} when absent
   */
  private static int indexOfImportDirective(String css, int fromIndex) {
    int max = css.length() - IMPORT_DIRECTIVE.length();
    for (int index = Math.max(0, fromIndex); index <= max; index++) {
      if (css.regionMatches(true, index, IMPORT_DIRECTIVE, 0, IMPORT_DIRECTIVE.length())) {
        return index;
      }
    }
    return -1;
  }

  /**
   * Checks whether a position contains CSS whitespace.
   *
   * @param css CSS text being scanned
   * @param offset candidate character position
   * @return {@code true} when the offset is in range and points at whitespace
   */
  private static boolean hasWhitespaceAt(String css, int offset) {
    return offset < css.length() && Character.isWhitespace(css.charAt(offset));
  }

  /**
   * Skips consecutive whitespace characters from a starting position.
   *
   * @param css CSS text being scanned
   * @param offset first position to inspect
   * @return first non-whitespace position, or {@code css.length()}
   */
  private static int skipWhitespace(String css, int offset) {
    int position = offset;
    while (position < css.length() && Character.isWhitespace(css.charAt(position))) {
      position++;
    }
    return position;
  }

  /**
   * Checks whether a CSS import value starts with {@code url(} at a specific position.
   *
   * @param css CSS text to scan
   * @param offset candidate prefix position
   * @return {@code true} when {@code url(} starts at the offset
   */
  private static boolean startsWithUrlFunction(String css, int offset) {
    return offset <= css.length() - URL_FUNCTION_PREFIX.length()
        && css.regionMatches(true, offset, URL_FUNCTION_PREFIX, 0, URL_FUNCTION_PREFIX.length());
  }

  /**
   * Checks whether a character starts or ends a quoted import token.
   *
   * @param character character to classify
   * @return {@code true} for single and double quotes
   */
  private static boolean isQuote(char character) {
    return character == '\'' || character == '"';
  }

  /**
   * Checks whether a character terminates the import token recognized by UI lint.
   *
   * @param character character to classify
   * @return {@code true} when the scanner should stop collecting the import value
   */
  private static boolean isImportValueTerminator(char character) {
    return isQuote(character)
        || character == ';'
        || character == ')'
        || Character.isWhitespace(character);
  }

  /**
   * Checks whether an import value points at a remote resource.
   *
   * @param value extracted import token without surrounding quotes
   * @return {@code true} for HTTP, HTTPS, and protocol-relative references
   */
  private static boolean isRemoteReference(String value) {
    String normalized = value.toLowerCase(Locale.ROOT);
    return normalized.startsWith("http://")
        || normalized.startsWith("https://")
        || normalized.startsWith("//");
  }

  /**
   * Checks whether a local import uses the normalized path form accepted by UI lint.
   *
   * @param value extracted import token without surrounding quotes
   * @return {@code true} for non-empty relative paths without traversal or redundant prefixes
   */
  private static boolean isNormalizedLocalImport(String value) {
    return !value.startsWith("/")
        && !value.contains("\\")
        && !value.contains("..")
        && !value.startsWith("./")
        && !value.isBlank();
  }

  /**
   * Result of scanning a CSS import directive.
   *
   * @param value extracted import token, if a token was present
   * @param nextIndex next safe character offset for the caller's outer scan
   */
  private record ImportValue(Optional<String> value, int nextIndex) {
    private static ImportValue found(String value, int nextIndex) {
      return new ImportValue(Optional.of(value), nextIndex);
    }

    private static ImportValue missing(int nextIndex) {
      return new ImportValue(Optional.empty(), nextIndex);
    }
  }
}
