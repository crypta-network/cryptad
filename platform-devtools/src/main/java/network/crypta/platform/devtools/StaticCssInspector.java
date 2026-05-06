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
 * paths. Remote and scheme-like imports are always fatal because app-owned UI must stay local;
 * non-normalized local imports follow the strict-mode severity chosen by the CLI.
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
   * <p>The scanner reports remote and scheme-like non-local imports as errors and local imports
   * that are not normalized as strict-mode findings. It does not resolve imports or read additional
   * files; the surrounding linter decides which CSS files are local and safe to scan.
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
    } else if (isNonLocalReference(value)) {
      findings.add(
          new AppUiLintFinding(
              "non-local-css-import",
              AppUiLinter.CATEGORY_CSP,
              AppUiLintSeverity.ERROR,
              "CSS @import must reference a local bundle-relative stylesheet.",
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
   * <p>This method intentionally recognizes a small CSS token subset: whitespace after the import
   * directive followed by an optional {@code url(} wrapper, or the compact valid form where a
   * quoted string starts immediately after the directive. It does not treat identifier
   * continuations such as {@code importfoo} or {@code importurl(...)} as import rules. The scanner
   * advances at least past the directive offset for malformed imports so callers can continue
   * scanning in linear time.
   *
   * @param css CSS text decoded from a local app UI file
   * @param offset position immediately after {@code @import}
   * @return extracted value and the next safe scan position
   */
  private static ImportValue readImportValue(String css, int offset) {
    boolean hasWhitespace = hasWhitespaceAt(css, offset);
    if (!hasWhitespace && !hasQuoteAt(css, offset)) {
      return ImportValue.missing(offset);
    }
    int position = hasWhitespace ? skipWhitespace(css, offset) : offset;
    if (hasWhitespace && startsWithUrlFunction(css, position)) {
      position = skipWhitespace(css, position + URL_FUNCTION_PREFIX.length());
    }
    if (position >= css.length()) {
      return ImportValue.missing(position);
    }
    char quote = 0;
    if (isQuote(css.charAt(position))) {
      quote = css.charAt(position);
      position++;
    }
    int valueStart = position;
    while (position < css.length() && !isImportValueTerminator(css.charAt(position))) {
      position++;
    }
    if (position == valueStart) {
      return ImportValue.missing(position);
    }
    int nextIndex =
        quote != 0 && position < css.length() && css.charAt(position) == quote
            ? position + 1
            : position;
    return ImportValue.found(css.substring(valueStart, position).trim(), nextIndex);
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
    int index = Math.max(0, fromIndex);
    while (index <= max) {
      int skippedIndex = skipCssCommentOrString(css, index);
      if (skippedIndex != index) {
        index = skippedIndex;
        continue;
      }
      if (css.regionMatches(true, index, IMPORT_DIRECTIVE, 0, IMPORT_DIRECTIVE.length())) {
        return index;
      }
      index++;
    }
    return -1;
  }

  /**
   * Skips a CSS comment or quoted string that starts at the current scan offset.
   *
   * @param css CSS text to scan
   * @param index current candidate offset
   * @return first offset after the ignored range, or {@code index} when no ignored range starts
   *     here
   */
  private static int skipCssCommentOrString(String css, int index) {
    if (startsCssComment(css, index)) {
      return cssCommentEnd(css, index + 2);
    }
    if (index < css.length() && isQuote(css.charAt(index))) {
      return quotedCssStringEnd(css, index, css.charAt(index));
    }
    return index;
  }

  /**
   * Checks whether a CSS block comment starts at an offset.
   *
   * @param css CSS text being scanned
   * @param index candidate comment opener position
   * @return {@code true} when a block comment starts here
   */
  private static boolean startsCssComment(String css, int index) {
    return index + 1 < css.length() && css.charAt(index) == '/' && css.charAt(index + 1) == '*';
  }

  /**
   * Finds the first offset after a CSS block comment.
   *
   * @param css CSS text being scanned
   * @param index first character after the comment opener
   * @return first offset after the comment terminator, or source end for an unterminated comment
   */
  private static int cssCommentEnd(String css, int index) {
    int close = css.indexOf("*/", index);
    return close < 0 ? css.length() : close + 2;
  }

  /**
   * Finds the first offset after a quoted CSS string.
   *
   * @param css CSS text being scanned
   * @param quoteIndex offset of the opening quote
   * @param quote quote character that closes the string
   * @return first offset after the closing quote, or source end when unterminated
   */
  private static int quotedCssStringEnd(String css, int quoteIndex, char quote) {
    int index = quoteIndex + 1;
    while (index < css.length()) {
      char character = css.charAt(index);
      if (character == '\\') {
        index += 2;
      } else if (character == quote) {
        return index + 1;
      } else {
        index++;
      }
    }
    return css.length();
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
   * Checks whether a position contains a CSS quote token.
   *
   * @param css CSS text being scanned
   * @param offset candidate character position
   * @return {@code true} when the offset is in range and points at a quote
   */
  private static boolean hasQuoteAt(String css, int offset) {
    return offset < css.length() && isQuote(css.charAt(offset));
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
   * Checks whether an import value uses a non-local URL scheme.
   *
   * <p>App-owned UI serves immutable bundle files under a self-only CSP. Scheme-like imports such
   * as {@code data:}, {@code file:}, and extension-specific pseudo-protocols are therefore not
   * bundle-relative resources even when they are not network remote URLs.
   *
   * @param value extracted import token without surrounding quotes
   * @return {@code true} when the token begins with a URL scheme and colon
   */
  private static boolean isNonLocalReference(String value) {
    int colonIndex = value.indexOf(':');
    if (colonIndex <= 0 || !Character.isLetter(value.charAt(0))) {
      return false;
    }
    for (int index = 1; index < colonIndex; index++) {
      char character = value.charAt(index);
      if (!Character.isLetterOrDigit(character)
          && character != '+'
          && character != '-'
          && character != '.') {
        return false;
      }
    }
    return true;
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
