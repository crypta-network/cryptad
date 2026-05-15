package network.crypta.platform.devtools;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Report redaction helpers shared by developer test and publication-plan output.
 *
 * <p>The developer toolkit writes human-readable summaries and optional machine-readable JSON from
 * checks that may touch local files, fixture directories, bootstrap responses, and signing
 * material. This helper centralizes the last-mile sanitization used before those values leave the
 * process. It removes common absolute Unix and Windows paths, likely file-path fragments with
 * sensitive extensions, and browser-session-like tokens from status text.
 *
 * <p>The redactor is intentionally conservative and dependency-free. It is not a JSON parser, a log
 * scrubber for arbitrary input, or a cryptographic guarantee; callers should still avoid passing
 * private key bytes, passwords, or raw exception traces into reports. The goal is to keep routine
 * CLI diagnostics useful while avoiding accidental disclosure of local operator paths and mock
 * session values.
 */
final class AppTestRedactor {
  /** Replacement text used whenever a local path is removed from report output. */
  private static final String REDACTED_PATH = "[REDACTED_PATH]";

  /** Extensions that make an absolute path worth redacting even when the path contains spaces. */
  private static final Set<String> REDACTABLE_EXTENSIONS =
      Set.of(
          "json",
          "properties",
          "pem",
          "der",
          "key",
          "p12",
          "pfx",
          "zip",
          "jar",
          "txt",
          "html",
          "css",
          "js",
          "md",
          "xml",
          "yml",
          "yaml",
          "toml",
          "csv",
          "log");

  /** Characters that end a path-like token without consuming surrounding JSON or shell syntax. */
  private static final String FILE_PATH_STOP_CHARS = "\r\n\"'`{}[]<>";

  /** Characters that end compact path-like tokens that cannot contain spaces. */
  private static final String COMPACT_PATH_STOP_CHARS = "\r\n\"'`{}[]";

  /** Header and field shapes that commonly carry mock app browser-session values. */
  private static final Pattern SESSION_TOKEN =
      Pattern.compile(
          "browserSessionToken[=: ][-a-z0-9._~+/=]+"
              + "|X-Crypta-App-Session[=: ][-a-z0-9._~+/=]+"
              + "|session[=: ][-a-z0-9._~+/=]+",
          Pattern.CASE_INSENSITIVE);

  /** Prevents construction of this stateless utility class. */
  private AppTestRedactor() {}

  /**
   * Redacts common local paths and browser-session tokens from diagnostic text.
   *
   * <p>The method is null-safe and preserves the surrounding message so check summaries remain
   * actionable. More specific file-path scanners run before broader path-token scanners, which lets
   * reports hide directories with spaces when the final extension identifies a local artifact.
   *
   * @param value raw diagnostic value from a test, plan, or lower-level exception
   * @return sanitized value suitable for terminal summaries and JSON report fields
   */
  static String redact(String value) {
    String text = value == null ? "" : value;
    text = SESSION_TOKEN.matcher(text).replaceAll(match -> redactSessionToken(match.group()));
    text = redactAbsoluteFilePaths(text);
    return redactCompactAbsolutePaths(text);
  }

  /**
   * Redacts one matched session-token assignment while preserving the reported field name.
   *
   * @param assignment complete matched assignment such as {@code browserSessionToken=abc}
   * @return assignment with the original value replaced by a fixed marker
   */
  private static String redactSessionToken(String assignment) {
    for (int index = 0; index < assignment.length(); index++) {
      char character = assignment.charAt(index);
      if (character == '=' || character == ':' || character == ' ') {
        return assignment.substring(0, index) + "=[REDACTED]";
      }
    }
    return "[REDACTED]";
  }

  /**
   * Redacts absolute file paths that end with a known local-artifact extension.
   *
   * @param text diagnostic text after session-token redaction
   * @return text with extension-identified Unix and Windows paths replaced
   */
  private static String redactAbsoluteFilePaths(String text) {
    StringBuilder redacted = new StringBuilder(text.length());
    int index = 0;
    while (index < text.length()) {
      int end = absoluteFilePathEnd(text, index);
      if (end > index) {
        redacted.append(REDACTED_PATH);
        index = end;
      } else {
        redacted.append(text.charAt(index));
        index++;
      }
    }
    return redacted.toString();
  }

  /**
   * Finds the end of an absolute file path at one character offset.
   *
   * @param text diagnostic text being scanned
   * @param index candidate start offset
   * @return exclusive end offset for a redactable path, or {@code -1}
   */
  private static int absoluteFilePathEnd(String text, int index) {
    if (!isUnixPathStart(text, index) && !isWindowsPathStart(text, index)) {
      return -1;
    }
    return findRedactableExtensionEnd(text, index);
  }

  /**
   * Scans for the first known file extension before a stop character.
   *
   * @param text diagnostic text being scanned
   * @param start candidate path start offset
   * @return exclusive end offset for the extension match, or {@code -1}
   */
  private static int findRedactableExtensionEnd(String text, int start) {
    for (int index = start; index < text.length(); index++) {
      char character = text.charAt(index);
      if (FILE_PATH_STOP_CHARS.indexOf(character) >= 0) {
        return -1;
      }
      if (character == '.') {
        int extensionEnd = extensionEnd(text, index);
        if (extensionEnd > index) {
          return extensionEnd;
        }
      }
    }
    return -1;
  }

  /**
   * Checks whether a dot begins a known redacted file extension.
   *
   * @param text diagnostic text being scanned
   * @param dotIndex index of the candidate dot before the extension
   * @return exclusive extension end offset, or {@code -1}
   */
  private static int extensionEnd(String text, int dotIndex) {
    int start = dotIndex + 1;
    int end = start;
    while (end < text.length() && Character.isLetterOrDigit(text.charAt(end))) {
      end++;
    }
    if (end == start || !isExtensionBoundary(text, end)) {
      return -1;
    }
    String extension = text.substring(start, end).toLowerCase(Locale.ROOT);
    return REDACTABLE_EXTENSIONS.contains(extension) ? end : -1;
  }

  /**
   * Checks whether an extension is followed by a non-word boundary.
   *
   * @param text diagnostic text being scanned
   * @param index exclusive extension end offset
   * @return {@code true} when the extension is complete at this offset
   */
  private static boolean isExtensionBoundary(String text, int index) {
    if (index >= text.length()) {
      return true;
    }
    char next = text.charAt(index);
    return !Character.isLetterOrDigit(next) && next != '_';
  }

  /**
   * Redacts compact absolute path tokens that do not contain whitespace.
   *
   * @param text diagnostic text after extension-bearing paths have been redacted
   * @return text with remaining compact absolute path tokens replaced
   */
  private static String redactCompactAbsolutePaths(String text) {
    StringBuilder redacted = new StringBuilder(text.length());
    int index = 0;
    while (index < text.length()) {
      int end = compactPathEnd(text, index);
      if (end > index) {
        redacted.append(REDACTED_PATH);
        index = end;
      } else {
        redacted.append(text.charAt(index));
        index++;
      }
    }
    return redacted.toString();
  }

  /**
   * Finds the end of a compact Unix or Windows path token at one offset.
   *
   * @param text diagnostic text being scanned
   * @param index candidate path start offset
   * @return exclusive token end offset, or {@code -1}
   */
  private static int compactPathEnd(String text, int index) {
    if (isUnixPathStart(text, index)) {
      return scanCompactPathEnd(text, index, index + 1);
    }
    if (isWindowsPathStart(text, index)) {
      return scanCompactPathEnd(text, index, index + 3);
    }
    return -1;
  }

  /**
   * Scans a compact path token until whitespace or shell/JSON punctuation.
   *
   * @param text diagnostic text being scanned
   * @param start candidate path start offset
   * @param minimumEnd shortest exclusive end offset accepted for this path shape
   * @return exclusive token end offset, or {@code -1}
   */
  private static int scanCompactPathEnd(String text, int start, int minimumEnd) {
    int end = start;
    while (end < text.length()
        && !Character.isWhitespace(text.charAt(end))
        && COMPACT_PATH_STOP_CHARS.indexOf(text.charAt(end)) < 0) {
      end++;
    }
    return end > minimumEnd ? end : -1;
  }

  /**
   * Checks whether a character offset starts a local-looking Unix absolute path.
   *
   * @param text diagnostic text being scanned
   * @param index candidate slash offset
   * @return {@code true} when the slash can start a local path token
   */
  private static boolean isUnixPathStart(String text, int index) {
    if (text.charAt(index) != '/') {
      return false;
    }
    if (index == 0) {
      return text.length() > 1;
    }
    char previous = text.charAt(index - 1);
    return previous != '/'
        && previous != ':'
        && !isAsciiLetter(previous)
        && !Character.isDigit(previous);
  }

  /**
   * Checks whether a character offset starts a Windows drive absolute path.
   *
   * @param text diagnostic text being scanned
   * @param index candidate drive-letter offset
   * @return {@code true} when the offset starts a {@code C:\} style path
   */
  private static boolean isWindowsPathStart(String text, int index) {
    return index + 2 < text.length()
        && isAsciiLetter(text.charAt(index))
        && text.charAt(index + 1) == ':'
        && text.charAt(index + 2) == '\\';
  }

  /**
   * Checks whether a character is an ASCII letter.
   *
   * @param character character to inspect
   * @return {@code true} for {@code A-Z} and {@code a-z}
   */
  private static boolean isAsciiLetter(char character) {
    return (character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z');
  }

  /**
   * Returns only the final name for a path that may be included in a report.
   *
   * <p>Publication plans need to name the catalog and signature files without exposing the
   * developer's workspace or temporary directory. A missing path or final component becomes the
   * empty string so callers can still serialize deterministic output.
   *
   * @param path local file path that should not be reported verbatim
   * @return final path component, or an empty string when no file name exists
   */
  static String fileName(Path path) {
    if (path == null || path.getFileName() == null) {
      return "";
    }
    return path.getFileName().toString();
  }
}
