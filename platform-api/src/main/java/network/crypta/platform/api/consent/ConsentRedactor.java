package network.crypta.platform.api.consent;

import java.util.regex.Pattern;

/**
 * Redacts sensitive material before it can reach consent previews or audit summaries.
 *
 * <p>The consent layer intentionally works with summaries from catalogs, app manifests, update
 * plans, and service descriptors. Some of that text is supplied by apps or catalog authors, so this
 * helper applies a conservative last-pass scrub before values become preview JSON, snapshot digest
 * input, or audit records. It masks private insert URI forms, simple secret assignments, and
 * obvious host-local absolute paths.
 *
 * <p>This is not a general data-loss-prevention engine. Callers must still avoid passing raw
 * request bodies, backup payloads, app-data values, private keys, or command lines into consent
 * summaries. Redaction is a defense-in-depth boundary for short display strings.
 */
final class ConsentRedactor {
  /** Matches common one-token secret assignment forms in catalog or migration summary text. */
  private static final Pattern TOKEN_ASSIGNMENT =
      Pattern.compile(
          "(?i)\\b(?:bearer|token|secret|authorization|password|key)\\b\\s*[:=]\\s*\\S+");

  private static final String REDACTED_PRIVATE_URI = "[redacted-private-uri]";
  private static final String REDACTED_LOCAL_PATH = "[redacted-local-path]";

  /** Utility class; instances are not needed. */
  private ConsentRedactor() {}

  /**
   * Redacts supported sensitive patterns from one display string.
   *
   * <p>{@code null} and empty input are returned unchanged so record constructors can preserve
   * existing optional-field semantics. Non-empty text is processed in a fixed order and can contain
   * more than one redacted token.
   *
   * @param value display text or summary text to scrub
   * @return redacted text with supported sensitive patterns replaced by stable placeholders
   */
  static String redact(String value) {
    if (value == null || value.isEmpty()) {
      return value;
    }
    String redacted = redactPrivateInsertUris(value);
    redacted = TOKEN_ASSIGNMENT.matcher(redacted).replaceAll("[redacted-secret]");
    return redactLocalPaths(redacted);
  }

  private static String redactPrivateInsertUris(String value) {
    StringBuilder redacted = null;
    int copyFrom = 0;
    int index = 0;
    while (index < value.length()) {
      int uriEnd = privateInsertUriEnd(value, index);
      if (uriEnd > index) {
        if (redacted == null) {
          redacted = new StringBuilder(value.length());
        }
        redacted.append(value, copyFrom, index).append(REDACTED_PRIVATE_URI);
        index = uriEnd;
        copyFrom = uriEnd;
      } else {
        index++;
      }
    }
    if (redacted == null) {
      return value;
    }
    return redacted.append(value, copyFrom, value.length()).toString();
  }

  private static int privateInsertUriEnd(String value, int start) {
    if (!startsPrivateInsertUri(value, start)) {
      return -1;
    }
    int index = start + 4;
    while (index < value.length() && isPrivateUriCharacter(value.charAt(index))) {
      index++;
    }
    return index > start + 4 ? index : -1;
  }

  private static boolean startsPrivateInsertUri(String value, int start) {
    return start + 4 <= value.length()
        && hasAsciiWordBoundaryBefore(value, start)
        && (value.regionMatches(true, start, "CHK@", 0, 4)
            || value.regionMatches(true, start, "SSK@", 0, 4)
            || value.regionMatches(true, start, "USK@", 0, 4)
            || value.regionMatches(true, start, "KSK@", 0, 4));
  }

  private static boolean isPrivateUriCharacter(char value) {
    return isAsciiAlphanumeric(value)
        || value == '~'
        || value == '_'
        || value == '.'
        || value == ','
        || value == '%'
        || value == ':'
        || value == '/'
        || value == '+'
        || value == '-';
  }

  private static String redactLocalPaths(String value) {
    StringBuilder redacted = null;
    int copyFrom = 0;
    int index = 0;
    while (index < value.length()) {
      int pathEnd = localPathEnd(value, index);
      if (pathEnd > index) {
        if (redacted == null) {
          redacted = new StringBuilder(value.length());
        }
        redacted.append(value, copyFrom, index).append(REDACTED_LOCAL_PATH);
        index = pathEnd;
        copyFrom = pathEnd;
      } else {
        index++;
      }
    }
    if (redacted == null) {
      return value;
    }
    return redacted.append(value, copyFrom, value.length()).toString();
  }

  private static int localPathEnd(String value, int start) {
    int windowsEnd = windowsPathEnd(value, start);
    return windowsEnd > start ? windowsEnd : unixPathEnd(value, start);
  }

  private static int windowsPathEnd(String value, int start) {
    if (!startsWindowsPath(value, start)) {
      return -1;
    }
    int index = start + 3;
    int segments = 0;
    boolean readingSegments = true;
    while (index < value.length() && readingSegments) {
      int segmentStart = index;
      index = windowsSegmentEnd(value, index);
      if (index == segmentStart) {
        return -1;
      }
      segments++;
      readingSegments = hasWindowsSegmentAfterSeparator(value, index);
      index += readingSegments ? 1 : 0;
    }
    return segments >= 2 ? index : -1;
  }

  private static int windowsSegmentEnd(String value, int start) {
    int index = start;
    while (index < value.length()
        && value.charAt(index) != '\\'
        && !Character.isWhitespace(value.charAt(index))) {
      index++;
    }
    return index;
  }

  private static boolean hasWindowsSegmentAfterSeparator(String value, int separatorIndex) {
    return separatorIndex < value.length()
        && value.charAt(separatorIndex) == '\\'
        && separatorIndex + 1 < value.length()
        && value.charAt(separatorIndex + 1) != '\\'
        && !Character.isWhitespace(value.charAt(separatorIndex + 1));
  }

  private static boolean startsWindowsPath(String value, int start) {
    return start + 2 < value.length()
        && hasAsciiWordBoundaryBefore(value, start)
        && isAsciiLetter(value.charAt(start))
        && value.charAt(start + 1) == ':'
        && value.charAt(start + 2) == '\\';
  }

  private static int unixPathEnd(String value, int start) {
    if (value.charAt(start) != '/' || (start > 0 && isAsciiAlphanumeric(value.charAt(start - 1)))) {
      return -1;
    }
    int index = start + 1;
    int segments = 0;
    boolean readingSegments = true;
    while (index < value.length() && readingSegments) {
      int segmentStart = index;
      index = unixSegmentEnd(value, index);
      if (index == segmentStart) {
        return -1;
      }
      segments++;
      readingSegments = hasUnixSegmentAfterSeparator(value, index);
      index += readingSegments ? 1 : 0;
    }
    return segments >= 3 ? index : -1;
  }

  private static int unixSegmentEnd(String value, int start) {
    int index = start;
    while (index < value.length() && isUnixPathCharacter(value.charAt(index))) {
      index++;
    }
    return index;
  }

  private static boolean hasUnixSegmentAfterSeparator(String value, int separatorIndex) {
    return separatorIndex < value.length()
        && value.charAt(separatorIndex) == '/'
        && separatorIndex + 1 < value.length()
        && isUnixPathCharacter(value.charAt(separatorIndex + 1));
  }

  private static boolean isUnixPathCharacter(char value) {
    return isAsciiAlphanumeric(value) || value == '.' || value == '_' || value == '-';
  }

  private static boolean hasAsciiWordBoundaryBefore(String value, int start) {
    return start == 0 || isAsciiWordBoundary(value.charAt(start - 1));
  }

  private static boolean isAsciiWordBoundary(char value) {
    return !isAsciiAlphanumeric(value) && value != '_';
  }

  private static boolean isAsciiAlphanumeric(char value) {
    return isAsciiLetter(value) || ('0' <= value && value <= '9');
  }

  private static boolean isAsciiLetter(char value) {
    return ('A' <= value && value <= 'Z') || ('a' <= value && value <= 'z');
  }
}
