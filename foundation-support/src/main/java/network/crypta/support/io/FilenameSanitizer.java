package network.crypta.support.io;

import java.nio.CharBuffer;
import java.nio.charset.Charset;
import network.crypta.support.StringValidityChecker;

/**
 * Pure filename sanitization helpers.
 *
 * <p>This utility contains only the string- and charset-level rules needed to turn an arbitrary
 * user-facing name into a filesystem-safe suggestion. It is shared by {@link FileUtil} and by
 * leaf-friendly callers that need filename sanitization without inheriting broader file utility
 * dependencies such as MIME detection, runtime startup helpers, or temporary-file management.
 *
 * <p>The implementation is deliberately side-effect free. It performs character filtering,
 * platform-specific reserved-name handling, and whitespace cleanup, but it does not touch the
 * filesystem, inspect directories, or guarantee uniqueness. Callers that need collision handling or
 * path construction must layer that behavior on top.
 */
public final class FilenameSanitizer {

  private FilenameSanitizer() {}

  /**
   * Produces a safe filename for the supplied platform flags.
   *
   * <p>The sanitizer first drops characters that cannot be represented in the supplied charset,
   * then replaces control characters, whitespace, platform-reserved filename characters, and any
   * explicitly forbidden extra characters with a fallback replacement character. After that it
   * applies Windows-specific trailing-character and reserved-basename rules and finally trims any
   * leading or trailing whitespace introduced by charset decoding.
   *
   * <p>The returned value is a single filename suggestion, not a path. It may still need further
   * handling for collisions, length limits imposed by a specific filesystem, or caller-specific
   * naming policies.
   *
   * @param fileName input filename candidate to sanitize into a single filesystem-safe name
   * @param fileNameCharset charset used to discard characters that cannot be represented
   * @param windowsLike whether Windows filename restrictions should be enforced
   * @param macLike whether macOS filename restrictions should be enforced
   * @param unixLike whether Unix filename restrictions should be enforced
   * @param extraChars additional caller-specified characters to replace regardless of platform
   * @return a sanitized filename suggestion derived from {@code fileName}
   * @throws IllegalArgumentException if {@code extraChars} forbids every supported replacement
   *     character for substituted content
   */
  public static String sanitizeFileName(
      String fileName,
      Charset fileNameCharset,
      boolean windowsLike,
      boolean macLike,
      boolean unixLike,
      String extraChars) {
    // Filter out any characters that do not exist in the charset.
    CharBuffer buffer =
        fileNameCharset.decode(fileNameCharset.encode(fileName)); // Charsets are thread-safe

    StringBuilder sb = new StringBuilder(fileName.length() + 1);
    char def = chooseDefaultReplacement(extraChars);

    for (char c : buffer.array()) { // Note that this will add extra whitespace to the end, which
      // we will trim later.
      boolean replace = shouldReplaceChar(c, windowsLike, macLike, unixLike, extraChars);
      sb.append(replace ? def : c);
    }

    // On Windows, a filename must not end with a space or dot; remove any trailing instances.
    trimWindowsTrailingSpaceDot(sb, windowsLike);

    // Avoid Windows reserved basenames (e.g., CON, NUL) by prefixing an underscore when needed.
    fixWindowsReservedBasename(sb, windowsLike);

    if (sb.isEmpty()) {
      sb.append("Invalid filename"); // Note: not localized
    }

    return sb.toString().trim(); // Trim leading and trailing whitespace.
    // Some of the trailing whitespace may be from the CharBuffer.
  }

  private static char chooseDefaultReplacement(String extraChars) {
    if (extraChars.indexOf(' ') == -1) return ' ';
    if (extraChars.indexOf('_') == -1) return '_';
    if (extraChars.indexOf('-') == -1) return '-';
    throw new IllegalArgumentException("What do you want me to use instead of spaces???");
  }

  private static boolean isReservedForAnyOS(char c) {
    return StringValidityChecker.isWindowsReservedPrintableFilenameCharacter(c)
        || StringValidityChecker.isMacOSReservedPrintableFilenameCharacter(c)
        || StringValidityChecker.isUnixReservedPrintableFilenameCharacter(c);
  }

  private static boolean isReservedForOS(
      boolean windowsLike, boolean macLike, boolean unixLike, char c) {
    if (windowsLike && StringValidityChecker.isWindowsReservedPrintableFilenameCharacter(c))
      return true;
    if (macLike && StringValidityChecker.isMacOSReservedPrintableFilenameCharacter(c)) return true;
    return unixLike && StringValidityChecker.isUnixReservedPrintableFilenameCharacter(c);
  }

  private static boolean shouldReplaceChar(
      char c, boolean windowsLike, boolean macLike, boolean unixLike, String extraChars) {
    boolean anyOs = windowsLike || macLike || unixLike;
    return extraChars.indexOf(c) != -1
        || Character.getType(c) == Character.CONTROL
        || Character.isWhitespace(c)
        || (anyOs ? isReservedForOS(windowsLike, macLike, unixLike, c) : isReservedForAnyOS(c));
  }

  private static void trimWindowsTrailingSpaceDot(StringBuilder sb, boolean windowsLike) {
    if (windowsLike) {
      int lastCharIndex = sb.length() - 1;
      while (lastCharIndex >= 0) {
        char lastChar = sb.charAt(lastCharIndex);
        if (lastChar == ' ' || lastChar == '.') sb.deleteCharAt(lastCharIndex--);
        else break;
      }
    }
  }

  private static void fixWindowsReservedBasename(StringBuilder sb, boolean windowsLike) {
    if (windowsLike && StringValidityChecker.isWindowsReservedFilename(sb.toString())) {
      sb.insert(0, '_');
    }
  }
}
