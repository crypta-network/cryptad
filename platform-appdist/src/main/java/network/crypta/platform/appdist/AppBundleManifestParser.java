package network.crypta.platform.appdist;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Properties;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Parser and validator for the v1 staged-bundle manifest format.
 *
 * <p>This keeps the signed-bundle tooling aligned with AppHost's narrow manifest semantics without
 * introducing an upward dependency on AppHost classes. The parser accepts the properties-style
 * syntax used by {@code cryptad-app.properties}, strips a leading UTF-8 byte-order mark, preserves
 * literal Windows backslashes in {@code app.exec} where Java {@link Properties#load} would treat
 * them as escapes, and still decodes ordinary escaped text for other fields.
 *
 * <p>Validation is intentionally strict because the manifest is part of the signed payload. Missing
 * required keys, blank optional values, unsupported schema versions, invalid permissions, unsafe
 * executable paths, and executable paths that point at distribution sidecars are rejected before
 * the bundle can be digested or installed. Filesystem launchability checks live in {@link
 * AppBundleStructureValidator}; this class only validates manifest syntax and normalized values.
 */
public final class AppBundleManifestParser {
  /**
   * Canonical manifest filename stored at the bundle root.
   *
   * <p>This file is always included in the digest sidecar, so changes to manifest metadata after
   * signing invalidate the bundle.
   */
  public static final String MANIFEST_FILE_NAME = "cryptad-app.properties";

  private static final char UTF_8_BOM = '\uFEFF';
  private static final Pattern PERMISSION_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final Pattern WINDOWS_DRIVE_PREFIX_PATTERN = Pattern.compile("^[a-zA-Z]:.*");

  private AppBundleManifestParser() {}

  /**
   * Parses a manifest from UTF-8 text content.
   *
   * <p>This entry point is useful for tests and callers that already loaded the manifest text. It
   * applies the same syntax rules as {@link #parse(Path)}, including BOM removal, comment handling,
   * key/value separator parsing, and manifest field validation.
   *
   * @param content manifest content in the supported properties-style syntax
   * @return validated staged-bundle manifest snapshot with normalized field values
   * @throws IOException if the manifest content is invalid, incomplete, or unsupported
   */
  public static AppBundleManifest parseContent(String content) throws IOException {
    return parse(parseProperties(stripLeadingBom(content)));
  }

  /**
   * Parses a manifest from an on-disk properties file.
   *
   * <p>The manifest path must be a regular file and must not be a symbolic link. This prevents
   * staged bundles from pointing manifest parsing at content outside the bundle tree before the
   * digest writer or AppHost performs its broader directory-boundary checks.
   *
   * @param manifestFile path to {@code cryptad-app.properties}
   * @return validated staged-bundle manifest snapshot with normalized field values
   * @throws IOException if the file cannot be read safely or the manifest content is invalid
   */
  public static AppBundleManifest parse(Path manifestFile) throws IOException {
    if (Files.isSymbolicLink(manifestFile)) {
      throw new AppDistributionException("manifest file must not be a symlink: " + manifestFile);
    }
    if (!Files.isRegularFile(manifestFile, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppDistributionException("missing manifest file: " + manifestFile);
    }
    return parseContent(Files.readString(manifestFile));
  }

  private static Properties parseProperties(String content) throws IOException {
    Properties properties = new Properties();
    try (BufferedReader reader = new BufferedReader(new StringReader(content))) {
      String line;
      int lineNumber = 0;
      while ((line = reader.readLine()) != null) {
        lineNumber++;
        parsePropertyLine(properties, line, lineNumber);
      }
      return properties;
    }
  }

  private static String stripLeadingBom(String content) {
    if (!content.isEmpty() && content.charAt(0) == UTF_8_BOM) {
      return content.substring(1);
    }
    return content;
  }

  private static void parsePropertyLine(Properties properties, String line, int lineNumber)
      throws AppDistributionException {
    String trimmedLine = line.trim();
    if (trimmedLine.isEmpty() || trimmedLine.startsWith("#") || trimmedLine.startsWith("!")) {
      return;
    }
    int separatorIndex = findSeparatorIndex(line);
    if (separatorIndex < 0) {
      throw new AppDistributionException("invalid manifest line " + lineNumber + ": " + line);
    }
    String key =
        decodePropertiesComponent(line.substring(0, separatorIndex).trim(), lineNumber, true, true);
    if (key.isEmpty()) {
      throw new AppDistributionException("invalid manifest line " + lineNumber + ": " + line);
    }
    String rawValue = line.substring(separatorIndex + 1).trim();
    String value =
        decodePropertiesComponent(
            rawValue, lineNumber, false, shouldDecodeUnicodeEscapesInValue(key, rawValue));
    properties.setProperty(key, value);
  }

  private static boolean shouldDecodeUnicodeEscapesInValue(String key, String rawValue) {
    if (!key.equals("app.exec")) {
      return true;
    }
    return rawValue.contains("/")
        || rawValue.contains("\\\\")
        || rawValue.startsWith("\\u")
        || rawValue.startsWith("\\U")
        || (containsUnicodeEscape(rawValue) && !containsPlainBackslash(rawValue));
  }

  private static boolean containsUnicodeEscape(String rawValue) {
    for (int index = 0; index + 5 < rawValue.length(); index++) {
      if (rawValue.charAt(index) == '\\'
          && (rawValue.charAt(index + 1) == 'u' || rawValue.charAt(index + 1) == 'U')
          && isHexSequence(rawValue, index + 2)) {
        return true;
      }
    }
    return false;
  }

  private static boolean containsPlainBackslash(String rawValue) {
    for (int index = 0; index < rawValue.length() - 1; index++) {
      if (rawValue.charAt(index) == '\\'
          && rawValue.charAt(index + 1) != 'u'
          && rawValue.charAt(index + 1) != 'U') {
        return true;
      }
    }
    return false;
  }

  private static boolean isHexSequence(String rawValue, int startIndex) {
    if (startIndex + 4 > rawValue.length()) {
      return false;
    }
    for (int offset = 0; offset < 4; offset++) {
      if (Character.digit(rawValue.charAt(startIndex + offset), 16) < 0) {
        return false;
      }
    }
    return true;
  }

  private static int findSeparatorIndex(String line) {
    int equalsIndex = line.indexOf('=');
    int colonIndex = line.indexOf(':');
    if (equalsIndex < 0) {
      return colonIndex;
    }
    if (colonIndex < 0) {
      return equalsIndex;
    }
    return Math.min(equalsIndex, colonIndex);
  }

  private static String decodePropertiesComponent(
      String text, int lineNumber, boolean decodeControlEscapes, boolean decodeUnicodeEscapes)
      throws AppDistributionException {
    StringBuilder decoded = new StringBuilder(text.length());
    int index = 0;
    while (index < text.length()) {
      char character = text.charAt(index);
      if (character != '\\' || index + 1 >= text.length()) {
        decoded.append(character);
        index++;
      } else {
        index =
            appendEscapedCharacter(
                decoded, text, index, lineNumber, decodeControlEscapes, decodeUnicodeEscapes);
      }
    }
    return decoded.toString();
  }

  private static int appendEscapedCharacter(
      StringBuilder decoded,
      String text,
      int escapeIndex,
      int lineNumber,
      boolean decodeControlEscapes,
      boolean decodeUnicodeEscapes)
      throws AppDistributionException {
    int nextIndex = escapeIndex + 1;
    char escaped = text.charAt(nextIndex);
    switch (escaped) {
      case 't' -> appendControlEscape(decoded, escaped, '\t', decodeControlEscapes);
      case 'n' -> appendControlEscape(decoded, escaped, '\n', decodeControlEscapes);
      case 'r' -> appendControlEscape(decoded, escaped, '\r', decodeControlEscapes);
      case 'f' -> appendControlEscape(decoded, escaped, '\f', decodeControlEscapes);
      case '\\' -> decoded.append('\\');
      case ' ' -> decoded.append(' ');
      case ':', '=', '#', '!' -> decoded.append(escaped);
      case 'u' -> {
        if (decodeUnicodeEscapes) {
          decoded.append(decodeUnicodeEscape(text, nextIndex, lineNumber));
          nextIndex += 4;
        } else {
          decoded.append('\\').append(escaped);
        }
      }
      default -> decoded.append('\\').append(escaped);
    }
    return nextIndex + 1;
  }

  private static void appendControlEscape(
      StringBuilder decoded, char escaped, char decodedValue, boolean decodeControlEscapes) {
    if (decodeControlEscapes) {
      decoded.append(decodedValue);
    } else {
      decoded.append('\\').append(escaped);
    }
  }

  private static char decodeUnicodeEscape(String text, int escapeStartIndex, int lineNumber)
      throws AppDistributionException {
    if (escapeStartIndex + 4 >= text.length()) {
      throw new AppDistributionException("invalid unicode escape in manifest line " + lineNumber);
    }
    int codePoint = 0;
    for (int offset = 1; offset <= 4; offset++) {
      int digit = Character.digit(text.charAt(escapeStartIndex + offset), 16);
      if (digit < 0) {
        throw new AppDistributionException("invalid unicode escape in manifest line " + lineNumber);
      }
      codePoint = (codePoint << 4) + digit;
    }
    return (char) codePoint;
  }

  private static AppBundleManifest parse(Properties properties) throws AppDistributionException {
    int manifestVersion = parseRequiredVersion(properties);
    String appId = required(properties, "app.id");
    String appName = required(properties, "app.name");
    String appVersion = required(properties, "app.version");
    String execPathText = normalizeExecPath(required(properties, "app.exec"));
    AppUiMode uiMode = parseUiMode(optional(properties, "app.ui.mode"));
    String uiEntry = optionalUiEntry(properties);
    List<String> permissions = parsePermissions(optional(properties, "app.permissions"));
    Long dataQuotaBytes = parseOptionalLong(properties, "quota.data.bytes");
    Long cacheQuotaBytes = parseOptionalLong(properties, "quota.cache.bytes");
    AppRestartPolicy restartPolicy = parseRestartPolicy(optional(properties, "app.restart.policy"));
    int restartMaxAttempts = parseRestartMaxAttempts(properties);
    long restartBackoffMillis = parseRestartBackoffMillis(properties);
    try {
      return new AppBundleManifest(
          manifestVersion,
          appId,
          appName,
          appVersion,
          execPathText,
          uiMode,
          uiEntry,
          permissions,
          dataQuotaBytes,
          cacheQuotaBytes,
          restartPolicy,
          restartMaxAttempts,
          restartBackoffMillis);
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException(exception.getMessage(), exception);
    }
  }

  private static AppRestartPolicy parseRestartPolicy(String rawValue)
      throws AppDistributionException {
    try {
      return AppRestartPolicy.parseManifestValue(rawValue);
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException(exception.getMessage(), exception);
    }
  }

  private static AppUiMode parseUiMode(String rawValue) throws AppDistributionException {
    try {
      return AppUiMode.parseManifestValue(rawValue);
    } catch (IllegalArgumentException exception) {
      throw new AppDistributionException(exception.getMessage(), exception);
    }
  }

  private static int parseRequiredVersion(Properties properties) throws AppDistributionException {
    String value = required(properties, "manifest.version");
    try {
      int version = Integer.parseInt(value);
      if (version != 1) {
        throw new AppDistributionException("unsupported manifest.version: " + value);
      }
      return version;
    } catch (NumberFormatException exception) {
      throw new AppDistributionException("invalid manifest.version: " + value, exception);
    }
  }

  private static String normalizeExecPath(String rawValue) throws AppDistributionException {
    String normalized = rawValue.trim().replace('\\', '/');
    if (normalized.isEmpty()) {
      throw new AppDistributionException("app.exec must not be blank");
    }
    if (normalized.startsWith("/")
        || normalized.startsWith("\\")
        || WINDOWS_DRIVE_PREFIX_PATTERN.matcher(normalized).matches()) {
      throw new AppDistributionException("app.exec must be relative: " + rawValue);
    }
    ArrayList<String> normalizedSegments = new ArrayList<>();
    StringBuilder current = new StringBuilder();
    for (int index = 0; index < normalized.length(); index++) {
      char character = normalized.charAt(index);
      if (character == '/') {
        addExecSegment(normalizedSegments, current, rawValue);
      } else {
        current.append(character);
      }
    }
    addExecSegment(normalizedSegments, current, rawValue);
    for (String segment : normalizedSegments) {
      if (segment.isBlank()) {
        throw new AppDistributionException("app.exec must be normalized: " + rawValue);
      }
      if (segment.equals(".") || segment.equals("..")) {
        throw new AppDistributionException("app.exec must stay under the app root: " + rawValue);
      }
    }
    String execPath = String.join("/", normalizedSegments);
    if (AppDistributionSidecars.isDistributionSidecar(execPath)) {
      throw new AppDistributionException(
          "app.exec must not point at distribution sidecar: " + execPath);
    }
    return execPath;
  }

  private static List<String> parsePermissions(String rawPermissions)
      throws AppDistributionException {
    if (rawPermissions == null) {
      return List.of();
    }
    LinkedHashSet<String> normalized = new LinkedHashSet<>();
    StringBuilder current = new StringBuilder();
    for (int index = 0; index < rawPermissions.length(); index++) {
      char character = rawPermissions.charAt(index);
      if (character == ',') {
        addPermission(normalized, current, rawPermissions);
      } else {
        current.append(character);
      }
    }
    addPermission(normalized, current, rawPermissions);
    return List.copyOf(normalized);
  }

  private static void addExecSegment(
      List<String> normalizedSegments, StringBuilder current, String rawValue)
      throws AppDistributionException {
    String segment = current.toString();
    current.setLength(0);
    if (segment.isBlank()) {
      throw new AppDistributionException("app.exec must be normalized: " + rawValue);
    }
    normalizedSegments.add(segment);
  }

  private static void addPermission(
      Set<String> normalized, StringBuilder current, String rawPermissions)
      throws AppDistributionException {
    String permission = current.toString().trim().toLowerCase(Locale.ROOT);
    current.setLength(0);
    if (permission.isEmpty()) {
      throw new AppDistributionException("app.permissions must not contain blank entries");
    }
    if (!PERMISSION_PATTERN.matcher(permission).matches()) {
      throw new AppDistributionException("invalid permission in manifest: " + rawPermissions);
    }
    normalized.add(permission);
  }

  private static Long parseOptionalLong(Properties properties, String key)
      throws AppDistributionException {
    String value = optional(properties, key);
    if (value == null) {
      return null;
    }
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException exception) {
      throw new AppDistributionException("invalid " + key + ": " + value, exception);
    }
  }

  private static int parseRestartMaxAttempts(Properties properties)
      throws AppDistributionException {
    String key = "app.restart.maxAttempts";
    String value = optional(properties, key);
    if (value == null) {
      return 0;
    }
    try {
      int parsed = Integer.parseInt(value);
      if (parsed < 0) {
        throw new AppDistributionException(key + " must be >= 0");
      }
      return parsed;
    } catch (NumberFormatException exception) {
      throw new AppDistributionException("invalid " + key + ": " + value, exception);
    }
  }

  private static long parseRestartBackoffMillis(Properties properties)
      throws AppDistributionException {
    String key = "app.restart.backoff.ms";
    String value = optional(properties, key);
    if (value == null) {
      return 0L;
    }
    try {
      long parsed = Long.parseLong(value);
      if (parsed < 0L) {
        throw new AppDistributionException(key + " must be >= 0");
      }
      return parsed;
    } catch (NumberFormatException exception) {
      throw new AppDistributionException("invalid " + key + ": " + value, exception);
    }
  }

  private static String required(Properties properties, String key)
      throws AppDistributionException {
    String value = optional(properties, key);
    if (value == null) {
      throw new AppDistributionException("missing " + key);
    }
    return value;
  }

  private static String optional(Properties properties, String key)
      throws AppDistributionException {
    String value = properties.getProperty(key);
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    if (trimmed.isEmpty()) {
      throw new AppDistributionException(key + " must not be blank");
    }
    return trimmed;
  }

  private static String optionalUiEntry(Properties properties) throws AppDistributionException {
    String value = properties.getProperty("app.ui.entry");
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    if (trimmed.isEmpty()) {
      throw new AppDistributionException("app.ui.entry must not be blank");
    }
    return trimmed;
  }
}
