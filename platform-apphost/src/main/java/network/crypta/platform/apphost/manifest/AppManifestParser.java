package network.crypta.platform.apphost.manifest;

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
 * Parser and validator for the v1 app-host manifest format.
 *
 * <p>{@code AppManifestParser} converts the narrow properties-style {@code cryptad-app.properties}
 * format into an immutable {@link AppManifest}. The parser does not delegate blindly to the full
 * Java properties reader because AppHost needs tighter control over escaping, UTF-8 handling,
 * backslash preservation for Windows-style paths, and the small subset of keys that are valid for
 * the v1 manifest schema.
 *
 * <p>Parsing is intentionally strict. The parser rejects missing required properties, unsupported
 * schema versions, malformed numeric values, invalid permission identifiers, unsafe executable
 * paths, and ambiguous or blank values before runtime code is allowed to inspect the manifest. That
 * keeps bundle validation failures close to the source file and gives callers a deterministic
 * checked exception model.
 */
public final class AppManifestParser {
  /** Canonical manifest filename stored at the installed app root. */
  public static final String MANIFEST_FILE_NAME = "cryptad-app.properties";

  private static final char UTF_8_BOM = '\uFEFF';
  private static final Pattern PERMISSION_PATTERN =
      Pattern.compile("[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?");
  private static final Pattern WINDOWS_DRIVE_PREFIX_PATTERN = Pattern.compile("^[a-zA-Z]:.*");

  private AppManifestParser() {}

  /**
   * Parses a manifest from UTF-8 text content.
   *
   * <p>The manifest intentionally uses a narrow key/value syntax instead of Java's full {@link
   * Properties#load(java.io.Reader)} behavior so UTF-8 characters and literal backslashes survive
   * round-tripping before field validation normalizes them.
   *
   * @param content manifest content in properties-style syntax
   * @return the validated manifest snapshot
   * @throws IOException if the manifest content is invalid, incomplete, or cannot be normalized
   *     into the AppHost v1 manifest model
   */
  public static AppManifest parseContent(String content) throws IOException {
    return parse(parseProperties(stripLeadingBom(content)));
  }

  /**
   * Parses a manifest from an on-disk properties file.
   *
   * <p>The path must refer to a regular file and must not be a symbolic link. Callers that validate
   * a staged or installed bundle can therefore use this entry point without accidentally following
   * a manifest that escapes the intended bundle tree.
   *
   * @param manifestFile path to {@code cryptad-app.properties}
   * @return the validated manifest snapshot
   * @throws IOException if the file cannot be read safely or the manifest content is invalid
   */
  public static AppManifest parse(Path manifestFile) throws IOException {
    if (Files.isSymbolicLink(manifestFile)) {
      throw new AppManifestException("manifest file must not be a symlink: " + manifestFile);
    }
    if (!Files.isRegularFile(manifestFile, LinkOption.NOFOLLOW_LINKS)) {
      throw new AppManifestException("missing manifest file: " + manifestFile);
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
      throws AppManifestException {
    String trimmedLine = line.trim();
    if (trimmedLine.isEmpty() || trimmedLine.startsWith("#") || trimmedLine.startsWith("!")) {
      return;
    }
    int separatorIndex = findSeparatorIndex(line);
    if (separatorIndex < 0) {
      throw new AppManifestException("invalid manifest line " + lineNumber + ": " + line);
    }
    String key =
        decodePropertiesComponent(line.substring(0, separatorIndex).trim(), lineNumber, true, true);
    if (key.isEmpty()) {
      throw new AppManifestException("invalid manifest line " + lineNumber + ": " + line);
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
      throws AppManifestException {
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
      throws AppManifestException {
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
          decoded.append('\\');
          decoded.append(escaped);
        }
      }
      default -> {
        decoded.append('\\');
        decoded.append(escaped);
      }
    }
    return nextIndex + 1;
  }

  private static void appendControlEscape(
      StringBuilder decoded, char escaped, char decodedCharacter, boolean decodeControlEscapes) {
    if (decodeControlEscapes) {
      decoded.append(decodedCharacter);
    } else {
      decoded.append('\\');
      decoded.append(escaped);
    }
  }

  private static char decodeUnicodeEscape(String text, int escapeStartIndex, int lineNumber)
      throws AppManifestException {
    if (escapeStartIndex + 4 >= text.length()) {
      throw new AppManifestException("invalid unicode escape in manifest line " + lineNumber);
    }
    int codePoint = 0;
    for (int offset = 1; offset <= 4; offset++) {
      int digit = Character.digit(text.charAt(escapeStartIndex + offset), 16);
      if (digit < 0) {
        throw new AppManifestException("invalid unicode escape in manifest line " + lineNumber);
      }
      codePoint = (codePoint << 4) + digit;
    }
    return (char) codePoint;
  }

  private static AppManifest parse(Properties properties) throws AppManifestException {
    int manifestVersion = parseRequiredVersion(properties);
    String appId = required(properties, "app.id");
    String appName = required(properties, "app.name");
    String appVersion = required(properties, "app.version");
    String execPathText = normalizeExecPath(required(properties, "app.exec"));
    String uiEntry = optional(properties, "app.ui.entry");
    List<String> permissions = parsePermissions(optional(properties, "app.permissions"));
    Long dataQuotaBytes = parseOptionalLong(properties, "quota.data.bytes");
    Long cacheQuotaBytes = parseOptionalLong(properties, "quota.cache.bytes");
    try {
      return new AppManifest(
          manifestVersion,
          appId,
          appName,
          appVersion,
          execPathText,
          uiEntry,
          permissions,
          dataQuotaBytes,
          cacheQuotaBytes);
    } catch (IllegalArgumentException e) {
      throw new AppManifestException(e.getMessage(), e);
    }
  }

  private static int parseRequiredVersion(Properties properties) throws AppManifestException {
    String value = required(properties, "manifest.version");
    try {
      int version = Integer.parseInt(value);
      if (version != 1) {
        throw new AppManifestException("unsupported manifest.version: " + value);
      }
      return version;
    } catch (NumberFormatException e) {
      throw new AppManifestException("invalid manifest.version: " + value, e);
    }
  }

  private static String normalizeExecPath(String rawValue) throws AppManifestException {
    String normalized = rawValue.trim().replace('\\', '/');
    if (normalized.isEmpty()) {
      throw new AppManifestException("app.exec must not be blank");
    }
    if (normalized.startsWith("/")
        || normalized.startsWith("\\")
        || WINDOWS_DRIVE_PREFIX_PATTERN.matcher(normalized).matches()) {
      throw new AppManifestException("app.exec must be relative: " + rawValue);
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
        throw new AppManifestException("app.exec must be normalized: " + rawValue);
      }
      if (segment.equals(".") || segment.equals("..")) {
        throw new AppManifestException("app.exec must stay under the app root: " + rawValue);
      }
    }
    return String.join("/", normalizedSegments);
  }

  private static List<String> parsePermissions(String rawPermissions) throws AppManifestException {
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
      throws AppManifestException {
    String segment = current.toString();
    current.setLength(0);
    if (segment.isBlank()) {
      throw new AppManifestException("app.exec must be normalized: " + rawValue);
    }
    normalizedSegments.add(segment);
  }

  private static void addPermission(
      Set<String> normalized, StringBuilder current, String rawPermissions)
      throws AppManifestException {
    String permission = current.toString().trim().toLowerCase(Locale.ROOT);
    current.setLength(0);
    if (permission.isEmpty()) {
      throw new AppManifestException("app.permissions must not contain blank entries");
    }
    if (!PERMISSION_PATTERN.matcher(permission).matches()) {
      throw new AppManifestException("invalid app.permissions entry: " + rawPermissions);
    }
    normalized.add(permission);
  }

  private static Long parseOptionalLong(Properties properties, String key)
      throws AppManifestException {
    String value = optional(properties, key);
    if (value == null) {
      return null;
    }
    try {
      long parsed = Long.parseLong(value);
      if (parsed < 0L) {
        throw new AppManifestException(key + " must be >= 0");
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new AppManifestException("invalid " + key + ": " + value, e);
    }
  }

  private static String required(Properties properties, String key) throws AppManifestException {
    String value = optional(properties, key);
    if (value == null) {
      throw new AppManifestException("missing required property: " + key);
    }
    return value;
  }

  private static String optional(Properties properties, String key) throws AppManifestException {
    String value = properties.getProperty(key);
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    if (trimmed.isEmpty()) {
      throw new AppManifestException(key + " must not be blank");
    }
    return trimmed;
  }
}
