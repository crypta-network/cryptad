package network.crypta.platform.appdist;

import java.nio.file.Path;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Represents the relative bundle entrypoint declared for an app-data migration step.
 *
 * <p>This value object is part of the signed manifest model, so it validates the command before a
 * bundle can be accepted. The stored value is a normalized path inside the bundle, not a shell
 * string. Runtime code supplies migration mode, schema bounds, namespace, and payload locations
 * through platform-generated environment variables instead of parsing author-controlled arguments.
 *
 * <p>The validation is intentionally conservative and host-independent. It rejects absolute paths,
 * traversal, empty segments, Windows drive prefixes, control characters, and colon-containing
 * segments before bundle signing or catalog staging can turn the declaration into executable update
 * behavior.
 *
 * @param pathText normalized relative command path inside the signed app bundle
 */
public record AppDataMigrationCommand(String pathText) {
  /** Windows drive prefix pattern rejected even when parsing manifests on Unix hosts. */
  private static final Pattern WINDOWS_DRIVE_PREFIX_PATTERN = Pattern.compile("^[a-zA-Z]:.*");

  /**
   * Creates a normalized relative migration command path.
   *
   * <p>The value is a bundle path, not a shell command. Arguments are supplied later by the
   * platform through fixed environment variables, so whitespace and shell metacharacters have no
   * special meaning here. Absolute paths, traversal, blank segments, control characters, and
   * Windows drive prefixes are rejected before the manifest can be signed.
   *
   * @param pathText relative command path declared in {@code cryptad-app.properties}
   */
  public AppDataMigrationCommand {
    pathText = normalizePath(pathText);
  }

  /**
   * Returns the migration command as a normalized relative path.
   *
   * @return relative bundle path for the migration entrypoint
   */
  public Path path() {
    return Path.of(pathText).normalize();
  }

  /**
   * Normalizes and validates the raw manifest command path.
   *
   * <p>The returned string always uses forward slashes. Backslashes are treated as path separators
   * so Windows-authored manifests cannot smuggle alternate traversal syntax into a Unix runtime.
   *
   * @param rawValue command path value read from the signed manifest properties
   * @return normalized relative path text safe to resolve under a bundle root
   * @throws NullPointerException when {@code rawValue} is {@code null}
   * @throws IllegalArgumentException when the path is blank, absolute, or unsafe
   */
  static String normalizePath(String rawValue) {
    Objects.requireNonNull(rawValue, "pathText");
    String normalized = rawValue.trim().replace('\\', '/');
    if (normalized.isEmpty()) {
      throw new IllegalArgumentException("app.data migration command must not be blank");
    }
    if (normalized.startsWith("/")
        || normalized.startsWith("\\")
        || WINDOWS_DRIVE_PREFIX_PATTERN.matcher(normalized).matches()) {
      throw new IllegalArgumentException(
          "app.data migration command must be a relative bundle path");
    }
    String[] segments = normalized.split("/", -1);
    for (String segment : segments) {
      if (segment.isBlank() || segment.equals(".") || segment.equals("..")) {
        throw new IllegalArgumentException(
            "app.data migration command must stay under the app root");
      }
      if (segment.indexOf(':') >= 0 || containsControlCharacter(segment)) {
        throw new IllegalArgumentException(
            "app.data migration command contains an unsafe path segment");
      }
    }
    return String.join("/", segments);
  }

  /**
   * Returns whether a path segment contains ISO control characters.
   *
   * @param segment normalized path segment being validated
   * @return {@code true} when any character is an ISO control character
   */
  private static boolean containsControlCharacter(String segment) {
    for (int index = 0; index < segment.length(); index++) {
      if (Character.isISOControl(segment.charAt(index))) {
        return true;
      }
    }
    return false;
  }
}
