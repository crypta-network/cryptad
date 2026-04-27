package network.crypta.platform.apphost;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Redacts AppHost launch tokens from diagnostic strings and process-log tails.
 *
 * <p>The helper handles the leak shapes AppHost can reasonably recognize: the exact current launch
 * token, environment-style {@code CRYPTAD_APP_TOKEN=...} assignments printed by child processes,
 * and known AppHost-owned filesystem paths for the displayed app.
 *
 * <p>This class is deliberately a display-surface guard, not a parser for arbitrary untrusted log
 * formats. Callers should apply it immediately before exposing runtime diagnostics through APIs, UI
 * text, or log-tail snapshots. The redactor keeps replacement text stable so tests and operator
 * views can distinguish hidden tokens from hidden path roles without learning the underlying secret
 * or host filesystem layout.
 *
 * <p>Bounded log tails need special handling because the requested suffix may begin in the middle
 * of a token or path. Use {@link #redactionOverlapBytes(String, InstalledAppPaths)} to read enough
 * context before redaction, then apply the final display bound after sensitive text has been
 * replaced.
 */
public final class AppHostTokenRedactor {
  /**
   * Stable replacement used wherever launch tokens are hidden from display surfaces.
   *
   * <p>The placeholder is intentionally generic. It confirms that sensitive text was removed while
   * avoiding hints about token length, encoding, or how many distinct token values appeared in the
   * original diagnostic text.
   */
  public static final String REDACTED = "[REDACTED]";

  private static final String APP_INSTALL_DIR_PLACEHOLDER = "[APP_INSTALL_DIR]";
  private static final String APP_DATA_DIR_PLACEHOLDER = "[APP_DATA_DIR]";
  private static final String APP_CACHE_DIR_PLACEHOLDER = "[APP_CACHE_DIR]";
  private static final String APP_RUN_DIR_PLACEHOLDER = "[APP_RUN_DIR]";
  private static final String APP_PROCESS_LOG_PLACEHOLDER = "[APP_PROCESS_LOG]";
  private static final String TOKEN_ASSIGNMENT_PREFIX = "CRYPTAD_APP_TOKEN=";
  private static final int APPHOST_TOKEN_HEX_CHARS = 64;
  private static final int UNKNOWN_TOKEN_ASSIGNMENT_BYTES =
      TOKEN_ASSIGNMENT_PREFIX.length() + APPHOST_TOKEN_HEX_CHARS;
  private static final Pattern TOKEN_ASSIGNMENT_PATTERN =
      Pattern.compile("(CRYPTAD_APP_TOKEN\\s*[:=]\\s*)([^\\s,;\"'\\]}]+)");

  private AppHostTokenRedactor() {}

  /**
   * Redacts obvious AppHost token assignments from text.
   *
   * <p>This overload is useful when the exact launch token is unavailable, such as after daemon
   * restart while an older {@code process.log} remains on disk. It still recognizes common
   * environment-assignment shapes, including {@code CRYPTAD_APP_TOKEN=value} and {@code
   * CRYPTAD_APP_TOKEN: value}. It does not attempt to guess unrelated free-form secrets.
   *
   * @param text source diagnostic text to filter before display
   * @return text with recognizable token assignments redacted
   */
  @SuppressWarnings("unused")
  public static String redact(String text) {
    return redact(text, null);
  }

  /**
   * Redacts obvious AppHost token assignments and the exact current token from text.
   *
   * <p>The exact-token replacement covers cases where an app prints the token outside an
   * environment-assignment form, for example inside a custom debug line. Passing a blank or {@code
   * null} token falls back to assignment-pattern redaction only, which keeps stopped-app log reads
   * possible even when no current launch snapshot exists.
   *
   * @param text source diagnostic text to filter before display
   * @param token exact current or retained launch token, or {@code null} when unavailable
   * @return text with launch tokens redacted where they can be recognized
   */
  public static String redact(String text, String token) {
    Objects.requireNonNull(text, "text");
    String redacted =
        TOKEN_ASSIGNMENT_PATTERN.matcher(text).replaceAll(match -> match.group(1) + REDACTED);
    if (token == null || token.isBlank()) {
      return redacted;
    }
    return redacted.replace(token, REDACTED);
  }

  /**
   * Redacts launch tokens and known AppHost-owned filesystem paths from text.
   *
   * <p>This is intended for process-log display surfaces where an app may have printed its
   * environment or working directory. Replacements preserve the conceptual directory role without
   * exposing the daemon's absolute filesystem layout. The method removes the installed bundle root,
   * mutable data/cache/run directories, and the conventional process-log file path for the app
   * represented by {@code paths}.
   *
   * @param text source diagnostic text to filter before display
   * @param token exact current or retained launch token, or {@code null} when unavailable
   * @param paths AppHost-owned paths for the app whose diagnostic text is being displayed
   * @return text with launch tokens and known AppHost paths redacted
   */
  public static String redact(String text, String token, InstalledAppPaths paths) {
    Objects.requireNonNull(paths, "paths");
    return redactPaths(redact(text, token), paths);
  }

  /**
   * Returns the byte overlap needed to redact a bounded log tail safely.
   *
   * <p>A caller that wants the last {@code maxBytes} of a log should read this many extra bytes
   * before that suffix, redact the expanded text, and then apply the final bound. That ensures the
   * redactor can still see a complete token, recognizable token assignment, or known path when the
   * requested suffix starts in the middle of it.
   *
   * <p>The returned value is based on UTF-8 byte length, because process logs are tailed by bytes
   * before they are decoded for display. The calculation includes a fixed allowance for a
   * 64-character AppHost token assignment even when the exact token is unavailable, plus every
   * known AppHost path spelling that this redactor can replace.
   *
   * @param token exact current or last launch token, or {@code null} when unavailable
   * @param paths AppHost-owned paths for the app whose log is being tailed
   * @return extra bytes to read before the requested suffix before redaction and final trimming
   */
  public static int redactionOverlapBytes(String token, InstalledAppPaths paths) {
    Objects.requireNonNull(paths, "paths");
    int maxSensitiveBytes = UNKNOWN_TOKEN_ASSIGNMENT_BYTES;
    if (token != null && !token.isBlank()) {
      maxSensitiveBytes = Math.max(maxSensitiveBytes, utf8Length(token));
    }
    for (String pathText : allPathTexts(paths)) {
      maxSensitiveBytes = Math.max(maxSensitiveBytes, utf8Length(pathText));
    }
    return maxSensitiveBytes - 1;
  }

  private static String redactPaths(String text, InstalledAppPaths paths) {
    List<PathReplacement> replacements = new ArrayList<>();
    addPathReplacement(replacements, paths.processLogFile(), APP_PROCESS_LOG_PLACEHOLDER);
    addPathReplacement(replacements, paths.installedRoot(), APP_INSTALL_DIR_PLACEHOLDER);
    addPathReplacement(replacements, paths.dataDir(), APP_DATA_DIR_PLACEHOLDER);
    addPathReplacement(replacements, paths.cacheDir(), APP_CACHE_DIR_PLACEHOLDER);
    addPathReplacement(replacements, paths.runDir(), APP_RUN_DIR_PLACEHOLDER);
    replacements.sort(
        Comparator.comparingInt((PathReplacement replacement) -> replacement.text().length())
            .reversed());
    String redacted = text;
    for (PathReplacement replacement : replacements) {
      redacted = redacted.replace(replacement.text(), replacement.placeholder());
    }
    return redacted;
  }

  private static void addPathReplacement(
      List<PathReplacement> replacements, Path path, String placeholder) {
    for (String pathText : pathTexts(path)) {
      addPathText(replacements, pathText, placeholder);
    }
  }

  private static void addPathText(
      List<PathReplacement> replacements, String text, String placeholder) {
    if (!text.isBlank()) {
      replacements.add(new PathReplacement(text, placeholder));
    }
  }

  private static List<String> allPathTexts(InstalledAppPaths paths) {
    List<String> pathTexts = new ArrayList<>();
    pathTexts.addAll(pathTexts(paths.processLogFile()));
    pathTexts.addAll(pathTexts(paths.installedRoot()));
    pathTexts.addAll(pathTexts(paths.dataDir()));
    pathTexts.addAll(pathTexts(paths.cacheDir()));
    pathTexts.addAll(pathTexts(paths.runDir()));
    return pathTexts;
  }

  private static List<String> pathTexts(Path path) {
    return List.of(
        path.toString(),
        path.toAbsolutePath().normalize().toString(),
        path.toString().replace('\\', '/'));
  }

  private static int utf8Length(String text) {
    return text.getBytes(StandardCharsets.UTF_8).length;
  }

  private record PathReplacement(String text, String placeholder) {}
}
