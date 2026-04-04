package network.crypta.fs.readiness;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import network.crypta.fs.AppDirs;
import network.crypta.fs.AppEnv;
import network.crypta.fs.ServiceDirs;

/**
 * Reads, writes, and clears the launcher readiness file in the runtime directory.
 *
 * <p>The format is intentionally tiny: a UTF-8 properties-style file with one versioned ready
 * payload. Writers replace the file via a temporary sibling so the launcher does not observe a
 * partially written readiness signal, and readers treat missing or invalid content as "not ready"
 * instead of failing startup coordination.
 */
public final class LauncherReadinessFiles {
  /** Canonical readiness filename placed directly under the resolved runtime directory. */
  public static final String FILE_NAME = "platform-ui.properties";

  /** Suffix used for the sibling temporary file during replace-in-place writes. */
  private static final String TEMP_SUFFIX = ".tmp";

  /** Property key that carries the readiness-file schema version. */
  private static final String VERSION_KEY = "version";

  /** Properties key that marks the readiness state published by the daemon. */
  private static final String STATE_KEY = "state";

  /** Property key that carries the launcher-facing UI listen port. */
  private static final String UI_PORT_KEY = "ui.port";

  /** Property key that carries the launcher-facing UI root path. */
  private static final String UI_ROOT_KEY = "ui.root";

  /** Utility holder; use the static helpers instead of instantiating this type. */
  private LauncherReadinessFiles() {}

  /**
   * Stable snapshot of a parsed readiness file and the concrete file generation it came from.
   *
   * <p>The launcher uses this to ensure it validates readiness contents against the same file
   * generation it actually read, even when the daemon replaces the file atomically during startup.
   *
   * @param info parsed readiness payload
   * @param lastModifiedTime the file's last-modified timestamp in milliseconds for the read
   *     generation
   * @param fileKey filesystem file key for the read generation when available, otherwise {@code
   *     null}
   */
  public record ReadinessSnapshot(
      LauncherReadinessInfo info, long lastModifiedTime, Object fileKey) {
    /**
     * Creates a snapshot for one concrete readiness-file generation.
     *
     * @param info parsed readiness payload from the observed generation
     * @param lastModifiedTime last-modified timestamp in milliseconds for that generation
     * @param fileKey filesystem file key for that generation, or {@code null} when unavailable
     */
    public ReadinessSnapshot {
      Objects.requireNonNull(info);
    }
  }

  /**
   * Resolves the readiness-file path beneath the supplied runtime directory.
   *
   * @param runDir resolved runtime directory
   * @return readiness-file path under {@code runDir}
   */
  public static Path resolve(Path runDir) {
    return Objects.requireNonNull(runDir).resolve(FILE_NAME);
  }

  /**
   * Resolves the readiness-file path for the current process environment.
   *
   * <p>This uses the same {@link AppEnv}/{@link AppDirs}/{@link ServiceDirs} directory logic as
   * runtime bootstrap, so the desktop launcher does not need to hard-code platform-specific run
   * directory rules.
   *
   * @return readiness-file path for the current process' resolved runtime directory
   */
  @SuppressWarnings("unused")
  public static Path resolveCurrentProcessReadinessFile() {
    AppEnv env = new AppEnv();
    Path runDir =
        env.isServiceMode()
            ? new ServiceDirs().resolve().runDir()
            : new AppDirs().resolve().runDir();
    return resolve(runDir);
  }

  /**
   * Deletes a previously published readiness file if one exists.
   *
   * @param readinessFile concrete readiness-file path
   * @throws IOException if deletion fails for reasons other than the file being absent
   */
  public static void clear(Path readinessFile) throws IOException {
    Objects.requireNonNull(readinessFile);
    Files.deleteIfExists(readinessFile);
    Files.deleteIfExists(tempPath(readinessFile));
  }

  /**
   * Writes a readiness payload using best-effort atomic replacement.
   *
   * @param readinessFile concrete readiness-file path
   * @param info readiness payload to persist
   * @throws IOException if the temporary file cannot be written or moved into place
   */
  public static void write(Path readinessFile, LauncherReadinessInfo info) throws IOException {
    Objects.requireNonNull(readinessFile);
    Objects.requireNonNull(info);

    Path tempFile = tempPath(readinessFile);
    List<String> lines =
        List.of(
            VERSION_KEY + "=" + info.version(),
            STATE_KEY + "=" + info.state(),
            UI_PORT_KEY + "=" + info.uiPort(),
            UI_ROOT_KEY + "=" + info.uiRoot());
    Files.write(
        tempFile,
        lines,
        StandardCharsets.UTF_8,
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE);
    moveIntoPlace(tempFile, readinessFile);
  }

  /**
   * Reads a readiness payload if a valid ready file exists.
   *
   * @param readinessFile concrete readiness-file path
   * @return parsed readiness payload, or empty when the file is missing or invalid
   * @throws IOException if the file exists but cannot be read
   */
  public static Optional<LauncherReadinessInfo> read(Path readinessFile) throws IOException {
    return readSnapshot(readinessFile).map(ReadinessSnapshot::info);
  }

  /**
   * Reads a readiness payload and returns it with same-generation file metadata.
   *
   * <p>If the file is replaced while it is being read, this method retries a small number of times
   * and otherwise reports "not ready" so callers do not combine stale contents with fresh metadata.
   *
   * @param readinessFile concrete readiness-file path
   * @return parsed readiness snapshot, or empty when the file is missing, invalid, or changed
   *     during the read attempt
   * @throws IOException if the file exists but cannot be read
   */
  public static Optional<ReadinessSnapshot> readSnapshot(Path readinessFile) throws IOException {
    Objects.requireNonNull(readinessFile);
    for (int attempt = 0; attempt < 3; attempt++) {
      if (!Files.isRegularFile(readinessFile)) {
        return Optional.empty();
      }

      try {
        var before =
            Files.readAttributes(readinessFile, java.nio.file.attribute.BasicFileAttributes.class);
        if (!before.isRegularFile()) {
          return Optional.empty();
        }

        String content = Files.readString(readinessFile, StandardCharsets.UTF_8);
        var after =
            Files.readAttributes(readinessFile, java.nio.file.attribute.BasicFileAttributes.class);
        if (!isSameObservedGeneration(before, after)) {
          continue;
        }

        Optional<LauncherReadinessInfo> info = parse(content);
        return info.map(
            value ->
                new ReadinessSnapshot(value, after.lastModifiedTime().toMillis(), after.fileKey()));
      } catch (NoSuchFileException _) {
        return Optional.empty();
      }
    }
    return Optional.empty();
  }

  /**
   * Replaces the destination readiness file with the prepared temporary sibling.
   *
   * <p>The method prefers an atomic move, so the launcher never observes a partially written file,
   * but it falls back to a normal replacement when the target filesystem does not support atomic
   * renames.
   *
   * @param tempFile populated temporary sibling file
   * @param readinessFile final readiness-file destination
   * @throws IOException if neither move strategy succeeds
   */
  private static void moveIntoPlace(Path tempFile, Path readinessFile) throws IOException {
    try {
      Files.move(
          tempFile,
          readinessFile,
          StandardCopyOption.ATOMIC_MOVE,
          StandardCopyOption.REPLACE_EXISTING);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(tempFile, readinessFile, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  /**
   * Resolves the temporary sibling path used while writing a new readiness generation.
   *
   * @param readinessFile final readiness-file destination
   * @return sibling temporary path next to {@code readinessFile}
   */
  private static Path tempPath(Path readinessFile) {
    return readinessFile.resolveSibling(readinessFile.getFileName() + TEMP_SUFFIX);
  }

  /**
   * Checks whether two attribute reads still refer to the same on-disk file generation.
   *
   * <p>When the filesystem exposes stable file keys, they are the primary identity signal. The
   * timestamp, size, and creation-time fallback keeps the check useful on filesystems that do not
   * expose file keys.
   *
   * @param before attributes captured before reading file contents
   * @param after attributes captured after reading file contents
   * @return {@code true} when both attribute sets describe the same observed generation
   */
  private static boolean isSameObservedGeneration(
      java.nio.file.attribute.BasicFileAttributes before,
      java.nio.file.attribute.BasicFileAttributes after) {
    Object beforeFileKey = before.fileKey();
    Object afterFileKey = after.fileKey();
    if (beforeFileKey != null && afterFileKey != null) {
      return beforeFileKey.equals(afterFileKey);
    }
    return before.lastModifiedTime().equals(after.lastModifiedTime())
        && before.size() == after.size()
        && before.creationTime().equals(after.creationTime());
  }

  /**
   * Parses one readiness payload from the UTF-8 properties text content.
   *
   * <p>Unsupported versions, malformed numbers, unknown states, and invalid root paths are all
   * treated as "not ready" so callers can fall back without surfacing parser-specific failures.
   *
   * @param content UTF-8 properties-style readiness content
   * @return parsed readiness payload, or empty when the content is invalid for the current schema
   * @throws IOException if the {@link Properties} reader reports an I/O failure
   */
  private static Optional<LauncherReadinessInfo> parse(String content) throws IOException {
    Properties properties = new Properties();
    try (var reader = new StringReader(content)) {
      properties.load(reader);
    }

    Integer version = parsePositiveInt(properties.getProperty(VERSION_KEY));
    Integer uiPort = parsePositiveInt(properties.getProperty(UI_PORT_KEY));
    String state = trimToNull(properties.getProperty(STATE_KEY));
    String uiRoot = trimToNull(properties.getProperty(UI_ROOT_KEY));
    if (version == null
        || version != LauncherReadinessInfo.VERSION_1
        || uiPort == null
        || !LauncherReadinessInfo.READY_STATE.equals(state)) {
      return Optional.empty();
    }

    try {
      return Optional.of(
          new LauncherReadinessInfo(
              version,
              state,
              uiPort,
              uiRoot != null ? uiRoot : LauncherReadinessInfo.DEFAULT_UI_ROOT));
    } catch (IllegalArgumentException _) {
      return Optional.empty();
    }
  }

  /**
   * Parses a strictly positive integer from a readiness property.
   *
   * @param value raw property value
   * @return positive integer value, or {@code null} when the property is missing or invalid
   */
  private static Integer parsePositiveInt(String value) {
    String normalized = trimToNull(value);
    if (normalized == null) {
      return null;
    }
    try {
      int parsed = Integer.parseInt(normalized);
      return parsed > 0 ? parsed : null;
    } catch (NumberFormatException _) {
      return null;
    }
  }

  /**
   * Trims a readiness property and normalizes blank values to {@code null}.
   *
   * @param value raw property value
   * @return trimmed value, or {@code null} when the input is missing or blank
   */
  private static String trimToNull(String value) {
    if (value == null) {
      return null;
    }
    String trimmed = value.trim();
    return trimmed.isEmpty() ? null : trimmed;
  }
}
