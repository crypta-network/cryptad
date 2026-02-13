package network.crypta.support.io;

import static java.util.concurrent.TimeUnit.MINUTES;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import network.crypta.support.TimeUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Generates and maps temporary file names within a configured directory using a stable prefix.
 *
 * <p>This utility encapsulates the temporary directory and name prefix, provides a bidirectional
 * mapping between a {@code long} identifier and its on-disk file, and can proactively wipe any
 * pre-existing files that match the prefix. It also offers helpers to create new, uniquely named
 * temporary files using {@link File#createNewFile()} to avoid race conditions and symlink
 * confusion.
 *
 * <p>Although {@link File#createTempFile(String, String)} is a general alternative, this class
 * centralizes naming, enables predictable lookups via identifiers, and allows callers to supply a
 * stronger source of randomness when needed.
 *
 * <p>Thread-safety: instances are not explicitly thread-safe. If a single instance is shared across
 * threads, synchronize externally around calls that mutate state on the filesystem (e.g., {@link
 * #makeRandomFilename()} or {@link #makeRandomFile()}). Read-only accessors are safe to call
 * concurrently.
 *
 * <p>On Windows, prefix matching for cleanup is case-insensitive to reflect the platform's default
 * case-insensitive semantics; on other platforms it is case-sensitive.
 *
 * @author toad
 */
public final class FilenameGenerator {
  private static final Logger LOG = LoggerFactory.getLogger(FilenameGenerator.class);

  private final Random random;
  private final String prefix;
  private final File tmpDir;

  // Interval used to tell the service wrapper that startup work is still in progress while
  // scanning and wiping old temporary files. Prevents premature restarts on long cleanups.
  private static final int STARTING_SIGNAL_MILLIS = (int) MINUTES.toMillis(5);

  /**
   * Creates a new generator bound to the given directory and filename prefix.
   *
   * <p>If {@code dir} is {@code null}, the system temporary directory specified by the {@code
   * java.io.tmpdir} system property is used. The directory is canonicalized before use. When {@code
   * wipeFiles} is {@code true}, existing files in the directory whose names start with {@code
   * prefix} are deleted on best-effort basis. On Windows the match is case-insensitive.
   *
   * <p>Security: uniqueness is enforced by {@link File#createNewFile()} to avoid time-of-check to
   * time-of-use races. Callers can supply a stronger {@link Random} implementation if desired.
   *
   * @param random source of randomness for generating identifiers; must be non-null
   * @param wipeFiles whether to remove pre-existing files that begin with {@code prefix}
   * @param dir directory to create and manage temporary files in; if {@code null}, uses the default
   *     temporary directory
   * @param prefix filename prefix applied to all generated files and used for cleanup filtering
   * @throws IOException if the directory does not exist and cannot be created, is not a directory,
   *     lacks read/write permissions, or if an I/O error occurs during initialization
   */
  public FilenameGenerator(Random random, boolean wipeFiles, File dir, String prefix)
      throws IOException {
    this.random = random;
    this.prefix = prefix;
    tmpDir =
        FileUtil.getCanonicalFile(
            Objects.requireNonNullElseGet(
                dir, () -> new File(System.getProperty("java.io.tmpdir"))));
    if (!tmpDir.exists() && !tmpDir.mkdir() && !tmpDir.isDirectory()) {
      // Ensure the directory exists; fail fast when creation is not possible.
      throw new IOException("Failed to create temporary directory: " + tmpDir);
    }
    if (!(tmpDir.isDirectory() && tmpDir.canRead() && tmpDir.canWrite()))
      throw new IOException("Not a directory or cannot read/write: " + tmpDir);
    if (wipeFiles) {
      wipePrefixFiles(tmpDir, prefix);
    }
  }

  private static void wipePrefixFiles(File directory, String prefix) {
    long wipedFiles = 0;
    long wipeableFiles = 0;
    long startWipe = System.currentTimeMillis();
    File[] filenames = directory.listFiles();
    if (filenames == null) return;
    final boolean windows = (File.separatorChar == '\\');
    for (int i = 0; i < filenames.length; i++) {
      WrapperManager.signalStarting(STARTING_SIGNAL_MILLIS);
      if (shouldLogProgress(i)) {
        logProgress(i, wipeableFiles, wipedFiles);
      }
      File f = filenames[i];
      if (!shouldWipe(f.getName(), prefix, windows)) {
        continue;
      }
      wipeableFiles++;
      if (tryDeleteFile(f)) {
        wipedFiles++;
      }
    }
    logSummary(filenames.length, wipeableFiles, wipedFiles, startWipe, System.currentTimeMillis());
  }

  private static boolean shouldLogProgress(int index) {
    return index % 1024 == 0 && index > 0;
  }

  private static boolean shouldWipe(String name, String prefix, boolean windows) {
    return (windows && name.toLowerCase(Locale.ROOT).startsWith(prefix.toLowerCase(Locale.ROOT)))
        || name.startsWith(prefix);
  }

  private static boolean tryDeleteFile(File f) {
    try {
      // Count as wiped if it was deleted or if it did not exist (preserves original semantics).
      return Files.deleteIfExists(f.toPath()) || !f.exists();
    } catch (IOException e) {
      if (f.exists()) {
        LOG.warn("Unable to delete temporary file {} - permissions problem?", f, e);
        return false;
      }
      return true; // File disappeared meanwhile; consider it wiped just like before.
    }
  }

  private static void logProgress(int processedCount, long wipeableFiles, long wipedFiles) {
    long nonTemp = processedCount - wipeableFiles;
    LOG.info("Deleted {} temp files ({} non-temp files in temp dir)", wipedFiles, nonTemp);
  }

  private static void logSummary(
      int totalFiles, long wipeableFiles, long wipedFiles, long startMs, long endMs) {
    if (LOG.isInfoEnabled()) {
      LOG.info(
          "Deleted {} of {} temporary files ({} non-temp files in temp directory) in {}",
          wipedFiles,
          wipeableFiles,
          (totalFiles - wipeableFiles),
          TimeUtil.formatTime(endMs - startMs));
    }
  }

  /**
   * Generates a new random identifier and reserves the corresponding file on disk.
   *
   * <p>The identifier is produced by the configured {@link Random} and encoded as a lower-case
   * hexadecimal string via {@link Long#toHexString(long)}. The method attempts to create the file
   * atomically using {@link File#createNewFile()} and repeats with a new identifier until it
   * succeeds.
   *
   * <p>The value {@code -1} is never returned because it is reserved for error reporting.
   *
   * @return the newly generated identifier whose file was successfully created
   * @throws IOException if the file system reports an error while attempting to create a new file
   */
  public long makeRandomFilename() throws IOException {
    long randomFilename; // should be plenty
    while (true) {
      randomFilename = random.nextLong();
      if (randomFilename == -1) continue; // Disallowed as used for error reporting
      String filename = prefix + Long.toHexString(randomFilename);
      File ret = new File(tmpDir, filename);
      if (ret.createNewFile()) {
        if (LOG.isDebugEnabled()) LOG.debug("Made random filename: {}", ret);
        return randomFilename;
      }
    }
  }

  /**
   * Resolves the file path corresponding to an identifier, without creating the file.
   *
   * <p>The identifier is encoded as a lower-case hexadecimal string via {@link
   * Long#toHexString(long)} and prefixed with the generator's prefix. The returned {@link File} may
   * or may not exist.
   *
   * @param id identifier previously returned from {@link #makeRandomFilename()} or otherwise
   *     associated with this generator's namespace
   * @return the file path under the configured temporary directory
   */
  public File getFilename(long id) {
    return new File(tmpDir, prefix + Long.toHexString(id));
  }

  /**
   * Creates and returns a new, uniquely named file under the configured directory.
   *
   * <p>This is a convenience wrapper around {@link #makeRandomFilename()} and {@link
   * #getFilename(long)} that returns the {@link File} rather than the identifier.
   *
   * @return the newly created, empty file reserved on disk
   * @throws IOException if file creation fails
   */
  public File makeRandomFile() throws IOException {
    return getFilename(makeRandomFilename());
  }

  /**
   * Returns the canonical temporary directory used by this generator.
   *
   * @return the directory where files are created and resolved
   */
  public File getDir() {
    return tmpDir;
  }

  /**
   * Reports whether a file belongs to this generator's namespace.
   *
   * <p>A file matches when its parent directory equals the configured temporary directory and its
   * name starts with the configured prefix. The check is case-sensitive regardless of platform.
   *
   * @param file file to test; must be non-null
   * @return {@code true} if the file is under the generator's directory and begins with the prefix
   */
  protected boolean matches(File file) {
    return FileUtil.equals(file.getParentFile(), tmpDir) && file.getName().startsWith(prefix);
  }

  /**
   * Moves a file into this generator's directory/name scheme if it does not already match.
   *
   * <p>When {@code file} is already inside the configured directory and starts with the prefix, the
   * same instance is returned. Otherwise, a target path is computed using {@link
   * #getFilename(long)} and the file is moved on a best-effort basis. If the move fails, the
   * original file is returned and an error is logged.
   *
   * <p>Note: the exact move semantics (atomicity across filesystems, overwrite behavior, etc.) are
   * governed by {@link FileUtil#moveTo(File, File, boolean)}.
   *
   * @param file source file; must be non-null
   * @param id identifier to use when constructing the target file name
   * @return the destination file if the move succeeded; otherwise the original file
   */
  public File maybeMove(File file, long id) {
    if (matches(file)) return file;
    File newFile = getFilename(id);
    LOG.info("Moving tempfile {} to {}", file, newFile);
    if (FileUtil.moveTo(file, newFile, false)) return newFile;
    else {
      LOG.error("Unable to move old temporary file {} to {}", file, newFile);
      return file;
    }
  }
}
