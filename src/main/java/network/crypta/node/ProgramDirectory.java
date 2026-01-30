package network.crypta.node;

import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.api.StringCallback;

/**
 * Represents the node's program directory and tracks files stored under it.
 *
 * <p>This type holds the directory {@link File} and a set of basenames for files that code creates
 * beneath it. It exposes a {@link StringCallback} so configuration code can read or update the
 * directory path. Runtime moves are intentionally restricted: changing the path after initial
 * assignment is not supported except where explicitly allowed by the read/write callback variant.
 *
 * @author infinity0
 * @see <a href="http://new-wiki.freenetproject.org/Program_files">Program files documentation
 *     (new)</a>
 * @see <a href="http://wiki.freenetproject.org/Program_files">Program files documentation (old)</a>
 */
public class ProgramDirectory {

  /** Absolute or relative directory path; {@code null} until initialized. */
  protected File dir = null;

  /** Basenames of files created or requested via {@link #file(String)}. */
  protected final HashSet<String> files = new HashSet<>();

  private final StringCallback callback;
  private final String moveErrMsg;

  private static int sortOrder = 0;

  /**
   * Return a monotonically increasing order value.
   *
   * <p>Thread-safe via synchronization. Each call increments the internal counter by one and
   * returns the previous value.
   *
   * @return the next order value starting from zero
   */
  protected static synchronized int nextOrder() {
    return sortOrder++;
  }

  /**
   * Create a ProgramDirectory with a read-only {@link StringCallback}.
   *
   * <p>The callback refuses path changes after the first assignment.
   */
  public ProgramDirectory() {
    this(null);
  }

  /**
   * Create a ProgramDirectory with a read-write {@link StringCallback} when {@code moveErrMsg} is
   * non-{@code null}.
   *
   * <p>When writable, the callback attempts to create missing directories and, on failure, throws
   * an {@link InvalidConfigValueException} containing the localized message resolved from {@code
   * moveErrMsg}.
   *
   * @param moveErrMsg localization key for move errors; when {@code null}, the callback is
   *     read-only
   */
  public ProgramDirectory(String moveErrMsg) {
    this.moveErrMsg = moveErrMsg;
    this.callback = (moveErrMsg != null) ? new RWDirectoryCallback() : new DirectoryCallback();
  }

  /**
   * Assign or move the directory path.
   *
   * <p>Initial assignment sets the directory, creating it if necessary. Moving to a different path
   * after initialization is not implemented and throws an exception.
   *
   * @param file path to use as the program directory (absolute or relative)
   * @throws IOException if moving an initialized directory, or if the path exists but is not a
   *     directory and cannot be created
   */
  public void move(String file) throws IOException {
    File newDir = new File(file);
    if (this.dir != null && !newDir.equals(this.dir)) {
      throw new IOException("move not implemented");
    }

    if (!((newDir.exists() && newDir.isDirectory()) || newDir.mkdir())) {
      throw new IOException("Could not find or make a directory called: " + l10n(file));
    }

    this.dir = newDir;
  }

  public StringCallback getStringCallback() {
    return callback;
  }

  /**
   * Read-only configuration callback for the directory path.
   *
   * <p>Allows the first assignment and accepts idempotent writes; rejects changes thereafter.
   */
  public class DirectoryCallback extends StringCallback {
    @Override
    public String get() {
      return dir.getPath();
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (dir == null) {
        dir = new File(val);
        return;
      }
      if (dir.equals(new File(val))) return;
      // Disallow changing the path at runtime; keep message in English intentionally.
      throw new InvalidConfigValueException(
          "Moving program directory on the fly not supported at present");
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }
  }

  /**
   * Read-write configuration callback for the directory path.
   *
   * <p>Accepts changes and creates the target directory if it does not exist. On failure, throws an
   * {@link InvalidConfigValueException} with a localized message.
   */
  public class RWDirectoryCallback extends DirectoryCallback {
    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (dir == null) {
        dir = new File(val);
        return;
      }
      if (dir.equals(new File(val))) return;
      File f = new File(val);
      if (!((f.exists() && f.isDirectory()) || f.mkdir()))
        // Used in advanced setups; still common enough to translate.
        // Keep message localized for user-facing configuration errors.
        throw new InvalidConfigValueException(l10n(moveErrMsg));
      dir = new File(val);
    }

    @Override
    public boolean isReadOnly() {
      return false;
    }
  }

  /**
   * Resolve a child file under the program directory and record its basename.
   *
   * @param base basename of the file to resolve; must not contain path separators
   * @return file under {@link #dir} with the provided basename
   */
  public File file(String base) {
    files.add(base);
    return new File(dir, base);
  }

  /**
   * Return the current program directory.
   *
   * @return current directory, or {@code null} if not yet assigned
   */
  public File dir() {
    return dir;
  }

  private static String l10n(String key) {
    return NodeL10n.getBase().getString(key);
  }
}
