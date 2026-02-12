package network.crypta.node;

import java.io.File;
import java.io.IOException;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.l10n.NodeL10n;
import network.crypta.support.Ticker;
import network.crypta.support.api.StringCallback;

/**
 * Persister that takes its file locations from configuration.
 *
 * <p>This adapter wires a {@link Persistable} into the node configuration so the target file can be
 * viewed and changed via {@link SubConfig}. It registers a string option whose getter exposes the
 * current destination and whose setter validates and switches both the final target and its
 * temporary companion file. Files are created on demand and must be readable and writable.
 *
 * <p>Localization: human-readable error messages are resolved through {@link NodeL10n} using the
 * {@code ConfigurablePersister.*} keys.
 */
public final class ConfigurablePersister extends Persister {

  private static final String L10N_EXISTS_CANNOT_RW = "existsCannotReadWrite";
  private static final String L10N_DOES_NOT_EXIST_CANNOT_CREATE = "doesNotExistCannotCreate";

  /**
   * Creates and registers a configurable persister.
   *
   * <p>The constructor registers an option under {@code optionName} with {@code nodeConfig}. The
   * option defaults to {@code new File(baseDir, defaultFilename)}. Reading the option returns the
   * active file path. Writing the option triggers validation and an atomic swap of the destination
   * and its {@code .tmp} companion. On successful creation, the initial value is read from the
   * config and applied immediately.
   *
   * <p>Threading: path updates are synchronized on {@code this} to replace both files together. The
   * scheduling of persistence is delegated to {@link Ticker} via the base class.
   *
   * @param t source that can serialize throttle state
   * @param params bundle describing the option metadata and default path
   * @param ps scheduler used by the base persister
   * @throws NodeInitException when the configured file is invalid or cannot be created. The message
   *     derives from localization keys and the exit code is {@link
   *     NodeInitException#EXIT_THROTTLE_FILE_ERROR}.
   */
  public ConfigurablePersister(Persistable t, ConfigurablePersisterParams params, Ticker ps)
      throws NodeInitException {
    super(t, ps);
    params
        .nodeConfig()
        .register(
            params.optionName(),
            new File(params.baseDir(), params.defaultFilename()).toString(),
            params.optionMeta(),
            new StringCallback() {
              @Override
              public String get() {
                return persistTarget.toString();
              }

              @Override
              public void set(String val) throws InvalidConfigValueException {
                setThrottles(val);
              }
            });

    String throttleFile = params.nodeConfig().getString(params.optionName());
    try {
      setThrottles(throttleFile);
    } catch (InvalidConfigValueException e2) {
      throw new NodeInitException(NodeInitException.EXIT_THROTTLE_FILE_ERROR, e2.getMessage());
    }
  }

  /*
   * Validates and applies the persistence paths derived from the provided value.
   *
   * The value addresses the final file. Its temporary companion is {@code value + ".tmp"}.
   * Both files must exist or be creatable and must be readable and writable.
   */
  private void setThrottles(String val) throws InvalidConfigValueException {
    final File target = new File(val);
    final File temp = new File(target + ".tmp");

    // Validate or create the target file
    ensureExistsAndRw(target, temp);
    // Validate or create the temp file
    ensureExistsAndRw(temp, temp);

    // Atomically replace both paths to keep readers from observing a half-updated pair.
    synchronized (this) {
      persistTarget = target;
      persistTemp = temp;
    }
  }

  /**
   * Ensures that {@code file} exists and is readable/writable; creates it when missing.
   *
   * <p>Error messages intentionally reference {@code errorPath} to preserve historical behavior
   * (tests expect the ".tmp" path in messages).
   *
   * <p>Race-safety: If another thread/process creates the file between the initial existence check
   * and our {@link File#createNewFile()} attempt, we may observe {@code created == false} and
   * {@code file.exists() == true}. In that case we must still validate readability and writability;
   * otherwise we could silently accept an unusable file and fail later.
   *
   * @throws InvalidConfigValueException if the file cannot be created or lacks read/write
   *     permissions
   */
  private void ensureExistsAndRw(File file, File errorPath) throws InvalidConfigValueException {
    if (file.exists()) {
      if (!(file.canRead() && file.canWrite())) {
        throw new InvalidConfigValueException(l10n(L10N_EXISTS_CANNOT_RW) + " : " + errorPath);
      }
      return;
    }

    // Parent must be a directory if it exists; otherwise creation will fail with IOException.
    File parent = file.getAbsoluteFile().getParentFile();
    if (parent != null && parent.exists() && parent.isFile()) {
      throw new InvalidConfigValueException(
          l10n(L10N_DOES_NOT_EXIST_CANNOT_CREATE) + " : " + errorPath);
    }
    try {
      boolean created = file.createNewFile();

      // Whether we created it or another process did, re-validate the resulting file
      // to close the race window between exists() and createNewFile().
      if (file.exists()) {
        if (!(file.canRead() && file.canWrite())) {
          throw new InvalidConfigValueException(l10n(L10N_EXISTS_CANNOT_RW) + " : " + errorPath);
        }
        return;
      }

      // If creation reported false and the file still doesn't exist, treat as creation failure.
      if (!created) {
        throw new InvalidConfigValueException(
            l10n(L10N_DOES_NOT_EXIST_CANNOT_CREATE) + " : " + errorPath);
      }
    } catch (IOException _) {
      throw new InvalidConfigValueException(
          l10n(L10N_DOES_NOT_EXIST_CANNOT_CREATE) + " : " + errorPath);
    }
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("ConfigurablePersister." + key);
  }
}
