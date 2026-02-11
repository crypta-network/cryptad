package network.crypta.config;

import java.io.BufferedInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.LineReadingInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Configuration registry that persists to an on-disk file using an atomic writing strategy.
 *
 * <p>At construction, the class loads key/value pairs from the primary configuration file or its
 * temporary counterpart (if present) into a {@link SimpleFieldSet}. During initialization, {@link
 * SubConfig} instances register their {@link Option}s and consume matching entries from the field
 * set through {@link PersistentConfig#onRegister(SubConfig, Option)}. After {@link #finishedInit()}
 * completes, any remaining keys are reported as unknown, and the configuration is written back to
 * disk.
 *
 * <p>Writes are performed atomically by serializing to a temporary file and then moving it over the
 * original file. If {@link #store()} is invoked before initialization has finished, persistence is
 * deferred and performed immediately after {@link #finishedInit()}.
 *
 * <p>Thread-safety: external callers should not synchronize on this instance. The class uses an
 * internal lock ({@link #storeSync}) to guard disk writes and synchronizes on {@code this} only for
 * short critical sections when exporting.
 */
public class FilePersistentConfig extends PersistentConfig {
  private static final Logger LOG = LoggerFactory.getLogger(FilePersistentConfig.class);

  // Destination file path and the sidecar temp path used for atomic writes.
  final File filename;
  final File tempFilename;

  /** Optional header written at the top of the serialized config file; may be {@code null}. */
  protected final String header;

  /** Synchronization guard for write operations to avoid interleaving across threads. */
  protected final Object storeSync = new Object();

  /** When {@code true}, defers a requested {@link #store()} until {@link #finishedInit()}. */
  protected volatile boolean writeOnFinished;

  // No static initialization required.

  /**
   * Constructs a file-backed configuration, using the default header formatting.
   *
   * @param f the target configuration file
   * @return a new instance backed by {@code f}
   * @throws IOException if the file or its temporary counterpart cannot be read when required
   */
  @SuppressWarnings("unused")
  public static FilePersistentConfig constructFilePersistentConfig(File f) throws IOException {
    return constructFilePersistentConfig(f, null);
  }

  /**
   * Constructs a file-backed configuration with an optional header.
   *
   * <p>The header is written verbatim to the top of the file (subject to {@link SimpleFieldSet}
   * formatting rules). Use {@code null} for no header.
   *
   * @param f the target configuration file
   * @param header an optional header string; may be {@code null}
   * @return a new instance backed by {@code f}
   * @throws IOException if the file or its temporary counterpart cannot be read when required
   */
  public static FilePersistentConfig constructFilePersistentConfig(File f, String header)
      throws IOException {
    File tempFilename = new File(f.getPath() + ".tmp");
    return new FilePersistentConfig(load(f, tempFilename), f, tempFilename, header);
  }

  /**
   * Loads configuration from {@code filename} or {@code tempFilename} if present.
   *
   * <p>Preference is given to the primary file; if unreadable or empty, the method attempts to read
   * the temporary file. Warnings are logged when write permissions are missing. When neither file
   * yields a valid configuration, the method returns {@code null} to signal that a new file should
   * be created on first store.
   *
   * @param filename the primary configuration file
   * @param tempFilename the temporary file used for atomic writes
   * @return the parsed {@link SimpleFieldSet}, or {@code null} if no usable file is found
   * @throws IOException if a file exists but cannot be read in scenarios where fail-fast is desired
   */
  static SimpleFieldSet load(File filename, File tempFilename) throws IOException {
    boolean filenameExists = filename.exists();
    boolean tempFilenameExists = tempFilename.exists();
    if (filenameExists && !filename.canWrite()) {
      LOG.error("Warning: Cannot write to config file: {}", filename);
    }
    if (tempFilenameExists && !tempFilename.canWrite()) {
      LOG.error("Warning: Cannot write to config tempfile: {}", tempFilename);
    }

    if (filenameExists) {
      SimpleFieldSet sfs =
          tryLoadIfReadable(
              filename, false, "config file", " - checking for temp file " + tempFilename);
      if (sfs != null) return sfs;
    }

    if (tempFilename.exists()) {
      SimpleFieldSet sfs = tryLoadIfReadable(tempFilename, true, "(temp) config file", "");
      if (sfs != null) return sfs;
    }

    LOG.info("No config file found, creating new: {}", filename);
    return null;
  }

  /**
   * Creates a new instance with default header handling.
   *
   * @param origFS initial field set; may be {@code null}
   * @param fnam destination file
   * @param temp temporary file used during atomic writes
   */
  @SuppressWarnings("unused")
  protected FilePersistentConfig(SimpleFieldSet origFS, File fnam, File temp) {
    this(origFS, fnam, temp, null);
  }

  /**
   * Creates a new instance with an explicit header.
   *
   * @param origFS initial field set; may be {@code null}
   * @param fnam destination file
   * @param temp temporary file used during atomic writes
   * @param header header string to write, or {@code null} for no header
   */
  protected FilePersistentConfig(SimpleFieldSet origFS, File fnam, File temp, String header) {
    super(origFS);
    this.filename = fnam;
    this.tempFilename = temp;
    this.header = header;
  }

  /**
   * Loads a file into a {@link SimpleFieldSet} using relaxed parsing rules.
   *
   * <p>The file is parsed as UTF-8 via {@link LineReadingInputStream}. Parsing uses relaxed
   * settings to accommodate manual edits by advanced users.
   *
   * @param toRead file to parse; may be {@code null}
   * @return the parsed {@link SimpleFieldSet}, or {@code null} if {@code toRead} is {@code null}
   * @throws IOException if an I/O error occurs while reading or parsing
   */
  private static SimpleFieldSet initialLoad(File toRead) throws IOException {
    if (toRead == null) return null;
    try (FileInputStream fis = new FileInputStream(toRead);
        BufferedInputStream bis = new BufferedInputStream(fis);
        LineReadingInputStream lis = new LineReadingInputStream(bis)) {
      // Config file is UTF-8 too!
      return new SimpleFieldSet(
          lis,
          1024 * 1024,
          128,
          true,
          true,
          true); // Advanced users may edit the config file; allow relaxed parsing.
    }
  }

  /**
   * Attempts to load a field set when the file is readable and non-empty.
   *
   * <p>When {@code throwOnUnreadable} is {@code true} (typically for the temp file), conditions
   * that indicate the file exists but cannot be successfully read—including {@link EOFException}
   * from a truncated/partial writing—are propagated as {@link IOException}. This preserves
   * fail-fast behavior so we do not silently discard a partially written configuration.
   *
   * @param file the file to read
   * @param throwOnUnreadable whether to propagate unreadable conditions as {@link IOException}
   * @param description human-friendly label for logs
   * @param notFoundSuffix extra context appended to error logs when the file disappears mid-read
   * @return the parsed {@link SimpleFieldSet}, or {@code null} if the file cannot be read
   * @throws IOException if {@code throwOnUnreadable} is {@code true} and the file exists but cannot
   *     be read
   */
  private static SimpleFieldSet tryLoadIfReadable(
      File file, boolean throwOnUnreadable, String description, String notFoundSuffix)
      throws IOException {
    if (file.canRead() && file.length() > 0) {
      try {
        return initialLoad(file);
      } catch (FileNotFoundException e) {
        LOG.error("Cannot open {} {}: {}{}", description, file, e, notFoundSuffix);
      } catch (EOFException e) {
        // Treat EOF as a hard failure for temp files (truncated/partial writes) to avoid
        // overwriting a user's config with defaults.
        if (throwOnUnreadable) throw e;
        LOG.warn("EOF while reading {} {}", description, file);
      }
      // Other IOExceptions indicate a more serious problem and will propagate from the initialLoad.
    } else {
      // We probably won't be able to write it either.
      LOG.warn("Cannot read {} {}", description, file);
      if (throwOnUnreadable) {
        throw new IOException("Cannot read " + description + " " + file);
      }
    }
    return null;
  }

  /**
   * Persists the current configuration to disk.
   *
   * <p>If initialization has not finished, defers the writing and performs it immediately after
   * {@link #finishedInit()}. Otherwise, writes to the temporary file and atomically replaces the
   * destination file. Exceptions during the writing are logged.
   */
  @Override
  public void store() {
    if (!finishedInit) {
      writeOnFinished = true;
      return;
    }
    try {
      synchronized (storeSync) {
        innerStore();
      }
    } catch (IOException e) {
      LOG.error("Cannot store config: {}", e, e);
      // Avoid printing to System.err or dumping the stack; already logged.
    }
  }

  /**
   * Serializes and atomically stores the configuration.
   *
   * <p>Callers must hold {@link #storeSync}. The method serializes the export from {@link
   * #exportFieldSet()} to {@link #tempFilename} (including {@link #header} when provided), then
   * moves it over {@link #filename} via {@link FileUtil#moveTo(File, File)}.
   *
   * @throws IOException if writing or moving the file fails
   */
  protected final void innerStore() throws IOException {
    if (!finishedInit) throw new IllegalStateException("SHOULD NOT HAPPEN!!");

    SimpleFieldSet fs = exportFieldSet();
    if (LOG.isDebugEnabled()) LOG.debug("fs = {}", fs);
    try (FileOutputStream fos = new FileOutputStream(tempFilename)) {
      synchronized (this) {
        fs.setHeader(header);
        fs.writeToBigBuffer(fos);
      }
    }
    FileUtil.moveTo(tempFilename, filename);
  }

  /** Completes initialization and performs any deferred store. */
  @Override
  public synchronized void finishedInit() {
    super.finishedInit();
    if (writeOnFinished) {
      writeOnFinished = false;
      store();
    }
  }
}
