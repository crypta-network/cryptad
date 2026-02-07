package network.crypta.support.io;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * File-backed, non-persistent temporary bucket implementation.
 *
 * <p>This bucket stores data in a file located by a {@link FilenameGenerator}. Instances start
 * empty and, by design, operate directly on an already-existing file path (see {@link
 * #tempFileAlreadyExists()}). Reads and writes are coordinated by the {@link BaseFileBucket}
 * superclass.
 *
 * <p>Key characteristics: - Not persistent across process restarts ({@link #persistent()} returns
 * {@code false}). - Never registers files with {@link File#deleteOnExit()} to avoid JVM memory
 * leaks. - Deletes the underlying file on {@link #free()} when constructed with {@code
 * deleteOnFree=true} (default); read-only shadows do not deleting on free. - Supports converting to
 * a read-only random-access buffer via the superclass.
 *
 * <p>Serialization: this class implements {@link Serializable} only to allow derived persistent
 * implementations (e.g., {@code PersistentTempFileBucket}) to serialize the base state.
 * Serialization within this class is intentionally incomplete; {@link #storeTo(DataOutputStream)}
 * calls {@link #magic()}, which throws {@link UnsupportedOperationException} here. Subclasses that
 * support on-disk persistence must override {@link #magic()} and typically provide a matching
 * constructor reading from a {@link DataInputStream}.
 *
 * <p>Thread-safety: state mutations are synchronized in the superclass where needed. Instances are
 * not intended for unrestricted concurrent use without external coordination. Open streams must be
 * closed before calling {@link #free()}.
 *
 * @author giannij
 * @since 1
 */
public class TempFileBucket extends BaseFileBucket implements Bucket, Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(TempFileBucket.class);

  /**
   * Serialization identifier. Only superclass state is intended to be serialized from this class;
   * the {@link #magic()} method is not implemented here. Subclasses handle full persistence.
   */
  @Serial private static final long serialVersionUID = 1L;

  /** Stable identifier used by {@link FilenameGenerator} to derive the file path. */
  long filenameID;

  /** Non-serializable generator reattached on resume in persistent subclasses. */
  protected transient FilenameGenerator generator;

  /** When {@code true}, write operations are disallowed. */
  private volatile boolean readOnly;

  /** Whether {@link #free()} deletes the backing file. */
  private final boolean deleteOnFree;

  /** Cached file path; may be {@code null} for deserialized legacy instances. */
  private File file;

  /** Ensures {@link #onResume(ClientContext)} runs at most once. */
  private transient boolean resumed;

  /**
   * Creates a temp bucket for the given id and generator.
   *
   * <p>Files are not registered with {@link File#deleteOnExit()} because that API retains paths for
   * the lifetime of the JVM and can cause memory growth.
   *
   * @param id identifier used by the generator to compute the file path
   * @param generator filename generator; must be non-null
   */
  public TempFileBucket(long id, FilenameGenerator generator) {
    // Using deleteOnExit() for temp files retains entries for JVM lifetime and risks memory leaks.
    this(id, generator, true);
    this.file = generator.getFilename(id);
  }

  /**
   * Constructs a temp bucket with an explicit delete-on-free policy.
   *
   * <p>Subclasses call this to create normal buckets ({@code deleteOnFree=true}) or read-only
   * shadows ({@code deleteOnFree=false}).
   *
   * @param id stable identifier used by the generator
   * @param generator filename generator for locating the file; must be non-null
   * @param deleteOnFree whether {@link #free()} deletes the underlying file
   */
  protected TempFileBucket(long id, FilenameGenerator generator, boolean deleteOnFree) {
    super(generator.getFilename(id), false, false, true);
    this.filenameID = id;
    this.generator = generator;
    this.deleteOnFree = deleteOnFree;
    this.file = generator.getFilename(id);

    if (LOG.isTraceEnabled()) {
      LOG.trace("Initializing TempFileBucket({}", getFile());
    }
  }

  /** Default constructor for (de)serialization frameworks. */
  protected TempFileBucket() {
    // For serialization.
    deleteOnFree = false;
  }

  @Override
  protected boolean createFileOnly() {
    // Creation-only semantics are not used for existing temp files.
    return false;
  }

  @Override
  protected boolean deleteOnFree() {
    return deleteOnFree;
  }

  @Override
  public File getFile() {
    // Prefer a cached file path; fall back to the generator to recompute on demand.
    if (file != null) return file;
    return generator.getFilename(filenameID);
  }

  @Override
  public boolean isReadOnly() {
    return readOnly;
  }

  @Override
  public void setReadOnly() {
    readOnly = true;
  }

  @Override
  protected boolean deleteOnExit() {
    // Do not use File.deleteOnExit() for temp files (memory grows with tracked paths).
    return false;
  }

  @Override
  public RandomAccessBucket createShadow() {
    // Create a read-only view that does not delete the file on freeing.
    TempFileBucket ret = new TempFileBucket(filenameID, generator, false);
    ret.setReadOnly();
    if (!getFile().exists()) LOG.error("File does not exist when creating shadow: {}", getFile());
    return ret;
  }

  /**
   * Reattaches runtime state after deserialization in persistent subclasses.
   *
   * <p>This method updates {@link #generator} from {@link ClientContext#persistentFG}, verifies the
   * backing file exists (creating it if necessary), and relocates it using {@link
   * FilenameGenerator#maybeMove(File, long)} when the generator's directory has changed.
   *
   * @param context client context providing a persistent {@link FilenameGenerator}
   * @throws ResumeFailedException if the file is missing and cannot be created
   */
  protected void innerResume(ClientContext context) throws ResumeFailedException {
    generator = context.persistentFG;
    if (file == null) {
      // Legacy path (e.g., migration from older on-disk formats).
      file = generator.getFilename(filenameID);
      checkExists(file);
    } else {
      // File must exist; reconcile location changes.
      if (!file.exists()) {
        // Try the current generator location in case of moves since the last checkpoint.
        File f = generator.getFilename(filenameID);
        if (f.exists()) {
          file = f;
        }
      }
      checkExists(file);
      file = generator.maybeMove(file, filenameID);
    }
  }

  @Override
  public final void onResume(ClientContext context) throws ResumeFailedException {
    // Non-persistent buckets cannot be resumed.
    if (!persistent()) throw new UnsupportedOperationException();
    synchronized (this) {
      if (resumed) return;
      resumed = true;
    }
    super.onResume(context);
    innerResume(context);
  }

  /* Ensures the file exists, creating an empty file if necessary. */
  private void checkExists(File file) throws ResumeFailedException {
    try {
      if (!(file.createNewFile() || file.exists()))
        throw new ResumeFailedException(
            "Tempfile " + file + " does not exist and cannot be created");
    } catch (IOException _) {
      throw new ResumeFailedException("Tempfile cannot be created");
    }
  }

  /**
   * Indicates whether this bucket participates in persistence across restarts.
   *
   * @return always {@code false} for plain temp buckets
   */
  protected boolean persistent() {
    return false;
  }

  @Override
  protected boolean tempFileAlreadyExists() {
    // Temp file path is expected to pre-exist; writes occur directly.
    return true;
  }

  static final int VERSION = 1;

  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    // Subclasses must override magic() to enable persistence; this implementation throws.
    dos.writeInt(magic());
    super.storeTo(dos);
    dos.writeInt(VERSION);
    dos.writeLong(filenameID);
    dos.writeBoolean(readOnly);
    dos.writeBoolean(deleteOnFree);
    dos.writeUTF(file.toString());
  }

  /**
   * Returns a subclass-specific magic number used by on-disk persistence.
   *
   * <p>This base implementation throws {@link UnsupportedOperationException}. Persistent subclasses
   * must override and return stable magic (e.g., {@code 0x2ffdd4cf}).
   *
   * @return magic number identifying the concrete subclass
   * @throws UnsupportedOperationException always in this class
   */
  protected int magic() {
    throw new UnsupportedOperationException();
  }

  /**
   * Reconstructs minimal state from a serialized form produced by a subclass.
   *
   * <p>Callers must have already consumed the subclass-specific magic. The version field validates
   * format compatibility.
   *
   * @param dis source stream positioned after the subclass magic
   * @throws IOException on I/O errors
   * @throws StorageFormatException on unknown version or malformed fields
   */
  protected TempFileBucket(DataInputStream dis) throws IOException, StorageFormatException {
    super(dis);
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    filenameID = dis.readLong();
    if (filenameID == -1) throw new StorageFormatException("Bad filename ID");
    readOnly = dis.readBoolean();
    deleteOnFree = dis.readBoolean();
    file = new File(dis.readUTF());
  }

  @Override
  public int hashCode() {
    // Keep in sync with equals(): incorporate deleteOnFree, filenameID, and readOnly.
    final int prime = 31;
    int result = 1;
    result = prime * result + (deleteOnFree ? 1231 : 1237);
    result = prime * result + Long.hashCode(filenameID);
    result = prime * result + (readOnly ? 1231 : 1237);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof TempFileBucket other)) {
      return false;
    }
    if (deleteOnFree != other.deleteOnFree) {
      return false;
    }
    if (filenameID != other.filenameID) {
      return false;
    }
    return readOnly == other.readOnly;
  }
}
