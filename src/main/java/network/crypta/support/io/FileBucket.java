package network.crypta.support.io;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.Serial;
import java.io.Serializable;
import java.util.Objects;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.RandomAccessBucket;

/**
 * File-backed {@link Bucket} implementation.
 *
 * <p>This bucket persists data to a single {@link File}. Writes are staged via a temporary file in
 * the same directory and atomically moved into place on close (see {@link
 * #tempFileAlreadyExists()}). The class delegates most coordination, stream tracking, and lifecycle
 * management to {@link BaseFileBucket}.
 *
 * <p>Thread-safety: public methods that mutate or expose internal state synchronize on {@code
 * this}. Instances are not intended for broad sharing without external coordination.
 *
 * <p>Read-only behavior: once {@link #setReadOnly()} is called or a random-access view is derived
 * by the base type, subsequent write attempts fail with {@link java.io.IOException}.
 *
 * @author oskar
 */
public class FileBucket extends BaseFileBucket implements Bucket, Serializable {

  /** Serialization identifier. */
  @Serial private static final long serialVersionUID = 1L;

  /** Absolute path to the backing file. Never {@code null} for normal (non-deserialization) use. */
  protected final File file;

  /** Whether this bucket rejects further writes. Set by {@link #setReadOnly()}. */
  protected boolean readOnly;

  /**
   * Whether {@link #free()} deletes the backing file.
   *
   * <p>Naming: renamed from {@code deleteOnFree}. The new name avoids a symbol clash with the base
   * class method {@link #deleteOnFree()} and clarifies intent.
   *
   * <p>Serialization note: default Java serialization compatibility with older versions is not
   * preserved for this field rename. Old serialized streams will not populate this field, and it
   * may therefore default to {@code false} on deserialization. Use {@link
   * #storeTo(DataOutputStream)} for stable, versioned persistence.
   */
  protected boolean deleteOnFreeFlag;

  /**
   * Whether temporary files created by this instance are registered with {@link
   * File#deleteOnExit()} (JVM exit only).
   *
   * <p>Naming: renamed from {@code deleteOnExit}. The new name avoids a symbol clash with the base
   * class method {@link #deleteOnExit()} and clarifies intent.
   *
   * <p>Serialization note: default Java serialization compatibility with older versions is not
   * preserved for this field rename. Old serialized streams will not populate this field, and it
   * may therefore default to {@code false} on deserialization. Use {@link
   * #storeTo(DataOutputStream)} for stable, versioned persistence.
   */
  protected final boolean deleteOnExitFlag;

  /**
   * Whether the target must be created and must not pre-exist on the first open for write.
   *
   * <p>Naming: renamed from {@code createFileOnly}. The new name avoids a symbol clash with the
   * base class method {@link #createFileOnly()} and clarifies intent.
   *
   * <p>Serialization note: default Java serialization compatibility with older versions is not
   * preserved for this field rename. Old serialized streams will not populate this field, and it
   * may therefore default to {@code false} on deserialization. Use {@link
   * #storeTo(DataOutputStream)} for stable, versioned persistence.
   */
  protected final boolean createFileOnlyFlag;

  /*
   * Historical note: some runtimes historically cached file length metadata. This class relies on
   * {@link BaseFileBucket#size()} which queries {@link File#length()} directly; no additional size
   * cache is maintained here. The constructor resets the restart counter managed by the base class
   * to ensure stale streams are detected.
   */

  /**
   * Constructs a new file-backed bucket.
   *
   * <p>The {@code file} is resolved to its absolute form. When identical to the original reference,
   * a distinct {@link File} instance pointing to the same path is created so the file can be safely
   * deleted without impacting the caller’s instance.
   *
   * @param file backing file path; resolved to an absolute path (must be non-{@code null})
   * @param readOnly when {@code true}, subsequent write attempts fail immediately; can also be set
   *     later via {@link #setReadOnly()} (irreversible)
   * @param createFileOnly when {@code true}, the first open for writing fails if the target already
   *     exists; writes are staged via a temp file and atomically moved on close to minimize races
   *     and avoid symlink overwrites
   * @param deleteOnExit when {@code true}, registers temporary files for deletion on JVM exit;
   *     persistent objects must not set this (see {@link #storeTo(DataOutputStream)})
   * @param deleteOnFree when {@code true}, {@link #free()} attempts to delete the underlying file
   * @throws NullPointerException if {@code file} is {@code null}
   */
  @SuppressWarnings("ReferenceEquality")
  public FileBucket(
      File file,
      boolean readOnly,
      boolean createFileOnly,
      boolean deleteOnExit,
      boolean deleteOnFree) {
    super(file, deleteOnExit);
    Objects.requireNonNull(file, "file");
    File absFile = file.getAbsoluteFile();
    // Copy it so we can safely delete it.
    if (file == absFile) absFile = new File(absFile.getPath());
    this.readOnly = readOnly;
    this.createFileOnlyFlag = createFileOnly;
    this.file = absFile;
    this.deleteOnFreeFlag = deleteOnFree;
    this.deleteOnExitFlag = deleteOnExit;
    fileRestartCounter = 0;
  }

  /**
   * No-args constructor for serialization frameworks.
   *
   * <p>Instances created through this constructor are incomplete until restored from a serialized
   * form (see the {@link #FileBucket(DataInputStream)} constructor). In this state, {@link #file}
   * is {@code null}.
   */
  protected FileBucket() {
    // For serialization frameworks only.
    super();
    file = null;
    deleteOnExitFlag = false;
    createFileOnlyFlag = false;
  }

  /**
   * Returns the backing file.
   *
   * @return absolute {@link File} path backing this bucket; may be {@code null} only for partially
   *     constructed instances created via the no-args constructor for deserialization
   */
  @Override
  public synchronized File getFile() {
    return file;
  }

  /**
   * Indicates whether this bucket currently rejects writes.
   *
   * @return {@code true} if the bucket is read-only; {@code false} otherwise
   */
  @Override
  public synchronized boolean isReadOnly() {
    return readOnly;
  }

  /**
   * Makes this bucket read-only.
   *
   * <p>After calling this method, attempts to obtain an output stream or otherwise modify the
   * contents fail with {@link java.io.IOException}. This operation is irreversible.
   */
  @Override
  public synchronized void setReadOnly() {
    readOnly = true;
  }

  /**
   * Whether the first open for writing must create the file (and fail if it already exists).
   *
   * @return {@code true} to enforce creation-only semantics on the first write
   */
  @Override
  protected boolean createFileOnly() {
    return createFileOnlyFlag;
  }

  /**
   * Whether temporary files created by this instance are registered for deletion on JVM exit.
   *
   * @return {@code true} if temp files are registered with {@link File#deleteOnExit()}
   */
  @Override
  protected boolean deleteOnExit() {
    return deleteOnExitFlag;
  }

  /**
   * Whether {@link #free()} deletes the underlying file.
   *
   * @return {@code true} if the file is deleted when the bucket is freed
   */
  @Override
  protected boolean deleteOnFree() {
    return deleteOnFreeFlag;
  }

  /**
   * Creates a shallow, read-only view over the same file.
   *
   * <p>The returned bucket references the same path and is independent of this instance, but the
   * underlying file is shared. Deleting the file invalidates both.
   *
   * @return a new read-only bucket referencing the same file path
   */
  @Override
  public RandomAccessBucket createShadow() {
    String fnam = file.getPath();
    File newFile = new File(fnam);
    return new FileBucket(newFile, true, false, false, false);
  }

  /**
   * Indicates whether the target file is an existing temporary file.
   *
   * <p>This implementation always returns {@code false} to stage writes in a temporary file and
   * perform an atomic move on close.
   *
   * @return always {@code false}
   */
  @Override
  protected boolean tempFileAlreadyExists() {
    return false;
  }

  /** Serialization marker for this subclass when using {@link #storeTo(DataOutputStream)}. */
  public static final int MAGIC = 0x8fe6e41b;

  /** On-disk format version for this subclass. */
  static final int VERSION = 1;

  /**
   * Writes the minimal state required to reconstruct this bucket.
   *
   * <p>Format: {@link #MAGIC} (int), base header (see {@link BaseFileBucket#storeTo}), {@link
   * #VERSION} (int), absolute path (UTF), {@link #readOnly} (boolean), {@link #deleteOnFreeFlag}
   * (boolean), {@link #createFileOnlyFlag} (boolean). Persistent buckets must not request
   * delete-on-exit; an {@link IllegalStateException} is thrown in that case.
   *
   * @param dos destination stream
   * @throws IOException on I/O errors
   * @throws IllegalStateException if {@link #deleteOnExitFlag} is {@code true}
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    super.storeTo(dos);
    dos.writeInt(VERSION);
    dos.writeUTF(file.toString());
    dos.writeBoolean(readOnly);
    dos.writeBoolean(deleteOnFreeFlag);
    if (deleteOnExitFlag) throw new IllegalStateException("Must not free on exit if persistent");
    dos.writeBoolean(createFileOnlyFlag);
  }

  /**
   * Reconstructs an instance from a stream produced by {@link #storeTo(DataOutputStream)}.
   *
   * <p>Precondition: the caller must have already consumed this subclass’s magic (see {@link
   * #MAGIC}). This constructor reads and validates the base header via {@link
   * BaseFileBucket#BaseFileBucket(DataInputStream)}, then validates the subclass {@link #VERSION}
   * and restores the flags. The {@link #deleteOnExitFlag} is always restored as {@code false} to
   * avoid relying on JVM-exit semantics for persisted objects.
   *
   * @param dis source stream positioned at the subclass header
   * @throws IOException on I/O errors
   * @throws StorageFormatException if the version is unknown or the data is malformed
   */
  protected FileBucket(DataInputStream dis) throws IOException, StorageFormatException {
    super(dis);
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    file = new File(dis.readUTF());
    readOnly = dis.readBoolean();
    deleteOnFreeFlag = dis.readBoolean();
    deleteOnExitFlag = false;
    createFileOnlyFlag = dis.readBoolean();
  }

  /** {@inheritDoc} */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + (createFileOnlyFlag ? 1231 : 1237);
    result = prime * result + (deleteOnExitFlag ? 1231 : 1237);
    result = prime * result + (deleteOnFreeFlag ? 1231 : 1237);
    result = prime * result + ((file == null) ? 0 : file.hashCode());
    result = prime * result + (readOnly ? 1231 : 1237);
    return result;
  }

  /** {@inheritDoc} */
  @Override
  @SuppressWarnings("EqualsGetClass")
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (obj == null) {
      return false;
    }
    if (getClass() != obj.getClass()) {
      return false;
    }
    FileBucket other = (FileBucket) obj;
    if (createFileOnlyFlag != other.createFileOnlyFlag) {
      return false;
    }
    if (deleteOnExitFlag != other.deleteOnExitFlag) {
      return false;
    }
    if (deleteOnFreeFlag != other.deleteOnFreeFlag) {
      return false;
    }
    if (file == null) {
      if (other.file != null) {
        return false;
      }
    } else if (!file.equals(other.file)) {
      return false;
    }
    return readOnly == other.readOnly;
  }
}
