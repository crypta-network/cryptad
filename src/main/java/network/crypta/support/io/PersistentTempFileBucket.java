package network.crypta.support.io;

import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.async.ClientContext;
import network.crypta.support.api.RandomAccessBucket;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Persistent, file-backed temporary bucket that survives process restarts.
 *
 * <p>This bucket stores its data in the persistent temp directory and is designed to be resumed
 * after a node restart. Unlike plain {@link TempFileBucket}, it never registers files with {@link
 * java.io.File#deleteOnExit()} and participates in the persistent file tracking managed by {@link
 * PersistentFileTracker}.
 *
 * <p>Thread-safety: instances synchronize internal state changes in the superclasses. They are not
 * intended for unrestricted concurrent use without external coordination. Streams opened from a
 * bucket must be closed before calling {@link #free()}.
 *
 * @since 1
 */
public class PersistentTempFileBucket extends TempFileBucket implements Serializable {
  private static final Logger LOG = LoggerFactory.getLogger(PersistentTempFileBucket.class);

  @Serial private static final long serialVersionUID = 1L;

  /**
   * Tracker used to check disk space and register files on resume. This field is transient and is
   * reattached from the {@link ClientContext} during {@link #innerResume(ClientContext)}; it does
   * not participate in equality.
   */
  transient PersistentFileTracker tracker;

  /**
   * Creates a persistent temp bucket for the given filename id.
   *
   * @param id stable identifier used by {@link FilenameGenerator} to derive the backing file name
   * @param generator filename generator for locating/migrating the file
   * @param tracker persistent file tracker providing disk-space checks and registration on resume
   */
  public PersistentTempFileBucket(
      long id, FilenameGenerator generator, PersistentFileTracker tracker) {
    this(id, generator, tracker, true);
  }

  /**
   * Constructs a persistent temp bucket with explicit delete-on-free policy.
   *
   * <p>Subclasses call this to create either a normal bucket ({@code deleteOnFree=true}) or a
   * shadow/read-only view ({@code deleteOnFree=false}).
   *
   * @param id stable identifier used by the generator
   * @param generator filename generator for locating/migrating the file
   * @param tracker persistent file tracker for disk checks and registration
   * @param deleteOnFree whether {@link #free()} deletes the backing file
   */
  protected PersistentTempFileBucket(
      long id, FilenameGenerator generator, PersistentFileTracker tracker, boolean deleteOnFree) {
    super(id, generator, deleteOnFree);
    this.tracker = tracker;
  }

  /** Default constructor for serialization frameworks. */
  @SuppressWarnings("unused")
  protected PersistentTempFileBucket() {
    // For serialization.
  }

  @Override
  protected boolean deleteOnExit() {
    // Never use File.deleteOnExit() for persistent temp files; cleanup is managed explicitly.
    return false;
  }

  static final int BUFFER_SIZE = 4096;

  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    /*
     * Wrap the superclass' unbuffered stream with a disk-space checking stream. The checker uses
     * the {@link PersistentFileTracker} to verify free space approximately every
     * {@link #BUFFER_SIZE} bytes written.
     *
     * @throws IOException if the bucket is freed or read-only, or if creation/validation of the
     *     underlying file fails. The implementation may also throw more specific subclasses such as
     *     {@link FileExistsException} and {@link FileDoesNotExistException} originating from the
     *     superclass.
     */
    OutputStream os = super.getOutputStreamUnbuffered();
    os = new DiskSpaceCheckingOutputStream(os, tracker, getFile(), BUFFER_SIZE);
    return os;
  }

  /**
   * Opens a buffered {@link OutputStream} positioned at the start of the file.
   *
   * <p>This is a convenience wrapper around {@link #getOutputStreamUnbuffered()} that applies a
   * {@link BufferedOutputStream} with the same internal buffer size used for disk-space checks.
   *
   * @return a buffered output stream for writing the bucket contents
   * @throws IOException if opening the underlying stream fails or the bucket is read-only/freed
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    return new BufferedOutputStream(getOutputStreamUnbuffered(), BUFFER_SIZE);
  }

  /**
   * Creates a read-only shadow view that is also persistent.
   *
   * <p>The returned bucket shares the same underlying file and is marked read-only. It does not
   * delete the file when freed. This override ensures the shadow preserves persistence semantics
   * (no delete-on-exit, no finalize-based deletion).
   *
   * @return a persistent, read-only {@link RandomAccessBucket} over the same file
   */
  @Override
  public RandomAccessBucket createShadow() {
    PersistentTempFileBucket ret =
        new PersistentTempFileBucket(filenameID, generator, tracker, false);
    ret.setReadOnly();
    // If the file is unexpectedly missing, log for diagnostics; shadow creation proceeds.
    if (!getFile().exists()) LOG.error("File does not exist when creating shadow: {}", getFile());
    return ret;
  }

  @Override
  protected void innerResume(ClientContext context) throws ResumeFailedException {
    /*
     * Reattaches runtime dependencies after deserialization and registers the file with the
     * persistent tracker.
     *
     * <p>Order matters: delegate to {@link TempFileBucket#innerResume(ClientContext)} first to
     * resolve the generator and file location, then wire the tracker and register the file so it is
     * not collected during persistent-temp cleanup.
     *
     * @param context client context providing {@link PersistentFileTracker}
     * @throws ResumeFailedException if the backing file cannot be located or validated
     */
    super.innerResume(context);
    if (LOG.isDebugEnabled()) LOG.debug("Resuming {}", this);
    tracker = context.getPersistentFileTracker();
    tracker.register(getFile());
  }

  /**
   * Indicates that this bucket participates in resume across restarts.
   *
   * @return always {@code true}
   */
  @Override
  protected boolean persistent() {
    return true;
  }

  /** Magic number written by {@link #storeTo} to identify this bucket subtype on disk. */
  public static final int MAGIC = 0x2ffdd4cf;

  /**
   * Returns the subtype-specific magic number used by persistence.
   *
   * @return magic constant written by {@link #storeTo(java.io.DataOutputStream)}
   */
  @Override
  protected int magic() {
    return MAGIC;
  }

  /**
   * Reconstructs an instance from its serialized form.
   *
   * @param dis source stream positioned after the subclass magic
   * @throws IOException on I/O errors
   * @throws StorageFormatException if the persisted data is malformed or version-mismatched
   */
  protected PersistentTempFileBucket(DataInputStream dis)
      throws IOException, StorageFormatException {
    super(dis);
  }

  /**
   * Returns the stable identifier used to group temporary artifacts on disk.
   *
   * @return the filename identifier associated with this bucket
   */
  @Override
  protected long getPersistentTempID() {
    return filenameID;
  }

  // Subclasses that add fields should override equals/hashCode. The tracker is transient and not
  // part of logical identity; delegate to super to preserve TempFileBucket's equality semantics.
  @Override
  public boolean equals(Object obj) {
    return super.equals(obj);
  }

  @Override
  public int hashCode() {
    return super.hashCode();
  }
}
