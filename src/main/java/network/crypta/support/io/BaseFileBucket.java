package network.crypta.support.io;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import network.crypta.client.async.ClientContext;
import network.crypta.fs.AppEnv;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.tanukisoftware.wrapper.WrapperManager;

/**
 * Base implementation for file-backed {@link RandomAccessBucket} instances.
 *
 * <p>This class coordinates access to a single underlying {@link File} and tracks open input/output
 * streams so they can be closed on {@link #free()} and optionally deleted from disk depending on
 * {@link #deleteOnFree()}.
 *
 * <p>Thread-safety: methods that mutate internal state synchronize on {@code this}. Instances are
 * not intended to be shared across unrelated subsystems without external coordination.
 *
 * <p>Read-only behavior: once {@link #setReadOnly()} is called or {@link #toRandomAccessBuffer()}
 * is invoked, write operations fail with {@link IOException}.
 */
public abstract class BaseFileBucket implements RandomAccessBucket, AutoCloseable {
  private static final Logger LOG = LoggerFactory.getLogger(BaseFileBucket.class);

  /**
   * Monotonic counter incremented each time a new output stream is obtained. Used to detect and
   * prevent writes from stale streams after a reopening.
   */
  protected long fileRestartCounter;

  /** Has the bucket been freed? If true, no further operations may be performed. */
  private boolean freed;

  /**
   * Currently open streams associated with the underlying file. Present only while the bucket is in
   * use and cleared on {@link #free()}.
   *
   * <p>Serializable subclasses rely on this field being {@code transient} so that live {@link
   * java.io.InputStream}/{@link java.io.OutputStream} instances are not serialized (they are not
   * {@link java.io.Serializable}). This prevents {@link java.io.NotSerializableException} during
   * checkpointing when streams are still open.
   *
   * <p>The list itself is not thread-safe; access is guarded by synchronization in {@link
   * #addStream(Closeable)} and {@link #removeStream(Closeable)}.
   */
  @SuppressWarnings(
      "java:S2065") // Base is not Serializable; subclasses are. Keep transient to avoid serializing
  // live streams.
  private transient List<Closeable> streams;

  // Sentinels for stream-detach results
  private static final Closeable[] NO_STREAMS = new Closeable[0];
  private static final Closeable[] ALREADY_FREED = new Closeable[0];

  /**
   * Directory used for temporary files created by this bucket implementation. Resolved at class
   * initialization; see static initializer for the exact resolution order.
   */
  protected static String tempDir;

  /**
   * Constructs a new bucket that targets the provided file.
   *
   * @param file target file; must be non-null
   * @param deleteOnExit when {@code true}, registers the file with {@link File#deleteOnExit()}.
   *     Note: this mechanism retains file paths until JVM shutdown and should be used sparingly. To
   *     actually delete temporary files on exit, subclasses must also return {@code true} from
   *     {@link #deleteOnExit()} so temporary files created by this class are registered too.
   * @throws NullPointerException if {@code file} is {@code null}
   */
  @SuppressWarnings("unused")
  protected BaseFileBucket(File file, boolean deleteOnExit) {
    this(file, deleteOnExit, false, false);
  }

  /**
   * Constructs a new bucket and validates file-mode invariants without invoking subclass methods.
   *
   * @param file target file; must be non-null
   * @param deleteOnExit when {@code true}, registers the file with {@link File#deleteOnExit()}
   * @param createFileOnly whether writes must fail when the target file already exists
   * @param tempFileAlreadyExists whether writes operate directly on an existing temporary file
   * @throws NullPointerException if {@code file} is {@code null}
   * @throws AssertionError if {@code createFileOnly} and {@code tempFileAlreadyExists} are both
   *     {@code true}
   */
  protected BaseFileBucket(
      File file, boolean deleteOnExit, boolean createFileOnly, boolean tempFileAlreadyExists) {
    if (file == null) throw new NullPointerException();
    maybeSetDeleteOnExit(deleteOnExit, file);
    assert !(createFileOnly && tempFileAlreadyExists); // Mutually incompatible!
  }

  /** Default constructor for deserialization frameworks. */
  protected BaseFileBucket() {
    // For serialization frameworks only.
  }

  /** Register {@code file} for deletion on JVM exit when requested. */
  private void maybeSetDeleteOnExit(boolean deleteOnExit, File file) {
    if (deleteOnExit) setDeleteOnExit(file);
  }

  /**
   * Registers the given file with {@link File#deleteOnExit()} and logs rare JVM failures observed
   * during shutdown sequences (e.g., in Wrapper-managed lifecycles).
   *
   * @param file file to register
   */
  protected void setDeleteOnExit(File file) {
    try {
      file.deleteOnExit();
    } catch (NullPointerException e) {
      if (WrapperManager.hasShutdownHookBeenTriggered()) {
        LOG.info(
            "NullPointerException setting deleteOnExit while shutting down - buggy JVM code: {}",
            e,
            e);
      } else {
        LOG.error("Caught {} doing deleteOnExit() for {} - JVM bug ????", e, file);
      }
    }
  }

  /**
   * Opens a new unbuffered {@link OutputStream} for writing from the beginning of the file.
   *
   * <p>When {@link #tempFileAlreadyExists()} is {@code false}, data is first written to a temporary
   * file in the same directory and atomically moved into place on close. When {@code true}, the
   * underlying file must already exist and will be written directly.
   *
   * <p>Side effects: the stream is tracked internally and automatically removed on close or {@link
   * #free()}.
   *
   * @return an unbuffered output stream positioned at offset 0
   * @throws IOException if the bucket has been freed or is read-only
   * @throws FileExistsException if {@link #createFileOnly()} is {@code true} and the file already
   *     exists on first open
   * @throws FileDoesNotExistException if {@link #tempFileAlreadyExists()} is {@code true} but the
   *     file is absent or not readable/writable
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    synchronized (this) {
      File file = getFile();
      if (freed) throw new IOException("File already freed: " + this);
      if (isReadOnly()) throw new IOException("Bucket is read-only: " + this);

      if (createFileOnly()
          && // Fail if the file already exists
          fileRestartCounter == 0
          && // Ignore if we're just clobbering our own file after a previous getOutputStream()
          !file.createNewFile()) {
        throw new FileExistsException(file);
      }
      if (tempFileAlreadyExists() && !(file.exists() && file.canRead() && file.canWrite())) {
        throw new FileDoesNotExistException(file);
      }

      if (streams != null && !streams.isEmpty())
        LOG.error("Streams open on {} while opening an output stream!: {}", this, streams);

      boolean rename = !tempFileAlreadyExists();
      File tempfile = rename ? getTempfile() : file;
      long streamNumber = ++fileRestartCounter;

      FileBucketOutputStream os = new FileBucketOutputStream(tempfile, streamNumber);

      if (LOG.isTraceEnabled()) LOG.trace("Creating output stream {}", os);

      addStream(os);
      return os;
    }
  }

  /**
   * Opens a buffered {@link OutputStream} equivalent to {@link #getOutputStreamUnbuffered()} but
   * wrapped in a {@link BufferedOutputStream}.
   *
   * @return a buffered output stream positioned at offset 0
   * @throws IOException if opening the underlying stream fails
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    return new BufferedOutputStream(getOutputStreamUnbuffered());
  }

  /** Adds the stream to the internal tracking list. Guarded by {@code this}. */
  private synchronized void addStream(Closeable stream) {
    // Keep memory overhead low; allocate lazily and collapse back to null when empty.
    if (streams == null) streams = new ArrayList<>(1);
    streams.add(stream);
  }

  /** Removes the stream from the tracking list. Guarded by {@code this}. */
  private synchronized void removeStream(Closeable stream) {
    // Streams may already be cleared if free() raced; tolerate missing list.
    if (streams == null) return;
    streams.remove(stream);
    if (streams.isEmpty()) streams = null;
  }

  /**
   * Indicates whether the file is a pre-existing temporary file.
   *
   * <p>When {@code true}, operations open the file in-place. When {@code false}, writes are staged
   * to a temporary file and atomically moved into place on close.
   *
   * <p>Must be mutually exclusive with {@link #createFileOnly()}.
   *
   * @return {@code true} if the target already exists and is opened directly
   */
  protected abstract boolean tempFileAlreadyExists();

  /**
   * Indicates that writes should fail if the target file already exists.
   *
   * <p>Must be mutually exclusive with {@link #tempFileAlreadyExists()}.
   *
   * @return {@code true} to enforce creation-only semantics
   */
  protected abstract boolean createFileOnly();

  /**
   * Whether temporary files created by this bucket should be registered with {@link
   * File#deleteOnExit()}.
   *
   * @return {@code true} if temp files should be removed on JVM exit
   */
  protected abstract boolean deleteOnExit();

  /**
   * Whether the underlying file should be deleted when {@link #free()} is called.
   *
   * @return {@code true} if {@link #free()} deletes the file
   */
  protected abstract boolean deleteOnFree();

  /**
   * Creates a temporary file in the same directory as the target file.
   *
   * @return a new temporary file path
   * @throws IOException if creating the file fails
   */
  protected File getTempfile() throws IOException {
    File file = getFile();
    File f = FileUtil.createTempFile(file.getName(), ".freenet-tmp", file.getParentFile());
    if (deleteOnExit()) f.deleteOnExit();
    return f;
  }

  /**
   * Output stream used by the bucket to stage or write data to disk.
   *
   * <p>When creation-only semantics are required, data is written to a temp file and atomically
   * moved into place on close to prevent races and symlink attacks.
   */
  class FileBucketOutputStream extends FileOutputStream {

    private final long restartCount;
    private final File tempfile;
    private boolean closed;

    protected FileBucketOutputStream(File tempfile, long restartCount)
        throws FileNotFoundException {
      super(tempfile, false);
      if (LOG.isDebugEnabled()) LOG.debug("Writing to {} for {} : {}", tempfile, getFile(), this);
      this.tempfile = tempfile;
      this.restartCount = restartCount;
      closed = false;
    }

    /** Ensures the stream is still valid and the bucket is writable. */
    protected void confirmWriteSynchronized() throws IOException {
      synchronized (BaseFileBucket.this) {
        if (fileRestartCounter > restartCount)
          throw new IllegalStateException("writing to file after restart");
        if (freed) throw new IOException("writing to file after it has been freed");
      }
      if (isReadOnly()) throw new IOException("File is read-only");
    }

    @Override
    public void write(byte @NotNull [] b) throws IOException {
      synchronized (BaseFileBucket.this) {
        confirmWriteSynchronized();
        super.write(b);
      }
    }

    @Override
    public void write(byte @NotNull [] b, int off, int len) throws IOException {
      synchronized (BaseFileBucket.this) {
        confirmWriteSynchronized();
        super.write(b, off, len);
      }
    }

    @Override
    public void write(int b) throws IOException {
      synchronized (BaseFileBucket.this) {
        confirmWriteSynchronized();
        super.write(b);
      }
    }

    @Override
    public void close() throws IOException {
      File file;
      synchronized (this) {
        if (closed) return;
        closed = true;
        file = getFile();
      }
      boolean renaming = !tempFileAlreadyExists();
      removeStream(this);
      if (LOG.isDebugEnabled()) LOG.debug("Closing output stream for {}", BaseFileBucket.this);
      try {
        super.close();
      } catch (IOException e) {
        handleCloseFailure(renaming, e);
        return; // Unreachable but keeps static analyzers happy
      }
      finalizeRenameIfRequired(file, renaming);
    }

    private void handleCloseFailure(boolean renaming, IOException e) throws IOException {
      if (LOG.isDebugEnabled())
        LOG.debug("Output stream close failed for {}: {}", BaseFileBucket.this, e, e);
      if (renaming) deleteTempFileQuietly();
      throw e;
    }

    private void finalizeRenameIfRequired(File file, boolean renaming) throws IOException {
      // getOutputStream() creates the file as a marker, so DON'T check for its existence,
      // even if createFileOnly() is true.
      if (renaming && !FileUtil.moveTo(tempfile, file)) {
        deleteTempFileQuietly();
        if (LOG.isDebugEnabled()) LOG.debug("Rename failed after delete for {}", this);
        throw new IOException("Cannot rename file");
      }
    }

    private void deleteTempFileQuietly() {
      try {
        Files.deleteIfExists(tempfile.toPath());
      } catch (IOException ioe1) {
        if (LOG.isDebugEnabled())
          LOG.debug("Temp file delete failed {}: {}", tempfile, ioe1.toString());
      }
    }

    @Override
    public String toString() {
      return super.toString() + ":" + BaseFileBucket.this;
    }
  }

  class FileBucketInputStream extends FileInputStream {
    boolean closed;

    public FileBucketInputStream(File f) throws IOException {
      super(f);
    }

    @Override
    public void close() throws IOException {
      synchronized (this) {
        if (closed) return;
        closed = true;
      }
      removeStream(this);
      super.close();
    }

    @Override
    public String toString() {
      return super.toString() + ":" + BaseFileBucket.this;
    }
  }

  /**
   * Opens an unbuffered {@link InputStream} that reads from the beginning of the file, or a {@link
   * NullInputStream} if the file does not exist.
   *
   * @return an input stream, possibly {@link NullInputStream} when the file is missing
   * @throws IOException if the bucket has been freed
   */
  @Override
  public synchronized InputStream getInputStreamUnbuffered() throws IOException {
    if (freed) throw new IOException("File already freed: " + this);
    File file = getFile();
    if (!file.exists()) {
      LOG.info("File does not exist: {} for {}", file, this);
      return new NullInputStream();
    } else {
      FileBucketInputStream is = new FileBucketInputStream(file);
      addStream(is);
      if (LOG.isTraceEnabled()) LOG.trace("Creating input stream {}", is);
      return is;
    }
  }

  /** Returns a buffered {@link InputStream} backed by {@link #getInputStreamUnbuffered()}. */
  @Override
  public InputStream getInputStream() throws IOException {
    return new BufferedInputStream(getInputStreamUnbuffered());
  }

  /** Returns the file name component of {@link #getFile()}. */
  @Override
  public synchronized String getName() {
    return getFile().getName();
  }

  /** Returns the current length of the underlying file in bytes. */
  @Override
  public synchronized long size() {
    return getFile().length();
  }

  /**
   * Deletes the underlying file using NIO for clearer error reporting. Does not throw on failure;
   * logs a warning instead. Callers should verify existence separately when required.
   */
  protected synchronized void deleteFile() {
    if (LOG.isDebugEnabled()) LOG.debug("Deleting bucket file {} for {}", getFile(), this);
    try {
      Files.delete(getFile().toPath());
    } catch (IOException e) {
      // Preserve existing behavior: do not throw, but provide clearer context.
      LOG.warn("Bucket file delete failed {}: {}", getFile(), e.toString());
    }
  }

  /*
   * Resolve the temporary directory once at class-load time:
   *   1) java.io.tmpdir system property
   *   2) Platform-specific fallbacks (/tmp, /var/tmp on Linux; common TEMP paths on Windows)
   *   3) user.dir as a last resort
   */
  static {
    // Try the Java property (1.2 and above)
    tempDir = System.getProperty("java.io.tmpdir");

    // Deprecated calls removed.

    // Try TEMP and TMP
    // Deprecated TEMP/TMP environment probing removed; rely on standard properties

    // make some semi-educated guesses based on OS.

    if (tempDir == null) {
      AppEnv env = new AppEnv();
      String[] candidates = null;
      if (env.isLinux()) {
        candidates = new String[] {"/tmp", "/var/tmp"};
      } else if (env.isWindows()) {
        candidates = new String[] {"C:\\TEMP", "C:\\WINDOWS\\TEMP"};
      }
      if (candidates != null) {
        for (String candidate : candidates) {
          File path = new File(candidate);
          if (path.exists() && path.isDirectory() && path.canWrite()) {
            tempDir = candidate;
            break;
          }
        }
      }
    }

    // last resort -- use the current working directory

    if (tempDir == null) {
      // This can be null -- but that's OK, null => cwd for File constructor, anyway.
      tempDir = System.getProperty("user.dir");
    }
  }

  /**
   * Splits the file into contiguous read-only {@link Bucket} slices of at most {@code splitSize}
   * bytes each.
   *
   * <p>Ownership: the caller is responsible for closing/freeing the returned buckets. Slices are
   * independent views over the same file; deleting the underlying file invalidates all slices.
   *
   * @param splitSize requested size in bytes for each slice; the last slice may be smaller
   * @return an array of read-only buckets covering the full file content; never {@code null}
   * @throws IllegalArgumentException if the file is excessively large for the requested slice size
   */
  public synchronized Bucket[] split(int splitSize) {
    long length = size();
    if (length > ((long) Integer.MAX_VALUE) * splitSize)
      throw new IllegalArgumentException("Way too big!: " + length + " for " + splitSize);
    int bucketCount = (int) (length / splitSize);
    if (length % splitSize > 0) bucketCount++;
    Bucket[] buckets = new Bucket[bucketCount];
    File file = getFile();
    for (int i = 0; i < buckets.length; i++) {
      long startAt = (long) i * splitSize;
      long endAt = Math.min(startAt + splitSize, length);
      long len = endAt - startAt;
      // The caller takes ownership and is responsible for closing/freeing the bucket.
      //noinspection resource
      buckets[i] = new ReadOnlyFileSliceBucket(file, startAt, len);
    }
    return buckets;
  }

  /** Frees resources associated with the bucket; delegates to {@link #free(boolean)}. */
  @Override
  public void free() {
    free(false);
  }

  /**
   * Closes this bucket, releasing any associated resources.
   *
   * <p>This is an alias for {@link #free()}; provided to integrate with try-with-resources where
   * applicable.
   */
  @Override
  public void close() {
    free();
  }

  /**
   * Frees the bucket and optionally deletes the file.
   *
   * <p>Closes any open streams tracked by this bucket. If {@link #deleteOnFree()} is {@code true}
   * or {@code forceFree} is {@code true}, attempts to delete the underlying file.
   *
   * @param forceFree when {@code true}, forces deletion even if {@link #deleteOnFree()} is {@code
   *     false}
   */
  public void free(boolean forceFree) {
    if (LOG.isDebugEnabled()) LOG.debug("Freeing bucket {}", this);
    Closeable[] toClose = markFreedAndDetachStreams();
    if (toClose == ALREADY_FREED) return;
    if (toClose.length > 0) closeStreams(toClose);
    deleteIfRequested(forceFree);
  }

  private synchronized Closeable[] markFreedAndDetachStreams() {
    if (freed) return ALREADY_FREED;
    freed = true;
    Closeable[] result = streams == null ? NO_STREAMS : streams.toArray(new Closeable[0]);
    streams = null;
    return result;
  }

  /** Logs and closes any streams left open at free-time. */
  private void closeStreams(Closeable[] toClose) {
    if (LOG.isErrorEnabled()) {
      LOG.error("Streams still open during free {}: {}", this, Arrays.toString(toClose));
    }
    for (Closeable strm : toClose) {
      try {
        strm.close();
      } catch (Exception e) {
        LOG.error("Caught closing stream in free(): {}", e, e);
      }
    }
  }

  /** Deletes the underlying file if policy or caller requested it. */
  private void deleteIfRequested(boolean forceFree) {
    File file = getFile();
    if ((deleteOnFree() || forceFree) && file.exists()) {
      LOG.trace("Deleting bucket file on free {}", file);
      deleteFile();
      if (file.exists()) LOG.error("Bucket file still exists after delete {}", file);
    }
  }

  /** Returns a diagnostic string including the file path and the number of open streams. */
  @Override
  public synchronized String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append(super.toString());
    sb.append(':');
    File f = getFile();
    if (f != null) sb.append(f.getPath());
    else sb.append("???");
    sb.append(":streams=");
    sb.append(streams == null ? 0 : streams.size());
    return sb.toString();
  }

  /** Returns the file that backs this bucket. */
  public abstract File getFile();

  /** No-op resume hook; subclasses may override to restore persistence contracts. */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    // Intentionally empty
  }

  /** Serialization marker for buckets stored via {@link #storeTo(DataOutputStream)}. */
  public static final int MAGIC = 0xc4b7533d;

  /** On-disk format version for {@link #storeTo(DataOutputStream)}. */
  static final int VERSION = 1;

  /**
   * Writes minimal state required to reconstruct this bucket instance.
   *
   * @param dos destination stream
   * @throws IOException on I/O errors
   * @since 1
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    dos.writeBoolean(freed);
  }

  /**
   * Reconstructs the bucket from a previously stored stream produced by {@link #storeTo}.
   *
   * @param dis source stream positioned at the bucket header
   * @throws IOException on I/O errors
   * @throws StorageFormatException when the data is malformed or uses an unknown version
   */
  protected BaseFileBucket(DataInputStream dis) throws IOException, StorageFormatException {
    // Read and validate the header
    int magic = dis.readInt();
    if (magic != MAGIC) throw new StorageFormatException("Bad magic");
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    freed = dis.readBoolean();
  }

  /**
   * Converts this bucket to a {@link LockableRandomAccessBuffer} for random read access.
   *
   * <p>Marks the bucket read-only prior to conversion. The file must be non-empty.
   *
   * @return a random-access buffer over the same file
   * @throws IOException if the bucket is already freed or empty
   */
  @Override
  public LockableRandomAccessBuffer toRandomAccessBuffer() throws IOException {
    if (freed) throw new IOException("Already freed");
    setReadOnly();
    long size = size();
    if (size == 0) throw new IOException("Must not be empty");
    return new PooledFileRandomAccessBuffer(
        getFile(), true, size, getPersistentTempID(), deleteOnFree());
  }

  /**
   * Returns a stable identifier to group temporary artifacts on disk, or {@code -1} to disable.
   * Subclasses may override to provide a non-negative persistent ID.
   */
  protected long getPersistentTempID() {
    return -1;
  }
}
