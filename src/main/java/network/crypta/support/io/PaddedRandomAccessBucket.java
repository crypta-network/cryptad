package network.crypta.support.io;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.OutputStream;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import org.jetbrains.annotations.NotNull;

/**
 * Random-access bucket wrapper that pads the underlying storage to a power-of-two length.
 *
 * <p>This wrapper measures the number of bytes written through its output stream and, when the
 * stream is closed, adds pseudorandom padding (via {@link FileUtil#fill(OutputStream, long)}) so
 * that the stored length becomes the next power of two, with a minimum of {@code 1024} bytes. The
 * {@link #size()} reported by this wrapper is the actual data length (excluding padding). Readers
 * returned by {@link #getInputStream()} and {@link #getInputStreamUnbuffered()} expose only the
 * actual data and stop at {@code size()}, even if the underlying storage is larger due to padding.
 *
 * <p>Thread-safety: instances synchronize on {@code this} to guard internal counters and the
 * single-output-stream invariant. It is safe to get streams from different threads as long as
 * callers respect the “one open OutputStream at a time” rule.
 *
 * <p>Serialization: this class supports both the versioned persistence used by the recovery path
 * (see {@link #storeTo(DataOutputStream)} and the matching restoring constructor) and Java object
 * serialization. The wrapped {@link RandomAccessBucket} is {@code transient} and is written/read by
 * custom {@code writeObject}/{@code readObject} methods because it may not be {@link Serializable}.
 */
public final class PaddedRandomAccessBucket implements RandomAccessBucket, Serializable {
  @Serial private static final long serialVersionUID = 1L;
  // The underlying bucket may not be java.io.Serializable; keep transient and handle via
  // Java-serialization hooks similar to DelayedFreeBucket/PaddedBucket.
  private transient RandomAccessBucket underlying;
  private long size;
  private transient boolean outputStreamOpen;
  private boolean readOnly;

  /**
   * Constructs a wrapper over an empty underlying bucket.
   *
   * @param underlying the bucket to wrap; must be non-{@code null}
   */
  public PaddedRandomAccessBucket(RandomAccessBucket underlying) {
    this(underlying, 0);
  }

  /**
   * Constructs a wrapper over an existing bucket with a known data size.
   *
   * <p>The provided {@code size} is the actual data length in bytes (excluding any padding already
   * present on the underlying storage). The wrapper does not persist this value by itself; it is
   * used to limit readers and to report {@link #size()}.
   *
   * @param underlying the bucket to wrap; must be non-{@code null}
   * @param size actual data length in bytes (excludes padding)
   */
  public PaddedRandomAccessBucket(RandomAccessBucket underlying, long size) {
    this.underlying = underlying;
    this.size = size;
  }

  /**
   * No-arg constructor for Java serialization frameworks.
   *
   * <p>The runtime restoring path should prefer the versioned constructor that accepts a {@link
   * DataInputStream} and metadata helpers.
   */
  @SuppressWarnings("unused")
  PaddedRandomAccessBucket() {
    // For serialization.
    underlying = null;
    size = 0;
  }

  /**
   * Opens a buffered output stream positioned at offset {@code 0}.
   *
   * <p>Only one output stream may be open at a time. Opening a new stream resets the tracked {@link
   * #size()} to {@code 0}. On {@link OutputStream#close()}, the stream writes padding so the
   * underlying storage reaches the next power-of-two length (minimum {@code 1024} bytes).
   *
   * @return a buffered {@link OutputStream}
   * @throws IOException if an output stream is already open, or the underlying bucket fails to
   *     provide a stream
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    OutputStream os;
    synchronized (this) {
      if (outputStreamOpen)
        throw new IOException(
            "Already have an OutputStream for " + java.util.Objects.toIdentityString(this));
      os = underlying.getOutputStream();
      outputStreamOpen = true;
      size = 0;
    }
    return new MyOutputStream(os);
  }

  /**
   * Opens an unbuffered output stream positioned at offset {@code 0}.
   *
   * <p>Padding behavior is identical to {@link #getOutputStream()} and occurs when the returned
   * stream is closed.
   *
   * @return an unbuffered {@link OutputStream}
   * @throws IOException if an output stream is already open, or the underlying bucket fails to
   *     provide a stream
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    OutputStream os;
    synchronized (this) {
      if (outputStreamOpen)
        throw new IOException(
            "Already have an OutputStream for " + java.util.Objects.toIdentityString(this));
      os = underlying.getOutputStreamUnbuffered();
      outputStreamOpen = true;
      size = 0;
    }
    return new MyOutputStream(os);
  }

  private class MyOutputStream extends FilterOutputStream {

    private boolean closed;

    MyOutputStream(OutputStream os) {
      super(os);
    }

    @Override
    public void write(int b) throws IOException {
      out.write(b);
      synchronized (PaddedRandomAccessBucket.this) {
        size++;
      }
    }

    @Override
    public void write(byte @NotNull [] buf) throws IOException {
      out.write(buf);
      synchronized (PaddedRandomAccessBucket.this) {
        if (closed) throw new IOException("Already closed");
        size += buf.length;
      }
    }

    @Override
    public void write(byte @NotNull [] buf, int offset, int length) throws IOException {
      out.write(buf, offset, length);
      synchronized (PaddedRandomAccessBucket.this) {
        if (closed) throw new IOException("Already closed");
        size += length;
      }
    }

    @Override
    public void close() throws IOException {
      try {
        long padding;
        synchronized (PaddedRandomAccessBucket.this) {
          if (closed) return;
          closed = true;
          long paddedLength = paddedLength(size);
          padding = paddedLength - size;
        }
        FileUtil.fill(out, padding);
        out.close();
      } finally {
        synchronized (PaddedRandomAccessBucket.this) {
          outputStreamOpen = false;
        }
      }
    }

    @Override
    public String toString() {
      return "TrivialPaddedBucketOutputStream:"
          + out
          + "("
          + java.util.Objects.toIdentityString(PaddedRandomAccessBucket.this)
          + ")";
    }

    private static final long MIN_PADDED_SIZE = 1024;

    /**
     * Compute the padded length using a minimum of {@value MIN_PADDED_SIZE} and powers of two. The
     * result is always greater than or equal to the provided size.
     */
    private long paddedLength(long currentSize) {
      long s = Math.max(currentSize, MIN_PADDED_SIZE);
      if (s == MIN_PADDED_SIZE) return s;
      long min = MIN_PADDED_SIZE;
      long max = MIN_PADDED_SIZE << 1;
      while (true) {
        if (max < 0)
          throw new IllegalStateException(
              "Impossible size: " + s + " - min=" + min + ", max=" + max);
        if (s <= max) {
          return max;
        }
        min = max;
        max = max << 1;
      }
    }
  }

  /**
   * Opens a buffered input stream that exposes only the actual data length.
   *
   * <p>The returned stream reaches EOF after {@link #size()} bytes even if the underlying storage
   * contains additional padding.
   *
   * @return a buffered {@link InputStream}
   * @throws IOException if the underlying bucket cannot provide a stream
   */
  @Override
  public InputStream getInputStream() throws IOException {
    return new MyInputStream(underlying.getInputStream());
  }

  /**
   * Opens an unbuffered input stream that exposes only the actual data length.
   *
   * @return an unbuffered {@link InputStream}
   * @throws IOException if the underlying bucket cannot provide a stream
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    return new MyInputStream(underlying.getInputStreamUnbuffered());
  }

  private class MyInputStream extends FilterInputStream {

    private long counter;

    public MyInputStream(InputStream is) {
      super(is);
    }

    @Override
    public int read() throws IOException {
      byte[] buf = new byte[1];
      int length = read(buf, 0, 1);
      if (length > 0) {
        return Byte.toUnsignedInt(buf[0]);
      }
      return -1;
    }

    @Override
    public int read(byte @NotNull [] buf) throws IOException {
      return read(buf, 0, buf.length);
    }

    @Override
    public int read(byte @NotNull [] buf, int offset, int length) throws IOException {
      synchronized (PaddedRandomAccessBucket.this) {
        if (length < 0) return -1;
        if (length == 0) return 0;
        if (counter >= size) return -1;
        if (counter + length >= size) {
          length = (int) Math.min(length, size - counter);
        }
      }
      int ret = in.read(buf, offset, length);
      synchronized (PaddedRandomAccessBucket.this) {
        if (ret > 0) counter += ret;
      }
      return ret;
    }

    @Override
    public long skip(long length) throws IOException {
      synchronized (PaddedRandomAccessBucket.this) {
        if (counter >= size) return -1;
        if (counter + length >= size) {
          length = (int) Math.min(length, counter + length - size);
        }
      }
      long ret = in.skip(length);
      synchronized (PaddedRandomAccessBucket.this) {
        if (ret > 0) counter += ret;
      }
      return ret;
    }

    @Override
    public int available() throws IOException {
      int ret = in.available();
      synchronized (PaddedRandomAccessBucket.this) {
        long max = size - counter;
        if (max < ret) ret = (int) max;
      }
      return Math.max(ret, 0);
    }
  }

  /**
   * Returns a diagnostic name prefixed with {@code "Padded:"}.
   *
   * @return a human-readable identifier derived from the underlying bucket name
   */
  @Override
  public String getName() {
    return "Padded:" + underlying.getName();
  }

  /**
   * Returns the number of data bytes written, excluding any padding.
   *
   * @return actual data length in bytes
   */
  @Override
  public synchronized long size() {
    return size;
  }

  /**
   * Indicates whether this wrapper is marked read-only.
   *
   * <p>Note: This flag is advisory in this implementation and is not enforced by the class when
   * getting output streams. Callers should treat it as a contract and avoid writing once it is set.
   *
   * @return {@code true} if {@link #setReadOnly()} has been called; otherwise {@code false}
   */
  @Override
  public synchronized boolean isReadOnly() {
    return readOnly;
  }

  /** Marks this wrapper read-only. The operation is irreversible. */
  @Override
  public synchronized void setReadOnly() {
    readOnly = true;
  }

  /** Frees the underlying bucket, if supported by its implementation. */
  @Override
  public void free() {
    underlying.free();
  }

  /**
   * Creates a read-only shallow copy that shares the same external storage.
   *
   * @return a read-only wrapper over a shadow of the underlying bucket
   */
  @Override
  public RandomAccessBucket createShadow() {
    long currentSize;
    synchronized (this) {
      currentSize = size;
    }
    RandomAccessBucket shadow = underlying.createShadow();
    PaddedRandomAccessBucket ret = new PaddedRandomAccessBucket(shadow, currentSize);
    ret.setReadOnly();
    return ret;
  }

  /**
   * Reattaches runtime state after a restart and delegates to the underlying bucket.
   *
   * @param context runtime context used by nested bucket implementations
   * @throws ResumeFailedException if the underlying bucket cannot resume
   */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    underlying.onResume(context);
  }

  static final int MAGIC = 0x95c42e34;
  static final int VERSION = 1;

  /**
   * Writes a compact, versioned representation used by the recovery path.
   *
   * <p>Format: {@link #MAGIC} (int), {@link #VERSION} (int), {@code size} (long), {@code readOnly}
   * (boolean), followed by the serialized underlying bucket (via {@link
   * network.crypta.support.api.Bucket#storeTo(java.io.DataOutputStream)}).
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    long currentSize;
    boolean currentReadOnly;
    synchronized (this) {
      currentSize = size;
      currentReadOnly = readOnly;
    }
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    dos.writeLong(currentSize);
    dos.writeBoolean(currentReadOnly);
    underlying.storeTo(dos);
  }

  /**
   * Restoring constructor used by {@link BucketTools#restoreFrom(DataInputStream,
   * FilenameGenerator, PersistentFileTracker, MasterSecret)}.
   *
   * @param dis source stream positioned after this class's {@link #MAGIC}
   * @param fg filename generator used by file-backed bucket implementations
   * @param persistentFileTracker tracker used by persistent bucket types
   * @param masterKey master secret used by encrypted bucket types
   * @throws IOException if reading fails
   * @throws StorageFormatException if the on-disk format version is unknown or malformed
   * @throws ResumeFailedException if resuming a persistent artifact fails
   */
  PaddedRandomAccessBucket(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws IOException, StorageFormatException, ResumeFailedException {
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    size = dis.readLong();
    readOnly = dis.readBoolean();
    underlying =
        (RandomAccessBucket) BucketTools.restoreFrom(dis, fg, persistentFileTracker, masterKey);
  }

  /**
   * Converts to a {@link LockableRandomAccessBuffer} without copying and enforces the real size.
   *
   * <p>Precondition: no output stream is open. On success, this wrapper and the underlying bucket
   * are marked read-only. The returned buffer exposes exactly {@link #size()} bytes; attempts to
   * read/write beyond that throw {@link IOException} (enforced by {@link
   * PaddedRandomAccessBuffer}).
   *
   * @return a random-access buffer limited to the real data size
   * @throws IOException if an output stream is open or the underlying conversion fails
   */
  @Override
  public LockableRandomAccessBuffer toRandomAccessBuffer() throws IOException {
    long currentSize;
    synchronized (this) {
      if (outputStreamOpen) throw new IOException("Must close first");
      readOnly = true;
      currentSize = size;
    }
    underlying.setReadOnly();
    LockableRandomAccessBuffer u = underlying.toRandomAccessBuffer();
    return new PaddedRandomAccessBuffer(u, currentSize);
  }

  /**
   * Returns the wrapped bucket.
   *
   * @return the underlying random-access bucket (never {@code null} after successful construction
   *     or restore)
   */
  public RandomAccessBucket getUnderlying() {
    return underlying;
  }

  /* ===== Java serialization support ===== */
  // Preserve backward compatibility with the legacy Java-serialization layout where 'underlying'
  // was
  // included in the default field block. We include the actual underlying in the field block, so
  // older readers (serialVersionUID 1) do not need to read any trailing data. Newer readers keep
  // accepting both forms.

  private static final String FIELD_SIZE = "size";
  private static final String FIELD_READ_ONLY = "readOnly";
  private static final String FIELD_UNDERLYING = "underlying";

  @SuppressWarnings("unused")
  @Serial
  private static final ObjectStreamField[] serialPersistentFields = {
    new ObjectStreamField(FIELD_SIZE, long.class),
    new ObjectStreamField(FIELD_READ_ONLY, boolean.class),
    new ObjectStreamField(FIELD_UNDERLYING, RandomAccessBucket.class)
  };

  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    ObjectOutputStream.PutField fields = out.putFields();
    fields.put(FIELD_SIZE, size);
    fields.put(FIELD_READ_ONLY, readOnly);
    if (underlying instanceof Serializable serializable) {
      // Write the actual underlying into the field block for legacy readers.
      fields.put(FIELD_UNDERLYING, serializable);
    } else {
      throw new NotSerializableException(
          underlying == null ? "nullBucket" : underlying.getClass().getName());
    }
    out.writeFields();
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField fields = in.readFields();
    size = fields.get(FIELD_SIZE, 0L);
    readOnly = fields.get(FIELD_READ_ONLY, false);
    Object legacy = fields.get(FIELD_UNDERLYING, null);
    if (legacy instanceof RandomAccessBucket rab) {
      // Legacy form: underlying was serialized as part of the field set.
      underlying = rab;
    } else {
      // New form: read a trailing underlying object written after the fields.
      underlying = (RandomAccessBucket) in.readObject();
    }
  }
}
