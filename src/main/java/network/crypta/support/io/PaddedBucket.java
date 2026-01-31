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
import network.crypta.support.api.Bucket;
import org.jetbrains.annotations.NotNull;

/**
 * Bucket wrapper that pads written data to the next power-of-two byte length.
 *
 * <p>This class tracks the number of bytes written through its output stream and, on {@link
 * OutputStream#close()}, adds pseudorandom padding (via {@link FileUtil#fill(OutputStream, long)})
 * so the underlying storage length becomes a power of two, with a minimum of 1024 bytes. The {@link
 * #size()} reported by this wrapper is the actual data size (excluding padding). Readers returned
 * by {@link #getInputStream()} and {@link #getInputStreamUnbuffered()} expose only the actual data
 * and stop at {@code size()}, even if the underlying storage is larger due to padding.
 *
 * <p>Thread-safety: this class synchronizes on {@code this} to guard its internal counters and the
 * single-output-stream invariant. It is safe to call the various accessors from different threads
 * provided callers respect the “one open output stream at a time” contract.
 *
 * <p>Serialization: Java serialization is supported. For backward compatibility with historical
 * releases where the {@code underlying} field was serialized as part of the default field set, the
 * custom serialization logic reads a legacy field when present and otherwise reads a trailing
 * serialized object. See {@link #serialPersistentFields}, {@link #writeObject(ObjectOutputStream)}
 * and {@link #readObject(ObjectInputStream)} for details.
 */
public class PaddedBucket implements Bucket, Serializable {
  @Serial private static final long serialVersionUID = 1L;
  // Wrapped bucket may not be java.io.Serializable; keep transient and handle via
  // Java-serialization hooks similar to DelayedFreeBucket.
  private transient Bucket underlying;
  private long size;
  private transient boolean outputStreamOpen;
  private boolean readOnly;

  /**
   * Constructs a wrapper over an empty underlying bucket.
   *
   * @param underlying the bucket to wrap; must be non-null
   */
  public PaddedBucket(Bucket underlying) {
    this(underlying, 0);
  }

  /**
   * Constructs a wrapper over an existing bucket with a known data size.
   *
   * <p>The provided {@code size} is the actual data length (excluding any padding already present
   * on the underlying storage). The wrapper does not persist this value by itself.
   *
   * @param underlying the bucket to wrap; must be non-null
   * @param size actual data length in bytes (excludes padding)
   */
  public PaddedBucket(Bucket underlying, long size) {
    this.underlying = underlying;
    this.size = size;
  }

  /** No-arg constructor for Java serialization frameworks. */
  @SuppressWarnings("unused")
  protected PaddedBucket() {
    // Initialized by deserialization paths.
    underlying = null;
    size = 0;
  }

  /**
   * Opens a buffered output stream that starts writing at the beginning.
   *
   * <p>Only one output stream may be open at a time. Opening a new stream resets the tracked {@code
   * size} to 0. On {@link OutputStream#close()}, the stream writes padding so the underlying
   * storage reaches the next power-of-two length (minimum 1024 bytes).
   *
   * @return a buffered {@link OutputStream}
   * @throws IOException if an output stream is already open or the underlying bucket fails
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    OutputStream os;
    synchronized (this) {
      if (outputStreamOpen) throw new IOException("Already have an OutputStream for " + this);
      os = underlying.getOutputStream();
      outputStreamOpen = true;
      size = 0;
    }
    return new MyOutputStream(os);
  }

  /**
   * Opens an unbuffered output stream that starts writing at the beginning. Padding is still added
   * on close.
   *
   * @return an unbuffered {@link OutputStream}
   * @throws IOException if an output stream is already open or the underlying bucket fails
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    OutputStream os;
    synchronized (this) {
      if (outputStreamOpen) throw new IOException("Already have an OutputStream for " + this);
      os = underlying.getOutputStreamUnbuffered();
      outputStreamOpen = true;
      size = 0;
    }
    return new MyOutputStream(os);
  }

  private class MyOutputStream extends FilterOutputStream {

    MyOutputStream(OutputStream os) {
      super(os);
    }

    @Override
    public void write(int b) throws IOException {
      out.write(b);
      synchronized (PaddedBucket.this) {
        size++;
      }
    }

    @Override
    public void write(byte @NotNull [] buf) throws IOException {
      out.write(buf);
      synchronized (PaddedBucket.this) {
        size += buf.length;
      }
    }

    @Override
    public void write(byte @NotNull [] buf, int offset, int length) throws IOException {
      out.write(buf, offset, length);
      synchronized (PaddedBucket.this) {
        size += length;
      }
    }

    @Override
    public void close() throws IOException {
      try {
        long padding;
        synchronized (PaddedBucket.this) {
          long paddedLength = paddedLength(size);
          padding = paddedLength - size;
        }
        FileUtil.fill(out, padding);
        out.close();
      } finally {
        synchronized (PaddedBucket.this) {
          outputStreamOpen = false;
        }
      }
    }

    @Override
    public String toString() {
      return "TrivialPaddedBucketOutputStream:" + out + "(" + PaddedBucket.this + ")";
    }

    /**
     * Computes the padded length for the given size using a minimum of {@link #MIN_PADDED_SIZE} and
     * powers of two growth. The result is always {@code >=} the provided size.
     */
    private long paddedLength(long size) {
      if (size < MIN_PADDED_SIZE) size = MIN_PADDED_SIZE;
      if (size == MIN_PADDED_SIZE) return size;
      long min = MIN_PADDED_SIZE;
      long max = MIN_PADDED_SIZE << 1;
      while (true) {
        if (max < 0)
          throw new IllegalStateException(
              "Impossible size: " + size + " - min=" + min + ", max=" + max);
        // size is always >= min at this point; only need to compare to upper bound
        if (size <= max) {
          return max;
        }
        min = max;
        max = max << 1;
      }
    }
  }

  private static final long MIN_PADDED_SIZE = 1024;

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
      synchronized (PaddedBucket.this) {
        if (length < 0) return -1;
        if (length == 0) return 0;
        if (counter >= size) return -1;
        if (counter + length >= size) {
          length = (int) Math.min(length, size - counter);
        }
      }
      int ret = in.read(buf, offset, length);
      synchronized (PaddedBucket.this) {
        if (ret > 0) counter += ret;
      }
      return ret;
    }

    @Override
    public long skip(long length) throws IOException {
      synchronized (PaddedBucket.this) {
        if (counter >= size) return -1;
        if (counter + length >= size) {
          length = (int) Math.min(length, counter + length - size);
        }
      }
      long ret = in.skip(length);
      synchronized (PaddedBucket.this) {
        if (ret > 0) counter += ret;
      }
      return ret;
    }

    @Override
    public synchronized int available() throws IOException {
      long max = size - counter;
      int ret = in.available();
      if (max < ret) ret = (int) max;
      return Math.max(ret, 0);
    }
  }

  /**
   * Returns a diagnostic name prefixed with {@code Padded:}.
   *
   * @return human-readable identifier derived from the underlying bucket
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
   * Indicates whether this wrapper is read-only.
   *
   * @return {@code true} if {@link #setReadOnly()} has been called; otherwise {@code false}
   */
  @Override
  public synchronized boolean isReadOnly() {
    return readOnly;
  }

  /** Makes this wrapper read-only. Irreversible. */
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
  public Bucket createShadow() {
    Bucket shadow = underlying.createShadow();
    PaddedBucket ret = new PaddedBucket(shadow, size);
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

  static final int MAGIC = 0xdaff6185;
  static final int VERSION = 1;

  // Field names used for custom Java serialization layout.
  private static final String FIELD_SIZE = "size";
  private static final String FIELD_READ_ONLY = "readOnly";
  private static final String FIELD_UNDERLYING = "underlying";

  // Preserve backward compatibility with historical Java-serialization layout where 'underlying'
  // was a non-transient field written via default serialization. We keep a declared persistent
  // field for it so readObject() can consume legacy streams that still carry it.
  @Serial
  private static final ObjectStreamField[] serialPersistentFields = {
    new ObjectStreamField(FIELD_SIZE, long.class),
    new ObjectStreamField(FIELD_READ_ONLY, boolean.class),
    new ObjectStreamField(FIELD_UNDERLYING, Bucket.class)
  };

  /**
   * Writes a compact, versioned representation used by the recovery path.
   *
   * <p>Format: {@link #MAGIC} (int), {@link #VERSION} (int), {@code size} (long), {@code readOnly}
   * (boolean), followed by the serialized underlying bucket (via {@link Bucket#storeTo}).
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    dos.writeLong(size);
    dos.writeBoolean(readOnly);
    underlying.storeTo(dos);
  }

  /**
   * Restoring constructor used by {@link BucketTools#restoreFrom}.
   *
   * @param dis source stream positioned after this class's {@link #MAGIC}
   * @param fg filename generator used by file-backed bucket implementations
   * @param persistentFileTracker tracker used by persistent bucket types
   * @param masterKey master secret used by encrypted bucket types
   * @throws IOException if reading fails
   * @throws StorageFormatException if the on-disk format version is unknown or malformed
   * @throws ResumeFailedException if resuming a persistent artifact fails
   */
  protected PaddedBucket(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws IOException, StorageFormatException, ResumeFailedException {
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Bad version");
    size = dis.readLong();
    readOnly = dis.readBoolean();
    underlying = BucketTools.restoreFrom(dis, fg, persistentFileTracker, masterKey);
  }

  /* ===== Java serialization support ===== */
  // Backward-compatible Java-serialization layout: include the underlying bucket in the field set
  // as older releases did. This ensures older readers (serialVersionUID 1) can deserialize without
  // reading any trailing data. Newer readers continue to accept both forms.

  /**
   * Custom Java serialization writer that preserves backward compatibility.
   *
   * <p>Historically, {@code underlying} was serialized as part of the default field set. New
   * versions reserve the field name (as {@code null}) and write the actual bucket after the fields.
   * This allows both old and new readers to reconstruct the object graph.
   *
   * @param out destination stream
   * @throws IOException if writing fails or if the underlying bucket is not serializable
   */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    assert serialPersistentFields.length > 0;
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

  /**
   * Custom Java serialization reader that handles both legacy and current layouts.
   *
   * <p>If a legacy stream contains {@code underlying} in the field set, it is used directly;
   * otherwise the underlying bucket is read as a trailing object.
   *
   * @param in source stream
   * @throws IOException if reading fails
   * @throws ClassNotFoundException if the underlying bucket class is unavailable
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField fields = in.readFields();
    size = fields.get(FIELD_SIZE, 0L);
    readOnly = fields.get(FIELD_READ_ONLY, false);
    Object legacy = fields.get(FIELD_UNDERLYING, null);
    if (legacy instanceof Bucket b) {
      // Old stream format: 'underlying' was serialized as part of the field set.
      underlying = b;
    } else {
      // New stream format: read the trailing serialized bucket after the fields.
      underlying = (Bucket) in.readObject();
    }
  }
}
