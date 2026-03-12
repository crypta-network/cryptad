package network.crypta.support.io;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.Serial;
import java.io.Serializable;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.LockableRandomAccessBuffer;

/**
 * A {@link LockableRandomAccessBuffer} wrapper that exposes a logical prefix of the underlying
 * buffer.
 *
 * <p>Callers can use this type to constrain reads and writes to the first {@code realSize} bytes of
 * an existing random-access buffer that may be larger on disk (for example, because it includes
 * padding or alignment). All I/O delegates to the wrapped buffer; this class only enforces bounds.
 *
 * <h2>Behavior</h2>
 *
 * <ul>
 *   <li>For {@code length > 0}, operations require {@code fileOffset + length <= realSize}. The
 *       check is overflow-safe.
 *   <li>For {@code length == 0}, operations require {@code fileOffset <= realSize}.
 *   <li>Argument validation (e.g., negative offsets) and concurrency guarantees are provided by the
 *       wrapped buffer as required by the {@link network.crypta.support.api.RandomAccessBuffer}
 *       contract.
 * </ul>
 *
 * <h2>Persistence</h2>
 *
 * <ul>
 *   <li><strong>Runtime format:</strong> {@link #storeTo(DataOutputStream)} writes a marker, the
 *       logical size, then the wrapped buffer. The matching constructor restores the wrapper and
 *       verifies that the wrapped size is at least {@code realSize}.
 *   <li><strong>Java serialization:</strong> The class is {@link Serializable}. Custom
 *       serialization declares persistent fields for both the wrapped buffer and the logical size
 *       (see {@code serialPersistentFields}) to remain compatible with previously serialized forms.
 *       The wrapped buffer itself must be {@link Serializable}.
 * </ul>
 */
public final class PaddedRandomAccessBuffer implements LockableRandomAccessBuffer, Serializable {
  @Serial private static final long serialVersionUID = 1L;
  // Wrapped buffer reference; may not be Serializable. Keep transient to satisfy serialization
  // safety checks and handle persistence compatibly via custom writeObject/readObject.
  private transient LockableRandomAccessBuffer raf;
  private long realSize;

  /**
   * Creates a wrapper that exposes only the first {@code realSize} bytes of an existing buffer.
   *
   * <p>No range check is performed here; callers must ensure {@code 0 <= realSize <= raf.size()}.
   *
   * @param raf the underlying random-access buffer to delegate I/O to
   * @param realSize the logical size to expose, in bytes
   */
  public PaddedRandomAccessBuffer(LockableRandomAccessBuffer raf, long realSize) {
    this.raf = raf;
    this.realSize = realSize;
  }

  /**
   * Returns the logical size (bytes) enforced by this wrapper.
   *
   * @return the number of bytes visible to callers
   */
  @Override
  public long size() {
    return realSize;
  }

  /**
   * Reads from the wrapped buffer enforcing {@code realSize} as an upper bound.
   *
   * <p>For {@code length > 0}, requires {@code fileOffset + length <= realSize}. For {@code length
   * == 0}, requires {@code fileOffset <= realSize}. Other argument checks and concurrency are
   * delegated to the wrapped buffer.
   *
   * @param fileOffset the absolute offset to read from
   * @param buf the destination array
   * @param bufOffset the first index in {@code buf} to write to
   * @param length the number of bytes to read
   * @throws IOException if the request exceeds the logical size or the underlying I/O fails
   * @throws IllegalArgumentException if the underlying buffer rejects the arguments (e.g., negative
   *     offset)
   */
  @Override
  public void pread(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    if ((length == 0 && fileOffset > realSize) || (length > 0 && fileOffset > realSize - length)) {
      throw new IOException("Length limit exceeded");
    }
    raf.pread(fileOffset, buf, bufOffset, length);
  }

  /**
   * Writes to the wrapped buffer enforcing {@code realSize} as an upper bound.
   *
   * <p>For {@code length > 0}, requires {@code fileOffset + length <= realSize}. For {@code length
   * == 0}, requires {@code fileOffset <= realSize}. Other argument checks and concurrency are
   * delegated to the wrapped buffer.
   *
   * @param fileOffset the absolute offset to write to
   * @param buf the source array
   * @param bufOffset the first index in {@code buf} to read from
   * @param length the number of bytes to write
   * @throws IOException if the request exceeds the logical size or the underlying I/O fails
   * @throws IllegalArgumentException if the underlying buffer rejects the arguments (e.g., negative
   *     offset)
   */
  @Override
  public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    if ((length == 0 && fileOffset > realSize) || (length > 0 && fileOffset > realSize - length)) {
      throw new IOException("Length limit exceeded");
    }
    raf.pwrite(fileOffset, buf, bufOffset, length);
  }

  /** Closes the wrapped buffer. */
  @Override
  public void close() {
    raf.close();
  }

  /** Frees the wrapped buffer. */
  @Override
  public void free() {
    raf.free();
  }

  /**
   * Returns a lock that keeps the wrapped buffer open for a short period. The caller must unlock it
   * via {@link RAFLock#unlock()}.
   *
   * @return a lock object representing an open handle
   * @throws IOException if the underlying buffer cannot provide a lock
   */
  @Override
  public RAFLock lockOpen() throws IOException {
    return raf.lockOpen();
  }

  /**
   * Reattaches runtime state after Java deserialization or a node resume.
   *
   * @param context runtime context providing registries and factories
   * @throws ResumeFailedException if the wrapped buffer cannot resume
   */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    raf.onResume(context);
  }

  /** Magic number for the runtime persistence format. */
  static final int MAGIC = 0x1eaaf330;

  /**
   * Writes the runtime-persistence form for this wrapper.
   *
   * <p>Format: {@link #MAGIC} (int), {@code realSize} (long), then the wrapped buffer via {@link
   * LockableRandomAccessBuffer#storeTo(DataOutputStream)}.
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeLong(realSize);
    raf.storeTo(dos);
  }

  /**
   * Restores an instance from the runtime-persistence form written by {@link #storeTo}.
   *
   * <p>The caller must have already consumed {@link #MAGIC}. The constructor reads {@code
   * realSize}, restores the wrapped buffer, and verifies that the wrapped size is at least {@code
   * realSize}.
   *
   * @param dis source stream positioned after {@link #MAGIC}
   * @param fg filename generator used for nested buffer reconstruction
   * @param persistentFileTracker tracker used by nested buffer types
   * @param masterSecret master secret used by encrypted buffers if present
   * @throws ResumeFailedException if the wrapped buffer is smaller than {@code realSize}
   * @throws IOException on I/O errors
   * @throws StorageFormatException if the stored data is malformed
   */
  public PaddedRandomAccessBuffer(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterSecret)
      throws ResumeFailedException, IOException, StorageFormatException {
    realSize = dis.readLong();
    if (realSize < 0) throw new StorageFormatException("Negative length");
    LockableRandomAccessBuffer restored =
        BucketTools.restoreRAFFrom(dis, fg, persistentFileTracker, masterSecret);
    boolean success = false;
    try {
      if (realSize > restored.size())
        throw new ResumeFailedException("Padded file is smaller than expected length");
      raf = restored;
      success = true;
    } finally {
      if (!success) IOUtils.closeQuietly(restored);
    }
  }

  /**
   * Computes a hash code based on the wrapped buffer and the logical size.
   *
   * @return a hash code consistent with {@link #equals(Object)}
   */
  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + raf.hashCode();
    result = prime * result + Long.hashCode(realSize);
    return result;
  }

  /**
   * Compares for equality with another object.
   *
   * <p>Two instances are equal when their wrapped buffers are equal, and they expose the same
   * logical size.
   *
   * @param obj the object to compare
   * @return {@code true} if equal as described; otherwise {@code false}
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof PaddedRandomAccessBuffer other)) {
      return false;
    }
    if (!raf.equals(other.raf)) {
      return false;
    }
    return realSize == other.realSize;
  }

  /* ===== Java serialization support (backward-compatible) ===== */

  // Keep explicit field names to match previously serialized layouts and avoid format drift.
  private static final String FIELD_RAF = "raf";
  private static final String FIELD_REAL_SIZE = "realSize";

  // Persist the same logical fields as before, explicitly, even though 'raf' is transient now.
  // This keeps on-the-wire layout compatible with older streams that wrote 'raf' inside default
  // object data when it was non-transient.
  /** Declares persistent fields to keep on-the-wire layout stable across versions. */
  @Serial
  private static final ObjectStreamField[] serialPersistentFields =
      new ObjectStreamField[] {
        new ObjectStreamField(FIELD_RAF, LockableRandomAccessBuffer.class),
        new ObjectStreamField(FIELD_REAL_SIZE, long.class)
      };

  /** Writes the declared fields using the standard {@link ObjectOutputStream} protocol. */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    assert serialPersistentFields.length > 0;
    ObjectOutputStream.PutField fields = out.putFields();
    if (!(raf instanceof Serializable)) {
      throw new NotSerializableException(raf == null ? "nullRaf" : raf.getClass().getName());
    }
    fields.put(FIELD_RAF, raf);
    fields.put(FIELD_REAL_SIZE, realSize);
    out.writeFields();
  }

  /** Reads the declared fields using the standard {@link ObjectInputStream} protocol. */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField fields = in.readFields();
    // 'raf' was part of previous default data; recover it from the persistent fields set.
    Object r = fields.get(FIELD_RAF, null);
    raf = (LockableRandomAccessBuffer) r;
    realSize = fields.get(FIELD_REAL_SIZE, 0L);
  }
}
