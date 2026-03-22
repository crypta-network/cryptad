package network.crypta.support.io;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.ResumeContext;

/**
 * Read-only decorator for {@link LockableRandomAccessBuffer}.
 *
 * <p>This wrapper forwards all read-related and lifecycle operations to an underlying {@link
 * LockableRandomAccessBuffer} while rejecting all write attempts. It is useful when code must
 * expose a random-access view that cannot be modified, including across persistence boundaries. The
 * wrapper participates in the persistence format via {@link #storeTo} and is reconstructed by
 * {@link BucketTools#restoreRAFFrom(DataInputStream, FilenameGenerator, PersistentFileTracker,
 * MasterSecret)}.
 *
 * <p><strong>Thread-safety:</strong> This class provides no additional synchronization beyond what
 * the wrapped instance offers. Concurrency semantics are those of {@code underlying}.
 *
 * <p><strong>Equality:</strong> {@link #equals(Object)} and {@link #hashCode()} delegate to the
 * underlying buffer; two wrappers are equal if and only if their underlying instances are equal.
 */
public final class ReadOnlyRandomAccessBuffer implements LockableRandomAccessBuffer {

  private final LockableRandomAccessBuffer underlying;

  /**
   * Creates a read-only view over an existing buffer.
   *
   * <p>All reads and management operations are delegated to {@code underlying}. Any attempt to
   * write through this wrapper throws an {@link IOException}.
   *
   * @param underlying the buffer to wrap; must not be {@code null}
   */
  public ReadOnlyRandomAccessBuffer(LockableRandomAccessBuffer underlying) {
    this.underlying = underlying;
  }

  /**
   * Restoring constructor used by {@link BucketTools#restoreRAFFrom(DataInputStream,
   * FilenameGenerator, PersistentFileTracker, MasterSecret)}.
   *
   * <p>The caller must have already consumed this class's type header (the {@link #MAGIC} value)
   * from {@code dis}. This constructor then delegates to {@code BucketTools.restoreRAFFrom(...)} to
   * read and reconstruct the wrapped {@link LockableRandomAccessBuffer} that follows in the stream.
   *
   * @param dis source stream positioned after {@link #MAGIC}
   * @param fg filename generator used by file-backed implementations during restore
   * @param persistentFileTracker tracker for coordinating persistent temporary files
   * @param masterSecret master key required by encrypted implementations
   * @throws IOException if reading from the stream fails
   * @throws StorageFormatException if the serialized data is invalid or of an unknown type
   * @throws ResumeFailedException if a persistent artifact cannot be resumed (e.g., missing file)
   */
  public ReadOnlyRandomAccessBuffer(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterSecret)
      throws IOException, StorageFormatException, ResumeFailedException {
    this.underlying = BucketTools.restoreRAFFrom(dis, fg, persistentFileTracker, masterSecret);
  }

  /**
   * Returns the logical size in bytes.
   *
   * <p>Delegates to the wrapped buffer.
   *
   * @return number of bytes in the buffer
   */
  @Override
  public long size() {
    return underlying.size();
  }

  /**
   * Reads a range of bytes from the given file offset.
   *
   * <p>Delegates to the wrapped buffer. See {@link LockableRandomAccessBuffer#pread(long, byte[],
   * int, int)} for parameter semantics and error conditions.
   *
   * @throws IOException if the underlying read fails or is out of bounds
   * @throws IllegalArgumentException if {@code fileOffset} is negative (as per the contract)
   */
  @Override
  public void pread(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    underlying.pread(fileOffset, buf, bufOffset, length);
  }

  /**
   * Always rejects writes to preserve read-only semantics.
   *
   * @throws IOException always thrown with message {@code "Read only"}
   */
  @Override
  public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    throw new IOException("Read only");
  }

  /**
   * Closes the wrapped buffer.
   *
   * <p>Delegates to {@link LockableRandomAccessBuffer#close()} on the underlying instance.
   */
  @Override
  public void close() {
    underlying.close();
  }

  /**
   * Frees the underlying resources.
   *
   * <p>Delegates to {@link LockableRandomAccessBuffer#free()} on the underlying instance.
   */
  @Override
  public void free() {
    underlying.free();
  }

  /**
   * Acquires a temporary "lock-open" handle on the underlying buffer.
   *
   * <p>Delegates to {@link LockableRandomAccessBuffer#lockOpen()}. Concurrency guarantees (if any)
   * are those of the wrapped implementation.
   *
   * @return a lock to be released via {@link RAFLock#unlock()}
   * @throws IOException if the underlying buffer cannot provide a lock
   */
  @Override
  public RAFLock lockOpen() throws IOException {
    return underlying.lockOpen();
  }

  /**
   * Notifies the wrapped buffer that the node resumed from persisted state.
   *
   * <p>Delegates to the underlying instance so it can re-register transient resources.
   *
   * @param context client context provided by the caller
   * @throws ResumeFailedException if the underlying instance cannot resume correctly
   */
  @Override
  public void onResume(ResumeContext context) throws ResumeFailedException {
    underlying.onResume(context);
  }

  // Type identifier written by storeTo() and consumed by BucketTools during restore.
  static final int MAGIC = 0x648d24da;

  /**
   * Writes enough data to reconstruct this wrapper and its underlying buffer.
   *
   * <p>The format is: {@code int MAGIC} for this class, followed by the serialization of the
   * wrapped buffer via {@link LockableRandomAccessBuffer#storeTo(DataOutputStream)}. The matching
   * restoration path is {@link BucketTools#restoreRAFFrom(DataInputStream, FilenameGenerator,
   * PersistentFileTracker, MasterSecret)}.
   *
   * @param dos destination stream
   * @throws IOException if writing to {@code dos} fails
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    underlying.storeTo(dos);
  }

  /**
   * Computes a hash code consistent with {@link #equals(Object)} by delegating to the underlying
   * buffer.
   */
  @Override
  public int hashCode() {
    return underlying.hashCode();
  }

  /**
   * Compares for equality with another object.
   *
   * <p>Two wrappers are equal when they are the same class and their underlying buffers are equal.
   * The comparison does not attempt to unwrap recursively beyond a single level.
   *
   * @param obj object to compare with
   * @return {@code true} if equal by the rule above; otherwise {@code false}
   */
  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof ReadOnlyRandomAccessBuffer other)) {
      return false;
    }
    return underlying.equals(other.underlying);
  }
}
