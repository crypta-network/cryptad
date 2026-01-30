package network.crypta.support.io;

import java.io.*;
import java.util.concurrent.atomic.AtomicReference;
import network.crypta.client.async.ClientContext;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.Bucket;

/**
 * Wrapper for a {@link Bucket} that intentionally ignores {@link #free()}.
 *
 * <p>This class prevents accidental deletion of the underlying storage when ownership of a bucket
 * is handed off to code that may unconditionally call {@code free()}. All read/write and metadata
 * methods delegate directly to the wrapped instance; only {@code free()} differs and performs no
 * action.
 *
 * <p>Thread-safety: identical to the wrapped bucket. This class does not add synchronization.
 *
 * <p>Serialization: the wrapper itself is {@link Serializable}, but the wrapped bucket may not be.
 * The {@code proxy} field is {@code transient} and is serialized via {@link
 * #writeObject(ObjectOutputStream)} and restored by {@link #readObject(ObjectInputStream)}. If the
 * wrapped bucket does not implement {@link Serializable}, a {@link NotSerializableException} is
 * thrown during serialization. The streaming persistence APIs ({@link #storeTo(DataOutputStream)}
 * and the matching constructor) are also supported and preferred for cross-version stability.
 *
 * @since 1
 */
public class NoFreeBucket implements Bucket, Serializable {

  @Serial private static final long serialVersionUID = 1L;
  private static final String PROXY_FIELD_NAME = "proxy";

  // Delegate handle:
  // - transient: control Java serialization manually via writeObject/readObject because the
  //   wrapped Bucket may be non-Serializable; the default field block must not attempt to
  //   serialize it.
  // - volatile: safely publishes the reference itself across threads after construction or
  //   deserialization so racing readers cannot observe a null handle.
  // - AtomicReference: provides a thread-safe container for the delegate and allows an atomic
  //   replacement during deserialization/stream restore; also satisfies static analysis that a
  //   volatile inner value alone is insufficient for safe publication.
  @SuppressWarnings("java:S3077") // AtomicReference is used for safe publication
  private transient volatile AtomicReference<Bucket> proxyRef;

  // Preserve ability to read legacy streams where 'proxy' was persisted by default
  // (field was non-transient and no extra object followed). Declaring the field in
  // serialPersistentFields allows readObject(ObjectInputStream) to obtain it via
  // ObjectInputStream.GetField, even though the runtime field is now transient.
  @Serial
  private static final ObjectStreamField[] serialPersistentFields = {
    new ObjectStreamField(PROXY_FIELD_NAME, Bucket.class)
  };

  /**
   * Creates a wrapper that delegates all operations except {@link #free()} to the given bucket.
   *
   * <p>Precondition: {@code orig} should be non-{@code null}. Passing {@code null} results in a
   * {@link NullPointerException} when any method is later invoked.
   *
   * @param orig wrapped bucket; must remain valid for the lifetime of this wrapper
   */
  public NoFreeBucket(Bucket orig) {
    proxyRef = new AtomicReference<>(orig);
  }

  /**
   * No-arg constructor for Java serialization frameworks.
   *
   * <p>The {@code proxy} is left {@code null} and is populated by {@link #readObject} during
   * deserialization or by the streaming constructor used by {@link BucketTools#restoreFrom}.
   * Invoking other methods before the field is restored will throw {@link NullPointerException}.
   */
  protected NoFreeBucket() {
    // Used only by Java serialization. See doc above.
    proxyRef = new AtomicReference<>();
  }

  /**
   * Returns a buffered output stream positioned at offset {@code 0}.
   *
   * <p>Delegates to the wrapped bucket.
   *
   * @return an {@link OutputStream} suitable for writing from the beginning
   * @throws IOException if the wrapped bucket cannot provide a stream
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    return proxyRef.get().getOutputStream();
  }

  /**
   * Returns an unbuffered output stream positioned at offset {@code 0}.
   *
   * <p>Delegates to the wrapped bucket.
   *
   * @return an unbuffered {@link OutputStream}
   * @throws IOException if the wrapped bucket cannot provide a stream
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    return proxyRef.get().getOutputStreamUnbuffered();
  }

  /**
   * Returns a buffered input stream positioned at offset {@code 0}.
   *
   * <p>Delegates to the wrapped bucket. The return value may be {@code null} if the bucket contains
   * no data, following the contract of {@link Bucket#getInputStream()}.
   *
   * @return an {@link InputStream}, or {@code null} when the bucket is empty
   * @throws IOException if the wrapped bucket cannot provide a stream
   */
  @Override
  public InputStream getInputStream() throws IOException {
    return proxyRef.get().getInputStream();
  }

  /**
   * Returns an unbuffered input stream positioned at offset {@code 0}.
   *
   * <p>Delegates to the wrapped bucket. The return value may be {@code null} if the bucket contains
   * no data.
   *
   * @return an unbuffered {@link InputStream}, or {@code null} when empty
   * @throws IOException if the wrapped bucket cannot provide a stream
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    return proxyRef.get().getInputStreamUnbuffered();
  }

  /**
   * Returns the name reported by the wrapped bucket.
   *
   * @return a human-readable name; never {@code null}
   */
  @Override
  public String getName() {
    return proxyRef.get().getName();
  }

  /**
   * Returns the number of bytes currently stored by the wrapped bucket.
   *
   * @return size in bytes
   */
  @Override
  public long size() {
    return proxyRef.get().size();
  }

  /**
   * Indicates whether the wrapped bucket is read-only.
   *
   * @return {@code true} if writes are disallowed; {@code false} otherwise
   */
  @Override
  public boolean isReadOnly() {
    return proxyRef.get().isReadOnly();
  }

  /**
   * Makes the wrapped bucket read-only.
   *
   * <p>Delegates to the wrapped bucket. Idempotent if the implementation is idempotent.
   */
  @Override
  public void setReadOnly() {
    proxyRef.get().setReadOnly();
  }

  /**
   * No-op free.
   *
   * <p>Intentionally does nothing to prevent accidental deletion of the underlying storage. Use
   * this wrapper when code paths may call {@code free()} unconditionally, but the caller must
   * retain the data.
   */
  @Override
  public void free() {
    // Intentionally empty.
  }

  /**
   * Creates a shallow read-only copy by delegating to the wrapped bucket.
   *
   * @return a shadow bucket, or {@code null} if unsupported by the wrapped implementation
   */
  @Override
  public Bucket createShadow() {
    return proxyRef.get().createShadow();
  }

  /**
   * Reattaches runtime-only state after a restart and delegates to the wrapped bucket.
   *
   * <p>This wrapper has no persistent state of its own beyond the wrapped bucket.
   *
   * @param context runtime context
   * @throws ResumeFailedException if the wrapped bucket fails to resume
   */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    proxyRef.get().onResume(context);
  }

  // Type marker written before the wrapped bucket in {@link #storeTo(DataOutputStream)}. Recognized
  // by {@link BucketTools#restoreFrom(DataInputStream, FilenameGenerator, PersistentFileTracker,
  // MasterSecret)} to instantiate this wrapper.
  static final int MAGIC = 0xa88da5c2;

  /**
   * Writes this wrapper in a stream-friendly format.
   *
   * <p>Format: {@link #MAGIC} (int) immediately followed by the wrapped bucket via {@link
   * Bucket#storeTo(DataOutputStream)}.
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   * @throws UnsupportedOperationException if the wrapped bucket does not support streaming
   *     persistence
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    proxyRef.get().storeTo(dos);
  }

  /**
   * Restores an instance from bytes written by {@link #storeTo(DataOutputStream)}.
   *
   * <p>The caller must have already consumed {@link #MAGIC}.
   *
   * @param dis source positioned after the magic value
   * @param fg filename generator for nested buckets
   * @param persistentFileTracker tracker used by nested bucket types
   * @param masterKey master secret used by encrypted buckets, if any
   * @throws IOException on I/O errors
   * @throws StorageFormatException if the stream is malformed
   * @throws ResumeFailedException if a nested bucket cannot be resumed
   */
  protected NoFreeBucket(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws IOException, StorageFormatException, ResumeFailedException {
    proxyRef =
        new AtomicReference<>(BucketTools.restoreFrom(dis, fg, persistentFileTracker, masterKey));
  }

  /* ===== Java serialization support (patterned after DelayedFreeBucket) ===== */

  /**
   * Writes default serializable state and the wrapped bucket when it implements {@link
   * Serializable}.
   *
   * @param out destination stream
   * @throws IOException if writing fails or the wrapped bucket is not serializable
   */
  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    // Preserve compatibility with older releases that rely on default Java serialization
    // (no readObject) and expect the legacy 'proxy' field to carry the wrapped bucket when it is
    // serializable. Only when the wrapped bucket is not serializable do we throw, matching legacy
    // behavior.
    ObjectOutputStream.PutField pf = out.putFields();
    Bucket current = proxyRef.get();
    if (current instanceof Serializable serializable) {
      pf.put(PROXY_FIELD_NAME, serializable);
      out.writeFields();
      // Do NOT append another object; newer readers will fall back to the legacy field on EOF.
    } else {
      // Write defaults (proxy=null) so newer readers can still tolerate EOF and error early.
      out.writeFields();
      throw new NotSerializableException(
          current == null ? "nullBucket" : current.getClass().getName());
    }
  }

  /**
   * Restores default serializable state and the wrapped bucket previously written by {@link
   * #writeObject(ObjectOutputStream)}.
   *
   * @param in source stream
   * @throws IOException on I/O errors
   * @throws ClassNotFoundException if the wrapped type cannot be loaded
   */
  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    // Read default field block using GetField so we can extract the legacy 'proxy' value
    // when present in streams written by older releases.
    ObjectInputStream.GetField fields = in.readFields();
    Bucket legacyProxy = null;
    try {
      Object v = fields.get(PROXY_FIELD_NAME, null);
      if (v != null) legacyProxy = (Bucket) v;
    } catch (IllegalArgumentException _) {
      // Field not present in local descriptor; treat as absent.
    }

    // If legacy field is present, use it and return without reading further optional data.
    if (legacyProxy != null) {
      proxyRef = new AtomicReference<>(legacyProxy);
      return;
    }

    // Otherwise, support older "appended object" format written after the field block.
    try {
      Object appended = in.readObject();
      proxyRef = new AtomicReference<>((Bucket) appended);
    } catch (OptionalDataException e) {
      if (e.eof) {
        // No legacy field and no appended object — malformed stream for this type.
        throw new StreamCorruptedException("NoFreeBucket: missing delegate in serialized form");
      }
      throw e;
    } catch (EOFException _) {
      // Reached end of this object's data with no delegate present.
      throw new StreamCorruptedException("NoFreeBucket: unexpected EOF while reading delegate");
    }
  }
}
