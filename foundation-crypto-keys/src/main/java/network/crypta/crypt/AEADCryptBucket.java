package network.crypta.crypt;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.OptionalDataException;
import java.io.OutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.util.Arrays;
import network.crypta.support.api.Bucket;
import network.crypta.support.api.ResumeContext;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;

/**
 * Bucket wrapper that encrypts and authenticates all bytes with AES‑GCM.
 *
 * <p>Writes produce a single AEAD stream in the underlying bucket. The ciphertext stored in the
 * underlying includes a nonce/tag overhead of {@link #OVERHEAD} bytes; {@link #size()} reports the
 * plaintext length (that is, the underlying size minus the overhead). Reads decrypt and verify the
 * MAC; authentication may occur on the final {@code read()} or during {@code close()} depending on
 * how the stream is consumed.
 *
 * <p>Do not suppress {@code close()} on input streams obtained from this bucket. Swallowing
 * exceptions during close can hide authentication failures.
 *
 * <p>On‑disk persistence is versioned via {@link #storeTo(DataOutputStream)} and the matching
 * constructor that accepts a {@link DataInputStream}. Java object serialization is also supported
 * when the underlying bucket is {@link java.io.Serializable}; see the private {@code
 * writeObject}/{@code readObject} for details. The versioned on‑disk format should be preferred for
 * long‑term storage.
 *
 * @author toad
 */
public final class AEADCryptBucket implements Bucket, Serializable {
  @Serial private static final long serialVersionUID = 1L;
  // The underlying bucket may or may not be java.io.Serializable. Java serialization for this
  // wrapper is enabled only when the underlying is Serializable (see writeObject/readObject). The
  // versioned on‑disk persistence path uses storeTo()/restoreFrom() and does not rely on default
  // Java serialization.
  private Bucket underlying;
  private final byte[] key;
  private volatile boolean readOnly;
  static final int OVERHEAD = AEADOutputStream.AES_OVERHEAD;

  public AEADCryptBucket(Bucket underlying, byte[] key) {
    this.underlying = underlying;
    this.key = Arrays.copyOf(key, key.length);
  }

  @SuppressWarnings("unused")
  AEADCryptBucket() {
    // For serialization frameworks that instantiate first and hydrate fields later.
    underlying = null;
    key = null;
  }

  /**
   * Returns a buffered output stream that encrypts and authenticates all bytes written.
   *
   * @return a buffered stream that writes AEAD ciphertext to the underlying bucket
   * @throws IOException if the bucket is read‑only or the underlying output stream cannot be
   *     created
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    return new BufferedOutputStream(getOutputStreamUnbuffered());
  }

  /**
   * Returns an unbuffered output stream that encrypts and authenticates all bytes written.
   *
   * <p>The stream writes a single AEAD record with an overhead of {@link #OVERHEAD} bytes.
   *
   * @return a stream that writes AEAD ciphertext to the underlying bucket
   * @throws IOException if the bucket is read‑only or the underlying output stream cannot be
   *     created
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    if (readOnly) {
      throw new IOException("Read only");
    }
    OutputStream os = underlying.getOutputStreamUnbuffered();
    return AEADOutputStream.createAES(os, key, CryptoRandoms.shared());
  }

  /**
   * Returns a buffered input stream that decrypts and verifies the ciphertext from the underlying
   * bucket.
   *
   * @return a buffered stream over the plaintext bytes
   * @throws IOException if the underlying input stream cannot be created
   */
  @Override
  public InputStream getInputStream() throws IOException {
    return new BufferedInputStream(getInputStreamUnbuffered());
  }

  /**
   * Returns an unbuffered input stream that decrypts and verifies the ciphertext from the
   * underlying bucket.
   *
   * <p>The MAC may be verified on the last {@code read()} or when the stream is {@code close()}d,
   * depending on how the stream is consumed. Callers must close the stream and handle potential
   * authentication errors.
   *
   * @return a stream over the plaintext bytes
   * @throws IOException if the underlying input stream cannot be created
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    InputStream is = underlying.getInputStreamUnbuffered();
    return AEADInputStream.createAES(is, key);
  }

  /**
   * Human‑readable name for this bucket.
   *
   * @return {@code "AEADEncrypted:"} followed by the underlying bucket name
   */
  @Override
  public String getName() {
    return "AEADEncrypted:" + underlying.getName();
  }

  /**
   * Length of the plaintext currently stored.
   *
   * <p>This equals the underlying ciphertext size minus {@link #OVERHEAD}.
   *
   * @return plaintext size in bytes
   */
  @Override
  public long size() {
    return underlying.size() - OVERHEAD;
  }

  /** Returns whether this bucket rejects further writes. */
  @Override
  public boolean isReadOnly() {
    return readOnly;
  }

  /**
   * Make this bucket read‑only. After this call, obtaining an output stream fails.
   *
   * <p>This operation is irreversible for the lifetime of the instance.
   */
  @Override
  public void setReadOnly() {
    readOnly = true;
  }

  /**
   * Free resources associated with the underlying bucket.
   *
   * <p>Further I/O on this instance will typically fail according to the underlying implementation.
   */
  @Override
  public void free() {
    underlying.free();
  }

  /**
   * Create a read‑only shadow bucket that references the same ciphertext as the underlying.
   *
   * @return a read‑only AEAD bucket backed by a shadow of the underlying, or {@code null} if the
   *     underlying does not support shadows
   */
  @Override
  public Bucket createShadow() {
    Bucket undershadow = underlying.createShadow();
    AEADCryptBucket ret = new AEADCryptBucket(undershadow, key);
    ret.setReadOnly();
    return ret;
  }

  /**
   * Resume hook for persistent contexts; delegates to the underlying bucket.
   *
   * @param context runtime context
   * @throws ResumeFailedException if the underlying resume fails
   */
  @Override
  public void onResume(ResumeContext context) throws ResumeFailedException {
    underlying.onResume(context);
  }

  /**
   * Type discriminator written by {@link #storeTo(DataOutputStream)}. Used by dispatchers to select
   * the appropriate restore path.
   */
  public static final int MAGIC = 0xb25b32d6;

  static final int VERSION = 1;

  /**
   * Persist this bucket in a versioned binary format.
   *
   * <p>Layout (big‑endian):
   *
   * <pre>
   *   int    MAGIC
   *   int    VERSION
   *   byte   keyLength (16, 24, or 32)
   *   byte[] key (keyLength)
   *   boolean readOnly
   *   Bucket  underlying (delegates to {@link Bucket#storeTo(DataOutputStream)})
   * </pre>
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(VERSION);
    dos.writeByte(key.length);
    dos.write(key);
    dos.writeBoolean(readOnly);
    underlying.storeTo(dos);
  }

  /**
   * Restore a bucket previously written by {@link #storeTo(DataOutputStream)}.
   *
   * @param dis source stream positioned immediately after {@link #MAGIC}
   * @param fg filename generator used by underlying bucket types during restore
   * @param persistentFileTracker file tracker used by underlying bucket types during restore
   * @param masterKey master secret used for decrypting nested structures when required
   * @throws IOException on I/O errors
   * @throws StorageFormatException if the serialized form is invalid or unsupported
   * @throws ResumeFailedException if restoring the underlying bucket requires a failed resume
   */
  public AEADCryptBucket(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws IOException, StorageFormatException, ResumeFailedException {
    // Magic already read by caller.
    int version = dis.readInt();
    if (version != VERSION) throw new StorageFormatException("Unknown version " + version);
    int keyLength = dis.readByte();
    if (!(keyLength == 16 || keyLength == 24 || keyLength == 32))
      throw new StorageFormatException("Unknown key length " + keyLength);
    key = new byte[keyLength];
    dis.readFully(key);
    readOnly = dis.readBoolean();
    underlying = BucketTools.restoreFrom(dis, fg, persistentFileTracker, masterKey);
  }

  /* ===== Java serialization support (backward compatible) ===== */
  /*
   * The fields below define a stable default field block used by Java serialization. The
   * underlying bucket is included only when it implements java.io.Serializable; otherwise
   * writeObject throws NotSerializableException. The versioned on‑disk format above is preferred
   * for long‑term persistence.
   */
  private static final String FIELD_UNDERLYING = "underlying";
  private static final String FIELD_KEY = "key";
  private static final String FIELD_READONLY = "readOnly";

  @Serial
  @SuppressWarnings("unused") // Used reflectively by Java serialization.
  private static final ObjectStreamField[] serialPersistentFields = {
    new ObjectStreamField(FIELD_UNDERLYING, Bucket.class),
    new ObjectStreamField(FIELD_KEY, byte[].class),
    new ObjectStreamField(FIELD_READONLY, boolean.class)
  };

  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    // Write fields using the default field block. Include the underlying only when it is
    // Serializable; otherwise fail fast to avoid silently dropping data.
    ObjectOutputStream.PutField fields = out.putFields();
    fields.put(FIELD_KEY, key);
    fields.put(FIELD_READONLY, readOnly);
    if (underlying == null) {
      fields.put(FIELD_UNDERLYING, null);
      out.writeFields();
      return;
    }
    if (underlying instanceof Serializable serializable) {
      fields.put(FIELD_UNDERLYING, serializable);
      out.writeFields();
    } else {
      out.writeFields();
      throw new NotSerializableException(underlying.getClass().getName());
    }
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    // Read fields written by current and older versions. Current streams place the underlying in
    // the default field block (when Serializable). Older streams may append it as a trailing
    // object. Support both forms.
    in.defaultReadObject();
    if (underlying == null) {
      try {
        Object maybeBucket = in.readObject();
        underlying = (maybeBucket == null) ? null : (Bucket) maybeBucket;
      } catch (OptionalDataException e) {
        if (!e.eof) throw e; // No trailing object → keep field-set value
      }
    }
  }
}
