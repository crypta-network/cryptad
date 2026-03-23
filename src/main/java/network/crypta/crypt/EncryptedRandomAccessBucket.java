package network.crypta.crypt;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.FilterInputStream;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream.PutField;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamField;
import java.io.OptionalDataException;
import java.io.OutputStream;
import java.io.Serial;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import network.crypta.crypt.EncryptedRandomAccessBuffer.KdfInput;
import network.crypta.support.Fields;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.RandomAccessBucket;
import network.crypta.support.api.ResumeContext;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.NullInputStream;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.jetbrains.annotations.NotNull;

/**
 * A {@link RandomAccessBucket} whose contents are stored encrypted.
 *
 * <p>This bucket uses the same on-disk format and key-derivation scheme as {@link
 * EncryptedRandomAccessBuffer}, so conversion between the two is straightforward via {@link
 * #toRandomAccessBuffer()}.
 *
 * <p>On disk, data is prefixed with a fixed-size header of {@code type.headerLen} bytes:
 *
 * <ul>
 *   <li>{@code IV} — {@code type.encryptType.ivSize} bytes
 *   <li>Encrypted base key — {@code type.encryptKey.keySize/8} bytes
 *   <li>Header MAC — {@code type.macLen} bytes
 *   <li>Version (int, big-endian) — 4 bytes
 *   <li>Magic ({@code END_MAGIC}) — 8 bytes
 * </ul>
 *
 * <p>After the header, the payload is a stream-ciphered byte-for-byte transformation of the
 * plaintext; the reported size of this bucket equals the underlying size minus the header length.
 *
 * <p>Thread-safety: this class does not add synchronization beyond the underlying implementation.
 * Instances are not inherently thread-safe. Access from multiple threads requires external
 * coordination.
 *
 * @author toad
 */
public final class EncryptedRandomAccessBucket implements RandomAccessBucket, Serializable {

  @Serial private static final long serialVersionUID = 1L;

  private final EncryptedRandomAccessBufferType type;
  // RandomAccessBucket implementations are not required to be Serializable. Keep the reference
  // transient and handle it explicitly in writeObject/readObject, mirroring
  // network.crypta.support.api.ManifestElement.
  private transient RandomAccessBucket underlying;

  private transient ParametersWithIV cipherParams; // includes key

  private transient SecretKey headerMacKey;

  private transient volatile boolean isFreed = false;

  private transient SecretKey unencryptedBaseKey;

  private transient SecretKey headerEncKey;
  private transient byte[] headerEncIV;
  private volatile int version;

  private transient MasterSecret masterKey;

  private static final long END_MAGIC = 0x2c158a6c7772acd3L;
  private static final int VERSION_AND_MAGIC_LENGTH = 12;

  /**
   * Creates a new encrypted bucket that wraps an existing bucket.
   *
   * <p>No bytes are written at construction time. The header is written when an output stream is
   * first requested and data is emitted. Reads parse and validate the header when an input stream
   * is requested.
   *
   * @param type encryption/MAC parameters and header layout.
   * @param underlying destination storage that receives ciphertext including the header.
   * @param masterKey master secret used to derive header keys and the per-object base key.
   */
  public EncryptedRandomAccessBucket(
      EncryptedRandomAccessBufferType type, RandomAccessBucket underlying, MasterSecret masterKey) {
    this.type = type;
    this.underlying = underlying;
    this.masterKey = masterKey;
    baseSetup(masterKey);
  }

  /**
   * Initializes fields that depend only on the provided {@link MasterSecret} and the chosen {@link
   * EncryptedRandomAccessBufferType}. The per-object base key and IV are generated later when a
   * stream is opened.
   */
  private void baseSetup(MasterSecret masterKey) {

    this.headerEncKey = masterKey.deriveKey(type.encryptKey);
    this.headerMacKey = masterKey.deriveKey(type.macKey);

    version = type.bitmask;
  }

  private SkippingStreamCipher setup(OutputStream os) throws GeneralSecurityException, IOException {
    // Generate per-object IV and base key, then emit the header to the underlying stream before
    // any ciphertext. This method does not close the provided stream.
    this.headerEncIV = KeyGenUtils.genIV(type.encryptType.ivSize).getIV();
    this.unencryptedBaseKey = KeyGenUtils.genSecretKey(type.encryptKey);
    writeHeader(os);
    setupKeys();
    SkippingStreamCipher cipherWrite = this.type.get();
    cipherWrite.init(true, cipherParams);
    return cipherWrite;
  }

  private void writeHeader(OutputStream os) throws GeneralSecurityException, IOException {
    byte[] header = new byte[type.headerLen];
    int offset = 0;

    int ivLen = headerEncIV.length;
    System.arraycopy(headerEncIV, 0, header, offset, ivLen);
    offset += ivLen;

    byte[] encryptedKey;
    try {
      CryptByteBuffer crypt = new CryptByteBuffer(type.encryptType, headerEncKey, headerEncIV);
      encryptedKey = crypt.encryptCopy(unencryptedBaseKey.getEncoded());
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new GeneralSecurityException(
          "Something went wrong with key generation. please " + "report", e.fillInStackTrace());
    }
    System.arraycopy(encryptedKey, 0, header, offset, encryptedKey.length);
    offset += encryptedKey.length;

    byte[] ver = ByteBuffer.allocate(4).putInt(version).array();
    try {
      MessageAuthCode mac = new MessageAuthCode(type.macType, headerMacKey);
      byte[] macResult =
          Fields.copyToArray(mac.genMac(headerEncIV, unencryptedBaseKey.getEncoded(), ver));
      System.arraycopy(macResult, 0, header, offset, macResult.length);
      offset += macResult.length;
    } catch (InvalidKeyException e) {
      throw new GeneralSecurityException(
          "Something went wrong with key generation. please " + "report", e.fillInStackTrace());
    }

    System.arraycopy(ver, 0, header, offset, ver.length);
    offset += ver.length;

    byte[] magic = ByteBuffer.allocate(8).putLong(END_MAGIC).array();
    System.arraycopy(magic, 0, header, offset, magic.length);

    os.write(header);
  }

  private SkippingStreamCipher setup(InputStream is) throws IOException, GeneralSecurityException {
    byte[] fullHeader = new byte[type.headerLen];
    try {
      new DataInputStream(is).readFully(fullHeader);
    } catch (EOFException _) {
      // Historical message refers to a "footer" although we are reading the header.
      throw new IOException(
          "Underlying RandomAccessBuffer is not long enough to include the " + "footer.");
    }
    byte[] header =
        Arrays.copyOfRange(
            fullHeader, fullHeader.length - VERSION_AND_MAGIC_LENGTH, fullHeader.length);
    int offset = 0;
    int readVersion = ByteBuffer.wrap(header, offset, 4).getInt();
    offset += 4;
    long magic = ByteBuffer.wrap(header, offset, 8).getLong();
    if (END_MAGIC != magic) {
      // The exception text mentions EncryptedRandomAccessBuffer for historical reasons; the format
      // is shared with EncryptedRandomAccessBucket.
      throw new IOException("This is not an EncryptedRandomAccessBuffer!");
    }
    if (readVersion != version) {
      // Version mismatch: the stored header is incompatible with the configured type for this
      // instance.
      throw new IOException(
          "Version of the underlying RandomAccessBuffer is " + "incompatible with this ERATType");
    }
    if (!verifyHeader(fullHeader)) throw new GeneralSecurityException("MAC is incorrect");
    setupKeys();
    SkippingStreamCipher cipherRead = this.type.get();
    cipherRead.init(false, cipherParams);
    return cipherRead;
  }

  private boolean verifyHeader(byte[] fullHeader) throws IOException, InvalidKeyException {
    // Everything except the trailing version and magic. Historically called "footer".
    byte[] footer = Arrays.copyOfRange(fullHeader, 0, fullHeader.length - VERSION_AND_MAGIC_LENGTH);
    int offset = 0;

    headerEncIV = new byte[type.encryptType.ivSize];
    System.arraycopy(footer, offset, headerEncIV, 0, headerEncIV.length);
    offset += headerEncIV.length;

    int keySize = type.encryptKey.keySize >> 3;
    byte[] encryptedKey = new byte[keySize];
    System.arraycopy(footer, offset, encryptedKey, 0, keySize);
    offset += keySize;
    try {
      CryptByteBuffer crypt = new CryptByteBuffer(type.encryptType, headerEncKey, headerEncIV);
      unencryptedBaseKey =
          KeyGenUtils.getSecretKey(type.encryptKey, crypt.decryptCopy(encryptedKey));
    } catch (InvalidKeyException | InvalidAlgorithmParameterException _) {
      throw new IOException("Error reading encryption keys from header.");
    }

    byte[] mac = new byte[type.macLen];
    System.arraycopy(footer, offset, mac, 0, type.macLen);

    byte[] ver = ByteBuffer.allocate(4).putInt(version).array();
    MessageAuthCode authcode = new MessageAuthCode(type.macType, headerMacKey);
    return authcode.verifyData(mac, headerEncIV, unencryptedBaseKey.getEncoded(), ver);
  }

  private void setupKeys() {
    ParametersWithIV tempPram;
    try {
      KeyParameter cipherKey =
          new KeyParameter(
              KeyGenUtils.deriveSecretKey(
                      unencryptedBaseKey,
                      EncryptedRandomAccessBuffer.class,
                      KdfInput.underlyingKey.input,
                      type.encryptKey)
                  .getEncoded());
      tempPram =
          new ParametersWithIV(
              cipherKey,
              KeyGenUtils.deriveIvParameterSpec(
                      unencryptedBaseKey,
                      EncryptedRandomAccessBuffer.class,
                      KdfInput.underlyingIV.input,
                      type.encryptKey)
                  .getIV());
    } catch (InvalidKeyException e) {
      // Derivation uses keys generated locally in this process; invalid keys indicate a defect.
      throw new IllegalStateException(e);
    }
    this.cipherParams = tempPram;
  }

  static class MyOutputStream extends FilterOutputStream {
    // Encrypts bytes on writing using the configured stream cipher. The caller has already
    // written the header.
    private final SkippingStreamCipher cipherWrite;

    public MyOutputStream(OutputStream out, SkippingStreamCipher cipher) {
      super(out);
      this.cipherWrite = cipher;
    }

    @Override
    public void write(int x) throws IOException {
      write(new byte[] {(byte) x}, 0, 1);
    }

    @Override
    public void write(byte @NotNull [] buf) throws IOException {
      write(buf, 0, buf.length);
    }

    @Override
    public void write(byte @NotNull [] buf, int offset, int length) throws IOException {
      byte[] ciphertext = new byte[length];
      cipherWrite.processBytes(buf, offset, length, ciphertext, 0);
      out.write(ciphertext);
    }
  }

  /**
   * Returns an output stream that writes ciphertext to the underlying bucket.
   *
   * <p>The stream writes the encryption header first, then encrypts bytes on the fly using a {@link
   * SkippingStreamCipher}. The returned stream does not add buffering; callers that need it should
   * use {@link #getOutputStream()}.
   *
   * @return an unbuffered stream that encrypts data as it is written.
   * @throws IOException if the bucket has been freed or cryptographic initialization fails.
   */
  @Override
  public OutputStream getOutputStreamUnbuffered() throws IOException {
    if (isFreed) {
      throw new IOException(
          "This RandomAccessBuffer has already been closed. This should not" + " happen.");
    }
    OutputStream uos = underlying.getOutputStreamUnbuffered();
    try {
      return new MyOutputStream(uos, setup(uos));
    } catch (GeneralSecurityException e) {
      throw new IOException("Unable to create encrypted bucket", e);
    }
  }

  static class MyInputStream extends FilterInputStream {
    // Decrypts bytes on read using the configured stream cipher. The caller validated and consumed
    // the header before constructing this stream.
    private final SkippingStreamCipher cipherRead;

    public MyInputStream(InputStream in, SkippingStreamCipher cipher) {
      super(in);
      this.cipherRead = cipher;
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
      int readBytes = in.read(buf, offset, length);
      if (readBytes <= 0) return readBytes;
      cipherRead.processBytes(buf, offset, readBytes, buf, offset);
      return readBytes;
    }
  }

  /**
   * Returns an input stream that decrypts data from the underlying bucket.
   *
   * <p>If the bucket is empty, a {@link NullInputStream} is returned. The returned stream is
   * unbuffered; see {@link #getInputStream()} for a buffered variant.
   *
   * @return an unbuffered stream that decrypts data as it is read.
   * @throws IOException if the bucket has been freed, or the header is missing/invalid.
   */
  @Override
  public InputStream getInputStreamUnbuffered() throws IOException {
    if (size() == 0) return new NullInputStream();
    if (isFreed) {
      throw new IOException(
          "This RandomAccessBuffer has already been closed. This should not" + " happen.");
    }
    InputStream is = underlying.getInputStreamUnbuffered();
    try {
      return new MyInputStream(is, setup(is));
    } catch (GeneralSecurityException e) {
      throw new IOException("Unable to read encrypted bucket", e);
    }
  }

  /**
   * Returns a descriptive name composed of the fully qualified class name and the underlying name.
   *
   * @return a stable identifier useful for logging and diagnostics.
   */
  @Override
  public String getName() {
    return getClass().getName() + ":" + underlying.getName();
  }

  /**
   * Returns the plaintext size in bytes.
   *
   * <p>For non-empty buckets this equals {@code underlying.size() - type.headerLen}. When the
   * underlying is empty, zero is returned without subtracting the header length.
   *
   * @return plaintext length in bytes.
   */
  @Override
  public long size() {
    long size = underlying.size();
    if (size == 0) return 0;
    return size - type.headerLen;
  }

  /** Returns whether the underlying bucket has been marked read-only. */
  @Override
  public boolean isReadOnly() {
    return underlying.isReadOnly();
  }

  /**
   * Marks the underlying bucket read-only. Subsequent write attempts will fail, according to the
   * underlying implementation's contract.
   */
  @Override
  public void setReadOnly() {
    underlying.setReadOnly();
  }

  /**
   * Releases resources held by this bucket and the underlying bucket.
   *
   * <p>Safe to call multiple times; later calls are no-ops.
   */
  @Override
  public void free() {
    if (isFreed) return;
    isFreed = true;
    underlying.free();
  }

  /**
   * Creates a shallow encrypted copy that wraps a shadow of the underlying bucket.
   *
   * @return a new encrypted bucket that references a shadow of the underlying storage.
   */
  @Override
  public RandomAccessBucket createShadow() {
    RandomAccessBucket copy = underlying.createShadow();
    return new EncryptedRandomAccessBucket(type, copy, masterKey);
  }

  /**
   * Converts this bucket to an {@link EncryptedRandomAccessBuffer} with the same format and keys.
   *
   * <p>The underlying bucket is marked read-only prior to conversion.
   *
   * @return a random-access buffer view of the same encrypted data.
   * @throws IOException if the underlying bucket is empty or cryptographic initialization fails.
   */
  @Override
  public LockableRandomAccessBuffer toRandomAccessBuffer() throws IOException {
    if (underlying.size() < type.headerLen) throw new IOException("Converting empty bucket");
    underlying.setReadOnly();
    LockableRandomAccessBuffer r = underlying.toRandomAccessBuffer();
    try {
      return new EncryptedRandomAccessBuffer(type, r, masterKey, false);
    } catch (GeneralSecurityException e) {
      throw new IOException("Unable to convert encrypted bucket", e);
    }
  }

  /**
   * Returns a buffered output stream that encrypts data as it is written.
   *
   * @return a buffered encrypting output stream.
   * @throws IOException if {@link #getOutputStreamUnbuffered()} fails.
   */
  @Override
  public OutputStream getOutputStream() throws IOException {
    return new BufferedOutputStream(getOutputStreamUnbuffered());
  }

  /**
   * Returns a buffered input stream that decrypts data as it is read.
   *
   * @return a buffered decrypting input stream.
   * @throws IOException if {@link #getInputStreamUnbuffered()} fails.
   */
  @Override
  public InputStream getInputStream() throws IOException {
    return new BufferedInputStream(getInputStreamUnbuffered());
  }

  /**
   * Reinitializes after process resume/deserialization.
   *
   * <p>Resumes the underlying bucket first, then refreshes cryptographic material using the
   * persistent master secret exposed by the supplied {@link CryptoResumeContext}.
   *
   * @param context resume context; encrypted state requires it to implement {@link
   *     CryptoResumeContext}.
   * @throws ResumeFailedException if the underlying bucket fails to resume.
   */
  @Override
  public void onResume(ResumeContext context) throws ResumeFailedException {
    underlying.onResume(context);
    this.masterKey = CryptoResumeContexts.require(context).getPersistentMasterSecret();
    baseSetup(masterKey);
  }

  /** Magic written by {@link #storeTo(DataOutputStream)} to identify this type. */
  public static final int MAGIC = 0xd8ba4c7e;

  /**
   * Stores this bucket's descriptor to a stream for later restoration.
   *
   * <p>Format: {@link #MAGIC} (int), {@code type.bitmask} (int), followed by the underlying bucket
   * via {@link RandomAccessBucket#storeTo(DataOutputStream)}.
   *
   * @param dos destination for the serialized descriptor.
   * @throws IOException if writing fails.
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(type.bitmask);
    underlying.storeTo(dos);
  }

  /**
   * Restores an encrypted bucket previously written by {@link #storeTo(DataOutputStream)}.
   *
   * @param dis input stream positioned at the type bitmask written by {@link #storeTo}.
   * @param fg filename generator used when restoring file-based buckets.
   * @param persistentFileTracker tracker for persisted files used by restored buckets.
   * @param masterKey2 master secret for deriving header keys for future stream operations.
   * @throws IOException on I/O errors or if the underlying descriptor is malformed.
   * @throws ResumeFailedException if the type is unknown or resume contracts fail.
   * @throws StorageFormatException if the underlying bucket cannot be restored from the stream.
   */
  public EncryptedRandomAccessBucket(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey2)
      throws IOException, ResumeFailedException, StorageFormatException {
    type = EncryptedRandomAccessBufferType.getByBitmask(dis.readInt());
    if (type == null) throw new ResumeFailedException("Unknown EncryptedRandomAccessBucket type");
    underlying =
        (RandomAccessBucket) BucketTools.restoreFrom(dis, fg, persistentFileTracker, masterKey2);
    this.baseSetup(masterKey2);
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + type.hashCode();
    result = prime * result + underlying.hashCode();
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    }
    if (!(obj instanceof EncryptedRandomAccessBucket other)) {
      return false;
    }
    if (type != other.type) {
      return false;
    }
    return underlying.equals(other.underlying);
  }

  /**
   * Returns the wrapped underlying bucket that stores ciphertext and the header.
   *
   * <p>Use with care: callers that bypass this wrapper operate on encrypted bytes and must not
   * assume plaintext semantics.
   *
   * @return the underlying bucket instance.
   */
  public RandomAccessBucket getUnderlying() {
    return underlying;
  }

  /* ===== Java serialization support (explicit underlying handling) ===== */
  private static final String FIELD_TYPE = "type";
  private static final String FIELD_UNDERLYING = "underlying";
  private static final String FIELD_VERSION = "version";

  @SuppressWarnings("unused") // Referenced reflectively by Java serialization.
  @Serial
  private static final ObjectStreamField[] serialPersistentFields = {
    new ObjectStreamField(FIELD_TYPE, EncryptedRandomAccessBufferType.class),
    new ObjectStreamField(FIELD_UNDERLYING, network.crypta.support.api.RandomAccessBucket.class),
    new ObjectStreamField(FIELD_VERSION, int.class)
  };

  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    // Persist core fields via the default field block. Include the underlying only when it is
    // Serializable; otherwise fail fast to avoid silently dropping data on checkpoint.
    PutField fields = out.putFields();
    fields.put(FIELD_TYPE, type);
    fields.put(FIELD_VERSION, version);
    if (underlying == null) {
      fields.put(FIELD_UNDERLYING, null);
      out.writeFields();
      return;
    }
    if (underlying instanceof Serializable serializable) {
      fields.put(FIELD_UNDERLYING, serializable);
      out.writeFields();
      return;
    }
    out.writeFields();
    throw new NotSerializableException(underlying.getClass().getName());
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    // Restore fields written by current and intermediary versions. Current streams place the
    // underlying in the default field block (when Serializable). Intermediary builds also wrote the
    // bucket as a trailing object after the default fields. To remain compatible with those streams
    // while ensuring correct stream alignment: we first read the default field block and then try
    // to read a trailing object. If the writer did not include one (the common case now),
    // attempting to read past the end of this class's data results in OptionalDataException with
    // eof=true. We swallow that and keep the field-restored value. This does NOT consume the next
    // top-level object in the stream; ObjectInputStream enforces class-data boundaries during
    // readObject().
    in.defaultReadObject();
    try {
      Object maybeBucket = in.readObject();
      underlying = (maybeBucket == null) ? null : (RandomAccessBucket) maybeBucket;
    } catch (OptionalDataException e) {
      if (!e.eof) throw e; // No trailing object for this class; keep field value.
    }
  }
}
