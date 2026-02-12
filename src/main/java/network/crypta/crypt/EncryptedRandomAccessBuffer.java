package network.crypta.crypt;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectOutputStream.PutField;
import java.io.ObjectStreamField;
import java.io.Serial;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.SecretKey;
import network.crypta.client.async.ClientContext;
import network.crypta.support.Fields;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.io.BucketTools;
import network.crypta.support.io.FilenameGenerator;
import network.crypta.support.io.PersistentFileTracker;
import network.crypta.support.io.ResumeFailedException;
import network.crypta.support.io.StorageFormatException;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * Encrypted wrapper over a {@link LockableRandomAccessBuffer} backed by a BouncyCastle {@link
 * SkippingStreamCipher}.
 *
 * <p>The underlying storage is partitioned into two regions:
 *
 * <ul>
 *   <li>a cleartext header at the start of the buffer of length {@code type.headerLen}, and
 *   <li>a data region that starts immediately after the header and has logical size {@code
 *       underlying.size() - type.headerLen}.
 * </ul>
 *
 * The header contains: an IV for header encryption, a base key encrypted under a key derived from
 * the {@code MasterSecret}, a MAC authenticating the header fields and version, a 32-bit version,
 * and an 8-byte magic value used as a sentinel. The data region is encrypted using a stream cipher
 * whose key and IV are deterministically derived from the decrypted base key.
 *
 * <p>Thread-safety: reads and writes guard cipher state with dedicated locks ({@code
 * readLock}/{@code writeLock}) so a read and a writing may proceed concurrently. Concurrency of the
 * actual I/O operations is delegated to the underlying buffer implementation.
 *
 * <p>Persistence: instances can be stored and restored via {@link #storeTo(DataOutputStream)} and
 * {@link #create(DataInputStream, FilenameGenerator, PersistentFileTracker, MasterSecret)}; an
 * {@link #onResume(ClientContext)} call re-derives transient crypto state from the master secret
 * and validates the header.
 *
 * @author unixninja92 Suggested {@link EncryptedRandomAccessBufferType} to use: ChaCha128
 */
public class EncryptedRandomAccessBuffer implements LockableRandomAccessBuffer, Serializable {

  @Serial private static final long serialVersionUID = 1L;
  private ReentrantLock readLock = new ReentrantLock();
  private ReentrantLock writeLock = new ReentrantLock();
  private final EncryptedRandomAccessBufferType type;
  // RandomAccessBuffer implementations are not required to be Serializable. Keep the reference
  // transient and handle persistence explicitly in writeObject/readObject, mirroring
  // network.crypta.support.api.ManifestElement.
  private transient LockableRandomAccessBuffer underlyingBuffer;

  private transient SkippingStreamCipher cipherRead;
  private transient SkippingStreamCipher cipherWrite;

  private transient SecretKey headerMacKey;

  private transient volatile boolean isClosed = false;

  private transient SecretKey unencryptedBaseKey;

  private transient SecretKey headerEncKey;
  private transient byte[] headerEncIV;
  private volatile int version;

  private static final long END_MAGIC = 0x2c158a6c7772acd3L;
  private static final int VERSION_AND_MAGIC_LENGTH = 12;
  // Detect whether Java assertions are enabled (-ea). Used to preserve assert semantics
  // without using the 'assert' keyword in public methods.
  private static final boolean ASSERTIONS_ENABLED;

  static {
    ASSERTIONS_ENABLED = EncryptedRandomAccessBuffer.class.desiredAssertionStatus();
  }

  /**
   * Constructs an encrypted random-access buffer over {@code underlying}.
   *
   * <p>When {@code newFile} is {@code true}, a fresh base key and IV are generated and a header is
   * written at offset {@code 0}. When {@code false}, the existing header is read, its MAC is
   * verified, and cipher state is derived from the decrypted base key. Keys for header encryption
   * and MAC computation are derived from the supplied {@code MasterSecret}.
   *
   * <p>Preconditions: {@code underlying.size() >= type.headerLen}.
   *
   * @param type Algorithm suite selecting cipher/MAC and header layout.
   * @param underlying The backing buffer storing ciphertext and the cleartext header; must be at
   *     least {@code type.headerLen} bytes long.
   * @param masterKey Master secret used to derive header and data keys.
   * @param newFile {@code true} to create a new header; {@code false} to open and verify an
   *     existing header.
   * @throws IOException If I/O fails or sizes are invalid.
   * @throws GeneralSecurityException If header verification or cryptographic initialization fails.
   */
  public EncryptedRandomAccessBuffer(
      EncryptedRandomAccessBufferType type,
      LockableRandomAccessBuffer underlying,
      MasterSecret masterKey,
      boolean newFile)
      throws IOException, GeneralSecurityException {
    this.type = type;
    this.underlyingBuffer = underlying;

    setup(masterKey, newFile);
  }

  private void setup(MasterSecret masterKey, boolean newFile)
      throws IOException, GeneralSecurityException {
    this.cipherRead = this.type.get();
    this.cipherWrite = this.type.get();

    this.headerEncKey = masterKey.deriveKey(type.encryptKey);

    this.headerMacKey = masterKey.deriveKey(type.macKey);

    if (underlyingBuffer.size() < type.headerLen) {
      throw new IOException(
          "Underlying RandomAccessBuffer is not long enough to include the " + "footer.");
    }

    byte[] header = new byte[VERSION_AND_MAGIC_LENGTH];
    int offset = 0;
    underlyingBuffer.pread(
        ((long) type.headerLen) - VERSION_AND_MAGIC_LENGTH,
        header,
        offset,
        VERSION_AND_MAGIC_LENGTH);

    int readVersion = ByteBuffer.wrap(header, offset, 4).getInt();
    offset += 4;
    long magic = ByteBuffer.wrap(header, offset, 8).getLong();

    if (!newFile && END_MAGIC != magic) {
      throw new IOException("This is not an EncryptedRandomAccessBuffer!");
    }

    version = type.bitmask;
    if (newFile) {
      this.headerEncIV = KeyGenUtils.genIV(type.encryptType.ivSize).getIV();
      this.unencryptedBaseKey = KeyGenUtils.genSecretKey(type.encryptKey);
      writeHeader();
    } else {
      if (readVersion != version) {
        throw new IOException(
            "Version of the underlying RandomAccessBuffer is " + "incompatible with this ERATType");
      }

      if (!verifyHeader()) {
        throw new GeneralSecurityException("MAC is incorrect");
      }
    }
    try {
      KeyParameter cipherKey =
          new KeyParameter(
              KeyGenUtils.deriveSecretKey(
                      unencryptedBaseKey, getClass(), KdfInput.underlyingKey.input, type.encryptKey)
                  .getEncoded());
      ParametersWithIV cipherParams =
          new ParametersWithIV(
              cipherKey,
              KeyGenUtils.deriveIvParameterSpec(
                      unencryptedBaseKey, getClass(), KdfInput.underlyingIV.input, type.encryptKey)
                  .getIV());
      Objects.requireNonNull(cipherRead, "cipherRead");
      Objects.requireNonNull(cipherWrite, "cipherWrite");
      cipherRead.init(false, cipherParams);
      cipherWrite.init(true, cipherParams);
    } catch (InvalidKeyException e) {
      throw new IllegalStateException(e); // Must be a bug.
    }
  }

  /**
   * Returns the logical size, in bytes, of the data region that can be addressed by {@link
   * #pread(long, byte[], int, int)} and {@link #pwrite(long, byte[], int, int)}.
   *
   * <p>This equals {@code underlying.size() - type.headerLen}.
   *
   * @return number of readable/writable bytes in the data region
   */
  @Override
  public long size() {
    return underlyingBuffer.size() - type.headerLen;
  }

  /**
   * Decrypts bytes from the data region into {@code buf}.
   *
   * <p>Thread-safety: guarded by an internal read lock; independent of the write lock.
   *
   * @param fileOffset Zero-based offset within the logical data region.
   * @param buf Destination array for plaintext bytes.
   * @param bufOffset Offset within {@code buf} to start writing.
   * @param length Number of bytes to read.
   * @throws IllegalArgumentException If {@code fileOffset} is negative.
   * @throws IOException If the request crosses the end of the data region, the buffer is closed, or
   *     the underlying read fails.
   */
  @Override
  public void pread(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    if (isClosed) {
      throw new IOException(
          "This RandomAccessBuffer has already been closed. It can no longer" + " be read from.");
    }

    if (fileOffset < 0) throw new IllegalArgumentException("Cannot read before zero");
    if (fileOffset + length > size()) {
      throw new IOException(
          "Cannot read after end: trying to read from "
              + fileOffset
              + " to "
              + (fileOffset + length)
              + " on block length "
              + size());
    }

    byte[] cipherText = new byte[length];
    underlyingBuffer.pread(fileOffset + type.headerLen, cipherText, 0, length);

    readLock.lock();
    try {
      // seekTo() would reset() and then skip() from 0; that is slow for large files.
      // Uses the published skip() API for positioning.
      long position = cipherRead.getPosition();
      long delta = fileOffset - position;
      cipherRead.skip(delta);
      if (ASSERTIONS_ENABLED && cipherRead.getPosition() != fileOffset) {
        throw new AssertionError("Cipher position mismatch before read");
      }
      cipherRead.processBytes(cipherText, 0, length, buf, bufOffset);
      if (ASSERTIONS_ENABLED && cipherRead.getPosition() != fileOffset + length) {
        throw new AssertionError("Cipher position mismatch after read");
      }
    } finally {
      readLock.unlock();
    }
  }

  /**
   * Encrypts {@code length} bytes from {@code buf} and writes them to the data region.
   *
   * <p>Thread-safety: guarded by an internal write lock; independent of the read lock.
   *
   * @param fileOffset Zero-based offset within the logical data region.
   * @param buf Source array containing plaintext bytes.
   * @param bufOffset Offset within {@code buf} to start reading.
   * @param length Number of bytes to write.
   * @throws IllegalArgumentException If {@code fileOffset} is negative.
   * @throws IOException If the request crosses the end of the data region, the buffer is closed, or
   *     the underlying writing fails.
   */
  @Override
  public void pwrite(long fileOffset, byte[] buf, int bufOffset, int length) throws IOException {
    if (isClosed) {
      throw new IOException(
          "This RandomAccessBuffer has already been closed. It can no longer" + " be written to.");
    }

    if (fileOffset < 0) throw new IllegalArgumentException("Cannot read before zero");
    if (fileOffset + length > size()) {
      throw new IOException(
          "Cannot write after end: trying to write from "
              + fileOffset
              + " to "
              + (fileOffset + length)
              + " on block length "
              + size());
    }

    byte[] cipherText = new byte[length];

    writeLock.lock();
    try {
      // seekTo() would reset() and then skip() from 0; that is slow for large files.
      // Uses the published skip() API for positioning.
      long position = cipherWrite.getPosition();
      long delta = fileOffset - position;
      cipherWrite.skip(delta);
      if (ASSERTIONS_ENABLED && cipherWrite.getPosition() != fileOffset) {
        throw new AssertionError("Cipher position mismatch before write");
      }
      cipherWrite.processBytes(buf, bufOffset, length, cipherText, 0);
      if (ASSERTIONS_ENABLED && cipherWrite.getPosition() != fileOffset + length) {
        throw new AssertionError("Cipher position mismatch after write");
      }
    } finally {
      writeLock.unlock();
    }
    underlyingBuffer.pwrite(fileOffset + type.headerLen, cipherText, 0, length);
  }

  /**
   * Closes this buffer and its underlying storage for later I/O.
   *
   * <p>Idempotent. After the first call, further calls to {@link #pread(long, byte[], int, int)}
   * and {@link #pwrite(long, byte[], int, int)} throw {@link IOException}.
   */
  @Override
  public void close() {
    if (!isClosed) {
      isClosed = true;
      underlyingBuffer.close();
    }
  }

  /**
   * Releases resources. Calls {@link #close()} and delegates to {@link
   * LockableRandomAccessBuffer#free()} on the underlying buffer.
   */
  @Override
  public void free() {
    close();
    underlyingBuffer.free();
  }

  /**
   * Writes the cleartext header at the start of the underlying buffer.
   *
   * @throws IOException If the buffer is closed or I/O fails.
   * @throws GeneralSecurityException If key derivation or encryption fails.
   */
  private void writeHeader() throws IOException, GeneralSecurityException {
    if (isClosed) {
      throw new IOException(
          "This RandomAccessBuffer has already been closed. This should not" + " happen.");
    }
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

    underlyingBuffer.pwrite(0, header, 0, header.length);
  }

  /**
   * Reads the IV, the encrypted base key, and the MAC from the header, then decrypts the key, and
   * verifies the MAC.
   *
   * @return {@code true} if the MAC verifies; {@code false} otherwise.
   * @throws IOException If I/O fails or the buffer is closed.
   * @throws InvalidKeyException If the MAC cannot be initialized.
   */
  private boolean verifyHeader() throws IOException, InvalidKeyException {
    if (isClosed) {
      throw new IOException(
          "This RandomAccessBuffer has already been closed. This should not" + " happen.");
    }
    byte[] footer = new byte[type.headerLen - VERSION_AND_MAGIC_LENGTH];
    int offset = 0;
    underlyingBuffer.pread(0, footer, offset, type.headerLen - VERSION_AND_MAGIC_LENGTH);

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

  /** The inputs used to derive keys and IVs from the {@code unencryptedBaseKey}. */
  static final class KdfInput {
    /** For deriving the key that encrypts the underlying data region. */
    public static final KdfInput underlyingKey = new KdfInput("underlyingKey");

    /** For deriving the IV used to encrypt the underlying data region. */
    public static final KdfInput underlyingIV = new KdfInput("underlyingIV");

    /** The literal input string fed into the KDF. */
    public final String input;

    private KdfInput(String input) {
      this.input = input;
    }
  }

  /**
   * Opens a lock for coordinated access. Delegates to the underlying buffer.
   *
   * @return a lock object representing the open lifetime
   * @throws IOException if the underlying buffer cannot open the lock
   */
  @Override
  public RAFLock lockOpen() throws IOException {
    return underlyingBuffer.lockOpen();
  }

  /**
   * Persistence tag written by {@link #storeTo(DataOutputStream)}. The caller that restores a
   * buffer is expected to check this marker before calling {@link #create(DataInputStream,
   * FilenameGenerator, PersistentFileTracker, MasterSecret)}.
   */
  public static final int MAGIC = 0x39ea94c2;

  /**
   * Recreates transient crypto state after deserialization or process restart.
   *
   * <p>Derives keys from the persistent master secret in {@code context}, verifies the header, and
   * initializes the stream ciphers.
   *
   * @throws ResumeFailedException If I/O or cryptographic initialization fails.
   */
  @Override
  public void onResume(ClientContext context) throws ResumeFailedException {
    underlyingBuffer.onResume(context);
    try {
      setup(context.getPersistentMasterSecret(), false);
    } catch (IOException e) {
      throw new ResumeFailedException(
          new IOException("Disk I/O error resuming EncryptedRandomAccessBuffer", e));
    } catch (GeneralSecurityException e) {
      throw new ResumeFailedException(
          new GeneralSecurityException(
              "Security error resuming EncryptedRandomAccessBuffer (maybe missing codec)", e));
    }
  }

  /**
   * Writes a persistent representation to {@code dos}: {@link #MAGIC}, the algorithm bitmask, and
   * the underlying buffer via its own persistence format.
   *
   * @param dos destination stream
   * @throws IOException if writing fails
   */
  @Override
  public void storeTo(DataOutputStream dos) throws IOException {
    dos.writeInt(MAGIC);
    dos.writeInt(type.bitmask);
    underlyingBuffer.storeTo(dos);
  }

  /* ===== Java serialization support (explicit underlying handling) ===== */
  private static final String FIELD_TYPE = "type";
  private static final String FIELD_UNDERLYING = "underlyingBuffer";
  private static final String FIELD_VERSION = "version";

  @Serial
  private static final ObjectStreamField[] serialPersistentFields = {
    new ObjectStreamField(FIELD_TYPE, EncryptedRandomAccessBufferType.class),
    new ObjectStreamField(FIELD_UNDERLYING, LockableRandomAccessBuffer.class),
    new ObjectStreamField(FIELD_VERSION, int.class)
  };

  @Serial
  private void writeObject(ObjectOutputStream out) throws IOException {
    assert serialPersistentFields.length > 0;
    PutField fields = out.putFields();
    fields.put(FIELD_TYPE, type);
    fields.put(FIELD_VERSION, version);
    if (underlyingBuffer == null) {
      fields.put(FIELD_UNDERLYING, null);
      out.writeFields();
      return;
    }
    if (underlyingBuffer instanceof Serializable serializable) {
      fields.put(FIELD_UNDERLYING, serializable);
      out.writeFields();
      // Also, write the underlying as a trailing object for compatibility with intermediary
      // formats and to allow readObject() to restore transient fields via defaultReadObject().
      out.writeObject(serializable);
      return;
    }
    out.writeFields();
    throw new NotSerializableException(underlyingBuffer.getClass().getName());
  }

  @Serial
  private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
    // Restore non-transient fields (locks, type, version) via the default mechanism.
    in.defaultReadObject();
    // Recreate locks if they weren't part of the serialized field set.
    if (this.readLock == null) this.readLock = new ReentrantLock();
    if (this.writeLock == null) this.writeLock = new ReentrantLock();

    // Compatibility: if the underlying buffer wasn't restored from the default field block
    // (older/newer streams that omit it there), attempt to read a trailing object written by
    // intermediary versions. ObjectInputStream bounds class data, so a missing trailing object
    // results in OptionalDataException with eof=true and does not consume the next top‑level
    // object in the stream.
    if (this.underlyingBuffer == null) {
      try {
        Object maybeUnderlying = in.readObject();
        this.underlyingBuffer =
            (maybeUnderlying == null) ? null : (LockableRandomAccessBuffer) maybeUnderlying;
      } catch (java.io.OptionalDataException e) {
        if (!e.eof) throw e; // No trailing object for this class; keep field value (null).
      }
    }
  }

  /**
   * Restores an instance previously written with {@link #storeTo(DataOutputStream)}.
   *
   * <p>Callers are expected to have already read and validated {@link #MAGIC}. The input stream
   * must be positioned at the type bitmask written by {@link #storeTo(DataOutputStream)}.
   *
   * @param dis data input positioned to the algorithm bitmask
   * @param fg filename generator used while restoring the underlying buffer
   * @param persistentFileTracker tracker for files used by the underlying buffer
   * @param masterKey master secret used to derive keys
   * @return a ready-to-use {@link LockableRandomAccessBuffer}
   * @throws IOException on I/O errors
   * @throws StorageFormatException if the algorithm bitmask is unknown
   * @throws ResumeFailedException if cryptographic initialization fails
   */
  public static LockableRandomAccessBuffer create(
      DataInputStream dis,
      FilenameGenerator fg,
      PersistentFileTracker persistentFileTracker,
      MasterSecret masterKey)
      throws IOException, StorageFormatException, ResumeFailedException {
    EncryptedRandomAccessBufferType type =
        EncryptedRandomAccessBufferType.getByBitmask(dis.readInt());
    if (type == null) throw new StorageFormatException("Unknown EncryptedRandomAccessBufferType");
    LockableRandomAccessBuffer underlying =
        BucketTools.restoreRAFFrom(dis, fg, persistentFileTracker, masterKey);
    try {
      return new EncryptedRandomAccessBuffer(type, underlying, masterKey, false);
    } catch (GeneralSecurityException e) {
      throw new ResumeFailedException(
          new GeneralSecurityException("Crypto error resuming EncryptedRandomAccessBuffer", e));
    }
  }

  @Override
  public int hashCode() {
    final int prime = 31;
    int result = 1;
    result = prime * result + ((type == null) ? 0 : type.hashCode());
    result = prime * result + ((underlyingBuffer == null) ? 0 : underlyingBuffer.hashCode());
    return result;
  }

  @Override
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
    EncryptedRandomAccessBuffer other = (EncryptedRandomAccessBuffer) obj;
    if (type != other.type) {
      return false;
    }
    return underlyingBuffer.equals(other.underlyingBuffer);
  }
}
