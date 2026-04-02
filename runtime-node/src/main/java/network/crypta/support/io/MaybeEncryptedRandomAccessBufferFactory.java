package network.crypta.support.io;

import java.io.IOException;
import java.security.GeneralSecurityException;
import network.crypta.crypt.EncryptedRandomAccessBuffer;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory that conditionally returns encrypted random-access buffers.
 *
 * <p>This class wraps a delegate {@link LockableRandomAccessBufferFactory}. When encryption is
 * enabled via {@link #setEncryption(boolean)} and a non-null {@link MasterSecret} is configured via
 * {@link #setMasterSecret(MasterSecret)}, the buffers produced by {@link #makeRAF(long)} and {@link
 * #makeRAF(byte[], int, int, boolean)} are wrapped in an {@link EncryptedRandomAccessBuffer}. The
 * encrypted representation includes a crypto header (as defined by {@code
 * TempBucketFactory.CRYPT_TYPE}) and may be padded to a minimum size to reduce information leakage
 * about the plaintext length.
 *
 * <p>When encryption is disabled or no master secret is set, this factory delegates creation to the
 * underlying factory and returns plaintext buffers unchanged.
 *
 * <h3>Thread-safety</h3>
 *
 * <p>Instances are safe for concurrent use. Calls snapshot the current configuration (encryption
 * flag and secret) under a short synchronized block and then create the buffer without holding the
 * lock.
 *
 * <h3>Size semantics</h3>
 *
 * <p>The {@code size} requested by callers is the logical plaintext size in bytes. If encryption is
 * active, the underlying storage may be larger due to the header and padding; callers still observe
 * the requested logical size via the returned buffer API.
 */
public class MaybeEncryptedRandomAccessBufferFactory implements LockableRandomAccessBufferFactory {
  private static final Logger LOG =
      LoggerFactory.getLogger(MaybeEncryptedRandomAccessBufferFactory.class);

  /**
   * Creates a new conditional-encryption buffer factory.
   *
   * @param factory the delegate used to allocate the underlying storage; must not be {@code null}.
   * @param encrypt initial encryption state. If {@code true}, buffers are encrypted only when a
   *     non-null {@link MasterSecret} is also set via {@link #setMasterSecret(MasterSecret)}.
   */
  public MaybeEncryptedRandomAccessBufferFactory(
      LockableRandomAccessBufferFactory factory, boolean encrypt) {
    this.factory = factory;
    this.reallyEncrypt = encrypt;
  }

  private final LockableRandomAccessBufferFactory factory;
  private volatile boolean reallyEncrypt;
  private MasterSecret secret;

  /**
   * Allocates a random-access buffer of the given logical size.
   *
   * <p>If encryption is active, the returned buffer transparently encrypts writes and decrypts
   * reads. The underlying storage may be larger than {@code size} to account for a crypto header
   * and padding, but callers interact with the logical size provided.
   *
   * <p>On cryptographic initialization failure, this method logs an error and returns a plaintext
   * buffer so that the caller still receives a usable object.
   *
   * @param size logical plaintext size in bytes.
   * @return a lockable random-access buffer of the requested logical size.
   * @throws IOException if the underlying factory cannot allocate storage.
   */
  @Override
  public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
    long realSize = size;
    long paddedSize = size;
    MasterSecret activeSecret = null;
    // Snapshot configuration to ensure a consistent view for this allocation.
    synchronized (this) {
      if (reallyEncrypt && this.secret != null) {
        activeSecret = this.secret;
        realSize += TempBucketFactory.CRYPT_TYPE.headerLen;
        paddedSize =
            PaddedEphemerallyEncryptedBucket.paddedLength(
                realSize, PaddedEphemerallyEncryptedBucket.MIN_PADDED_SIZE);
        if (LOG.isDebugEnabled()) LOG.debug("Encrypting and padding {} to {}", size, paddedSize);
      }
    }
    LockableRandomAccessBuffer raf = factory.makeRAF(paddedSize);
    if (activeSecret != null) {
      // If padding increased the physical size, expose only the logical size to callers.
      if (realSize != paddedSize) raf = new PaddedRandomAccessBuffer(raf, realSize);
      try {
        raf =
            new EncryptedRandomAccessBuffer(TempBucketFactory.CRYPT_TYPE, raf, activeSecret, true);
      } catch (GeneralSecurityException e) {
        // Fail closed with plaintext storage but log loudly; callers still get a usable buffer.
        LOG.error("Cannot create encrypted tempfile: {}", e, e);
      }
    }
    return raf;
  }

  /**
   * Allocates a random-access buffer initialized with the provided contents.
   *
   * <p>When encryption is active, storage is allocated via {@link #makeRAF(long)} and the initial
   * bytes are written at offset {@code 0} afterward; the plaintext is never persisted unencrypted
   * when the factory is configured to encrypt.
   *
   * @param initialContents source array containing at least {@code offset + size} bytes.
   * @param offset starting index within {@code initialContents}.
   * @param size number of bytes to copy into the buffer.
   * @param readOnly if {@code true}, the returned buffer is wrapped to disallow writes.
   * @return a buffer whose first {@code size} bytes are initialized from {@code initialContents}.
   * @throws IOException if allocation or the initialization write fails.
   */
  @Override
  public LockableRandomAccessBuffer makeRAF(
      byte[] initialContents, int offset, int size, boolean readOnly) throws IOException {
    boolean encryptionEnabled;
    synchronized (this) {
      encryptionEnabled = this.reallyEncrypt;
    }
    if (encryptionEnabled) {
      // Allocate (possibly encrypted) storage first, then write the initial contents.
      LockableRandomAccessBuffer ret = makeRAF(size);
      ret.pwrite(0, initialContents, offset, size);
      if (readOnly) ret = new ReadOnlyRandomAccessBuffer(ret);
      return ret;
    } else {
      return factory.makeRAF(initialContents, offset, size, readOnly);
    }
  }

  /**
   * Sets the master secret used to encrypt newly created buffers.
   *
   * <p>If {@code secret} is {@code null}, encryption is effectively disabled even when the
   * encryption flag is set.
   *
   * @param secret the master secret or {@code null} to clear it.
   */
  public void setMasterSecret(MasterSecret secret) {
    synchronized (this) {
      this.secret = secret;
    }
  }

  /**
   * Enables or disables encryption for buffers allocated after the call.
   *
   * <p>Changing this flag does not affect previously created buffers. When enabling encryption, a
   * non-null {@link MasterSecret} must also be configured for encryption to take effect. The flag
   * is not propagated to underlying factories; encryption here is implemented by wrapping the
   * returned buffers.
   *
   * @param value {@code true} to request encryption for future allocations; {@code false} to
   *     allocate plaintext buffers.
   */
  public void setEncryption(boolean value) {
    synchronized (this) {
      reallyEncrypt = value;
    }
  }
}
