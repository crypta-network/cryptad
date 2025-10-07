package network.crypta.support.io;

import java.io.IOException;
import java.security.GeneralSecurityException;
import network.crypta.crypt.EncryptedRandomAccessBuffer;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.api.LockableRandomAccessBuffer;
import network.crypta.support.api.LockableRandomAccessBufferFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Wraps another LockableRandomAccessBufferFactory to enable encryption if currently turned on. */
public class MaybeEncryptedRandomAccessBufferFactory implements LockableRandomAccessBufferFactory {
  private static final Logger LOG =
      LoggerFactory.getLogger(MaybeEncryptedRandomAccessBufferFactory.class);

  public MaybeEncryptedRandomAccessBufferFactory(
      LockableRandomAccessBufferFactory factory, boolean encrypt) {
    this.factory = factory;
    this.reallyEncrypt = encrypt;
  }

  private final LockableRandomAccessBufferFactory factory;
  private volatile boolean reallyEncrypt;
  private MasterSecret secret;

  static {
  }

  @Override
  public LockableRandomAccessBuffer makeRAF(long size) throws IOException {
    long realSize = size;
    long paddedSize = size;
    MasterSecret secret = null;
    synchronized (this) {
      if (reallyEncrypt && this.secret != null) {
        secret = this.secret;
        realSize += TempBucketFactory.CRYPT_TYPE.headerLen;
        paddedSize =
            PaddedEphemerallyEncryptedBucket.paddedLength(
                realSize, PaddedEphemerallyEncryptedBucket.MIN_PADDED_SIZE);
        if (LOG.isDebugEnabled()) LOG.debug("Encrypting and padding " + size + " to " + paddedSize);
      }
    }
    LockableRandomAccessBuffer raf = factory.makeRAF(paddedSize);
    if (secret != null) {
      if (realSize != paddedSize) raf = new PaddedRandomAccessBuffer(raf, realSize);
      try {
        raf = new EncryptedRandomAccessBuffer(TempBucketFactory.CRYPT_TYPE, raf, secret, true);
      } catch (GeneralSecurityException e) {
        LOG.error("Cannot create encrypted tempfile: " + e, e);
      }
    }
    return raf;
  }

  @Override
  public LockableRandomAccessBuffer makeRAF(
      byte[] initialContents, int offset, int size, boolean readOnly) throws IOException {
    boolean reallyEncrypt = false;
    synchronized (this) {
      reallyEncrypt = this.reallyEncrypt;
    }
    if (reallyEncrypt) {
      // FIXME do the encryption in memory? Test it ...
      LockableRandomAccessBuffer ret = makeRAF(size);
      ret.pwrite(0, initialContents, offset, size);
      if (readOnly) ret = new ReadOnlyRandomAccessBuffer(ret);
      return ret;
    } else {
      return factory.makeRAF(initialContents, offset, size, readOnly);
    }
  }

  public void setMasterSecret(MasterSecret secret) {
    synchronized (this) {
      this.secret = secret;
    }
  }

  public void setEncryption(boolean value) {
    synchronized (this) {
      reallyEncrypt = value;
    }
    if (factory instanceof PooledFileRandomAccessBufferFactory bufferFactory)
      bufferFactory.enableCrypto(value);
  }
}
