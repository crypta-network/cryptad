package network.crypta.store;

import java.io.IOException;
import network.crypta.crypt.CryptFormatException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.keys.KeyVerifyException;
import network.crypta.keys.PubkeyVerifyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PubkeyStore extends StoreCallback<DSAPublicKey> {
  private static final Logger LOG = LoggerFactory.getLogger(PubkeyStore.class);

  @Override
  public boolean collisionPossible() {
    return false;
  }

  @Override
  public DSAPublicKey construct(
      byte[] data,
      byte[] headers,
      byte[] routingKey,
      byte[] fullKey,
      boolean canReadClientCache,
      boolean canReadSlashdotCache,
      BlockMetadata meta,
      DSAPublicKey ignored)
      throws KeyVerifyException {
    if (data == null) throw new PubkeyVerifyException("Need data to construct pubkey");
    try {
      return DSAPublicKey.create(data);
    } catch (CryptFormatException e) {
      throw new PubkeyVerifyException(e);
    }
  }

  public DSAPublicKey fetch(
      byte[] hash, boolean dontPromote, boolean ignoreOldBlocks, BlockMetadata meta)
      throws IOException {
    return store.fetch(hash, null, dontPromote, false, false, ignoreOldBlocks, meta);
  }

  private static final byte[] empty = new byte[0];

  public void put(byte[] hash, DSAPublicKey key, boolean isOldBlock) throws IOException {
    try {
      store.put(key, key.asPaddedBytes(), empty, false, isOldBlock);
    } catch (KeyCollisionException e) {
      LOG.error("Impossible for PubkeyStore: {}", e.toString(), e);
    }
  }

  @Override
  public int dataLength() {
    return DSAPublicKey.PADDED_SIZE;
  }

  @Override
  public int fullKeyLength() {
    return DSAPublicKey.HASH_LENGTH;
  }

  @Override
  public int headerLength() {
    return 0;
  }

  @Override
  public int routingKeyLength() {
    return DSAPublicKey.HASH_LENGTH;
  }

  @Override
  public boolean storeFullKeys() {
    return false;
  }

  @Override
  public boolean constructNeedsKey() {
    return false;
  }

  @Override
  public byte[] routingKeyFromFullKey(byte[] keyBuf) {
    return keyBuf;
  }
}
