package network.crypta.store;

import java.io.IOException;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.support.HexUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleGetPubkey implements GetPubkey {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleGetPubkey.class);

  final PubkeyStore store;

  public SimpleGetPubkey(PubkeyStore store) {
    this.store = store;
  }

  @Override
  public DSAPublicKey getKey(
      byte[] hash, boolean canReadClientCache, boolean forULPR, BlockMetadata meta) {
    try {
      return store.fetch(hash, false, false, meta);
    } catch (IOException e) {
      LOG.error("Caught {} fetching pubkey for {}", e.toString(), HexUtil.bytesToHex(hash));
      return null;
    }
  }

  @Override
  public void cacheKey(
      byte[] hash,
      DSAPublicKey key,
      boolean deep,
      boolean canWriteClientCache,
      boolean canWriteDatastore,
      boolean forULPR,
      boolean writeLocalToDatastore) {
    try {
      store.put(hash, key, false);
    } catch (IOException e) {
      LOG.error("Caught {} storing pubkey for {}", e.toString(), HexUtil.bytesToHex(hash));
    }
  }
}
