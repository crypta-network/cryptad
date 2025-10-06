package network.crypta.client.async;

import java.util.HashMap;
import java.util.Set;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.KeyVerifyException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple BlockSet implementation, keeps all keys in RAM.
 *
 * @author toad
 */
public class SimpleBlockSet implements BlockSet {
  private static final Logger LOG = LoggerFactory.getLogger(SimpleBlockSet.class);

  private final HashMap<Key, KeyBlock> blocksByKey = new HashMap<>();

  @Override
  public synchronized void add(KeyBlock block) {
    blocksByKey.put(block.getKey(), block);
  }

  @Override
  public synchronized KeyBlock get(Key key) {
    return blocksByKey.get(key);
  }

  @Override
  public synchronized Set<Key> keys() {
    return blocksByKey.keySet();
  }

  @Override
  public ClientKeyBlock get(ClientKey key) {
    KeyBlock block = get(key.getNodeKey(false));
    if (block == null) return null;
    try {
      return Key.createKeyBlock(key, block);
    } catch (KeyVerifyException e) {
      LOG.error("Caught decoding block with " + key + " : " + e, e);
      return null;
    }
  }
}
