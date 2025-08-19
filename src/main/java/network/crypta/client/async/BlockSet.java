package network.crypta.client.async;

import java.util.Set;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;

/**
 * A set of KeyBlock's.
 *
 * @author toad
 */
public interface BlockSet {

  /**
   * Get a block by its key.
   *
   * @param key The key of the block to get.
   * @return A block, or null if there is no block with that key.
   */
  KeyBlock get(Key key);

  /**
   * Add a block.
   *
   * @param block The block to add.
   */
  void add(KeyBlock block);

  /**
   * Get the set of all the keys of all the blocks.
   *
   * @return A set of the keys of the blocks in the BlockSet. Not guaranteed to be kept up to date.
   *     Read only.
   */
  Set<Key> keys();

  /** Get a high level block, given a high level key */
  ClientKeyBlock get(ClientKey key);
}
