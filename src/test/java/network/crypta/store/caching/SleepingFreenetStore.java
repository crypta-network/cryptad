package network.crypta.store.caching;

import java.io.IOException;
import network.crypta.store.FreenetStore;
import network.crypta.store.KeyCollisionException;
import network.crypta.store.ProxyFreenetStore;
import network.crypta.store.StorableBlock;

/**
 * @deprecated Usually WriteBlockableFreenetStore is more appropriate.
 */
@Deprecated
public class SleepingFreenetStore<T extends StorableBlock> extends ProxyFreenetStore<T> {

  private final int delay;

  public SleepingFreenetStore(int delay, FreenetStore<T> underlying) {
    super(underlying);
    this.delay = delay;
  }

  @Override
  public void put(T block, byte[] data, byte[] header, boolean overwrite, boolean oldBlock)
      throws IOException, KeyCollisionException {
    try {
      Thread.sleep(delay);
    } catch (InterruptedException e) {
      // Ignore.
    }
    super.put(block, data, header, overwrite, oldBlock);
  }
}
