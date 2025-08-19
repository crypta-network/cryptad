package network.crypta.client.async;

import network.crypta.support.api.Bucket;

public interface HealingQueue {

  /** Queue a Bucket of data to insert as a CHK. */
  void queue(Bucket data, byte[] cryptoKey, byte cryptoAlgorithm, ClientContext context);
}
