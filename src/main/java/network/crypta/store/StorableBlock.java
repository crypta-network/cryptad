package network.crypta.store;

public interface StorableBlock {

  byte[] getRoutingKey();

  byte[] getFullKey();
}
