package network.crypta.client.async;

import network.crypta.client.Metadata;

public class DumperSnoopMetadata implements SnoopMetadata {

  @Override
  public boolean snoopMetadata(Metadata meta, ClientContext context) {
    System.err.print(meta.dump());
    return false;
  }
}
