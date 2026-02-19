package network.crypta.node;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

class NodeCliTest {
  @Test
  void classIsLoadable() {
    assertNotNull(NodeCli.class);
  }
}
