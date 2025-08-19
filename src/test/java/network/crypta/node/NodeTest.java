package network.crypta.node;

import static org.junit.Assert.*;

import org.junit.Test;

/** Sanity tests for Node. TODO: add more tests. */
public class NodeTest {

  /** Tests for sanity of default store sizes. */
  @Test
  public void testDefaultStoreSizeSanity() {
    assertTrue(Node.MIN_STORE_SIZE <= Node.DEFAULT_STORE_SIZE);
    assertTrue(Node.MIN_CLIENT_CACHE_SIZE <= Node.DEFAULT_CLIENT_CACHE_SIZE);
    assertTrue(Node.MIN_SLASHDOT_CACHE_SIZE <= Node.DEFAULT_SLASHDOT_CACHE_SIZE);
  }
}
