package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import network.crypta.keys.CHKBlock;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.ClientKey;
import network.crypta.keys.ClientKeyBlock;
import network.crypta.keys.Key;
import network.crypta.keys.KeyVerifyException;
import network.crypta.keys.NodeCHK;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SimpleBlockSetTest {

  private static final byte ALGO = Key.ALGO_AES_CTR_256_SHA256;

  private static CHKBlock newUncheckedCHKBlock(NodeCHK key, byte fill) {
    byte[] headers = new byte[CHKBlock.TOTAL_HEADERS_LENGTH];
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    // When verify=false and a key is provided, CHKBlock trusts the key and skips content hashing.
    // Header content is irrelevant then; still set a valid hash id (0x0001) for clarity.
    headers[0] = 0x00;
    headers[1] = 0x01;
    Arrays.fill(data, fill);
    try {
      return new CHKBlock(data, headers, key, /* verify= */ false, ALGO);
    } catch (Exception e) {
      throw new AssertionError("Unexpected CHKBlock construction failure", e);
    }
  }

  private static CHKBlock newVerifiedCHKBlock(byte fill) {
    byte[] headers = new byte[CHKBlock.TOTAL_HEADERS_LENGTH];
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    headers[0] = 0x00;
    headers[1] = 0x01; // HASH_SHA256
    Arrays.fill(data, fill);
    try {
      return CHKBlock.construct(data, headers, ALGO);
    } catch (Exception e) {
      throw new AssertionError("Unexpected CHKBlock construct() failure", e);
    }
  }

  @Test
  void add_and_get_byKey_returnsSameBlock() {
    SimpleBlockSet set = new SimpleBlockSet();
    NodeCHK key = new NodeCHK(new byte[NodeCHK.KEY_LENGTH], ALGO);
    CHKBlock block = newUncheckedCHKBlock(key, (byte) 7);

    set.add(block);

    assertSame(block, set.get(key));
  }

  @Test
  void keys_afterAddingTwo_containsBothKeys_andReflectsSize() {
    SimpleBlockSet set = new SimpleBlockSet();
    NodeCHK key1 = new NodeCHK(new byte[NodeCHK.KEY_LENGTH], ALGO);
    NodeCHK key2 = new NodeCHK(new byte[NodeCHK.KEY_LENGTH], ALGO);
    // Ensure keys differ
    key2.getRoutingKey()[0] = 1;
    CHKBlock block1 = newUncheckedCHKBlock(key1, (byte) 1);
    CHKBlock block2 = newUncheckedCHKBlock(key2, (byte) 2);

    set.add(block1);
    set.add(block2);

    assertEquals(2, set.keys().size());
    // The set view should contain both keys
    // Use get() to check presence deterministically
    assertSame(block1, set.get(key1));
    assertSame(block2, set.get(key2));
  }

  @Test
  void add_whenSameKey_overwritesPreviousBlock() {
    SimpleBlockSet set = new SimpleBlockSet();
    NodeCHK sharedKey = new NodeCHK(new byte[NodeCHK.KEY_LENGTH], ALGO);
    CHKBlock first = newUncheckedCHKBlock(sharedKey, (byte) 3);
    CHKBlock second = newUncheckedCHKBlock(sharedKey, (byte) 4);

    set.add(first);
    set.add(second);

    assertSame(second, set.get(sharedKey));
    assertEquals(1, set.keys().size());
  }

  @Test
  void get_whenKeyNull_returnsNull() {
    SimpleBlockSet set = new SimpleBlockSet();
    assertNull(set.get((Key) null));
  }

  @Test
  void add_whenBlockNull_throwsNullPointerException() {
    SimpleBlockSet set = new SimpleBlockSet();
    assertThrows(NullPointerException.class, () -> set.add(null));
  }

  @Test
  void getClientKey_whenNull_throwsNullPointerException() {
    SimpleBlockSet set = new SimpleBlockSet();
    //noinspection DataFlowIssue
    assertThrows(NullPointerException.class, () -> set.get((ClientKey) null));
  }

  @Test
  void getClientKey_whenBlockPresent_returnsClientKeyBlock() {
    // Arrange: build a real CHK block and matching ClientCHK key
    CHKBlock block = newVerifiedCHKBlock((byte) 9);
    NodeCHK nodeKey = block.getKey();
    ClientCHK clientKey =
        new ClientCHK(
            nodeKey.getRoutingKey(),
            new byte[ClientCHK.CRYPTO_KEY_LENGTH],
            false,
            ALGO,
            (short) -1);

    SimpleBlockSet set = new SimpleBlockSet();
    set.add(block);

    // Act
    ClientKeyBlock ckb = set.get(clientKey);

    // Assert
    assertNotNull(ckb);
    // A new CHKBlock instance is constructed internally; compare by value.
    assertEquals(nodeKey, ckb.getKey());
    assertEquals(block, ckb.getBlock());
  }

  @Test
  void getClientKey_whenCreateKeyBlockThrows_returnsNull() {
    // Arrange
    CHKBlock block = newVerifiedCHKBlock((byte) 5);
    NodeCHK nodeKey = block.getKey();
    ClientCHK clientKey =
        new ClientCHK(
            nodeKey.getRoutingKey(),
            new byte[ClientCHK.CRYPTO_KEY_LENGTH],
            false,
            ALGO,
            (short) -1);

    SimpleBlockSet set = new SimpleBlockSet();
    set.add(block);

    try (MockedStatic<Key> mocked = Mockito.mockStatic(Key.class)) {
      mocked
          .when(() -> Key.createKeyBlock(clientKey, block))
          .thenThrow(new KeyVerifyException("boom"));

      // Act
      ClientKeyBlock result = set.get(clientKey);

      // Assert
      assertNull(result);
    }
  }
}
