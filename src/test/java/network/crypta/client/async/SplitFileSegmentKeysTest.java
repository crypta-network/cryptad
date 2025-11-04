package network.crypta.client.async;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.util.Arrays;
import network.crypta.keys.ClientCHK;
import network.crypta.keys.Key;
import network.crypta.keys.NodeCHK;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class SplitFileSegmentKeysTest {

  private static ClientCHK newClientKey(byte[] rk, byte[] ck, byte algo) throws Exception {
    return new ClientCHK(rk, ck, ClientCHK.getExtra(algo, (short) -1, false));
  }

  private static byte[] rk(int seed) {
    byte[] rk = new byte[NodeCHK.KEY_LENGTH];
    rk[0] = (byte) seed;
    return rk;
  }

  private static byte[] ck(int seed) {
    byte[] ck = new byte[ClientCHK.CRYPTO_KEY_LENGTH];
    ck[0] = (byte) seed;
    return ck;
  }

  @Test
  void storedKeysLength_and_roundTrip_withCommonDecryptKey_matchExpectations() throws Exception {
    int data = 3;
    int check = 2;
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    byte[] common = ck(77);

    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(data, check, common, algo);
    for (int i = 0; i < data + check; i++) {
      keys.setKey(i, newClientKey(rk(10 + i), ck(80 + i), algo));
    }

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    keys.writeKeys(dos, /*check*/ false);
    keys.writeKeys(dos, /*check*/ true);
    dos.close();

    int expected = SplitFileSegmentKeys.storedKeysLength(data, check, /*common*/ true);
    assertEquals(expected, bos.size(), "Stored byte length must match computation");

    // Read back and verify equality
    SplitFileSegmentKeys read = new SplitFileSegmentKeys(data, check, common, algo);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    read.readKeys(dis, /*check*/ false);
    read.readKeys(dis, /*check*/ true);

    assertEquals(keys, read);
    assertEquals(data, read.getDataBlocks());
    assertEquals(check, read.getCheckBlocks());
    assertEquals(data + check, read.totalKeys());
  }

  @Test
  void storedKeysLength_and_roundTrip_withoutCommonDecryptKey_matchExpectations() throws Exception {
    int data = 2;
    int check = 1;
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;

    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(data, check, null, algo);
    for (int i = 0; i < data + check; i++) {
      keys.setKey(i, newClientKey(rk(20 + i), ck(90 + i), algo));
    }

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    keys.writeKeys(dos, /*check*/ false);
    keys.writeKeys(dos, /*check*/ true);
    dos.close();

    int expected = SplitFileSegmentKeys.storedKeysLength(data, check, /*common*/ false);
    assertEquals(expected, bos.size(), "Stored byte length must match computation");

    // Read back and verify equality
    SplitFileSegmentKeys read = new SplitFileSegmentKeys(data, check, null, algo);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()));
    read.readKeys(dis, /*check*/ false);
    read.readKeys(dis, /*check*/ true);

    assertEquals(keys, read);
  }

  @Test
  void getBlockNumber_ClientCHK_withCommonKey_returnsIndexAndHonorsIgnoreMask() throws Exception {
    int data = 3;
    int check = 1;
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    byte[] common = ck(7);
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(data, check, common, algo);
    // Fill routing keys only (per-block crypto/extra not stored in this mode)
    for (int i = 0; i < data + check; i++) {
      keys.setKey(i, newClientKey(rk(1 + i), ck(55 + i), algo));
    }

    int target = 2;
    ClientCHK probe = newClientKey(rk(1 + target), common, algo);
    assertEquals(target, keys.getBlockNumber(probe, /*ignore*/ null));

    boolean[] ignore = new boolean[data + check];
    ignore[target] = true;
    assertEquals(-1, keys.getBlockNumber(probe, ignore));

    // Wrong crypto key should not match when commonDecryptKey is enforced
    ClientCHK wrongCrypto = newClientKey(rk(1 + target), ck(99), algo);
    assertEquals(-1, keys.getBlockNumber(wrongCrypto, /*ignore*/ null));
  }

  @Test
  void getBlockNumber_ClientCHK_withoutCommonKey_checksRoutingCryptoAndExtra() throws Exception {
    int data = 2;
    int check = 1;
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(data, check, null, algo);

    for (int i = 0; i < data + check; i++) {
      keys.setKey(i, newClientKey(rk(30 + i), ck(40 + i), algo));
    }

    int target = 1;
    ClientCHK match = newClientKey(rk(30 + target), ck(40 + target), algo);
    assertEquals(target, keys.getBlockNumber(match, null));

    // Mismatch crypto
    ClientCHK wrongCk = newClientKey(rk(30 + target), ck(99), algo);
    assertEquals(-1, keys.getBlockNumber(wrongCk, null));

    // Mismatch extra (different algorithm)
    ClientCHK wrongExtra =
        newClientKey(rk(30 + target), ck(40 + target), Key.ALGO_AES_CTR_256_SHA256);
    assertEquals(-1, keys.getBlockNumber(wrongExtra, null));
  }

  @Test
  void getBlockNumber_NodeCHK_returnsIndexAndAllMatches() throws Exception {
    int data = 3;
    int check = 1;
    byte algo = Key.ALGO_AES_CTR_256_SHA256;
    byte[] common = ck(1);
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(data, check, common, algo);
    // Create duplicate routing keys at positions 0 and 3
    keys.setKey(0, newClientKey(rk(77), ck(10), algo));
    keys.setKey(1, newClientKey(rk(78), ck(11), algo));
    keys.setKey(2, newClientKey(rk(79), ck(12), algo));
    keys.setKey(3, newClientKey(rk(77), ck(13), algo));

    NodeCHK node = new NodeCHK(rk(77), algo);
    assertEquals(0, keys.getBlockNumber(node, null));

    int[] all = keys.getBlockNumbers(node, null);
    assertArrayEquals(new int[] {0, 3}, all);

    boolean[] ignore = new boolean[data + check];
    ignore[0] = true;
    assertEquals(3, keys.getBlockNumber(node, ignore));
  }

  @Test
  void getKey_copySemantics_withCommonDecryptKey_controlsCryptoArraySharing() throws Exception {
    int data = 1;
    int check = 0;
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    byte[] common = ck(5);
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(data, check, common, algo);
    keys.setKey(0, newClientKey(rk(100), ck(101), algo));

    // copy=false should share the commonDecryptKey array
    ClientCHK k1 = keys.getKey(0, /*ignore*/ null, /*copy*/ false);
    assertSame(common, k1.getCryptoKey());

    // copy=true should clone the commonDecryptKey array
    ClientCHK k2 = keys.getKey(0, null, true);
    assertNotSame(common, k2.getCryptoKey());
    assertArrayEquals(common, k2.getCryptoKey());

    // Ignore mask prevents key retrieval
    boolean[] ignore = new boolean[] {true};
    assertNull(keys.getKey(0, ignore, false));
  }

  @Test
  void getNodeKey_algorithmDerivedFromExtra_ignoresCopyFlag() throws Exception {
    int data = 2;
    int check = 0;
    byte algo = Key.ALGO_AES_CTR_256_SHA256;
    byte[] common = ck(9);
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(data, check, common, algo);
    keys.setKey(0, newClientKey(rk(1), ck(2), algo));
    keys.setKey(1, newClientKey(rk(2), ck(3), algo));

    NodeCHK n1 = keys.getNodeKey(0, null, false);
    NodeCHK n2 = keys.getNodeKey(0, null, true);
    assertNotNull(n1);
    assertNotNull(n2);
    assertArrayEquals(n1.getFullKey(), n2.getFullKey());
    byte parsedAlgo = NodeCHK.cryptoAlgorithmFromFullKey(n1.getFullKey());
    assertEquals(algo, parsedAlgo);

    boolean[] ignore = new boolean[] {true, false};
    assertNull(keys.getNodeKey(0, ignore, false));
  }

  @Test
  void listNodeKeys_honorsFoundMask_andReturnsAllOthers() throws Exception {
    int data = 2;
    int check = 1;
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    byte[] common = ck(3);
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(data, check, common, algo);
    for (int i = 0; i < data + check; i++) {
      keys.setKey(i, newClientKey(rk(50 + i), ck(60 + i), algo));
    }

    boolean[] found = new boolean[] {false, true, false};
    NodeCHK[] listed = keys.listNodeKeys(found, /*copy*/ true);
    assertEquals(2, listed.length);
    assertTrue(
        Arrays.equals(listed[0].getFullKey(), new NodeCHK(rk(50), algo).getFullKey())
            || Arrays.equals(listed[1].getFullKey(), new NodeCHK(rk(50), algo).getFullKey()));
  }

  @Test
  void getKey_withInvalidAlgorithm_throwsIllegalStateException() throws Exception {
    int data = 1;
    int check = 0;
    byte invalidAlgo = (byte) 42; // not one of the supported constants
    byte[] common = ck(7);
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(data, check, common, invalidAlgo);
    keys.setKey(0, newClientKey(rk(7), ck(8), Key.ALGO_AES_PCFB_256_SHA256));
    assertThrows(IllegalStateException.class, () -> keys.getKey(0, null, false));
  }

  @Test
  void readKeys_withoutCommonKey_invalidExtra_throwsIOException() throws Exception {
    int data = 1;
    int check = 0;
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    SplitFileSegmentKeys keys = new SplitFileSegmentKeys(data, check, null, algo);
    keys.setKey(0, newClientKey(rk(9), ck(10), algo));

    // Serialize keys, corrupt the first block's extra[1] (algorithm) byte, then read back.
    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    DataOutputStream dos = new DataOutputStream(bos);
    keys.writeKeys(dos, /*check*/ false);
    dos.close();
    byte[] buf = bos.toByteArray();
    // Layout without common key per block: EXTRA[5] + ROUTING[32] + CRYPTO[32]
    buf[1] = (byte) 99; // invalidate algorithm

    SplitFileSegmentKeys corrupted = new SplitFileSegmentKeys(data, check, null, algo);
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(buf));
    assertThrows(java.io.IOException.class, () -> corrupted.readKeys(dis, /*check*/ false));
  }
}
