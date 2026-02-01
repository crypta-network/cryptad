package network.crypta.keys;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import network.crypta.node.Node;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import network.crypta.support.io.ArrayBucketFactory;
import network.crypta.support.io.BucketTools;
import network.crypta.support.math.MersenneTwister;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100")
class ClientCHKBlockTest {

  @Test
  void testEncodeDecodeEmptyBlock() throws Exception {
    byte[] buf = new byte[0];
    checkBlock(buf, false);
    checkBlock(buf, true);
  }

  @Test
  void testEncodeDecodeFullBlock() throws Exception {
    byte[] fullBlock = new byte[CHKBlock.DATA_LENGTH];
    MersenneTwister random = new MersenneTwister(42);
    for (int i = 0; i < 10; i++) {
      random.nextBytes(fullBlock);
      checkBlock(fullBlock, false);
      checkBlock(fullBlock, true);
    }
  }

  @Test
  void testEncodeDecodeShortInteger() throws Exception {
    for (int i = 0; i < 100; i++) {
      String s = Integer.toString(i);
      checkBlock(s.getBytes(StandardCharsets.UTF_8), false);
      checkBlock(s.getBytes(StandardCharsets.UTF_8), true);
    }
  }

  @Test
  void testEncodeDecodeRandomLength() throws Exception {
    MersenneTwister random = new MersenneTwister(42);
    for (int i = 0; i < 10; i++) {
      byte[] buf = new byte[random.nextInt(CHKBlock.DATA_LENGTH + 1)];
      random.nextBytes(buf);
      checkBlock(buf, false);
      checkBlock(buf, true);
    }
  }

  @Test
  void testEncodeDecodeNearlyFullBlock() throws Exception {
    MersenneTwister random = new MersenneTwister(68);
    for (int i = 0; i < 10; i++) {
      byte[] buf = new byte[CHKBlock.DATA_LENGTH - i];
      random.nextBytes(buf);
      checkBlock(buf, false);
      checkBlock(buf, true);
    }
    for (int i = 0; i < 10; i++) {
      byte[] buf = new byte[CHKBlock.DATA_LENGTH - (1 << i)];
      random.nextBytes(buf);
      checkBlock(buf, false);
      checkBlock(buf, true);
    }
  }

  private void checkBlock(byte[] data, boolean newAlgo) throws Exception {
    byte cryptoAlgorithm = newAlgo ? Key.ALGO_AES_CTR_256_SHA256 : Key.ALGO_AES_PCFB_256_SHA256;
    byte[] copyOfData = new byte[data.length];
    System.arraycopy(data, 0, copyOfData, 0, data.length);
    ClientCHKBlock encodedBlock =
        ClientCHKBlock.encode(
            new BlockEncodeParams(
                new ArrayBucket(data), false, false, (short) -1, data.length, null),
            null,
            cryptoAlgorithm);
    // Not modified in-place.
    assertArrayEquals(copyOfData, data);
    ClientCHK key = encodedBlock.getClientKey();
    if (newAlgo) {
      // Check with no JCA.
      ClientCHKBlock otherEncodedBlock =
          ClientCHKBlock.encode(
              new BlockEncodeParams(
                  new ArrayBucket(data), false, false, (short) -1, data.length, null),
              null,
              cryptoAlgorithm,
              true);
      assertEquals(key, otherEncodedBlock.getClientKey());
      assertArrayEquals(otherEncodedBlock.getBlock().data, encodedBlock.getBlock().data);
      assertArrayEquals(otherEncodedBlock.getBlock().headers, encodedBlock.getBlock().headers);
    }
    // Verify it.
    CHKBlock block =
        CHKBlock.construct(
            encodedBlock.getBlock().data, encodedBlock.getBlock().headers, cryptoAlgorithm);
    ClientCHKBlock checkBlock = new ClientCHKBlock(block, key);
    try (Bucket checkData = checkBlock.decode(new ArrayBucketFactory(), data.length, false)) {
      assertArrayEquals(data, BucketTools.toByteArray(checkData));
    }
    if (newAlgo) {
      try (Bucket checkData =
          checkBlock.decode(new ArrayBucketFactory(), data.length, false, true)) {
        assertArrayEquals(data, BucketTools.toByteArray(checkData));
      }
    }
  }

  @Test
  void memoryDecode_whenCtrNoCompression_returnsOriginal() throws Exception {
    byte[] buf = "hello world".getBytes(StandardCharsets.UTF_8);
    ClientCHKBlock block =
        ClientCHKBlock.encode(
            buf, /* asMetadata= */ false, /* dontCompress= */ true, (short) -1, buf.length, null);
    byte[] decoded = block.memoryDecode();
    assertArrayEquals(buf, decoded);
  }

  @Test
  void decode_whenWrongKey_expectCHKDecodeException() throws Exception {
    byte[] data = "wrong-key test".getBytes(StandardCharsets.UTF_8);
    ClientCHKBlock good =
        ClientCHKBlock.encode(
            data, /* asMetadata= */ false, /* dontCompress= */ true, (short) -1, data.length, null);

    // Rebuild a block with the same bytes but a different client key (HMAC mismatch).
    ClientCHK correctKey = good.getClientKey();
    byte[] routing = correctKey.getRoutingKey();
    byte[] extra = correctKey.getExtra();
    byte[] wrongEnc = correctKey.getCryptoKey().clone();
    wrongEnc[0] ^= 0x7F; // flip bits deterministically
    ClientCHK wrongKey = new ClientCHK(routing, wrongEnc, extra);
    ClientCHKBlock forged = forgeBlock(good, wrongKey);

    assertThrows(
        CHKDecodeException.class,
        () -> {
          try (Bucket ignored =
              forged.decode(new ArrayBucketFactory(), data.length, /* dontCompress= */ false)) {
            // Touch the resource to avoid an empty try block warning.
            ignored.size();
          }
        });
  }

  @Test
  void decode_whenCryptoKeyTooShort_expectCHKDecodeException() throws Exception {
    byte[] data = "short-key test".getBytes(StandardCharsets.UTF_8);
    ClientCHKBlock good =
        ClientCHKBlock.encode(
            data, /* asMetadata= */ false, /* dontCompress= */ true, (short) -1, data.length, null);

    ClientCHK goodKey = good.getClientKey();
    byte[] routing = goodKey.getRoutingKey();
    byte[] extra = goodKey.getExtra();
    // Use a deterministic short key: length SYMMETRIC_KEY_LENGTH - 1
    byte[] shortKey = Arrays.copyOf(goodKey.getCryptoKey(), Node.SYMMETRIC_KEY_LENGTH - 1);
    ClientCHK shortClientKey = new ClientCHK(routing, shortKey, extra);

    ClientCHKBlock forged = forgeBlock(good, shortClientKey);

    CHKDecodeException ex =
        assertThrows(
            CHKDecodeException.class,
            () -> {
              try (Bucket ignored =
                  forged.decode(new ArrayBucketFactory(), data.length, /* dontCompress= */ false)) {
                // Touch the resource to avoid an empty try block warning.
                ignored.size();
              }
            });
    // Message is stable in implementation; assert for clarity.
    assertEquals("Crypto key too short", ex.getMessage());
  }

  @Test
  void equalsAndHashCode_whenSameContent_expectEqual() throws Exception {
    byte[] payload = "equality-check".getBytes(StandardCharsets.UTF_8);
    ClientCHKBlock a =
        ClientCHKBlock.encode(
            payload,
            /* asMetadata= */ false,
            /* dontCompress= */ true,
            (short) -1,
            payload.length,
            null);
    ClientCHKBlock b =
        ClientCHKBlock.encode(
            payload,
            /* asMetadata= */ false,
            /* dontCompress= */ true,
            (short) -1,
            payload.length,
            null);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());

    ClientCHKBlock different =
        ClientCHKBlock.encode(
            "different".getBytes(StandardCharsets.UTF_8),
            /* asMetadata= */ false,
            /* dontCompress= */ true,
            (short) -1,
            "different".length(),
            null);
    assertNotEquals(a, different);
  }

  @Test
  void getClientKey_and_isMetadata_exposeExpectedValues() throws Exception {
    byte[] payload = "meta".getBytes(StandardCharsets.UTF_8);
    ClientCHKBlock meta =
        ClientCHKBlock.encode(
            payload,
            /* asMetadata= */ true,
            /* dontCompress= */ true,
            (short) -1,
            payload.length,
            null);
    assertNotNull(meta.getClientKey());
    assertTrue(meta.isMetadata());

    ClientCHKBlock nonMeta =
        ClientCHKBlock.encode(
            payload,
            /* asMetadata= */ false,
            /* dontCompress= */ true,
            (short) -1,
            payload.length,
            null);
    assertFalse(nonMeta.isMetadata());
  }

  @Test
  void encodeNew_throwsOnWrongAlgorithm() {
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    byte[] encKey = new byte[Node.SYMMETRIC_KEY_LENGTH];
    MessageDigest md = network.crypta.crypt.SHA256.getMessageDigest();
    ClientCHKEncodeParams params =
        new ClientCHKEncodeParams(
            new ClientCHKEncodePayload(data, /* dataLength= */ 0, md, encKey),
            new ClientCHKEncodeAlgorithms(
                /* asMetadata= */ false,
                (short) -1,
                Key.ALGO_AES_PCFB_256_SHA256,
                KeyBlock.HASH_SHA256));
    assertThrows(IllegalArgumentException.class, () -> ClientCHKBlock.encodeNew(params));
  }

  @Test
  void innerEncode_doesNotModifyInputArray() {
    byte[] data = new byte[CHKBlock.DATA_LENGTH];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i & 0xFF);
    byte[] original = data.clone();
    MessageDigest md = network.crypta.crypt.SHA256.getMessageDigest();
    byte[] encKey = new byte[Node.SYMMETRIC_KEY_LENGTH];
    ClientCHKBlock.innerEncode(
        new ClientCHKEncodeParams(
            new ClientCHKEncodePayload(data, /* dataLength= */ 123, md, encKey),
            new ClientCHKEncodeAlgorithms(
                /* asMetadata= */ false,
                (short) -1,
                Key.ALGO_AES_PCFB_256_SHA256,
                KeyBlock.HASH_SHA256)));
    // Ensure the original input array was not mutated
    assertArrayEquals(original, data);
  }

  // Helpers
  private static ClientCHKBlock forgeBlock(ClientCHKBlock template, ClientCHK newClientKey)
      throws CHKVerifyException {
    return new ClientCHKBlock(
        template.getBlock().getData(),
        template.getBlock().getHeaders(),
        newClientKey,
        /* verify= */ false);
  }
}
