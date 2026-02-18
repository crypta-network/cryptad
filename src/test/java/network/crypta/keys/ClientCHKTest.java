package network.crypta.keys;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // test method naming convention: method_whenCondition_expectOutcome
class ClientCHKTest {

  private static byte[] bytes32(int start) {
    byte[] b = new byte[32];
    for (int i = 0; i < 32; i++) {
      b[i] = (byte) (start + i);
    }
    return b;
  }

  private static byte[] rk32() {
    return bytes32(0);
  }

  private static byte[] ck32() {
    return bytes32(32);
  }

  @Test
  void constants_haveExpectedValues() {
    assertEquals(5, ClientCHK.EXTRA_LENGTH);
    assertEquals(32, ClientCHK.CRYPTO_KEY_LENGTH);
    assertNotNull(ClientCHK.TEST_KEY);
  }

  @Test
  void constructor_components_whenValid_setsFields() {
    byte[] rk = rk32();
    byte[] ck = ck32();
    boolean control = true;
    byte algo = Key.ALGO_AES_CTR_256_SHA256;
    short compression = -1; // uncompressed

    ClientCHK key = new ClientCHK(rk, ck, control, algo, compression);

    assertSame(rk, key.getRoutingKey());
    assertSame(ck, key.getCryptoKey());
    assertEquals(algo, key.getCryptoAlgorithm());
    assertTrue(key.isMetadata());
    assertFalse(key.isCompressed());
  }

  @Test
  void constructor_components_whenRoutingKeyNull_throwsNpe() {
    byte[] ck = ck32();
    assertThrows(
        NullPointerException.class, () -> new ClientCHK(null, ck, false, (byte) 2, (short) -1));
  }

  @Test
  void constructor_components_whenEncKeyNull_throwsNpe() {
    byte[] rk = rk32();
    // NPE arises from Fields.hashCode(encKey) during construction
    assertThrows(
        NullPointerException.class, () -> new ClientCHK(rk, null, false, (byte) 2, (short) -1));
  }

  @Test
  void constructor_extra_whenValid_parsesFlagsAndAlgorithm() throws Exception {
    byte[] rk = rk32();
    byte[] ck = ck32();
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    short compression = 0; // compressed (codec id 0 for test)
    boolean control = true;
    byte[] extra = ClientCHK.getExtra(algo, compression, control);

    ClientCHK key = new ClientCHK(rk, ck, extra);

    assertEquals(algo, key.getCryptoAlgorithm());
    assertTrue(key.isMetadata());
    assertTrue(key.isCompressed());
    assertArrayEquals(rk, key.getRoutingKey());
    assertArrayEquals(ck, key.getCryptoKey());
  }

  @Test
  void constructor_extra_whenTooShort_throwsMalformedUrl() {
    byte[] rk = rk32();
    byte[] ck = ck32();
    byte[] extra = new byte[4];
    assertThrows(MalformedURLException.class, () -> new ClientCHK(rk, ck, extra));
  }

  @Test
  void constructor_extra_whenInvalidAlgorithm_throwsMalformedUrl() {
    byte[] rk = rk32();
    byte[] ck = ck32();
    byte[] extra = ClientCHK.getExtra((byte) 99, (short) -1, false);
    assertThrows(MalformedURLException.class, () -> new ClientCHK(rk, ck, extra));
  }

  @Test
  void constructor_uri_whenValid_buildsKey() throws Exception {
    byte[] rk = rk32();
    byte[] ck = ck32();
    byte algo = Key.ALGO_AES_CTR_256_SHA256;
    short compression = -1;
    boolean control = false;
    FreenetURI uri =
        new FreenetURI("CHK", null, rk, ck, ClientCHK.getExtra(algo, compression, control));

    ClientCHK key = new ClientCHK(uri);

    assertArrayEquals(rk, key.getRoutingKey());
    assertArrayEquals(ck, key.getCryptoKey());
    assertEquals(algo, key.getCryptoAlgorithm());
    assertFalse(key.isMetadata());
    assertFalse(key.isCompressed());
  }

  @Test
  void constructor_uri_whenWrongType_throwsMalformedUrl() {
    byte[] rk = rk32();
    byte[] ck = ck32();
    FreenetURI ssk =
        new FreenetURI("SSK", "doc", rk, ck, ClientCHK.getExtra((byte) 2, (short) -1, false));
    assertThrows(MalformedURLException.class, () -> new ClientCHK(ssk));
  }

  @Test
  void constructor_dataInputStream_whenValid_readsAll() throws Exception {
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    short compression = -1;
    boolean control = false;
    byte[] extra = ClientCHK.getExtra(algo, compression, control);
    byte[] rk = rk32();
    byte[] ck = ck32();

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.write(extra);
      dos.write(rk);
      dos.write(ck);
    }

    ClientCHK key;
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
      key = new ClientCHK(dis);
    }

    assertArrayEquals(rk, key.getRoutingKey());
    assertArrayEquals(ck, key.getCryptoKey());
    assertEquals(algo, key.getCryptoAlgorithm());
  }

  @Test
  void constructor_dataInputStream_whenInvalidAlgorithm_throwsMalformedUrl() throws IOException {
    byte[] extra = ClientCHK.getExtra((byte) 99, (short) -1, false);
    byte[] rk = rk32();
    byte[] ck = ck32();

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(bos)) {
      dos.write(extra);
      dos.write(rk);
      dos.write(ck);
    }

    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(bos.toByteArray()))) {
      assertThrows(MalformedURLException.class, () -> new ClientCHK(dis));
    }
  }

  @Test
  void writeRawBinaryKey_whenRoundTripped_matchesOriginal() throws Exception {
    ClientCHK original =
        new ClientCHK(rk32(), ck32(), false, Key.ALGO_AES_CTR_256_SHA256, (short) -1);

    byte[] serialized;
    try (ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(bos)) {
      original.writeRawBinaryKey(dos);
      serialized = bos.toByteArray();
    }

    ClientCHK restored;
    try (DataInputStream dis = new DataInputStream(new ByteArrayInputStream(serialized))) {
      restored = ClientCHK.readRawBinaryKey(dis);
    }

    assertEquals(original, restored);
    assertEquals(original.hashCode(), restored.hashCode());
  }

  @Test
  void getExtra_staticAndInstance_agreeAndEncodeFlags() throws Exception {
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    short compression = (short) -1;
    boolean control = true;
    byte[] extra = ClientCHK.getExtra(algo, compression, control);

    // Byte layout: [reserved/highbits, algo, flags, comp_hi, comp_lo]
    assertEquals(0, extra[0]);
    assertEquals(algo, extra[1]);
    assertEquals((byte) 0x02, extra[2]);
    assertEquals((byte) 0xFF, extra[3]);
    assertEquals((byte) 0xFF, extra[4]);

    ClientCHK key = new ClientCHK(rk32(), ck32(), extra);
    assertArrayEquals(extra, key.getExtra());
  }

  @Test
  void getCryptoAlgorithmFromExtra_whenCalled_returnsByte1() {
    byte[] extra = ClientCHK.getExtra(Key.ALGO_AES_CTR_256_SHA256, (short) 0, false);
    assertEquals(Key.ALGO_AES_CTR_256_SHA256, ClientCHK.getCryptoAlgorithmFromExtra(extra));
  }

  @Test
  void getNodeKey_whenCloneRequested_returnsDistinctButEqualNodeKey() {
    ClientCHK key = new ClientCHK(rk32(), ck32(), false, Key.ALGO_AES_CTR_256_SHA256, (short) -1);

    // Ensure lazy init and caching
    NodeCHK nk1 = key.getNodeCHK();
    NodeCHK nk2 = key.getNodeCHK();
    assertSame(nk1, nk2);

    // getNodeKey(false) returns the cached instance; true returns a clone
    assertSame(nk1, key.getNodeKey(false));
    Key cloned = key.getNodeKey(true);
    assertNotSame(nk1, cloned);
    assertEquals(nk1, cloned);
  }

  @Test
  void getURI_whenRoundTripped_constructsEqualKey() throws Exception {
    ClientCHK original =
        new ClientCHK(rk32(), ck32(), true, Key.ALGO_AES_PCFB_256_SHA256, (short) 0);
    FreenetURI uri = original.getURI();

    ClientCHK rebuilt = new ClientCHK(uri);
    assertEquals(original, rebuilt);
  }

  @Test
  void equalsAndHashCode_whenContentSame_areEqual() {
    byte[] rk = rk32();
    byte[] ck = ck32();
    short comp = (short) 7;
    byte algo = Key.ALGO_AES_CTR_256_SHA256;

    ClientCHK a =
        new ClientCHK(Arrays.copyOf(rk, rk.length), Arrays.copyOf(ck, ck.length), true, algo, comp);
    ClientCHK b =
        new ClientCHK(Arrays.copyOf(rk, rk.length), Arrays.copyOf(ck, ck.length), true, algo, comp);

    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void cloneKey_whenCalled_returnsDeepCopyOfArrays() {
    ClientCHK original =
        new ClientCHK(rk32(), ck32(), false, Key.ALGO_AES_CTR_256_SHA256, (short) -1);
    ClientCHK clone = original.cloneKey();

    assertEquals(original, clone);
    assertNotSame(original.getRoutingKey(), clone.getRoutingKey());
    assertNotSame(original.getCryptoKey(), clone.getCryptoKey());
  }
}
