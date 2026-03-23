package network.crypta.keys;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.crypt.SHA256;
import network.crypta.store.BlockMetadata;
import network.crypta.store.GetPubkey;
import network.crypta.support.HexUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@SuppressWarnings("java:S100") // Test naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class NodeSSKTest {

  private static byte[] bytes(int len, int seed) {
    byte[] b = new byte[len];
    for (int i = 0; i < b.length; i++) b[i] = (byte) (seed + i);
    return b;
  }

  private static byte[] sha256(byte[] in) {
    return SHA256.getMessageDigest().digest(in);
  }

  @Test
  void constructor_whenLengthsInvalid_throwsIAE() {
    byte[] ehTooShort = new byte[NodeSSK.E_H_DOCNAME_SIZE - 1];
    byte[] ehTooLong = new byte[NodeSSK.E_H_DOCNAME_SIZE + 1];
    byte[] pkh = new byte[NodeSSK.PUBKEY_HASH_SIZE];

    assertThrows(IllegalArgumentException.class, () -> new NodeSSK(pkh, ehTooShort, (byte) 2));
    assertThrows(IllegalArgumentException.class, () -> new NodeSSK(pkh, ehTooLong, (byte) 2));

    byte[] eh = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    byte[] pkhTooShort = new byte[NodeSSK.PUBKEY_HASH_SIZE - 1];
    byte[] pkhTooLong = new byte[NodeSSK.PUBKEY_HASH_SIZE + 1];
    assertThrows(IllegalArgumentException.class, () -> new NodeSSK(pkhTooShort, eh, (byte) 2));
    assertThrows(IllegalArgumentException.class, () -> new NodeSSK(pkhTooLong, eh, (byte) 2));
  }

  @Test
  void constructor_withPubKey_whenHashDoesNotMatch_throwsSSKVerifyException(
      @Mock DSAPublicKey pub) {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x11);
    byte[] wrongHash = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x22);
    // Make pub.asBytes() deterministic but not matching wrongHash digest
    doReturn("pubkey-material".getBytes(StandardCharsets.US_ASCII)).when(pub).asBytes();
    assertThrows(SSKVerifyException.class, () -> new NodeSSK(wrongHash, eh, pub, (byte) 2));
  }

  @Test
  void constructor_withPubKey_whenHashMatches_succeedsAndStoresKey(@Mock DSAPublicKey pub)
      throws SSKVerifyException {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x33);
    byte[] pubBytes = "fixed-pubkey".getBytes(StandardCharsets.US_ASCII);
    byte[] pkh = sha256(pubBytes);
    doReturn(pubBytes).when(pub).asBytes();

    NodeSSK key = new NodeSSK(pkh, eh, pub, Key.ALGO_AES_PCFB_256_SHA256);
    assertTrue(key.hasPubKey());
    assertEquals(pub, key.getPubKey());
  }

  @Test
  void toString_containsHexOfPubkeyHashAndEncryptedDocname() {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x2A);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x55);
    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);

    String s = key.toString();
    assertTrue(s.contains("pkh=" + HexUtil.bytesToHex(pkh)));
    assertTrue(s.contains("ehd=" + HexUtil.bytesToHex(eh)));
  }

  @Test
  void getType_and_getFullKey_encodeHeaderAndPayload() {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x01);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x02);
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    NodeSSK key = new NodeSSK(pkh, eh, algo);

    short type = key.getType();
    assertEquals(NodeSSK.BASE_TYPE, (byte) (type >> 8));
    assertEquals((short) (algo & 0xFF), (short) (type & 0xFF));

    byte[] full = key.getFullKey();
    assertEquals(NodeSSK.FULL_KEY_LENGTH, full.length);
    assertEquals(NodeSSK.BASE_TYPE, full[0]);
    assertEquals(algo, full[1]);
    assertArrayEquals(eh, Arrays.copyOfRange(full, 2, 2 + NodeSSK.E_H_DOCNAME_SIZE));
    assertArrayEquals(
        pkh, Arrays.copyOfRange(full, 2 + NodeSSK.E_H_DOCNAME_SIZE, NodeSSK.FULL_KEY_LENGTH));
  }

  @Test
  void write_and_writeToDataOutputStream_followFullKeyFormat() throws IOException {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x10);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x20);
    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    byte[] expected = key.getFullKey();

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      key.writeToDataOutputStream(dos);
    }
    assertArrayEquals(expected, baos.toByteArray());
  }

  @Test
  void readSSK_whenExactPayload_readsKey() throws IOException {
    byte algo = Key.ALGO_AES_PCFB_256_SHA256;
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x05);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x06);

    // Binary payload for readSSK(): E(H(docname)) + pubKeyHash (no 2-byte header)
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DataOutputStream dos = new DataOutputStream(baos)) {
      dos.write(eh);
      dos.write(pkh);
    }
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(baos.toByteArray()));

    Key parsed = NodeSSK.readSSK(dis, algo);
    assertInstanceOf(NodeSSK.class, parsed);
    NodeSSK ssk = (NodeSSK) parsed;
    assertArrayEquals(eh, ssk.getKeyBytes());
    assertArrayEquals(pkh, ssk.getPubKeyHash());
    assertEquals(algo, (byte) (ssk.getType() & 0xFF));
  }

  @Test
  void read_whenFullKeyBuffer_dispatchesToNodeSSK() throws IOException {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x31);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x41);
    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    byte[] serialized = key.getFullKey();

    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(serialized));
    Key parsed = Key.read(dis);
    assertInstanceOf(NodeSSK.class, parsed);
    assertEquals(key.getType(), parsed.getType());
    assertArrayEquals(key.getFullKey(), parsed.getFullKey());
  }

  @Test
  void readSSK_whenTruncated_throwsEOFException() {
    // Need 64 bytes payload; provide fewer
    byte[] truncated = new byte[NodeSSK.E_H_DOCNAME_SIZE + NodeSSK.PUBKEY_HASH_SIZE - 1];
    DataInputStream dis = new DataInputStream(new ByteArrayInputStream(truncated));
    assertThrows(EOFException.class, () -> NodeSSK.readSSK(dis, Key.ALGO_AES_PCFB_256_SHA256));
  }

  @Test
  void construct_whenValidHeader_buildsKey() throws SSKVerifyException {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x60);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x61);
    NodeSSK original = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    NodeSSK parsed = NodeSSK.construct(original.getFullKey());
    assertArrayEquals(original.getFullKey(), parsed.getFullKey());
  }

  @Test
  void construct_whenWrongType_throwsSSKVerifyException() {
    byte[] buf = new byte[NodeSSK.FULL_KEY_LENGTH];
    buf[0] = 7; // not SSK BASE_TYPE
    buf[1] = Key.ALGO_AES_PCFB_256_SHA256;
    assertThrows(SSKVerifyException.class, () -> NodeSSK.construct(buf));
  }

  @Test
  void construct_whenUnknownAlgorithm_throwsSSKVerifyException() {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x10);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x11);
    NodeSSK key = new NodeSSK(pkh, eh, (byte) 99);
    byte[] full = key.getFullKey();
    // Make the header look like SSK but with unsupported algo
    full[0] = NodeSSK.BASE_TYPE;
    full[1] = Key.ALGO_AES_CTR_256_SHA256; // not accepted by construct()
    assertThrows(SSKVerifyException.class, () -> NodeSSK.construct(full));
  }

  @Test
  void hasPubKey_getPubKey_and_setPubKey_happyPath() throws SSKVerifyException {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x70);
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(7L));
    byte[] pubBytes = pub.asBytes();
    byte[] pkh = sha256(pubBytes);

    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    assertFalse(key.hasPubKey());

    key.setPubKey(pub);
    assertTrue(key.hasPubKey());
    assertEquals(pub, key.getPubKey());

    // Idempotent: setting the same instance is a no-op
    key.setPubKey(pub);
    assertEquals(pub, key.getPubKey());
  }

  @Test
  void setPubKey_whenHashMismatch_throwsSSKVerifyException() {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x42);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x43); // not equal to SHA256(pub.asBytes())
    DSAPublicKey pub = org.mockito.Mockito.mock(DSAPublicKey.class);
    doReturn("other".getBytes(StandardCharsets.US_ASCII)).when(pub).asBytes();

    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    assertThrows(SSKVerifyException.class, () -> key.setPubKey(pub));
  }

  @Test
  void setPubKey_whenAlreadySetAndNewHasSameHash_throwsCollisionError() throws SSKVerifyException {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x13);
    byte[] pubBytes = "same-hash".getBytes(StandardCharsets.US_ASCII);
    byte[] pkh = sha256(pubBytes);

    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    DSAPublicKey first = org.mockito.Mockito.mock(DSAPublicKey.class);
    DSAPublicKey second = org.mockito.Mockito.mock(DSAPublicKey.class);
    doReturn(pubBytes).when(first).asBytes();
    doReturn(pubBytes).when(second).asBytes();

    key.setPubKey(first);
    assertThrows(SSKVerifyException.class, () -> key.setPubKey(second));
  }

  @Test
  void setPubKey_whenNullProvided_isNoOp() throws SSKVerifyException {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x21);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x22);
    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    key.setPubKey(null);
    assertFalse(key.hasPubKey());
  }

  @Test
  void equals_and_hashCode_whenComponentsMatch_areEqual() {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x7A);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x7B);
    NodeSSK a = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    NodeSSK b =
        new NodeSSK(
            Arrays.copyOf(pkh, pkh.length), Arrays.copyOf(eh, eh.length), a.cryptoAlgorithm);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  void equals_whenDifferentDocnameOrHash_returnsFalse() {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x7C);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x7D);
    NodeSSK base = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);

    byte[] eh2 = Arrays.copyOf(eh, eh.length);
    eh2[0] ^= (byte) 0xFF;
    NodeSSK diffEhd = new NodeSSK(pkh, eh2, Key.ALGO_AES_PCFB_256_SHA256);

    byte[] pkh2 = Arrays.copyOf(pkh, pkh.length);
    pkh2[0] ^= (byte) 0x7F;
    NodeSSK diffPkh = new NodeSSK(pkh2, eh, Key.ALGO_AES_PCFB_256_SHA256);

    assertNotEquals(diffEhd, base);
    assertNotEquals(diffPkh, base);
    assertNotEquals(new Object(), base);
  }

  @Test
  void compareTo_whenComparedWithNodeCHK_returnsMinusOne() {
    NodeSSK ssk =
        new NodeSSK(
            bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x01),
            bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x02),
            Key.ALGO_AES_PCFB_256_SHA256);
    NodeCHK chk = new NodeCHK(bytes(NodeCHK.KEY_LENGTH, 0x03), Key.ALGO_AES_PCFB_256_SHA256);
    assertEquals(-1, ssk.compareTo(chk));
  }

  @Test
  void compareTo_ordersByEncryptedDocnameThenPubkeyHash() {
    byte[] ehA = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x00);
    byte[] ehB = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x00);
    ehA[0] = 0x00;
    ehB[0] = 0x01; // greater
    byte[] pkhA = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x10);
    byte[] pkhB = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x20);

    NodeSSK a = new NodeSSK(pkhA, ehA, Key.ALGO_AES_PCFB_256_SHA256);
    NodeSSK b = new NodeSSK(pkhB, ehB, Key.ALGO_AES_PCFB_256_SHA256);
    assertTrue(a.compareTo(b) < 0);
    assertTrue(b.compareTo(a) > 0);

    // Now equal ehd; ordered by pubkey hash
    NodeSSK c = new NodeSSK(pkhA, ehA, Key.ALGO_AES_PCFB_256_SHA256);
    NodeSSK d = new NodeSSK(pkhB, ehA, Key.ALGO_AES_PCFB_256_SHA256);
    assertTrue(c.compareTo(d) < 0);
  }

  @Test
  void routingKeyFromFullKey_whenLengthMismatch_logsButComputesDeterministically() {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x40);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x41);
    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    byte[] full = key.getFullKey();

    // Truncate to simulate the wrong length; Arrays.copyOfRange pads with zeros
    byte[] truncated = Arrays.copyOf(full, full.length - 3);
    byte[] rk = NodeSSK.routingKeyFromFullKey(truncated);

    // Expected routing key is SHA256( E(H(docname)) || pubKeyHash ) regardless of header
    MessageDigest md = SHA256.getMessageDigest();
    md.update(Arrays.copyOfRange(truncated, 2, 2 + NodeSSK.E_H_DOCNAME_SIZE));
    md.update(
        Arrays.copyOfRange(
            truncated,
            2 + NodeSSK.E_H_DOCNAME_SIZE,
            2 + NodeSSK.E_H_DOCNAME_SIZE + NodeSSK.PUBKEY_HASH_SIZE));
    byte[] expected = md.digest();
    assertArrayEquals(expected, rk);
  }

  @Test
  void archivalCopy_returnsArchiveNodeSSK_andIsIndependent() {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x50);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x51);
    NodeSSK original = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);

    Key archived = original.archivalCopy();
    assertInstanceOf(NodeSSK.class, archived);
    assertNotNull(archived);
    assertArrayEquals(original.getFullKey(), archived.getFullKey());
    // setPubKey/grabPubkey are disabled on ArchiveNodeSSK
    assertThrows(UnsupportedOperationException.class, () -> ((NodeSSK) archived).setPubKey(null));
  }

  @Test
  void archivalCopy_whenGrabPubkeyCalled_throwsUnsupportedOperationException(
      @Mock GetPubkey<DSAPublicKey> cache) {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x52);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x53);
    NodeSSK archived = (NodeSSK) new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256).archivalCopy();
    BlockMetadata meta = new BlockMetadata();

    assertThrows(
        UnsupportedOperationException.class, () -> archived.grabPubkey(cache, true, true, meta));
  }

  @Test
  void grabPubkey_whenCacheHasKey_setsAndReturnsTrue(
      @Mock GetPubkey<DSAPublicKey> cache, @Mock DSAPublicKey pub) {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x71);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x72);
    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    BlockMetadata meta = new BlockMetadata();

    doReturn(pub).when(cache).getKey(pkh, true, false, meta);
    boolean grabbed = key.grabPubkey(cache, true, false, meta);

    assertTrue(grabbed);
    assertEquals(pub, key.getPubKey());
    verify(cache).getKey(pkh, true, false, meta);
  }

  @Test
  void grabPubkey_whenCacheMiss_returnsFalseAndKeepsNull(@Mock GetPubkey<DSAPublicKey> cache) {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x74);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x75);
    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);

    doReturn(null).when(cache).getKey(pkh, false, true, null);
    boolean grabbed = key.grabPubkey(cache, false, true, null);
    assertFalse(grabbed);
    assertFalse(key.hasPubKey());
  }

  @Test
  void grabPubkey_whenAlreadyHasKey_doesNotCallCache(
      @Mock GetPubkey<DSAPublicKey> cache, @Mock DSAPublicKey pub) throws SSKVerifyException {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x76);
    byte[] pubBytes = "grabbed".getBytes(StandardCharsets.US_ASCII);
    byte[] pkh = sha256(pubBytes);
    doReturn(pubBytes).when(pub).asBytes();
    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    key.setPubKey(pub);

    BlockMetadata meta = new BlockMetadata();
    boolean grabbed = key.grabPubkey(cache, true, true, meta);
    assertFalse(grabbed);
    // Ensure cache.getKey() was not called at all (any args)
    verify(cache, never())
        .getKey(any(byte[].class), anyBoolean(), anyBoolean(), any(BlockMetadata.class));
  }

  @Test
  void getKeyBytes_returnsEncryptedHashedDocname() {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x0A);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x0B);
    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    assertArrayEquals(eh, key.getKeyBytes());
  }

  @ParameterizedTest
  @ValueSource(booleans = {true, false})
  void routingKeyFromFullKey_roundTripMatchesInstance(boolean modifyHeader) {
    byte[] eh = bytes(NodeSSK.E_H_DOCNAME_SIZE, 0x19);
    byte[] pkh = bytes(NodeSSK.PUBKEY_HASH_SIZE, 0x1A);
    NodeSSK key = new NodeSSK(pkh, eh, Key.ALGO_AES_PCFB_256_SHA256);
    byte[] full = key.getFullKey();
    if (modifyHeader) {
      // Change algo byte; method ignores header and hashes payload parts only
      full[1] = (byte) (full[1] ^ 0x7F);
    }
    byte[] rk = NodeSSK.routingKeyFromFullKey(full);

    // Compute expected: SHA256(ehd || pkh)
    MessageDigest md = SHA256.getMessageDigest();
    md.update(Arrays.copyOfRange(full, 2, 2 + NodeSSK.E_H_DOCNAME_SIZE));
    md.update(Arrays.copyOfRange(full, 2 + NodeSSK.E_H_DOCNAME_SIZE, NodeSSK.FULL_KEY_LENGTH));
    byte[] expected = md.digest();
    assertArrayEquals(expected, rk);
  }

  @Test
  void constructor_whenNullArguments_throwNPE() {
    byte[] eh = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    byte[] pkh = new byte[NodeSSK.PUBKEY_HASH_SIZE];
    assertThrows(NullPointerException.class, () -> new NodeSSK(null, eh, (byte) 2));
    assertThrows(NullPointerException.class, () -> new NodeSSK(pkh, null, (byte) 2));
  }
}
