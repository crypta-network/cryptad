package network.crypta.keys;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.util.Arrays;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // Test method naming convention per project rules
class ClientSSKTest {

  private static final byte[] BYTES_32_A;
  private static final byte[] BYTES_32_B;

  static {
    BYTES_32_A = new byte[32];
    BYTES_32_B = new byte[32];
    for (int i = 0; i < 32; i++) {
      BYTES_32_A[i] = (byte) i; // 0..31
      BYTES_32_B[i] = (byte) (255 - i); // 255..224
    }
  }

  // Helper removed to avoid constant-parameter smell; use ClientSSK.getExtraBytes directly.

  @Test
  void getExtraBytes_whenAlgoAES256_expectFiveByteHeader() {
    byte[] extra = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    assertEquals(5, extra.length, "SSK extras must be 5 bytes");
    assertArrayEquals(new byte[] {NodeSSK.SSK_VERSION, 0, 2, 0, KeyBlock.HASH_SHA256}, extra);
  }

  @Test
  void constructor_whenNullDocName_expectMalformedURLException() {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    assertThrows(
        MalformedURLException.class,
        () -> new ClientSSK(null, BYTES_32_A, extras, null, BYTES_32_B));
  }

  @Test
  void constructor_whenExtrasNull_expectMalformedURLException() {
    assertThrows(
        MalformedURLException.class,
        () -> new ClientSSK("index.html", BYTES_32_A, null, null, BYTES_32_B));
  }

  @Test
  void constructor_whenExtrasTooShort_expectMalformedURLException() {
    byte[] extras = new byte[] {1, 2, 3, 4};
    MalformedURLException ex =
        assertThrows(
            MalformedURLException.class,
            () -> new ClientSSK("index.html", BYTES_32_A, extras, null, BYTES_32_B));
    assertTrue(ex.getMessage().startsWith("Extra bytes too short"));
  }

  @Test
  void constructor_whenUnknownAlgorithm_expectMalformedURLException() {
    // Build an extras header with unsupported algorithm (3)
    byte[] extras = new byte[] {NodeSSK.SSK_VERSION, 0, Key.ALGO_AES_CTR_256_SHA256, 0, 1};
    MalformedURLException ex =
        assertThrows(
            MalformedURLException.class,
            () -> new ClientSSK("index.html", BYTES_32_A, extras, null, BYTES_32_B));
    assertTrue(ex.getMessage().contains("Unknown encryption algorithm"));
  }

  @Test
  void constructor_whenWrongExtrasBytes_expectMalformedURLException() {
    // Correct algo but wrong hash algorithm low byte -> should trip "Wrong extra bytes"
    byte[] extras = new byte[] {NodeSSK.SSK_VERSION, 0, Key.ALGO_AES_PCFB_256_SHA256, 0, 2};
    MalformedURLException ex =
        assertThrows(
            MalformedURLException.class,
            () -> new ClientSSK("index.html", BYTES_32_A, extras, null, BYTES_32_B));
    assertEquals("Wrong extra bytes", ex.getMessage());
  }

  @Test
  void constructor_whenPubKeyHashWrongLength_expectMalformedURLException() {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    byte[] badHash = Arrays.copyOf(BYTES_32_A, 31);
    MalformedURLException ex =
        assertThrows(
            MalformedURLException.class,
            () -> new ClientSSK("index.html", badHash, extras, null, BYTES_32_B));
    assertTrue(ex.getMessage().startsWith("Pubkey hash wrong length"));
  }

  @Test
  void constructor_whenCryptoKeyWrongLength_expectMalformedURLException() {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    byte[] badKey = Arrays.copyOf(BYTES_32_B, 31);
    MalformedURLException ex =
        assertThrows(
            MalformedURLException.class,
            () -> new ClientSSK("index.html", BYTES_32_A, extras, null, badKey));
    assertTrue(ex.getMessage().startsWith("Decryption key wrong length"));
  }

  @Test
  void constructor_whenPubKeyProvidedButHashMismatch_expectIllegalArgumentException() {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    // Build a real public key whose hash will not match BYTES_32_A
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(2));
    IllegalArgumentException ex =
        assertThrows(
            IllegalArgumentException.class,
            () -> new ClientSSK("index.html", BYTES_32_A, extras, pub, BYTES_32_B));
    assertNull(ex.getMessage()); // Message not specified; just ensure the type
  }

  @Test
  void constructor_whenHappyPathWithNullPubKey_expectFieldsInitializedAndURIConsistent()
      throws Exception {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    String doc = "index.html";
    ClientSSK ssk = new ClientSSK(doc, BYTES_32_A, extras, null, BYTES_32_B);

    // Basic fields
    assertEquals(Key.ALGO_AES_PCFB_256_SHA256, ssk.cryptoAlgorithm);
    assertEquals(doc, ssk.docName);
    assertNull(ssk.getPubKey());
    assertArrayEquals(BYTES_32_A, ssk.pubKeyHash);
    assertArrayEquals(BYTES_32_B, ssk.cryptoKey);
    assertNotNull(ssk.ehDocname);
    assertEquals(32, ssk.ehDocname.length);

    // URI round-trip
    FreenetURI uri = ssk.getURI();
    assertEquals("SSK", uri.getKeyType());
    assertEquals(doc, uri.getDocName());
    assertArrayEquals(BYTES_32_A, uri.getRoutingKey());
    assertArrayEquals(BYTES_32_B, uri.getCryptoKey());
    assertArrayEquals(extras, uri.getExtra());

    // toString must contain the URI and a prefix
    String ts = ssk.toString();
    assertTrue(ts.startsWith("ClientSSK:"));
    assertTrue(ts.contains("SSK@"));
  }

  @Test
  void constructor_whenHappyPathWithPubKey_expectNodeKeyHasPubKey() throws Exception {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(7));
    byte[] pubHash = pub.asBytesHash();
    ClientSSK ssk = new ClientSSK("doc", pubHash, extras, pub, BYTES_32_B);

    Key nodeKey = ssk.getNodeKey(false);
    assertInstanceOf(NodeSSK.class, nodeKey);
    assertTrue(((NodeSSK) nodeKey).hasPubKey());
    assertEquals(((NodeSSK) nodeKey).getPubKey(), pub);
    assertArrayEquals(pubHash, ((NodeSSK) nodeKey).getPubKeyHash());
  }

  @Test
  void constructor_fromFreenetURI_whenSSK_expectSuccess() throws Exception {
    String doc = "page.txt";
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    FreenetURI uri = new FreenetURI("SSK", doc, BYTES_32_A, BYTES_32_B, extras);
    ClientSSK ssk = new ClientSSK(uri);

    assertEquals(doc, ssk.docName);
    assertArrayEquals(BYTES_32_A, ssk.pubKeyHash);
    assertArrayEquals(BYTES_32_B, ssk.cryptoKey);
    assertEquals("SSK", ssk.getURI().getKeyType());
  }

  @Test
  void constructor_fromFreenetURI_whenNotSSK_expectMalformedURLException() {
    String doc = "page.txt";
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    // Build a CHK-shaped URI that still carries extras + keys so the delegated constructor works
    FreenetURI notSSK = new FreenetURI("CHK", doc, BYTES_32_A, BYTES_32_B, extras);
    assertThrows(MalformedURLException.class, () -> new ClientSSK(notSSK));
  }

  @Test
  void setPublicKey_whenHashesMismatch_expectIllegalArgumentException() throws Exception {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    ClientSSK ssk = new ClientSSK("doc", BYTES_32_A, extras, null, BYTES_32_B);
    DSAPublicKey wrong = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(5));

    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> ssk.setPublicKey(wrong));
    assertTrue(ex.getMessage().startsWith("New pubKey hash does not match"));
  }

  @Test
  void setPublicKey_whenFirstAssignmentMatchesHash_expectSuccessAndNodeKeyRebuilt()
      throws Exception {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(11));
    // Align the SSK to the pubkey's hash
    ClientSSK aligned = new ClientSSK("doc", pub.asBytesHash(), extras, null, BYTES_32_B);

    // Now set the pubkey on the aligned instance
    Key beforeAligned = aligned.getNodeKey(false);
    aligned.setPublicKey(pub);
    Key afterAligned = aligned.getNodeKey(false);

    assertNotSame(beforeAligned, afterAligned, "Cache must be invalidated when setting pubKey");
    assertTrue(((NodeSSK) afterAligned).hasPubKey());
  }

  @Test
  void setPublicKey_whenAlreadySetToDifferentKey_expectIllegalArgumentException() throws Exception {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    DSAPublicKey pub1 = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(13));
    ClientSSK ssk = new ClientSSK("doc", pub1.asBytesHash(), extras, pub1, BYTES_32_B);

    DSAPublicKey pub2 = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(17));
    IllegalArgumentException ex =
        assertThrows(IllegalArgumentException.class, () -> ssk.setPublicKey(pub2));
    assertTrue(ex.getMessage().startsWith("Cannot reassign: was "));
  }

  @Test
  void getNodeKey_whenCloneFlag_expectCloneOrSameInstance() throws Exception {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    ClientSSK ssk = new ClientSSK("doc", BYTES_32_A, extras, null, BYTES_32_B);

    Key a = ssk.getNodeKey(false);
    Key b = ssk.getNodeKey(false);
    assertSame(a, b, "Cached NodeSSK should be reused when cloneKey=false");

    Key c = ssk.getNodeKey(true);
    assertNotSame(a, c, "cloneKey=true should return a different instance");
    assertEquals(a, c, "Cloned NodeSSK must be value-equal");
  }

  @Test
  void equalsAndHashCode_whenIdenticalFields_expectEqual() throws Exception {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    ClientSSK s1 = new ClientSSK("doc", BYTES_32_A, extras, null, BYTES_32_B);
    ClientSSK s2 = new ClientSSK("doc", BYTES_32_A, extras, null, BYTES_32_B);

    assertEquals(s1, s2);
    assertEquals(s1.hashCode(), s2.hashCode());
    assertEquals(s1, s1.cloneKey());
  }

  @Test
  @DisplayName("equals(): different field should break equality")
  void equals_whenDifferentFields_expectNotEqual() throws Exception {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    ClientSSK base = new ClientSSK("doc", BYTES_32_A, extras, null, BYTES_32_B);

    ClientSSK diffDoc = new ClientSSK("other", BYTES_32_A, extras, null, BYTES_32_B);
    // Different pubKeyHash
    ClientSSK diffHash = new ClientSSK("doc", BYTES_32_B, extras, null, BYTES_32_B);
    // Different cryptoKey
    byte[] otherCrypto = Arrays.copyOf(BYTES_32_B, 32);
    otherCrypto[0] ^= 0x01; // ensure different content deterministically
    ClientSSK diffKey = new ClientSSK("doc", BYTES_32_A, extras, null, otherCrypto);

    assertNotEquals(base, diffDoc);
    assertNotEquals(base, diffHash);
    assertNotEquals(base, diffKey);
  }
}
