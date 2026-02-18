package network.crypta.keys;

import java.security.SecureRandom;
import java.util.Arrays;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.crypt.SHA256;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SuppressWarnings("java:S100")
class SSKBlockTest {

  private static final byte CRYPTO_ALGO = Key.ALGO_AES_PCFB_256_SHA256;

  private static NodeSSK newNodeSSK(DSAPublicKey pub, byte[] ehDocname) throws SSKVerifyException {
    byte[] pkHash = SHA256.digest(pub.asBytes());
    return new NodeSSK(pkHash, ehDocname, pub, CRYPTO_ALGO);
  }

  private static byte[] newData() {
    // Deterministic 1024 bytes.
    byte[] data = new byte[SSKBlock.DATA_LENGTH];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i & 0xFF);
    return data;
  }

  private static byte[] headersUnsignedPrefix(byte[] ehDocname) {
    return headersUnsignedPrefix(ehDocname, CRYPTO_ALGO);
  }

  private static byte[] headersUnsignedPrefix(byte[] ehDocname, short symCipher) {
    byte[] headers = new byte[SSKBlock.TOTAL_HEADERS_LENGTH];
    int x = 0;
    headers[x++] = 0; // HASH_SHA256 high byte
    headers[x++] = (byte) KeyBlock.HASH_SHA256; // low byte
    headers[x++] = (byte) (symCipher >> 8);
    headers[x++] = (byte) symCipher;
    System.arraycopy(ehDocname, 0, headers, x, SSKBlock.E_H_DOCNAME_LENGTH);
    x += SSKBlock.E_H_DOCNAME_LENGTH;
    for (int i = 0; i < SSKBlock.ENCRYPTED_HEADERS_LENGTH; i++) headers[x++] = (byte) (0xA0 + i);
    // Leave signature area zeroed for signing
    assertEquals(SSKBlock.TOTAL_HEADERS_LENGTH - 64, x);
    return headers;
  }

  private static void signHeaders(
      byte[] headers, byte[] data, DSAPrivateKey priv, boolean deterministic, byte[] randomSeed) {
    // Compute overallHash as SSKBlock does
    byte[] dataHash = SHA256.digest(data);
    int signedPrefixLen = 2 + 2 + SSKBlock.E_H_DOCNAME_LENGTH + SSKBlock.ENCRYPTED_HEADERS_LENGTH;
    // overallHash = SHA256(headers[0..prefix) || dataHash)
    byte[] tmp = new byte[signedPrefixLen + dataHash.length];
    System.arraycopy(headers, 0, tmp, 0, signedPrefixLen);
    System.arraycopy(dataHash, 0, tmp, signedPrefixLen, dataHash.length);
    byte[] overallHash = SHA256.digest(tmp);

    DSASigner dsa =
        deterministic ? new DSASigner(new HMacDSAKCalculator(new SHA256Digest())) : new DSASigner();
    DSAPrivateKeyParameters params =
        new DSAPrivateKeyParameters(priv.getX(), Global.getDSAgroupBigAParameters());
    if (deterministic) {
      dsa.init(true, params);
    } else {
      SecureRandom sr = new SecureRandom(randomSeed);
      dsa.init(true, new ParametersWithRandom(params, sr));
    }
    var sig = dsa.generateSignature(Global.truncateHash(overallHash));
    byte[] r = toFixed(sig[0].toByteArray(), SSKBlock.SIG_R_LENGTH);
    byte[] s = toFixed(sig[1].toByteArray(), SSKBlock.SIG_S_LENGTH);
    int x = signedPrefixLen;
    System.arraycopy(r, 0, headers, x, r.length);
    x += r.length;
    System.arraycopy(s, 0, headers, x, s.length);
  }

  private static byte[] toFixed(byte[] in, int len) {
    if (in.length == len) return in;
    if (in.length > len) {
      for (int i = 0; i < in.length - len; i++)
        if (in[i] != 0) throw new IllegalArgumentException("cannot truncate");
      return Arrays.copyOfRange(in, in.length - len, in.length);
    }
    byte[] out = new byte[len];
    System.arraycopy(in, 0, out, len - in.length, in.length);
    return out;
  }

  private static byte[] signedHeaders(
      byte[] ehDocname,
      short symCipher,
      byte[] data,
      DSAPrivateKey priv,
      boolean deterministic,
      byte[] seed) {
    byte[] headers = headersUnsignedPrefix(ehDocname, symCipher);
    signHeaders(headers, data, priv, deterministic, seed);
    return headers;
  }

  @Test
  @DisplayName("constructor_whenValidAndDontVerifyTrue_buildsBlock")
  void constructor_whenValidAndDontVerifyTrue_buildsBlock() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {9, 8, 7, 6}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x7B);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] data = newData();
    byte[] headers = signedHeaders(ehDocname, CRYPTO_ALGO, data, priv, true, null);

    SSKBlock block = new SSKBlock(data, headers, nodeKey, /* dontVerify= */ true);

    assertNotNull(block);
    assertArrayEquals(data, block.getRawData());
    assertArrayEquals(headers, block.getRawHeaders());
    assertArrayEquals(pub.asBytes(), block.getPubkeyBytes());
    assertArrayEquals(nodeKey.getFullKey(), block.getFullKey());
    assertArrayEquals(nodeKey.getRoutingKey(), block.getRoutingKey());
    assertEquals(nodeKey, block.getKey());
    assertEquals(pub, block.getPubKey());
  }

  @Test
  @DisplayName("constructor_whenHashIdentifierNotSHA256_throwsVerifyException")
  void constructor_whenHashIdentifierNotSHA256_throwsVerifyException() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {1, 1, 1, 1}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x11);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] data = newData();
    byte[] headers = headersUnsignedPrefix(ehDocname);
    // Corrupt hash identifier (bytes 0..1)
    headers[0] = 0;
    headers[1] = 2; // not HASH_SHA256

    assertThrows(SSKVerifyException.class, () -> new SSKBlock(data, headers, nodeKey, true));
  }

  @Test
  @DisplayName("constructor_whenEHDocnameMismatch_throwsVerifyException")
  void constructor_whenEHDocnameMismatch_throwsVerifyException() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {2, 2, 2, 2}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x22);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] data = newData();
    byte[] ehDocnameDifferent = ehDocname.clone();
    ehDocnameDifferent[0] ^= 0x01; // mismatch
    byte[] headers = signedHeaders(ehDocnameDifferent, CRYPTO_ALGO, data, priv, true, null);

    assertThrows(SSKVerifyException.class, () -> new SSKBlock(data, headers, nodeKey, false));
  }

  @Test
  @DisplayName("constructor_whenDataLengthWrong_throwsVerifyException")
  void constructor_whenDataLengthWrong_throwsVerifyException() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {3, 3, 3, 3}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x33);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] shortData = new byte[SSKBlock.DATA_LENGTH - 1];
    byte[] headers = signedHeaders(ehDocname, CRYPTO_ALGO, newData(), priv, true, null);

    assertThrows(SSKVerifyException.class, () -> new SSKBlock(shortData, headers, nodeKey, true));
  }

  @Test
  @DisplayName("constructor_whenHeadersLengthWrong_throwsIllegalArgument")
  void constructor_whenHeadersLengthWrong_throwsIllegalArgument() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {4, 4, 4, 4}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x44);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] data = newData();
    byte[] badHeaders =
        Arrays.copyOf(
            signedHeaders(ehDocname, CRYPTO_ALGO, data, priv, true, null),
            SSKBlock.TOTAL_HEADERS_LENGTH - 1);

    assertThrows(
        IllegalArgumentException.class, () -> new SSKBlock(data, badHeaders, nodeKey, true));
  }

  @Test
  @DisplayName("constructor_whenNodeKeyMissingPubkey_throwsVerifyException")
  void constructor_whenNodeKeyMissingPubkey_throwsVerifyException() {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {5, 5, 5, 5}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x55);
    // Create NodeSSK without a pubkey
    byte[] pkHash = SHA256.digest(pub.asBytes());
    NodeSSK nodeKey = new NodeSSK(pkHash, ehDocname, CRYPTO_ALGO);

    byte[] data = newData();
    byte[] headers = signedHeaders(ehDocname, CRYPTO_ALGO, data, priv, true, null);

    assertThrows(SSKVerifyException.class, () -> new SSKBlock(data, headers, nodeKey, true));
  }

  @Test
  @DisplayName("constructor_whenSignatureInvalidAndVerifyEnabled_throwsVerifyException")
  void constructor_whenSignatureInvalidAndVerifyEnabled_throwsVerifyException() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {6, 6, 6, 6}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x66);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] data = newData();
    byte[] headers = headersUnsignedPrefix(ehDocname);
    // With dontVerify=false, bogus R/S must fail verification.
    assertThrows(SSKVerifyException.class, () -> new SSKBlock(data, headers, nodeKey, false));
  }

  @Test
  @DisplayName("equals_whenHeadersDifferOnlyAfterCompareWindow_returnsTrue")
  void equals_whenHeadersDifferOnlyAfterCompareWindow_returnsTrue() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {7, 7, 7, 7}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x77);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] data = newData();
    // Same header prefix, different valid signatures (deterministic vs seeded random)
    byte[] headersA = signedHeaders(ehDocname, CRYPTO_ALGO, data, priv, true, null);
    byte[] headersB =
        signedHeaders(ehDocname, CRYPTO_ALGO, data, priv, false, new byte[] {9, 9, 9, 9});

    SSKBlock a = new SSKBlock(data, headersA, nodeKey, false);
    SSKBlock b = new SSKBlock(data, headersB, nodeKey, false);

    assertEquals(a, b);
  }

  @Test
  @DisplayName("hashCode_whenBlocksIdentical_returnsSameValue")
  void hashCode_whenBlocksIdentical_returnsSameValue() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {7, 7, 7, 7}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x77);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] data = newData();
    byte[] headers = signedHeaders(ehDocname, CRYPTO_ALGO, data, priv, true, null);

    SSKBlock a = new SSKBlock(data, headers, nodeKey, false);
    SSKBlock b = new SSKBlock(data, headers.clone(), nodeKey, false);

    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  @DisplayName("equals_whenHeadersDifferInsideCompareWindow_returnsFalse")
  void equals_whenHeadersDifferInsideCompareWindow_returnsFalse() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {8, 8, 8, 8}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x78);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] data = newData();
    byte[] headersA = signedHeaders(ehDocname, CRYPTO_ALGO, data, priv, true, null);
    // Change one byte within 0..70, then re-sign so constructor passes
    byte[] headersB = headersUnsignedPrefix(ehDocname);
    headersB[70] ^= 0x01;
    signHeaders(headersB, data, priv, true, null);

    SSKBlock a = new SSKBlock(data, headersA, nodeKey, false);
    SSKBlock b = new SSKBlock(data, headersB, nodeKey, false);

    assertNotEquals(a, b);
  }

  @Test
  @DisplayName("equals_whenDataDiffers_returnsFalse")
  void equals_whenDataDiffers_returnsFalse() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {10, 10, 10, 10}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x79);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] dataA = newData();
    byte[] dataB = newData();
    dataB[0] ^= 0x7F; // mutate one byte
    byte[] headersA = signedHeaders(ehDocname, CRYPTO_ALGO, dataA, priv, true, null);
    byte[] headersB = signedHeaders(ehDocname, CRYPTO_ALGO, dataB, priv, true, null);

    SSKBlock a = new SSKBlock(dataA, headersA, nodeKey, false);
    SSKBlock b = new SSKBlock(dataB, headersB, nodeKey, false);

    assertNotEquals(a, b);
  }

  @Test
  @DisplayName("equals_whenSymCipherIdentifierDiffers_returnsFalse")
  void equals_whenSymCipherIdentifierDiffers_returnsFalse() throws Exception {
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {11, 11, 11, 11}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x7A);
    NodeSSK nodeKey = newNodeSSK(pub, ehDocname);

    byte[] data = newData();
    byte[] headersA = signedHeaders(ehDocname, CRYPTO_ALGO, data, priv, true, null);
    byte[] headersB = signedHeaders(ehDocname, (short) (CRYPTO_ALGO + 1), data, priv, true, null);

    SSKBlock a = new SSKBlock(data, headersA, nodeKey, false);
    SSKBlock b = new SSKBlock(data, headersB, nodeKey, false);

    assertNotEquals(a, b);
  }
}
