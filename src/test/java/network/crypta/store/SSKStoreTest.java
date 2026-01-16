package network.crypta.store;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.security.SecureRandom;
import java.util.Arrays;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.Global;
import network.crypta.crypt.SHA256;
import network.crypta.keys.Key;
import network.crypta.keys.KeyBlock;
import network.crypta.keys.NodeSSK;
import network.crypta.keys.SSKBlock;
import network.crypta.keys.SSKVerifyException;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100") // Test method naming: method_whenCondition_expectOutcome
@ExtendWith(MockitoExtension.class)
class SSKStoreTest {

  private static final byte CRYPTO_ALGO = Key.ALGO_AES_PCFB_256_SHA256;

  @Mock private GetPubkey pubkeyCache;

  @Mock private FreenetStore<SSKBlock> mockStore;

  private static NodeSSK newNodeSSK(DSAPublicKey pub, byte[] ehDocname) throws SSKVerifyException {
    byte[] pkHash = SHA256.digest(pub.asBytes());
    return new NodeSSK(pkHash, ehDocname, pub, CRYPTO_ALGO);
  }

  private static NodeSSK newNodeSSKWithoutPub(byte[] pkHash, byte[] ehDocname)
      throws SSKVerifyException {
    return new NodeSSK(pkHash, ehDocname, null, CRYPTO_ALGO);
  }

  private static byte[] newData() {
    byte[] data = new byte[SSKBlock.DATA_LENGTH];
    for (int i = 0; i < data.length; i++) data[i] = (byte) (i & 0xFF);
    return data;
  }

  private static byte[] headersUnsignedPrefix(byte[] ehDocname) {
    byte[] headers = new byte[SSKBlock.TOTAL_HEADERS_LENGTH];
    int x = 0;
    headers[x++] = 0; // HASH_SHA256 high byte
    headers[x++] = (byte) KeyBlock.HASH_SHA256; // low byte
    headers[x++] = (byte) (CRYPTO_ALGO >> 8);
    headers[x++] = CRYPTO_ALGO;
    System.arraycopy(ehDocname, 0, headers, x, NodeSSK.E_H_DOCNAME_SIZE);
    x += NodeSSK.E_H_DOCNAME_SIZE;
    final int ENCRYPTED_HEADERS_LENGTH = 36;
    for (int i = 0; i < ENCRYPTED_HEADERS_LENGTH; i++) headers[x++] = (byte) (0xA0 + i);
    // Leave the signature area zeroed for signing
    return headers;
  }

  private static void signHeaders(byte[] headers, byte[] data, DSAPrivateKey priv) {
    // Compute the overall hash as SSKBlock does
    byte[] dataHash = SHA256.digest(data);
    final int ENCRYPTED_HEADERS_LENGTH = 36;
    int signedPrefixLen = 2 + 2 + NodeSSK.E_H_DOCNAME_SIZE + ENCRYPTED_HEADERS_LENGTH;
    byte[] tmp = new byte[signedPrefixLen + dataHash.length];
    System.arraycopy(headers, 0, tmp, 0, signedPrefixLen);
    System.arraycopy(dataHash, 0, tmp, signedPrefixLen, dataHash.length);
    byte[] overallHash = SHA256.digest(tmp);

    DSASigner dsa = new DSASigner(new HMacDSAKCalculator(new SHA256Digest()));
    DSAPrivateKeyParameters params =
        new DSAPrivateKeyParameters(priv.getX(), Global.getDSAgroupBigAParameters());
    dsa.init(true, params);
    var sig = dsa.generateSignature(Global.truncateHash(overallHash));
    byte[] r = toFixed32(sig[0].toByteArray());
    byte[] s = toFixed32(sig[1].toByteArray());
    int x = signedPrefixLen;
    System.arraycopy(r, 0, headers, x, r.length);
    x += r.length;
    System.arraycopy(s, 0, headers, x, s.length);
  }

  private static byte[] toFixed32(byte[] in) {
    final int len = 32;
    if (in.length == len) return in;
    if (in.length > len) {
      // Truncate leading zeros if present
      for (int i = 0; i < in.length - len; i++)
        if (in[i] != 0) throw new IllegalArgumentException();
      return Arrays.copyOfRange(in, in.length - len, in.length);
    }
    byte[] out = new byte[len];
    System.arraycopy(in, 0, out, len - in.length, in.length);
    return out;
  }

  private static byte[] signedHeaders(byte[] ehDocname, byte[] data, DSAPrivateKey priv) {
    byte[] headers = headersUnsignedPrefix(ehDocname);
    signHeaders(headers, data, priv);
    return headers;
  }

  @Test
  @DisplayName("construct_whenDataOrHeadersNull_throwsVerifyException")
  void construct_whenDataOrHeadersNull_throwsVerifyException() {
    // Arrange
    SSKStore sut = new SSKStore(pubkeyCache);

    // Act + Assert
    SSKVerifyException ex1 =
        assertThrows(
            SSKVerifyException.class,
            () ->
                sut.construct(
                    new StoreCallback.BlockPayload(
                        /*data*/ null,
                        new byte[SSKBlock.TOTAL_HEADERS_LENGTH],
                        /*routingKey*/ null,
                        new byte[NodeSSK.FULL_KEY_LENGTH]),
                    new StoreCallback.ConstructOptions(false, false, /*meta*/ null),
                    /*knownPub*/ null));
    assertEquals("Need data and headers", ex1.getMessage());

    SSKVerifyException ex2 =
        assertThrows(
            SSKVerifyException.class,
            () ->
                sut.construct(
                    new StoreCallback.BlockPayload(
                        new byte[SSKBlock.DATA_LENGTH],
                        /*headers*/ null,
                        /*routingKey*/ null,
                        new byte[NodeSSK.FULL_KEY_LENGTH]),
                    new StoreCallback.ConstructOptions(false, false, /*meta*/ null),
                    /*knownPub*/ null));
    assertEquals("Need data and headers", ex2.getMessage());
  }

  @Test
  @DisplayName("construct_whenFullKeyNull_throwsVerifyException")
  void construct_whenFullKeyNull_throwsVerifyException() {
    // Arrange
    SSKStore sut = new SSKStore(pubkeyCache);

    // Act + Assert
    SSKVerifyException ex =
        assertThrows(
            SSKVerifyException.class,
            () ->
                sut.construct(
                    new StoreCallback.BlockPayload(
                        new byte[SSKBlock.DATA_LENGTH],
                        new byte[SSKBlock.TOTAL_HEADERS_LENGTH],
                        /*routingKey*/ null,
                        /*fullKey*/ null),
                    new StoreCallback.ConstructOptions(false, false, /*meta*/ null),
                    /*knownPub*/ null));
    assertEquals("Need full key to reconstruct an SSK", ex.getMessage());
  }

  @Test
  @DisplayName("construct_whenKnownPubProvided_buildsBlockAndSkipsCache")
  void construct_whenKnownPubProvided_buildsBlockAndSkipsCache() throws Exception {
    // Arrange: build a consistent full key, headers and signature
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {1, 2, 3, 4}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x42);
    NodeSSK original = newNodeSSK(pub, ehDocname);
    byte[] fullKey = original.getFullKey();
    byte[] data = newData();
    byte[] headers = signedHeaders(ehDocname, data, priv);

    SSKStore sut = new SSKStore(pubkeyCache);

    // Act
    SSKBlock block =
        sut.construct(
            new StoreCallback.BlockPayload(data, headers, /*routingKey*/ null, fullKey),
            new StoreCallback.ConstructOptions(
                /*canReadClientCache*/ false, /*canReadSlashdotCache*/ false, /*meta*/ null),
            /*knownPublicKey*/ pub);

    // Assert
    assertNotNull(block);
    assertArrayEquals(data, block.getRawData());
    assertArrayEquals(headers, block.getRawHeaders());
    assertArrayEquals(NodeSSK.routingKeyFromFullKey(fullKey), block.getRoutingKey());
    assertArrayEquals(fullKey, block.getFullKey());
    assertSame(pub, block.getPubKey());
    verifyNoInteractions(pubkeyCache);
  }

  @Test
  @DisplayName("construct_whenPubKeyMissingInCache_throwsVerifyException")
  void construct_whenPubKeyMissingInCache_throwsVerifyException() throws Exception {
    // Arrange: full key with no attached pubkey in the serialized form
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {5, 6, 7, 8}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x55);
    // Create a NodeSSK without a pubkey and use it as the source of fullKey
    byte[] pkHash = SHA256.digest(pub.asBytes());
    NodeSSK noPub = newNodeSSKWithoutPub(pkHash, ehDocname);
    byte[] fullKey = noPub.getFullKey();

    // SSKBlock verification still needs a valid signature and the real pubkey; however, pubkeyCache
    // returns null to trigger the error path inside SSKStore.construct
    byte[] data = newData();
    byte[] headers = signedHeaders(ehDocname, data, priv);

    when(pubkeyCache.getKey(
            argThat(arg -> Arrays.equals(arg, pkHash)), eq(true), eq(false), isNull()))
        .thenReturn(null);

    SSKStore sut = new SSKStore(pubkeyCache);

    // Act + Assert
    SSKVerifyException ex =
        assertThrows(
            SSKVerifyException.class,
            () ->
                sut.construct(
                    new StoreCallback.BlockPayload(data, headers, /*routingKey*/ null, fullKey),
                    new StoreCallback.ConstructOptions(
                        /*canReadClientCache*/ true,
                        /*canReadSlashdotCache (forULPR)*/ false,
                        /*meta*/ null),
                    /*knownPublicKey*/ null));
    assertEquals("No pubkey found", ex.getMessage());
    verify(pubkeyCache, times(1))
        .getKey(argThat(arg -> Arrays.equals(arg, pkHash)), eq(true), eq(false), isNull());
  }

  @Test
  @DisplayName("construct_whenPubKeyFetchedFromCache_buildsBlock")
  void construct_whenPubKeyFetchedFromCache_buildsBlock() throws Exception {
    // Arrange: Build a full key that omits the pubkey so SSKStore must call the cache
    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {9, 9, 9, 9}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x7A);
    byte[] pkHash = SHA256.digest(pub.asBytes());
    NodeSSK noPub = newNodeSSKWithoutPub(pkHash, ehDocname);
    byte[] fullKey = noPub.getFullKey();

    byte[] data = newData();
    byte[] headers = signedHeaders(ehDocname, data, priv);

    BlockMetadata meta = new BlockMetadata();
    when(pubkeyCache.getKey(
            argThat(arg -> Arrays.equals(arg, pkHash)), eq(false), eq(true), same(meta)))
        .thenReturn(pub);

    SSKStore sut = new SSKStore(pubkeyCache);

    // Act
    SSKBlock block =
        sut.construct(
            new StoreCallback.BlockPayload(data, headers, /*routingKey*/ null, fullKey),
            new StoreCallback.ConstructOptions(
                /*canReadClientCache*/ false, /*canReadSlashdotCache (forULPR)*/ true, meta),
            /*knownPublicKey*/ null);

    // Assert
    assertNotNull(block);
    assertArrayEquals(data, block.getRawData());
    assertArrayEquals(headers, block.getRawHeaders());
    assertSame(pub, block.getPubKey());
    verify(pubkeyCache, times(1))
        .getKey(argThat(arg -> Arrays.equals(arg, pkHash)), eq(false), eq(true), same(meta));
  }

  @Test
  @DisplayName("fetch_whenDelegatesToStore_propagatesArgumentsAndReturnsResult")
  void fetch_whenDelegatesToStore_propagatesArgumentsAndReturnsResult() throws Exception {
    // Arrange
    SSKStore sut = new SSKStore(pubkeyCache);
    sut.setStore(mockStore);

    DSAPrivateKey priv =
        new DSAPrivateKey(Global.DSAgroupBigA, new SecureRandom(new byte[] {3, 3, 3, 3}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x33);
    NodeSSK key = newNodeSSK(pub, ehDocname);

    boolean dontPromote = true;
    boolean canReadClientCache = false;
    boolean canReadSlashdotCache = true;
    boolean ignoreOldBlocks = false;
    BlockMetadata meta = new BlockMetadata();

    SSKBlock expected =
        new SSKBlock(newData(), signedHeaders(ehDocname, newData(), priv), key, true);
    when(mockStore.fetch(
            eq(key.getRoutingKey()),
            eq(key.getFullKey()),
            eq(dontPromote),
            eq(canReadClientCache),
            eq(canReadSlashdotCache),
            eq(ignoreOldBlocks),
            same(meta)))
        .thenReturn(expected);

    // Act
    SSKBlock got =
        sut.fetch(
            key, dontPromote, canReadClientCache, canReadSlashdotCache, ignoreOldBlocks, meta);

    // Assert
    assertSame(expected, got);
    verify(mockStore, times(1))
        .fetch(
            eq(key.getRoutingKey()),
            eq(key.getFullKey()),
            eq(dontPromote),
            eq(canReadClientCache),
            eq(canReadSlashdotCache),
            eq(ignoreOldBlocks),
            same(meta));
  }

  @Test
  @DisplayName("put_whenDelegatesToStore_writesRawArraysAndFlags")
  void put_whenDelegatesToStore_writesRawArraysAndFlags() throws Exception {
    // Arrange
    SSKStore sut = new SSKStore(pubkeyCache);
    sut.setStore(mockStore);

    SSKBlock block = org.mockito.Mockito.mock(SSKBlock.class);
    byte[] data = new byte[SSKBlock.DATA_LENGTH];
    byte[] headers = new byte[SSKBlock.TOTAL_HEADERS_LENGTH];
    when(block.getRawData()).thenReturn(data);
    when(block.getRawHeaders()).thenReturn(headers);

    // Act
    sut.put(block, /*overwrite*/ true, /*isOldBlock*/ false);

    // Assert
    verify(mockStore, times(1)).put(same(block), same(data), same(headers), eq(true), eq(false));
  }

  @Test
  @DisplayName("put_whenStoreThrowsCollision_propagatesException")
  void put_whenStoreThrowsCollision_propagatesException() throws Exception {
    // Arrange
    SSKStore sut = new SSKStore(pubkeyCache);
    sut.setStore(mockStore);
    SSKBlock block = org.mockito.Mockito.mock(SSKBlock.class);
    when(block.getRawData()).thenReturn(new byte[SSKBlock.DATA_LENGTH]);
    when(block.getRawHeaders()).thenReturn(new byte[SSKBlock.TOTAL_HEADERS_LENGTH]);

    org.mockito.Mockito.doThrow(new KeyCollisionException())
        .when(mockStore)
        .put(any(), any(), any(), anyBoolean(), anyBoolean());

    // Act + Assert
    assertThrows(KeyCollisionException.class, () -> sut.put(block, false, true));
  }

  @Test
  @DisplayName("sizesAndFlags_returnExpectedConstants")
  void sizesAndFlags_returnExpectedConstants() {
    // Arrange
    SSKStore sut = new SSKStore(pubkeyCache);

    // Act + Assert
    assertEquals(SSKBlock.DATA_LENGTH, sut.dataLength());
    assertEquals(SSKBlock.TOTAL_HEADERS_LENGTH, sut.headerLength());
    assertEquals(NodeSSK.ROUTING_KEY_LENGTH, sut.routingKeyLength());
    assertEquals(NodeSSK.FULL_KEY_LENGTH, sut.fullKeyLength());
    // Flags
    org.junit.jupiter.api.Assertions.assertTrue(sut.storeFullKeys());
    org.junit.jupiter.api.Assertions.assertTrue(sut.collisionPossible());
    org.junit.jupiter.api.Assertions.assertTrue(sut.constructNeedsKey());
  }

  @Test
  @DisplayName("routingKeyFromFullKey_whenValid_returnsComputedRoutingKey")
  void routingKeyFromFullKey_whenValid_returnsComputedRoutingKey() throws Exception {
    // Arrange: build a proper full key
    DSAPrivateKey priv =
        new DSAPrivateKey(
            Global.DSAgroupBigA, new SecureRandom(new byte[] {0x12, 0x34, 0x56, 0x78}));
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] ehDocname = new byte[NodeSSK.E_H_DOCNAME_SIZE];
    Arrays.fill(ehDocname, (byte) 0x2A);
    NodeSSK key = newNodeSSK(pub, ehDocname);
    byte[] fullKey = key.getFullKey();

    SSKStore sut = new SSKStore(pubkeyCache);

    // Act
    byte[] routed = sut.routingKeyFromFullKey(fullKey);

    // Assert
    assertArrayEquals(NodeSSK.routingKeyFromFullKey(fullKey), routed);
  }
}
