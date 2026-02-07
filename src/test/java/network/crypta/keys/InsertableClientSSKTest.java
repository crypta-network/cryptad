package network.crypta.keys;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.math.BigInteger;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import network.crypta.crypt.DSAPrivateKey;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.Global;
import network.crypta.support.api.Bucket;
import network.crypta.support.io.ArrayBucket;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class InsertableClientSSKTest {

  private static final byte[] FIXED_CRYPTO_KEY = new byte[ClientSSK.CRYPTO_KEY_LENGTH];

  @BeforeEach
  void setUp() {
    for (int i = 0; i < FIXED_CRYPTO_KEY.length; i++) {
      FIXED_CRYPTO_KEY[i] = (byte) (i * 3 + 7);
    }
  }

  @Test
  void constructor_whenPubKeyNull_expectNullPointerException() {
    // Arrange
    DSAPrivateKey priv = new DSAPrivateKey(BigInteger.valueOf(5), Global.DSAgroupBigA);
    byte[] pubKeyHash = new byte[32];

    // Act / Assert
    assertThrows(
        NullPointerException.class,
        () ->
            new InsertableClientSSK(
                "doc.txt",
                pubKeyHash,
                null, // pubKey must not be null
                priv,
                FIXED_CRYPTO_KEY,
                Key.ALGO_AES_PCFB_256_SHA256));
  }

  @Test
  void constructor_whenUnknownAlgorithm_expectMalformedURLException() {
    // Arrange
    DSAPrivateKey priv = new DSAPrivateKey(BigInteger.valueOf(3), Global.DSAgroupBigA);
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    byte[] pubKeyHash = pub.asBytesHash();

    // Act / Assert
    MalformedURLException ex =
        assertThrows(
            MalformedURLException.class,
            () ->
                new InsertableClientSSK(
                    "doc.txt",
                    pubKeyHash,
                    pub,
                    priv,
                    FIXED_CRYPTO_KEY,
                    Key.ALGO_AES_CTR_256_SHA256));
    assertTrue(ex.getMessage().contains("Unknown encryption algorithm"));
  }

  @Test
  void create_whenKskURI_expectDelegatesToClientKSK() throws MalformedURLException {
    // Arrange
    FreenetURI ksk = new FreenetURI("KSK@readme.txt");

    // Act
    InsertableClientSSK fromInsertable = InsertableClientSSK.create(ksk);

    // Assert
    assertInstanceOf(ClientKSK.class, fromInsertable);
    assertEquals(ClientKSK.fromUri(ksk), fromInsertable);
  }

  @Test
  void create_whenValidSskPrivateURI_expectConstructedKeyMatchesURI() throws Exception {
    // Arrange: build an SSK insert URI
    BigInteger x = BigInteger.valueOf(12345);
    DSAPrivateKey priv = new DSAPrivateKey(x, Global.DSAgroupBigA);
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);

    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    extras[1] = 1; // mark as insert/private
    byte[] routingKey = x.toByteArray();
    byte[] cryptoKey = FIXED_CRYPTO_KEY.clone();

    FreenetURI uri = new FreenetURI("SSK", "file.txt", routingKey, cryptoKey, extras);

    // Act
    InsertableClientSSK ssk = InsertableClientSSK.create(uri);

    // Assert key material (avoid direct access to privKey to keep nullability analyzers happy)
    assertEquals("file.txt", ssk.docName);
    assertArrayEquals(cryptoKey, ssk.cryptoKey);
    assertEquals(Key.ALGO_AES_PCFB_256_SHA256, ssk.cryptoAlgorithm);
    // Insert URI must round-trip to the original components
    assertEquals(uri, ssk.getInsertURI());

    // Derived fields
    assertArrayEquals(pub.asBytesHash(), ssk.pubKeyHash);
    assertEquals(pub.getY(), ssk.getPubKey().getY());

    // Insert URI should have the private flag set
    FreenetURI insertUri = ssk.getInsertURI();
    assertEquals("SSK", insertUri.getKeyType());
    assertEquals("file.txt", insertUri.getDocName());
    assertArrayEquals(cryptoKey, insertUri.getCryptoKey());
    byte[] extraOut = insertUri.getExtra();
    assertEquals(5, extraOut.length);
    assertEquals(1, extraOut[1]);
  }

  @Test
  void getInsertURI_whenConstructed_expectPrivateExtrasAndRoutingKeyIsX() throws Exception {
    // Arrange
    DSAPrivateKey priv = new DSAPrivateKey(BigInteger.valueOf(77), Global.DSAgroupBigA);
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    InsertableClientSSK ssk =
        new InsertableClientSSK(
            "index.html",
            pub.asBytesHash(),
            pub,
            priv,
            FIXED_CRYPTO_KEY,
            Key.ALGO_AES_PCFB_256_SHA256);

    // Act
    FreenetURI insertUri = ssk.getInsertURI();

    // Assert
    assertEquals("SSK", insertUri.getKeyType());
    assertEquals("index.html", insertUri.getDocName());
    assertArrayEquals(BigInteger.valueOf(77).toByteArray(), insertUri.getRoutingKey());
    assertArrayEquals(FIXED_CRYPTO_KEY, insertUri.getCryptoKey());
    byte[] extra = insertUri.getExtra();
    assertEquals(NodeSSK.SSK_VERSION, extra[0]);
    assertEquals(1, extra[1]);
    assertEquals(Key.ALGO_AES_PCFB_256_SHA256, extra[2]);
  }

  @Test
  void getCryptoGroup_whenCalled_expectBigA() {
    // Arrange / Act
    InsertableClientSSK ssk = InsertableClientSSK.createRandom(new DummyRandomSource(42L), "d");

    // Assert
    assertEquals(Global.DSAgroupBigA, ssk.getCryptoGroup());
  }

  @Test
  void createRandom_whenSameSeedAndDocName_expectDeterministic() {
    // Arrange
    DummyRandomSource r1 = new DummyRandomSource(123456789L);
    DummyRandomSource r2 = new DummyRandomSource(123456789L);

    // Act
    InsertableClientSSK a = InsertableClientSSK.createRandom(r1, "doc");
    InsertableClientSSK b = InsertableClientSSK.createRandom(r2, "doc");

    // Assert: identical derived key material
    assertEquals(a, b);
    assertEquals(a.getInsertURI(), b.getInsertURI());
  }

  @Test
  void encode_andDecode_whenDontCompress_expectRoundTripAndNoCompression() throws Exception {
    // Arrange: deterministic insertable SSK
    DSAPrivateKey priv = new DSAPrivateKey(BigInteger.valueOf(101), Global.DSAgroupBigA);
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    InsertableClientSSK ssk =
        new InsertableClientSSK(
            "data.bin",
            pub.asBytesHash(),
            pub,
            priv,
            FIXED_CRYPTO_KEY,
            Key.ALGO_AES_PCFB_256_SHA256);

    byte[] payload = "Hello, world!".getBytes(StandardCharsets.UTF_8);
    Bucket input = new ArrayBucket(payload);

    // Act
    ClientSSKBlock block =
        ssk.encode(
            new BlockEncodeParams(
                input,
                /* asMetadata= */ false,
                /* dontCompress= */ true,
                /* alreadyCompressedCodec= */ (short) -1,
                /* sourceLength= */ payload.length,
                /* compressordescriptor= */ null));

    byte[] decoded = block.memoryDecode(false);

    // Assert
    assertArrayEquals(payload, decoded);
    assertEquals(-1, block.getCompressionCodec());
  }

  @Test
  void encode_andDecode_whenAsMetadataFlagSet_expectMetadataTrueAfterDecode() throws Exception {
    // Arrange
    DSAPrivateKey priv = new DSAPrivateKey(BigInteger.valueOf(202), Global.DSAgroupBigA);
    DSAPublicKey pub = new DSAPublicKey(Global.DSAgroupBigA, priv);
    InsertableClientSSK ssk =
        new InsertableClientSSK(
            "meta.json",
            pub.asBytesHash(),
            pub,
            priv,
            FIXED_CRYPTO_KEY,
            Key.ALGO_AES_PCFB_256_SHA256);

    byte[] payload = "{}".getBytes(StandardCharsets.UTF_8);
    Bucket input = new ArrayBucket(payload);

    ClientSSKBlock block =
        ssk.encode(
            new BlockEncodeParams(
                input,
                /* asMetadata= */ true,
                /* dontCompress= */ true,
                /* alreadyCompressedCodec= */ (short) -1,
                /* sourceLength= */ payload.length,
                /* compressordescriptor= */ null));

    // Need to decode before isMetadata() is accessible
    block.memoryDecode(true);
    assertTrue(block.isMetadata());
  }

  @ParameterizedTest
  @MethodSource("invalidInsertSskExtras")
  void create_whenInvalidExtras_expectMalformedURLException(byte[] extras, String expectedMessage) {
    byte[] routingKey = new byte[] {1}; // present but arbitrary; not validated until DSAPrivateKey
    byte[] cryptoKey = new byte[32];
    FreenetURI bad = new FreenetURI("SSK", "a", routingKey, cryptoKey, extras);
    MalformedURLException ex =
        assertThrows(MalformedURLException.class, () -> InsertableClientSSK.create(bad));
    assertTrue(ex.getMessage().contains(expectedMessage));
  }

  private static java.util.stream.Stream<Arguments> invalidInsertSskExtras() {
    byte[] base = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    byte[] notPrivate = base.clone();
    notPrivate[1] = 0; // fetch/public should be rejected for insert private URIs

    byte[] wrongAlgo = base.clone();
    wrongAlgo[1] = 1;
    wrongAlgo[2] = Key.ALGO_AES_CTR_256_SHA256; // unrecognized for SSK insert

    return java.util.stream.Stream.of(
        Arguments.of(null, "Inserting pre-1010 keys not supported"),
        Arguments.of(new byte[] {1, 1, 2, 0}, "SSK private key ,extra too short"),
        Arguments.of(notPrivate, "SSK not a private key"),
        Arguments.of(wrongAlgo, "Unrecognized crypto type in SSK private key"));
  }

  @Test
  void create_whenMissingRoutingKeyOrCryptoKey_expectMalformedURLException() {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    extras[1] = 1; // insert
    byte[] crypto = new byte[32];

    // Missing the routing key
    FreenetURI noRouting = new FreenetURI("SSK", "d", null, null, crypto, extras);
    MalformedURLException ex1 =
        assertThrows(MalformedURLException.class, () -> InsertableClientSSK.create(noRouting));
    assertTrue(ex1.getMessage().contains("must have a private key!"));

    // Missing crypto key
    byte[] dummyRouting = new byte[] {1};
    FreenetURI noCrypto = new FreenetURI("SSK", "d", null, dummyRouting, null, extras);
    MalformedURLException ex2 =
        assertThrows(MalformedURLException.class, () -> InsertableClientSSK.create(noCrypto));
    assertTrue(ex2.getMessage().contains("must have a private key!"));
  }

  @Test
  void create_whenDocNameNull_expectMalformedURLException() {
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    extras[1] = 1; // insert
    FreenetURI uri = new FreenetURI("SSK", null, new byte[] {1}, new byte[32], extras);
    MalformedURLException ex =
        assertThrows(MalformedURLException.class, () -> InsertableClientSSK.create(uri));
    assertTrue(ex.getMessage().contains("must have a document name"));
  }

  @Test
  void create_whenRoutingKeyInvalidBigInteger_expectMalformedURLException() {
    // Use q (group order) as x; DSAPrivateKey requires 0 < x < q, so x == q must fail.
    byte[] extras = ClientSSK.getExtraBytes(Key.ALGO_AES_PCFB_256_SHA256);
    extras[1] = 1; // insert
    byte[] xEqualsQ = Global.DSAgroupBigA.getQ().toByteArray();
    FreenetURI uri = new FreenetURI("SSK", "doc", xEqualsQ, new byte[32], extras);
    MalformedURLException ex =
        assertThrows(MalformedURLException.class, () -> InsertableClientSSK.create(uri));
    assertTrue(ex.getMessage().startsWith("SSK private key (routing key) is invalid:"));
  }
}
