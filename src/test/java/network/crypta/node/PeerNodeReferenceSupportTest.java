package network.crypta.node;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Field;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.DeflaterOutputStream;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.ECDSA;
import network.crypta.crypt.ECDSA.Curves;
import network.crypta.crypt.Global;
import network.crypta.crypt.SHA256;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.support.Base64;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerNodeReferenceSupportTest {

  private static final byte[] IDENTITY = fixedBytes((byte) 0x4A);
  private static final byte[] IDENTITY_HASH = SHA256.digest(IDENTITY);
  private static final byte[] IDENTITY_HASH_HASH = SHA256.digest(IDENTITY_HASH);

  private PeerNode peer;
  private PeerNodeReferenceSupport support;
  private ECDSA ecdsa;

  @BeforeEach
  void setUp() throws Exception {
    ecdsa = newDeterministicEcdsa(12345L);
    peer = mock(PeerNode.class);
    setField(peer, "identity", IDENTITY);
    setField(peer, "peerECDSAPubKey", ecdsa.getPublicKey());
    setField(peer, "peerECDSAPubKeyHash", SHA256.digest(ecdsa.getPublicKey().getEncoded()));
    support = new PeerNodeReferenceSupport(peer);
  }

  @Test
  void readPeerEcdsaKeyReturn_whenMissingSubset_throwsPeerTooOldException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    assertThrows(PeerTooOldException.class, () -> support.readPeerEcdsaKeyReturn(fs));
  }

  @Test
  void readPeerEcdsaKeyReturn_whenInvalidBase64_throwsFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    SimpleFieldSet ecdsaSfs = new SimpleFieldSet(true);
    SimpleFieldSet curve = new SimpleFieldSet(true);
    curve.putSingle("pub", "not_base64");
    ecdsaSfs.put("P256", curve);
    fs.put("ecdsa", ecdsaSfs);

    assertThrows(FSParseException.class, () -> support.readPeerEcdsaKeyReturn(fs));
  }

  @Test
  void readPeerEcdsaKeyReturn_whenTooLong_throwsFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    SimpleFieldSet ecdsaSfs = new SimpleFieldSet(true);
    SimpleFieldSet curve = new SimpleFieldSet(true);
    byte[] tooLong = new byte[Curves.P256.modulusSize + 1];
    curve.putSingle("pub", Base64.encode(tooLong));
    ecdsaSfs.put("P256", curve);
    fs.put("ecdsa", ecdsaSfs);

    assertThrows(FSParseException.class, () -> support.readPeerEcdsaKeyReturn(fs));
  }

  @Test
  void readPeerEcdsaKeyReturn_whenInvalidKey_throwsFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    SimpleFieldSet ecdsaSfs = new SimpleFieldSet(true);
    SimpleFieldSet curve = new SimpleFieldSet(true);
    byte[] invalid = new byte[10];
    Arrays.fill(invalid, (byte) 0x7F);
    curve.putSingle("pub", Base64.encode(invalid));
    ecdsaSfs.put("P256", curve);
    fs.put("ecdsa", ecdsaSfs);

    assertThrows(FSParseException.class, () -> support.readPeerEcdsaKeyReturn(fs));
  }

  @Test
  void readPeerEcdsaKeyReturn_whenValid_returnsKey() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("ecdsa", Curves.P256.getSFS(ecdsa.getPublicKey()));

    assertEquals(ecdsa.getPublicKey(), support.readPeerEcdsaKeyReturn(fs));
  }

  @Test
  void verifySignatureIfPresent_whenNoSig_setsSuccessTrue() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    support.verifySignatureIfPresent(fs, true);

    verify(peer).setSignatureVerificationSuccessfull(true);
  }

  @Test
  void readIdentityValues_whenIdentityPresent_returnsExpectedValues() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_IDENTITY, Base64.encode(IDENTITY));
    setField(peer, "peerECDSAPubKeyHash", new byte[] {1, 2, 3});

    PeerNode.IdentityValues values = support.readIdentityValues(fs);

    assertArrayEquals(IDENTITY, values.identity);
    assertEquals(Base64.encode(IDENTITY), values.identityAsBase64String);
    assertArrayEquals(IDENTITY_HASH, values.identityHash);
    assertArrayEquals(IDENTITY_HASH_HASH, values.identityHashHash);
    assertEquals(Fields.bytesToLong(IDENTITY_HASH_HASH), values.swapIdentifier);
    assertEquals(Fields.hashCode(new byte[] {1, 2, 3}), values.hashCode);
  }

  @Test
  void readIdentityValues_whenMissingIdentityAndDarknet_throwsPeerParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    when(peer.isDarknet()).thenReturn(true);

    assertThrows(PeerParseException.class, () -> support.readIdentityValues(fs));
  }

  @Test
  void readIdentityValues_whenMissingIdentityUsesDsaKey() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    DSAPublicKey dsaKey = new DSAPublicKey(Global.DSAgroupBigA, BigInteger.valueOf(2));
    fs.put("dsaPubKey", dsaKey.asFieldSet());
    when(peer.isDarknet()).thenReturn(false);
    setField(peer, "peerECDSAPubKeyHash", new byte[] {9, 8, 7});

    PeerNode.IdentityValues values = support.readIdentityValues(fs);

    byte[] expectedIdentity = SHA256.digest(dsaKey.asBytes());
    assertArrayEquals(expectedIdentity, values.identity);
    assertEquals(Base64.encode(expectedIdentity), values.identityAsBase64String);
  }

  @Test
  void computeIncomingSetupKey_whenCalled_xorsIdentityHashHash() {
    NodeCrypto crypto = mock(NodeCrypto.class);
    byte[] nodeHash = fixedBytes((byte) 0x0F);
    when(crypto.getIdentityHash()).thenReturn(nodeHash);

    byte[] key = support.computeIncomingSetupKey(crypto, IDENTITY_HASH_HASH);

    assertArrayEquals(xor(nodeHash, IDENTITY_HASH_HASH), key);
  }

  @Test
  void computeOutgoingSetupKey_whenCalled_xorsIdentityHash() {
    NodeCrypto crypto = mock(NodeCrypto.class);
    byte[] nodeHashHash = fixedBytes((byte) 0x33);
    when(crypto.getIdentityHashHash()).thenReturn(nodeHashHash);

    byte[] key = support.computeOutgoingSetupKey(crypto, IDENTITY_HASH);

    assertArrayEquals(xor(nodeHashHash, IDENTITY_HASH), key);
  }

  @Test
  void buildRijndaelCipher_whenValidKey_returnsInitializedCipher() {
    byte[] key = fixedBytes((byte) 0x22);

    BlockCipher cipher = support.buildRijndaelCipher(key);

    assertNotNull(cipher);
    assertEquals(256, cipher.getKeySize());
    assertEquals(256, cipher.getBlockSize());
  }

  @Test
  void computePeerPublicKeyHash_whenCalled_returnsSha256() {
    byte[] expected = SHA256.digest(ecdsa.getPublicKey().getEncoded());

    assertArrayEquals(expected, support.computePeerPublicKeyHash(ecdsa.getPublicKey()));
  }

  @Test
  void parsePeerEntryCompat_whenCommaAndPort_returnsPeers() throws Exception {
    List<Peer> peers = support.parsePeerEntryCompat("192.0.2.1,192.0.2.2:1234", false);

    assertEquals(2, peers.size());
    assertTrue(peers.contains(new Peer("192.0.2.1:1234", true, true)));
    assertTrue(peers.contains(new Peer("192.0.2.2:1234", true, true)));
  }

  @Test
  void parsePeerEntryCompat_whenCommaSeparatedPeers_returnsPeers() throws Exception {
    List<Peer> peers = support.parsePeerEntryCompat("192.0.2.1:1234,192.0.2.2:5678", false);

    assertEquals(2, peers.size());
    assertTrue(peers.contains(new Peer("192.0.2.1:1234", true, true)));
    assertTrue(peers.contains(new Peer("192.0.2.2:5678", true, true)));
  }

  @Test
  void parsePeerEntryCompat_whenInvalidWithoutComma_returnsEmptyList() {
    List<Peer> peers = support.parsePeerEntryCompat("not-a-peer", true);

    assertTrue(peers.isEmpty());
  }

  @Test
  void tryParsePeer_whenValid_returnsPeer() throws Exception {
    Peer parsed = support.tryParsePeer("198.51.100.10:9999");

    assertNotNull(parsed);
    assertEquals(new Peer("198.51.100.10:9999", true, true), parsed);
  }

  @Test
  void tryParsePeer_whenInvalid_returnsNull() {
    assertNull(support.tryParsePeer("invalid-peer"));
  }

  @Test
  void checkTestnetAndOpennet_whenTestnetEnabled_throwsFSParseException() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_TESTNET, "true");
    when(peer.getPeer()).thenReturn(new Peer("198.51.100.1:1234", true, true));

    assertThrows(FSParseException.class, () -> support.checkTestnetAndOpennet(fs, false, false));
  }

  @Test
  void checkTestnetAndOpennet_whenMissingOpennetOnFullRef_throwsFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    assertThrows(FSParseException.class, () -> support.checkTestnetAndOpennet(fs, false, true));
  }

  @Test
  void checkTestnetAndOpennet_whenOpennetMismatch_throwsFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_OPENNET, "true");
    when(peer.isOpennetForNoderef()).thenReturn(false);

    assertThrows(FSParseException.class, () -> support.checkTestnetAndOpennet(fs, false, false));
  }

  @Test
  void checkTestnetAndOpennet_whenInvalidOpennetValue_throwsFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_OPENNET, "not-a-bool");

    assertThrows(FSParseException.class, () -> support.checkTestnetAndOpennet(fs, false, false));
  }

  @Test
  void validateIdentity_whenIdentityMismatch_throwsFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_IDENTITY, Base64.encode(fixedBytes((byte) 0x01)));

    assertThrows(FSParseException.class, () -> support.validateIdentity(fs, false, true));
  }

  @Test
  void validateIdentity_whenMissingIdentityFullDarknet_throwsFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    when(peer.isDarknet()).thenReturn(true);

    assertThrows(FSParseException.class, () -> support.validateIdentity(fs, false, true));
  }

  @Test
  void validateIdentity_whenMissingIdentityFullOpennet_allows() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    when(peer.isDarknet()).thenReturn(false);

    support.validateIdentity(fs, false, true);
  }

  @Test
  void parseEcdsaFields_whenMatchingKey_allows() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.put("ecdsa", Curves.P256.getSFS(ecdsa.getPublicKey()));

    support.parseEcdsaFields(fs);

    assertEquals(ecdsa.getPublicKey(), getField(peer, "peerECDSAPubKey"));
  }

  @Test
  void parseEcdsaFields_whenChangingKey_throwsFSParseException() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    ECDSA other = newDeterministicEcdsa(999L);
    fs.put("ecdsa", Curves.P256.getSFS(other.getPublicKey()));

    assertThrows(FSParseException.class, () -> support.parseEcdsaFields(fs));
  }

  @Test
  void parseEcdsaFields_whenInvalidBase64_throwsFSParseException() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    SimpleFieldSet curve = new SimpleFieldSet(true);
    curve.putSingle("pub", "***");
    SimpleFieldSet ecdsaSfs = new SimpleFieldSet(true);
    ecdsaSfs.put("P256", curve);
    fs.put("ecdsa", ecdsaSfs);

    assertThrows(FSParseException.class, () -> support.parseEcdsaFields(fs));
  }

  @Test
  void putEcdsaFields_whenCalled_writesFieldSet() {
    SimpleFieldSet fs = new SimpleFieldSet(true);

    support.putEcdsaFields(fs, ecdsa.getPublicKey());

    assertNotNull(fs.subset("ecdsa.P256"));
  }

  @Test
  void verifyReferenceSignature_whenValid_setsFullFieldSet() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("version", "Cryptad,1");
    fs.putSingle("opennet", "false");
    String toSign = fs.toOrderedString();
    byte[] signature = ecdsa.sign(toSign.getBytes(StandardCharsets.UTF_8));
    fs.putSingle(PeerNode.SFS_KEY_SIG_P256, Base64.encode(signature));
    when(peer.dontKeepFullFieldSet()).thenReturn(false);

    assertTrue(support.verifyReferenceSignature(fs));

    verify(peer).setSignatureVerificationSuccessfull(true);
    assertEquals(fs, getField(peer, "fullFieldSet"));
  }

  @Test
  void verifyReferenceSignature_whenMissingSignature_throws() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("version", "Cryptad,1");

    assertThrows(
        ReferenceSignatureVerificationException.class, () -> support.verifyReferenceSignature(fs));

    verify(peer).setSignatureVerificationSuccessfull(false);
  }

  @Test
  void verifyReferenceSignature_whenInvalidBase64_throws() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("version", "Cryptad,1");
    fs.putSingle(PeerNode.SFS_KEY_SIG_P256, "not-base64");

    assertThrows(
        ReferenceSignatureVerificationException.class, () -> support.verifyReferenceSignature(fs));
  }

  @Test
  void formatPeerKeyHash_whenCalled_returnsHex() {
    byte[] hash = new byte[] {0x00, 0x0F, (byte) 0xA0};

    assertEquals(HexUtil.bytesToHex(hash), support.formatPeerKeyHash(hash));
  }

  @Test
  void formatDuration_whenCalled_delegatesToTimeUtil() {
    long millis = 123456L;

    assertEquals(TimeUtil.formatTime(millis), support.formatDuration(millis));
  }

  @Test
  void compressedNoderefToFieldSet_whenTooShort_throwsFSParseException() {
    byte[] data = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04};

    assertThrows(
        FSParseException.class,
        () -> PeerNodeReferenceSupport.compressedNoderefToFieldSet(data, 0, data.length));
  }

  @Test
  void compressedNoderefToFieldSet_whenCompressed_parsesFieldSet() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("version", "Cryptad,1");
    byte[] compressed = compressFieldSet(fs);
    byte[] data = new byte[compressed.length + 1];
    data[0] = 0x01;
    System.arraycopy(compressed, 0, data, 1, compressed.length);

    SimpleFieldSet parsed =
        PeerNodeReferenceSupport.compressedNoderefToFieldSet(data, 0, data.length);

    assertEquals("Cryptad,1", parsed.get("version"));
  }

  @Test
  void compressedNoderefToFieldSet_whenUncompressed_parsesFieldSet() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("version", "Cryptad,1");
    byte[] raw = rawFieldSetBytes(fs);
    byte[] data = new byte[raw.length + 1];
    data[0] = 0x00;
    System.arraycopy(raw, 0, data, 1, raw.length);

    SimpleFieldSet parsed =
        PeerNodeReferenceSupport.compressedNoderefToFieldSet(data, 0, data.length);

    assertEquals("Cryptad,1", parsed.get("version"));
  }

  @Test
  void compressedNoderefToFieldSet_whenInvalidCompressed_throwsFSParseException() {
    byte[] data = new byte[] {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    assertThrows(
        FSParseException.class,
        () -> PeerNodeReferenceSupport.compressedNoderefToFieldSet(data, 0, data.length));
  }

  @Test
  void isValidAddress_whenLoopback_returnsFalse() throws Exception {
    InetAddress addr = InetAddress.getByName("127.0.0.1");

    assertFalse(PeerNodeReferenceSupport.isValidAddress(addr));
  }

  @Test
  void isValidAddress_whenPublicAddress_returnsTrue() throws Exception {
    InetAddress addr = InetAddress.getByName("8.8.8.8");

    assertTrue(PeerNodeReferenceSupport.isValidAddress(addr));
  }

  @ParameterizedTest
  @MethodSource("splitVersionComponentsCases")
  void splitVersionComponents_whenCalled_returnsExpected(String input, String[] expected) {
    assertArrayEquals(expected, PeerNodeReferenceSupport.splitVersionComponents(input));
  }

  @Test
  void computeArk_whenPubKeyAndNumber_returnsUsk() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_ARK_PUBURI, sampleSskUri());
    fs.putSingle(PeerNode.SFS_KEY_ARK_NUMBER, "5");

    USK ark = PeerNodeReferenceSupport.computeArk(peer, fs, false, false, null);

    assertNotNull(ark);
    assertEquals(5L, ark.suggestedEdition);
  }

  @Test
  void computeArk_whenOnStartupIncrementsEdition() {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_ARK_PUBURI, sampleSskUri());
    fs.putSingle(PeerNode.SFS_KEY_ARK_NUMBER, "5");

    USK ark = PeerNodeReferenceSupport.computeArk(peer, fs, true, false, null);

    assertNotNull(ark);
    assertEquals(6L, ark.suggestedEdition);
  }

  @Test
  void computeArk_whenDiffRefUsesCurrentArk() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_ARK_NUMBER, "7");
    USK current = USK.create(new FreenetURI(sampleUskUri()));

    USK ark = PeerNodeReferenceSupport.computeArk(peer, fs, false, true, current);

    assertNotNull(ark);
    assertEquals(7L, ark.suggestedEdition);
  }

  @Test
  void computeArk_whenDiffRefHasPubKeyWithoutEdition_returnsNull() throws Exception {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle(PeerNode.SFS_KEY_ARK_PUBURI, sampleSskUri());
    USK current = USK.create(new FreenetURI(sampleUskUri()));

    assertNull(PeerNodeReferenceSupport.computeArk(peer, fs, false, true, current));
  }

  private static Stream<Arguments> splitVersionComponentsCases() {
    return Stream.of(
        Arguments.of(null, new String[0]),
        Arguments.of("", new String[0]),
        Arguments.of("a,b", new String[] {"a", "b"}),
        Arguments.of(" a , , b ", new String[] {"a", "b"}));
  }

  private static byte[] fixedBytes(byte value) {
    byte[] out = new byte[32];
    Arrays.fill(out, value);
    return out;
  }

  private static byte[] xor(byte[] left, byte[] right) {
    byte[] out = new byte[left.length];
    for (int i = 0; i < left.length; i++) {
      out[i] = (byte) (left[i] ^ right[i]);
    }
    return out;
  }

  private static byte[] rawFieldSetBytes(SimpleFieldSet fs) throws Exception {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    fs.writeTo(baos);
    return baos.toByteArray();
  }

  private static byte[] compressFieldSet(SimpleFieldSet fs) throws Exception {
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DeflaterOutputStream dos = new DeflaterOutputStream(baos)) {
      fs.writeTo(dos);
    }
    return baos.toByteArray();
  }

  private static ECDSA newDeterministicEcdsa(long seed) throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
    ECGenParameterSpec spec = new ECGenParameterSpec("secp256r1");
    SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
    random.setSeed(seed);
    kpg.initialize(spec, random);
    KeyPair kp = kpg.generateKeyPair();
    SimpleFieldSet sfs = new SimpleFieldSet(true);
    sfs.putSingle("pub", Base64.encode(kp.getPublic().getEncoded()));
    sfs.putSingle("pri", Base64.encode(kp.getPrivate().getEncoded()));
    return new ECDSA(sfs, Curves.P256);
  }

  private static void setField(Object target, String fieldName, Object value) throws Exception {
    Field field = PeerNode.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }

  private static Object getField(Object target, String fieldName) throws Exception {
    Field field = PeerNode.class.getDeclaredField(fieldName);
    field.setAccessible(true);
    return field.get(target);
  }

  private static String sampleSskUri() {
    return "SSK@5hH~39FtjA7A9~VXWtBKI~prUDTuJZURudDG0xFn3KA,"
        + "GDgRGt5f6xqbmo-WraQtU54x4H~871Sho9Hz6hC-0RA,AQACAAE/Search-17/index_d51.xml";
  }

  private static String sampleUskUri() {
    return "USK@0I8gctpUE32CM0iQhXaYpCMvtPPGfT4pjXm01oid5Zc,"
        + "3dAcn4fX2LyxO6uCnWFTx-2HKZ89uruurcKwLSCxbZ4,AQACAAE/FakeM3UHostingFreesite/23/";
  }
}
