package network.crypta.crypt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import network.crypta.crypt.ECDSA.Curves;
import network.crypta.node.FSParseException;
import network.crypta.support.Base64;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class ECDSATest {

  private ECDSA.Curves curveToTest;
  private ECDSA ecdsa;

  @BeforeEach
  void setUp() {
    curveToTest = Curves.P256;
    ecdsa = new ECDSA(curveToTest);
  }

  @Test
  void getPublicKey_whenGenerated_isPresentAndBounded() {
    PublicKey pub = ecdsa.getPublicKey();
    assertNotNull(pub);
    assertTrue(pub.getEncoded().length <= curveToTest.modulusSize);
  }

  @Test
  void sign_whenCalled_producesBytes() {
    byte[] sig = ecdsa.sign("test".getBytes(StandardCharsets.UTF_8));
    assertNotNull(sig);
    assertTrue(sig.length > 0);
  }

  @Test
  void sign_whenCalledTwiceWithSameData_isDeterministic() {
    byte[] m = "deterministic".getBytes(StandardCharsets.UTF_8);
    byte[] s1 = ecdsa.sign(m);
    byte[] s2 = ecdsa.sign(m);
    assertArrayEquals(s1, s2);
  }

  @Test
  void signToNetworkFormat_whenCalled_returnsFixedLength() {
    byte[] toSign = "test".getBytes(StandardCharsets.UTF_8);
    byte[] sig = ecdsa.signToNetworkFormat(toSign);
    assertNotNull(sig);
    assertEquals(curveToTest.maxSigSize, sig.length);
  }

  @Test
  void signToNetworkFormat_whenUnderlyingSignatureTooLong_throws() {
    ECDSA spy = Mockito.spy(new ECDSA(curveToTest));
    byte[] tooLong = new byte[curveToTest.maxSigSize + 1];
    Mockito.doReturn(tooLong).when(spy).sign(Mockito.any());
    byte[] smallMsg = "x".getBytes(StandardCharsets.UTF_8);
    assertThrows(IllegalStateException.class, () -> spy.signToNetworkFormat(smallMsg));
  }

  @Test
  void verify_whenValidSignature_succeeds() {
    String toSign = "test";
    byte[] sig = ecdsa.sign(toSign.getBytes(StandardCharsets.UTF_8));
    assertTrue(ecdsa.verify(sig, toSign.getBytes(StandardCharsets.UTF_8)));
    assertFalse(ecdsa.verify(sig, "".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void verify_whenUsingNetworkPaddedSignature_succeeds() {
    byte[] msg = "pad me".getBytes(StandardCharsets.UTF_8);
    byte[] padded = ecdsa.signToNetworkFormat(msg);
    assertTrue(ecdsa.verify(padded, msg));
  }

  @Test
  void verify_withOffsetAndExtraBytes_ignoresPaddingAndSuceeds() {
    byte[] msg = "offset ok".getBytes(StandardCharsets.UTF_8);
    byte[] padded = ecdsa.signToNetworkFormat(msg);
    byte[] container = new byte[10 + padded.length + 5];
    // Fill with non-zero noise around the signature to ensure we only use declared range
    Arrays.fill(container, (byte) 0x5A);
    int off = 10;
    System.arraycopy(padded, 0, container, off, padded.length);
    assertTrue(ecdsa.verify(container, off, padded.length + 5, msg));
  }

  @Test
  void verify_withTamperedSignature_fails() {
    byte[] msg = "tamper".getBytes(StandardCharsets.UTF_8);
    byte[] sig = ecdsa.sign(msg); // raw DER without network padding
    byte[] tampered = Arrays.copyOf(sig, sig.length);
    tampered[tampered.length - 1] ^= 0x01; // flip a byte inside the DER payload
    assertFalse(ecdsa.verify(tampered, msg));
  }

  @Test
  void verify_withMismatchedKey_fails() {
    byte[] msg = "wrong key".getBytes(StandardCharsets.UTF_8);
    byte[] sig = ecdsa.sign(msg);
    // New ECDSA with different key
    ECDSA other = new ECDSA(curveToTest);
    assertFalse(ECDSA.verify(curveToTest, other.getPublicKey(), sig, msg));
  }

  @Test
  void verify_withInvalidDerHeader_returnsFalse() {
    byte[] msg = "bad header".getBytes(StandardCharsets.UTF_8);
    byte[] sig = ecdsa.sign(msg);
    byte[] invalid = Arrays.copyOf(sig, sig.length);
    invalid[0] = 0x31; // not a DER SEQUENCE (should be 0x30)
    assertFalse(ecdsa.verify(invalid, msg));
  }

  @Test
  void staticVerify_withNullArgs_returnsFalse() {
    assertFalse(ECDSA.verify(curveToTest, null, new byte[0]));
    assertFalse(ECDSA.verify(null, ecdsa.getPublicKey(), new byte[0]));
    ECPublicKey key = ecdsa.getPublicKey();
    assertThrows(NullPointerException.class, () -> ECDSA.verify(curveToTest, key, null));
    assertFalse(ECDSA.verify(curveToTest, ecdsa.getPublicKey(), new byte[0], (byte[][]) null));
  }

  @Test
  void getPublicKeyStatic_whenInvalidBytes_returnsNull() {
    assertNull(ECDSA.getPublicKey(new byte[] {0x01, 0x02, 0x03}, curveToTest));
  }

  @Test
  void curvesGetSFS_whenCalled_containsBase64PubAndReconstructible() throws Exception {
    ECPublicKey pub = ecdsa.getPublicKey();
    SimpleFieldSet sfs = curveToTest.getSFS(pub);
    SimpleFieldSet subset = sfs.getSubset(curveToTest.name());
    assertNotNull(subset);
    assertNotNull(subset.get("pub"));
    byte[] decoded = Base64.decode(subset.get("pub"));
    ECPublicKey parsed = ECDSA.getPublicKey(decoded, curveToTest);
    assertNotNull(parsed);
    assertArrayEquals(pub.getEncoded(), parsed.getEncoded());
  }

  @Test
  void asFieldSet_whenIncludePrivate_controlsPresenceOfPriField() throws FSParseException {
    SimpleFieldSet privSFS = ecdsa.asFieldSet(true);
    assertNotNull(privSFS.getSubset(curveToTest.name()));
    assertNotNull(privSFS.get(curveToTest.name() + ".pub"));
    assertNotNull(privSFS.get(curveToTest.name() + ".pri"));

    SimpleFieldSet pubSFS = ecdsa.asFieldSet(false);
    assertNotNull(pubSFS.getSubset(curveToTest.name()));
    assertNotNull(pubSFS.get(curveToTest.name() + ".pub"));
    assertNull(pubSFS.get(curveToTest.name() + ".pri"));
  }

  @Test
  void serializeUnserialize_whenRoundTripped_preservesPublicKey() throws FSParseException {
    SimpleFieldSet sfs = ecdsa.asFieldSet(true);
    ECDSA ecdsa2 = new ECDSA(sfs.getSubset(curveToTest.name()), curveToTest);
    assertEquals(ecdsa.getPublicKey(), ecdsa2.getPublicKey());
  }

  @DisplayName("sign/verify works across all configured curves")
  @ParameterizedTest
  @EnumSource(Curves.class)
  void signVerify_acrossCurves_succeeds(Curves curve) {
    ECDSA local = new ECDSA(curve);
    byte[] msg1 = "hello".getBytes(StandardCharsets.UTF_8);
    byte[] msg2 = "world".getBytes(StandardCharsets.UTF_8);
    byte[] sig1 = local.sign(msg1);
    byte[] sig2 = local.signToNetworkFormat(msg2);
    assertTrue(local.verify(sig1, msg1));
    assertTrue(ECDSA.verify(curve, local.getPublicKey(), sig2, msg2));
  }
}
