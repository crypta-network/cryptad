package network.crypta.node;

import java.security.interfaces.ECPublicKey;
import network.crypta.support.SimpleFieldSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class PeerNodeConstructorSupportTest {

  @Mock private Node node;
  @Mock private NodeCrypto crypto;
  @Mock private PeerManager peers;
  @Mock private FNPPacketMangler outgoingMangler;
  @Mock private ECPublicKey peerEcdsaKey;

  @Test
  void prepareConstructorInit_whenValidDarknetInputs_expectConstructorInitPopulated()
      throws FSParseException {
    SimpleFieldSet fs = newBaseFieldSet(false, true);
    byte[] peerKeyHash = new byte[] {1, 2, 3};
    SimpleFieldSet verifiedFullFieldSet = new SimpleFieldSet(true);
    PeerNode.IdentityValues identityValues = newIdentityValues();
    PeerNodeReferenceSupport.SignatureVerificationResult signatureResult =
        new PeerNodeReferenceSupport.SignatureVerificationResult(true, verifiedFullFieldSet);

    when(crypto.isOpennet()).thenReturn(false);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class);
        MockedStatic<PeerNodeReferenceSupport> referenceMock =
            Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      versionMock.when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1")).thenReturn(101);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readPeerEcdsaKeyReturn(fs))
          .thenReturn(peerEcdsaKey);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.computePeerPublicKeyHash(peerEcdsaKey))
          .thenReturn(peerKeyHash);
      referenceMock
          .when(
              () ->
                  PeerNodeReferenceSupport.verifySignatureForConstruction(
                      fs, false, peerEcdsaKey, true))
          .thenReturn(signatureResult);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readIdentityValues(fs, true, peerKeyHash))
          .thenReturn(identityValues);

      PeerNode.ConstructorInit init =
          PeerNodeConstructorSupport.prepareConstructorInit(
              fs, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET);

      assertSame(fs, init.fs);
      assertSame(node, init.node);
      assertSame(crypto, init.crypto);
      assertFalse(init.fromLocal);
      assertSame(peers, init.peers);
      assertSame(outgoingMangler, init.outgoingMangler);
      assertEquals("Cryptad,1", init.version);
      assertEquals(101, init.simpleVersion);
      assertEquals("Cryptad,1", init.lastGoodVersion);
      assertFalse(init.testnetEnabled);
      assertArrayEquals(new int[] {5, 7}, init.negTypes);
      assertSame(peerEcdsaKey, init.validatedPeerECDSAPubKey);
      assertArrayEquals(peerKeyHash, init.validatedPeerECDSAPubKeyHash);
      assertTrue(init.signatureVerificationSuccessful);
      assertSame(verifiedFullFieldSet, init.verifiedFullFieldSet);
      assertSame(identityValues, init.identityValues);
    }
  }

  @Test
  void prepareConstructorInit_whenAnonymousInitiatorAndNegTypesMissing_expectFallbackAndNoSig()
      throws FSParseException {
    SimpleFieldSet fs = newBaseFieldSet(true, false);
    byte[] peerKeyHash = new byte[] {9, 8, 7};
    int[] supportedNegTypes = new int[] {11, 12};
    PeerNode.IdentityValues identityValues = newIdentityValues();
    PeerNodeReferenceSupport.SignatureVerificationResult signatureResult =
        new PeerNodeReferenceSupport.SignatureVerificationResult(true, null);

    when(crypto.isOpennet()).thenReturn(true);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);
    when(outgoingMangler.supportedNegTypes(false)).thenReturn(supportedNegTypes);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class);
        MockedStatic<PeerNodeReferenceSupport> referenceMock =
            Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      versionMock.when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1")).thenReturn(202);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readPeerEcdsaKeyReturn(fs))
          .thenReturn(peerEcdsaKey);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.computePeerPublicKeyHash(peerEcdsaKey))
          .thenReturn(peerKeyHash);
      referenceMock
          .when(
              () ->
                  PeerNodeReferenceSupport.verifySignatureForConstruction(
                      fs, true, peerEcdsaKey, false))
          .thenReturn(signatureResult);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readIdentityValues(fs, false, peerKeyHash))
          .thenReturn(identityValues);

      PeerNode.ConstructorInit init =
          PeerNodeConstructorSupport.prepareConstructorInit(
              fs, node, crypto, false, peers, PeerNode.ConstructorProfile.SEED_CLIENT);

      assertArrayEquals(supportedNegTypes, init.negTypes);
      assertEquals(202, init.simpleVersion);
    }
  }

  @Test
  void prepareConstructorInit_whenNoderefTypeMismatched_expectIllegalArgumentException() {
    SimpleFieldSet fs = newBaseFieldSet(false, true);
    when(crypto.isOpennet()).thenReturn(true);

    IllegalArgumentException exception =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                PeerNodeConstructorSupport.prepareConstructorInit(
                    fs, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET));

    assertEquals("Mismatched NodeCrypto for noderef type", exception.getMessage());
  }

  @Test
  void prepareConstructorInit_whenFsNull_expectNullPointerException() {
    NullPointerException exception =
        assertThrows(
            NullPointerException.class,
            () ->
                PeerNodeConstructorSupport.prepareConstructorInit(
                    null, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET));

    assertEquals("fs", exception.getMessage());
  }

  @Test
  void prepareConstructorInit_whenVersionParseFails_expectFSParseException() {
    SimpleFieldSet fs = newBaseFieldSet(false, true);
    when(crypto.isOpennet()).thenReturn(false);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class)) {
      versionMock
          .when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1"))
          .thenThrow(new VersionParseException("bad-version"));

      FSParseException exception =
          assertThrows(
              FSParseException.class,
              () ->
                  PeerNodeConstructorSupport.prepareConstructorInit(
                      fs, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET));

      assertTrue(exception.getMessage().startsWith("Invalid version Cryptad,1"));
    }
  }

  @Test
  void prepareConstructorInit_whenTestnetEnabled_expectFSParseException() {
    SimpleFieldSet fs = newBaseFieldSet(false, true);
    fs.put("testnet", true);
    when(crypto.isOpennet()).thenReturn(false);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class)) {
      versionMock.when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1")).thenReturn(303);

      FSParseException exception =
          assertThrows(
              FSParseException.class,
              () ->
                  PeerNodeConstructorSupport.prepareConstructorInit(
                      fs, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET));

      assertTrue(exception.getMessage().startsWith("Ignoring incompatible testnet node"));
    }
  }

  @Test
  void prepareConstructorInit_whenNegTypesMissingAndNotAnonymous_expectFSParseException() {
    SimpleFieldSet fs = newBaseFieldSet(false, false);
    when(crypto.isOpennet()).thenReturn(false);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class)) {
      versionMock.when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1")).thenReturn(404);

      FSParseException exception =
          assertThrows(
              FSParseException.class,
              () ->
                  PeerNodeConstructorSupport.prepareConstructorInit(
                      fs, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET));

      assertEquals("No negTypes!", exception.getMessage());
    }
  }

  @Test
  void prepareConstructorInit_whenOpennetFlagMismatched_expectFSParseException() {
    SimpleFieldSet fs = newBaseFieldSet(false, true);
    when(crypto.isOpennet()).thenReturn(true);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class)) {
      versionMock.when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1")).thenReturn(505);

      FSParseException exception =
          assertThrows(
              FSParseException.class,
              () ->
                  PeerNodeConstructorSupport.prepareConstructorInit(
                      fs, node, crypto, false, peers, PeerNode.ConstructorProfile.OPENNET));

      assertTrue(exception.getMessage().contains("Trying to parse a darknet peer as opennet"));
    }
  }

  @Test
  void prepareConstructorInit_whenReadPeerEcdsaKeyFailsWithFsParseException_expectPropagated() {
    SimpleFieldSet fs = newBaseFieldSet(false, true);
    FSParseException expected = new FSParseException("bad key");

    when(crypto.isOpennet()).thenReturn(false);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class);
        MockedStatic<PeerNodeReferenceSupport> referenceMock =
            Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      versionMock.when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1")).thenReturn(606);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readPeerEcdsaKeyReturn(fs))
          .thenThrow(expected);

      FSParseException thrown =
          assertThrows(
              FSParseException.class,
              () ->
                  PeerNodeConstructorSupport.prepareConstructorInit(
                      fs, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET));

      assertSame(expected, thrown);
    }
  }

  @Test
  void prepareConstructorInit_whenReadPeerEcdsaKeyFailsWithOtherException_expectWrapped() {
    SimpleFieldSet fs = newBaseFieldSet(false, true);
    IllegalStateException expectedCause = new IllegalStateException("key boom");

    when(crypto.isOpennet()).thenReturn(false);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class);
        MockedStatic<PeerNodeReferenceSupport> referenceMock =
            Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      versionMock.when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1")).thenReturn(707);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readPeerEcdsaKeyReturn(fs))
          .thenThrow(expectedCause);

      FSParseException thrown =
          assertThrows(
              FSParseException.class,
              () ->
                  PeerNodeConstructorSupport.prepareConstructorInit(
                      fs, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET));

      assertEquals("Invalid peer ECDSA key", thrown.getMessage());
      assertSame(expectedCause, thrown.getCause());
    }
  }

  @Test
  void prepareConstructorInit_whenSignatureVerificationFails_expectWrappedFsParseException() {
    SimpleFieldSet fs = newBaseFieldSet(false, true);
    byte[] peerKeyHash = new byte[] {4, 4, 4};
    PeerNode.IdentityValues identityValues = newIdentityValues();
    RuntimeException expectedCause = new RuntimeException("sig boom");

    when(crypto.isOpennet()).thenReturn(false);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class);
        MockedStatic<PeerNodeReferenceSupport> referenceMock =
            Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      versionMock.when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1")).thenReturn(808);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readPeerEcdsaKeyReturn(fs))
          .thenReturn(peerEcdsaKey);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.computePeerPublicKeyHash(peerEcdsaKey))
          .thenReturn(peerKeyHash);
      referenceMock
          .when(
              () ->
                  PeerNodeReferenceSupport.verifySignatureForConstruction(
                      fs, false, peerEcdsaKey, true))
          .thenThrow(expectedCause);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readIdentityValues(fs, true, peerKeyHash))
          .thenReturn(identityValues);

      FSParseException thrown =
          assertThrows(
              FSParseException.class,
              () ->
                  PeerNodeConstructorSupport.prepareConstructorInit(
                      fs, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET));

      assertEquals("Invalid peer noderef signature", thrown.getMessage());
      assertSame(expectedCause, thrown.getCause());
    }
  }

  @Test
  void prepareConstructorInit_whenIdentityParseFailsWithFsParseException_expectPropagated() {
    SimpleFieldSet fs = newBaseFieldSet(false, true);
    byte[] peerKeyHash = new byte[] {5, 5, 5};
    FSParseException expected = new FSParseException("identity bad");
    PeerNodeReferenceSupport.SignatureVerificationResult signatureResult =
        new PeerNodeReferenceSupport.SignatureVerificationResult(true, null);

    when(crypto.isOpennet()).thenReturn(false);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class);
        MockedStatic<PeerNodeReferenceSupport> referenceMock =
            Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      versionMock.when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1")).thenReturn(909);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readPeerEcdsaKeyReturn(fs))
          .thenReturn(peerEcdsaKey);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.computePeerPublicKeyHash(peerEcdsaKey))
          .thenReturn(peerKeyHash);
      referenceMock
          .when(
              () ->
                  PeerNodeReferenceSupport.verifySignatureForConstruction(
                      fs, false, peerEcdsaKey, true))
          .thenReturn(signatureResult);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readIdentityValues(fs, true, peerKeyHash))
          .thenThrow(expected);

      FSParseException thrown =
          assertThrows(
              FSParseException.class,
              () ->
                  PeerNodeConstructorSupport.prepareConstructorInit(
                      fs, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET));

      assertSame(expected, thrown);
    }
  }

  @Test
  void prepareConstructorInit_whenIdentityParseFailsWithOtherException_expectWrapped() {
    SimpleFieldSet fs = newBaseFieldSet(false, true);
    byte[] peerKeyHash = new byte[] {6, 6, 6};
    IllegalArgumentException expectedCause = new IllegalArgumentException("identity boom");
    PeerNodeReferenceSupport.SignatureVerificationResult signatureResult =
        new PeerNodeReferenceSupport.SignatureVerificationResult(true, null);

    when(crypto.isOpennet()).thenReturn(false);
    when(crypto.getPacketMangler()).thenReturn(outgoingMangler);

    try (MockedStatic<Version> versionMock = Mockito.mockStatic(Version.class);
        MockedStatic<PeerNodeReferenceSupport> referenceMock =
            Mockito.mockStatic(PeerNodeReferenceSupport.class)) {
      versionMock.when(() -> Version.parseBuildNumberFromVersionStr("Cryptad,1")).thenReturn(1001);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readPeerEcdsaKeyReturn(fs))
          .thenReturn(peerEcdsaKey);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.computePeerPublicKeyHash(peerEcdsaKey))
          .thenReturn(peerKeyHash);
      referenceMock
          .when(
              () ->
                  PeerNodeReferenceSupport.verifySignatureForConstruction(
                      fs, false, peerEcdsaKey, true))
          .thenReturn(signatureResult);
      referenceMock
          .when(() -> PeerNodeReferenceSupport.readIdentityValues(fs, true, peerKeyHash))
          .thenThrow(expectedCause);

      FSParseException thrown =
          assertThrows(
              FSParseException.class,
              () ->
                  PeerNodeConstructorSupport.prepareConstructorInit(
                      fs, node, crypto, false, peers, PeerNode.ConstructorProfile.DARKNET));

      assertEquals("Invalid peer identity", thrown.getMessage());
      assertSame(expectedCause, thrown.getCause());
    }
  }

  private static SimpleFieldSet newBaseFieldSet(boolean opennet, boolean includeNegTypes) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    fs.putSingle("version", "Cryptad,1");
    fs.putSingle("lastGoodVersion", "Cryptad,1");
    fs.put("opennet", opennet);
    if (includeNegTypes) {
      fs.put("auth.negTypes", new int[] {5, 7});
    }
    return fs;
  }

  private static PeerNode.IdentityValues newIdentityValues() {
    return new PeerNode.IdentityValues(
        new byte[] {1, 1}, "id", new byte[] {2, 2}, new byte[] {3, 3}, 4L, 5);
  }
}
