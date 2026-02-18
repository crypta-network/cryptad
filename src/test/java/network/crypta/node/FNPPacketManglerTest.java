package network.crypta.node;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.ECDH;
import network.crypta.crypt.PCFBMode;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.io.comm.IncomingPacketFilter.DECODED;
import network.crypta.io.comm.PacketSocketHandler;
import network.crypta.io.comm.Peer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100")
class FNPPacketManglerTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeCrypto crypto;
  @Mock private PacketSocketHandler sock;

  private FNPPacketMangler mangler;

  private Peer loopbackPeer;

  @BeforeEach
  void setUp() throws UnknownHostException {
    mangler = new FNPPacketMangler(node, crypto, sock);
    loopbackPeer = new Peer(InetAddress.getAllByName("127.0.0.1")[0], 4242);

    // Defaults that keep control-flow simple for most tests
    lenient().when(node.isStopping()).thenReturn(false);
    lenient().when(node.network().opennet()).thenReturn(null);
    lenient().when(crypto.getPeerNodes()).thenReturn(new PeerNode[0]);
    lenient().when(crypto.wantAnonAuth()).thenReturn(false);
    lenient().when(crypto.wantAnonAuthChangeIP()).thenReturn(false);
  }

  @Test
  void process_whenNodeStopping_returnsShuttingDown() {
    when(node.isStopping()).thenReturn(true);

    DECODED result = mangler.process(new byte[8], 0, 8, loopbackPeer, null);

    assertSame(DECODED.SHUTTING_DOWN, result);
  }

  @Test
  void process_whenNoMatch_andOpennetNull_returnsNotDecoded() {
    when(node.isStopping()).thenReturn(false);
    when(node.network().opennet()).thenReturn(null); // no old opennet peers to try
    when(crypto.wantAnonAuth()).thenReturn(false); // skip anon paths entirely

    DECODED result = mangler.process(new byte[8], 0, 8, loopbackPeer, null);

    assertSame(DECODED.NOT_DECODED, result);
  }

  @Test
  void process_whenOpennetPresentButDoesNotWantPeer_returnsDidntWantOpenNet() {
    OpennetManager opennet = Mockito.mock(OpennetManager.class);
    when(node.network().opennet()).thenReturn(opennet);
    // Signal: do not want peers now → code must not try old peers and should return
    // DIDNT_WANT_OPENNET
    when(opennet.wantPeer(null, false, true, true, OpennetManager.ConnectionType.RECONNECT))
        .thenReturn(false);
    when(crypto.wantAnonAuth()).thenReturn(false);

    DECODED result = mangler.process(new byte[8], 0, 8, loopbackPeer, null);

    assertSame(DECODED.DIDNT_WANT_OPENNET, result);
  }

  @Test
  void process_whenOpnManglerMismatch_ignoresProvidedPeerNode_andContinues() {
    PeerNode opn = Mockito.mock(PeerNode.class);
    OutgoingPacketMangler other = Mockito.mock(OutgoingPacketMangler.class);
    when(opn.getOutgoingMangler()).thenReturn(other); // not equal to our mangler
    when(crypto.wantAnonAuth()).thenReturn(false);

    DECODED result = mangler.process(new byte[8], 0, 8, loopbackPeer, opn);

    // With no anon auth and no opennet, this falls back to NOT_DECODED
    assertSame(DECODED.NOT_DECODED, result);
  }

  @Test
  void process_whenValidAnonAuthPacket_returnsDecoded() throws UnsupportedCipherException {
    // Arrange anonymous-auth acceptance
    when(crypto.wantAnonAuth()).thenReturn(true);
    when(crypto.wantAnonAuthChangeIP()).thenReturn(false);

    // Provide a concrete cipher used by both encoder and mangler
    Rijndael cipher = new Rijndael(256, 128);
    byte[] key = new byte[32];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (i * 7 + 3);
    cipher.initialize(key);
    when(crypto.getAnonSetupCipher()).thenReturn(cipher);

    // Build a minimal anonymous-initiator payload (phase 0 → responder path)
    byte[] payload =
        new byte[] {
          1, // version
          10, // negType (only 10 is supported)
          0, // packetType (phase 1)
          1 // setupType = SETUP_OPENNET_SEEDNODE
        };

    byte[] packet = buildAnonAuthPacket(cipher, payload);

    // Act
    DECODED result = mangler.process(packet, 0, packet.length, loopbackPeer, null);

    // Assert
    assertSame(DECODED.SUCCESS, result);
  }

  @Test
  void process_whenAnonAuthPacketWithBadHash_returnsNotDecoded() throws UnsupportedCipherException {
    when(crypto.wantAnonAuth()).thenReturn(true);
    when(crypto.wantAnonAuthChangeIP()).thenReturn(false);

    Rijndael cipher = new Rijndael(256, 128);
    byte[] key = new byte[32];
    Arrays.fill(key, (byte) 0xA5);
    cipher.initialize(key);
    when(crypto.getAnonSetupCipher()).thenReturn(cipher);

    byte[] payload = new byte[] {1, 10, 0, 1};
    // Deliberately corrupt the hash while keeping structure intact
    byte[] packet =
        buildAnonAuthPacketWithCustomHash(cipher, payload, new byte[SHA256.getDigestLength()]);

    DECODED result = mangler.process(packet, 0, packet.length, loopbackPeer, null);

    assertEquals(DECODED.NOT_DECODED, result);
  }

  @Test
  void isValidJfk3HeaderLengths_rejectsEmptyNonce() {
    int modulusLength = ECDH.Curves.P256.modulusSize;

    boolean valid =
        FNPPacketMangler.isValidJfk3HeaderLengths(
            new byte[0],
            new byte[16],
            new byte[modulusLength],
            new byte[modulusLength],
            new byte[SHA256.getDigestLength()],
            modulusLength);

    assertFalse(valid);
  }

  @Test
  void isValidJfk3HeaderLengths_acceptsExpectedSizes() {
    int modulusLength = ECDH.Curves.P256.modulusSize;

    boolean valid =
        FNPPacketMangler.isValidJfk3HeaderLengths(
            new byte[16],
            new byte[16],
            new byte[modulusLength],
            new byte[modulusLength],
            new byte[SHA256.getDigestLength()],
            modulusLength);

    assertTrue(valid);
  }

  // --- helpers --------------------------------------------------------------

  /** Builds an anonymous-auth packet: IV | E(hash) | E(len_hi) E(len_lo) | E(payload). */
  private static byte[] buildAnonAuthPacket(BlockCipher cipher, byte[] payload) {
    byte[] hash = SHA256.digest(payload);
    return buildAnonAuthPacketWithCustomHash(cipher, payload, hash);
  }

  private static byte[] buildAnonAuthPacketWithCustomHash(
      BlockCipher cipher, byte[] payload, byte[] hash) {
    int ivLen = PCFBMode.lengthIV(cipher);
    byte[] iv = new byte[ivLen]; // deterministic zero IV is fine for tests
    PCFBMode p = PCFBMode.create(cipher, iv);

    byte[] encHash = Arrays.copyOf(hash, hash.length);
    p.blockEncipher(encHash, 0, encHash.length);

    int len = payload.length;
    int b1 = (len >>> 8) & 0xFF;
    int b2 = len & 0xFF;
    byte e1 = (byte) p.encipher(b1);
    byte e2 = (byte) p.encipher(b2);

    byte[] encPayload = Arrays.copyOf(payload, payload.length);
    p.blockEncipher(encPayload, 0, encPayload.length);

    byte[] out = new byte[ivLen + encHash.length + 2 + encPayload.length];
    int ofs = 0;
    System.arraycopy(iv, 0, out, ofs, ivLen);
    ofs += ivLen;
    System.arraycopy(encHash, 0, out, ofs, encHash.length);
    ofs += encHash.length;
    out[ofs++] = e1;
    out[ofs++] = e2;
    System.arraycopy(encPayload, 0, out, ofs, encPayload.length);
    return out;
  }
}
