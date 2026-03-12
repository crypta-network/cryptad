package network.crypta.node;

import java.io.File;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.HashMap;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.ECDH;
import network.crypta.crypt.ECDHLightContext;
import network.crypta.crypt.ECDSA.Curves;
import network.crypta.crypt.ECDSA;
import network.crypta.crypt.HMAC;
import network.crypta.crypt.KeyAgreementSchemeContext;
import network.crypta.crypt.PCFBMode;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.Util;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.io.AddressTracker;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.IncomingPacketFilter.DECODED;
import network.crypta.io.comm.IncomingPacketFilter;
import network.crypta.io.comm.PacketSocketHandler;
import network.crypta.io.comm.Peer.LocalAddressException;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerContext;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.io.comm.SocketHandler;
import network.crypta.node.OpennetManager.ConnectionType;
import network.crypta.support.ByteArrayWrapper;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;
import network.crypta.support.LRUMap;
import network.crypta.support.SerialExecutor;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.io.FileUtil;
import network.crypta.support.io.InetAddressComparator;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.concurrent.TimeUnit.MINUTES;
import static java.util.concurrent.TimeUnit.SECONDS;

/**
 * Handles authenticated connection setup and complex packet decoding.
 *
 * <p>This component recognizes, decrypts, and validates negotiation packets when the sender is not
 * yet known with certainty. It implements the Just Fast Keying (JFKi) handshake with an outer
 * obfuscation layer keyed by both the remote peer identity and the local node identity.
 *
 * <p>Threading: the class is generally called from I/O threads; expensive or multi‑step handshake
 * processing is offloaded to a dedicated high‑priority {@link SerialExecutor} to preserve
 * responsiveness.
 *
 * <p>Side effects: may send handshake packets, update peer state (trackers/keys), and schedule
 * retries. All I/O occurs via the provided {@link PacketSocketHandler}.
 *
 * @author amphibian
 * @see IncomingPacketFilter
 * @see NewPacketFormat
 */
public class FNPPacketMangler implements OutgoingPacketMangler {
  private static final Logger LOG = LoggerFactory.getLogger(FNPPacketMangler.class);

  private final Node node;
  private final NodeCrypto crypto;
  private final PacketSocketHandler sock;

  /**
   * Cache of JFK(3)/JFK(4) messages keyed by their authenticator (HMAC).
   *
   * <p>Lookups are constant time by design to allow quick replay handling when duplicates arrive.
   */
  private final HashMap<ByteArrayWrapper, byte[]> authenticatorCache;

  /** The following is used in the HMAC calculation of JFK message3 and message4 */
  private static final byte[] JFK_PREFIX_INITIATOR = "I".getBytes(StandardCharsets.UTF_8);

  private static final byte[] JFK_PREFIX_RESPONDER = "R".getBytes(StandardCharsets.UTF_8);

  /* How often to generate a fresh ECDH context and append it to the FIFO. */
  public static final int DH_GENERATION_INTERVAL = 30000; // 30sec
  /* Maximum FIFO size. */
  public static final int DH_CONTEXT_BUFFER_SIZE = 20;
  /*
   * FIFO of pre-generated ECDH contexts.
   * Must hold the lock on {@code ecdhContextFIFO} before accessing.
   */
  private final ArrayDeque<ECDHLightContext> ecdhContextFIFO = new ArrayDeque<>();
  private ECDHLightContext ecdhContextToBePrunned;
  private static final ECDH.Curves ecdhCurveToUse = ECDH.Curves.P256;
  private long jfkECDHLastGenerationTimestamp = 0;

  private static final int HASH_LENGTH = SHA256.getDigestLength();

  /** The size in bytes of the transient key used to authenticate the HMAC. */
  private static final int TRANSIENT_KEY_SIZE = HASH_LENGTH;

  /** Nonce size for current negotiation types (bytes). */
  private static final int NONCE_SIZE = 16;

  private static final String FOR_STR = " for ";
  private static final String DATA_LENGTH_PREFIX = "Data length: ";
  private static final String ONE_EQ_STR = " (1 = ";
  private static final String TWO_EQ_STR = " 2 = ";
  private static final String LENGTH_STR = " length ";
  private static final String NT_STR = ", nt=";
  private static final String RIGHT_PAREN_FROM = ") from ";
  private static final String FROM_STR = " from ";
  private static final String POSSIBLY_FROM_STR = " possibly from ";
  private static final String JFK3_STR = "JFK(3)";
  private static final String HASH_STR = " hash ";
  private static final byte[] EMPTY_BYTES = new byte[0];

  /** The key used to authenticate the hmac */
  private final byte[] transientKey = new byte[TRANSIENT_KEY_SIZE];

  public static final long TRANSIENT_KEY_REKEYING_MIN_INTERVAL = MINUTES.toMillis(30);

  /** Rekeying interval for per-session packet tracker keys. */
  public static final long SESSION_KEY_REKEYING_INTERVAL = MINUTES.toMillis(60);

  /**
   * The max amount of time we will accept to use the current tracker when it should have been
   * replaced
   */
  public static final long MAX_SESSION_KEY_REKEYING_DELAY = MINUTES.toMillis(5);

  /** Number of plaintext bytes sent before requesting a rekey. */
  public static final int AMOUNT_OF_BYTES_ALLOWED_BEFORE_WE_REKEY = 1024 * 1024 * 1024;

  /** Periodic task that rotates the transient key on schedule. */
  private final Runnable transientKeyRekeyer = this::maybeResetTransientKey;

  private long lastConnectivityStatusUpdate;
  private AddressTracker.Status lastConnectivityStatus;

  public FNPPacketMangler(Node node, NodeCrypto crypt, PacketSocketHandler sock) {
    this.node = node;
    this.crypto = crypt;
    this.sock = sock;
    authenticatorCache = new HashMap<>();
  }

  /**
   * Initializes cryptographic state and background processing.
   *
   * <p>Side effects: derives an initial transient key, pre-fills the ECDH context FIFO, and starts
   * the high‑priority authentication handler thread.
   */
  public void start() {
    // Run it directly so that the transient key is set.
    maybeResetTransientKey();
    // Fill the DH FIFO on-thread
    for (int i = 0; i < DH_CONTEXT_BUFFER_SIZE; i++) {
      fillJfkEcdhFifo();
    }
    this.authHandlingThread.start(
        node.network().executor(), "FNP incoming auth packet handler thread");
  }

  /**
   * Attempts to decrypt and authenticate an incoming packet.
   *
   * <p>This method inspects the buffer at {@code offset} for a supported handshake format, attempts
   * to identify the sender, and performs integrity checks. On success, it forwards the packet to
   * the appropriate handlers. The provided buffer may be modified in-place during deciphering.
   *
   * @param buf input buffer containing the received packet (mutable)
   * @param offset start offset into {@code buf}
   * @param length number of bytes at {@code buf[offset..offset+length)}
   * @param peer network endpoint the packet arrived from
   * @param opn an expected {@link PeerNode} match, or {@code null} when unknown
   * @return a {@link DECODED} status describing whether and how the packet was handled
   */
  public DECODED process(byte[] buf, int offset, int length, Peer peer, PeerNode opn) {
    opn = sanitizePeerOrNull(opn);

    final boolean wantAnonAuth = crypto.wantAnonAuth();
    // Read once so tests and logic consistently observe the value even if we return early.
    if (LOG.isTraceEnabled() && wantAnonAuth && crypto.wantAnonAuthChangeIP()) {
      LOG.trace("AnonAuth change IP permitted");
    }

    if (tryExactPeerMatch(buf, offset, length, peer, opn)) return DECODED.SUCCESS;

    if (node.isStopping()) return DECODED.SHUTTING_DOWN;

    if (tryPeersAuthOrAnon(buf, offset, length, peer, opn, wantAnonAuth)) return DECODED.SUCCESS;

    if (maybeHandleAnonAuthChangeIPCombined(wantAnonAuth, opn, buf, offset, length, peer))
      return DECODED.SUCCESS;

    // Try legacy/old opennet peers. If one succeeds, return DECODED immediately.
    OldOpennetTryResult oldOpennetResult = tryOldOpennetPeers(buf, offset, length, peer);
    if (oldOpennetResult == OldOpennetTryResult.SUCCEEDED) return DECODED.SUCCESS;
    boolean didntTryOldOpennetPeers = oldOpennetResult == OldOpennetTryResult.DIDNT_TRY;

    // peers/anon already tried; no additional anon-auth checks needed here

    logUnmatchable(peer, wantAnonAuth, didntTryOldOpennetPeers);
    return !didntTryOldOpennetPeers ? DECODED.NOT_DECODED : DECODED.DIDNT_WANT_OPENNET;
  }

  private boolean tryExactPeerMatch(byte[] buf, int offset, int length, Peer peer, PeerNode opn) {
    if (opn == null) return false;
    if (LOG.isDebugEnabled()) LOG.debug("Trying exact match");
    if (length <= Node.SYMMETRIC_KEY_LENGTH /* iv */ + HASH_LENGTH + 2 || node.isStopping())
      return false;
    if (tryProcessAuth(buf, offset, length, opn, peer, false)) return true;
    return tryProcessAuthAnonReply(buf, offset, length, opn, peer);
  }

  private boolean tryPeersAuthExcept(
      byte[] buf, int offset, int length, Peer peer, PeerNode exclude) {
    PeerNode[] peers = crypto.getPeerNodes();
    if (peers == null) return false;
    for (PeerNode pn : peers) {
      if (java.util.Objects.equals(pn, exclude)) continue;
      if (LOG.isTraceEnabled()) LOG.trace("Trying auth with {}", pn);
      if (tryProcessAuth(buf, offset, length, pn, peer, false)) return true;
      if (pn.handshakeUnknownInitiator() && tryProcessAuthAnonReply(buf, offset, length, pn, peer))
        return true;
    }
    return false;
  }

  private PeerNode sanitizePeerOrNull(PeerNode opn) {
    if (opn != null && opn.getOutgoingMangler() != this) {
      LOG.warn("Contact arrives from {} on {}", opn, this);
      return null;
    }
    return opn;
  }

  private boolean tryPeersAuthExceptOrSkipByLength(
      byte[] buf, int offset, int length, Peer peer, PeerNode exclude) {
    if (length <= Node.SYMMETRIC_KEY_LENGTH /* iv */ + HASH_LENGTH + 2) return false;
    return tryPeersAuthExcept(buf, offset, length, peer, exclude);
  }

  private boolean tryPeersAuthOrAnon(
      byte[] buf, int offset, int length, Peer peer, PeerNode exclude, boolean wantAnonAuth) {
    if (tryPeersAuthExceptOrSkipByLength(buf, offset, length, peer, exclude)) return true;
    return wantAnonAuth && tryProcessAuthAnon(buf, offset, length, peer);
  }

  private enum OldOpennetTryResult {
    DIDNT_TRY,
    TRIED_AND_FAILED,
    SUCCEEDED
  }

  private OldOpennetTryResult tryOldOpennetPeers(byte[] buf, int offset, int length, Peer peer) {
    OpennetManager opennet = node.network().opennet();
    boolean wantOldPeers =
        opennet != null && opennet.wantPeer(null, false, true, true, ConnectionType.RECONNECT);
    if (wantOldPeers) {
      for (PeerNode oldPeer : opennet.getOldPeers()) {
        if (tryProcessAuth(buf, offset, length, oldPeer, peer, true)) {
          return OldOpennetTryResult.SUCCEEDED;
        }
      }
      return OldOpennetTryResult.TRIED_AND_FAILED;
    }
    // When we get here, wantOldPeers is false. If opennet exists but doesn't want
    // reconnections now, we didn't try; otherwise (no opennet) we treat as tried-and-failed
    // for the caller's fallback handling.
    return (opennet != null) ? OldOpennetTryResult.DIDNT_TRY : OldOpennetTryResult.TRIED_AND_FAILED;
  }

  private boolean maybeHandleAnonAuthChangeIPCombined(
      boolean wantAnonAuth, PeerNode opn, byte[] buf, int offset, int length, Peer peer) {
    if (!wantAnonAuth) return false;
    return checkAnonAuthChangeIP(opn, buf, offset, length, peer);
  }

  // combined; no separate 'after' needed once peers/anon were tried

  private void logUnmatchable(Peer peer, boolean wantAnonAuth, boolean didntTryOldOpennetPeers) {
    if (LOG.isDebugEnabled() && crypto.isOpennet() && wantAnonAuth) {
      if (!didntTryOldOpennetPeers) LOG.debug("Unmatchable packet (opennet path) from {}", peer);
    } else {
      LOG.info("Unmatchable packet (fallback path) from {}", peer);
    }
  }

  private boolean checkAnonAuthChangeIP(
      PeerNode opn, byte[] buf, int offset, int length, Peer peer) {
    PeerNode[] anonPeers = crypto.getAnonSetupPeerNodes();
    if (length > Node.SYMMETRIC_KEY_LENGTH /* iv */ + HASH_LENGTH + 3) {
      for (PeerNode pn : anonPeers) {
        if (java.util.Objects.equals(pn, opn)) continue;
        if (tryProcessAuthAnonReply(buf, offset, length, pn, peer)) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Determines whether the packet is a negotiation message and, if so, processes it.
   *
   * @param buf the buffer to read from
   * @param offset start position in {@code buf}
   * @param length total bytes available from {@code offset}
   * @param pn candidate peer
   * @param peer remote endpoint for any reply
   * @return {@code true} when a negotiation packet was recognized and handled
   */
  private boolean tryProcessAuth(
      byte[] buf, int offset, int length, PeerNode pn, Peer peer, boolean oldOpennetPeer) {
    BlockCipher authKey = (BlockCipher) pn.handshake().incomingSetupCipher();
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Auth decrypt key present (len={})" + FOR_STR + "{} : {} in tryProcessAuth",
          pn.incomingSetupKey.length,
          peer,
          pn);
    // Does the packet match IV E( H(data) data ) ?
    int ivLength = PCFBMode.lengthIV(authKey);
    int digestLength = HASH_LENGTH;
    if (isTooShortForAuth(length, ivLength, digestLength)) {
      logTooShortOrWrongTracker(length, ivLength, digestLength, buf);
      return false;
    }
    // IV at the beginning
    PCFBMode pcfb = PCFBMode.create(authKey, buf, offset);
    // Then the hash, then the data
    // => Data starts at ivLength + digestLength
    // Decrypt the hash
    byte[] hash = Arrays.copyOfRange(buf, offset + ivLength, offset + ivLength + digestLength);
    pcfb.blockDecipher(hash, 0, hash.length);

    int dataStart = ivLength + digestLength + offset + 2;

    int byte1 = (pcfb.decipher(buf[dataStart - 2]) & 0xff);
    int byte2 = (pcfb.decipher(buf[dataStart - 1]) & 0xff);
    int dataLength = (byte1 << 8) + byte2;
    if (LOG.isTraceEnabled())
      LOG.trace(
          "Auth " + DATA_LENGTH_PREFIX + "{}" + ONE_EQ_STR + "{}" + TWO_EQ_STR + "{})",
          dataLength,
          byte1,
          byte2);
    if (!isValidDataLength(dataLength, length, ivLength, hash.length)) {
      logInvalidDataLength(dataLength, length, ivLength, hash.length);
      return false;
    }
    // Decrypt the data
    byte[] payload = Arrays.copyOfRange(buf, dataStart, dataStart + dataLength);
    pcfb.blockDecipher(payload, 0, payload.length);

    byte[] realHash = SHA256.digest(payload);

    if (MessageDigest.isEqual(realHash, hash)) {
      // Got one
      processDecryptedAuth(payload, pn, peer, oldOpennetPeer);
      pn.reportIncomingBytes(length);
      return true;
    } else {
      logIncorrectHashAuth(peer, dataLength, realHash, hash);
      return false;
    }
  }

  private static boolean isTooShortForAuth(int length, int ivLength, int digestLength) {
    return length < digestLength + ivLength + 4;
  }

  private void logTooShortOrWrongTracker(int length, int ivLength, int digestLength, byte[] buf) {
    if (!LOG.isDebugEnabled()) return;
    if (buf.length < length) {
      LOG.debug(
          "The packet is smaller than the decrypted size: it's probably the wrong tracker ({}<{})",
          buf.length,
          length);
    } else {
      LOG.debug(
          "Auth packet too short (known peer): {} should be at least {}",
          length,
          (digestLength + ivLength + 4));
    }
  }

  private static boolean isValidDataLength(
      int dataLength, int packetLength, int ivLength, int hashLength) {
    return dataLength <= packetLength - (ivLength + hashLength + 2);
  }

  private void logInvalidDataLength(int dataLength, int length, int ivLength, int hashLen) {
    if (!LOG.isDebugEnabled()) return;
    LOG.debug(
        "Auth packet invalid data length: {} (max={})",
        dataLength,
        (length - (ivLength + hashLen + 2)));
  }

  private void logIncorrectHashAuth(Peer peer, int dataLength, byte[] realHash, byte[] badHash) {
    if (!LOG.isDebugEnabled()) return;
    LOG.debug(
        "Auth packet hash mismatch for {} (length={}, hashLen={}, expectedHashLen={})",
        peer,
        dataLength,
        realHash.length,
        badHash.length);
  }

  /**
   * Processes an anonymous‑initiator negotiation packet while acting as the responder.
   *
   * @param buf the buffer to read from
   * @param offset start position in {@code buf}
   * @param length total bytes available from {@code offset}
   * @param peer remote endpoint for any reply
   * @return {@code true} when a negotiation packet was recognized and handled
   */
  private boolean tryProcessAuthAnon(byte[] buf, int offset, int length, Peer peer) {
    BlockCipher authKey = crypto.getAnonSetupCipher();
    // Does the packet match IV E( H(data) data ) ?
    int ivLength = PCFBMode.lengthIV(authKey);
    int digestLength = HASH_LENGTH;
    if (length < digestLength + ivLength + 5) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Anon auth packet too short (responder): {} should be at least {}",
            length,
            digestLength + ivLength + 5);
      return false;
    }
    // IV at the beginning
    PCFBMode pcfb = PCFBMode.create(authKey, buf, offset);
    // Then the hash, then the data
    // => Data starts at ivLength + digestLength
    // Decrypt the hash
    byte[] hash = Arrays.copyOfRange(buf, offset + ivLength, offset + ivLength + digestLength);
    pcfb.blockDecipher(hash, 0, hash.length);

    int dataStart = ivLength + digestLength + offset + 2;

    int byte1 = (pcfb.decipher(buf[dataStart - 2]) & 0xff);
    int byte2 = (pcfb.decipher(buf[dataStart - 1]) & 0xff);
    int dataLength = (byte1 << 8) + byte2;
    if (LOG.isTraceEnabled())
      LOG.trace(
          "Anon auth " + DATA_LENGTH_PREFIX + "{}" + ONE_EQ_STR + "{}" + TWO_EQ_STR + "{})",
          dataLength,
          byte1,
          byte2);
    if (dataLength > length - (ivLength + hash.length + 2)) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Anon auth packet invalid data length: {} (max={})",
            dataLength,
            length - (ivLength + hash.length + 2));
      return false;
    }
    // Decrypt the data
    byte[] payload = Arrays.copyOfRange(buf, dataStart, dataStart + dataLength);
    pcfb.blockDecipher(payload, 0, payload.length);

    byte[] realHash = SHA256.digest(payload);

    if (MessageDigest.isEqual(realHash, hash)) {
      // Got one
      processDecryptedAuthAnon(payload, peer);
      return true;
    } else {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Anon auth packet hash mismatch for {} (length={}, hashLen={})",
            peer,
            dataLength,
            realHash.length);
      return false;
    }
  }

  /**
   * Processes a reply to an anonymous‑initiator negotiation while acting as the initiator.
   *
   * @param buf the buffer to read from
   * @param offset start position in {@code buf}
   * @param length total bytes available from {@code offset}
   * @param pn the peer we believe is responsible
   * @param peer remote endpoint for any reply
   * @return {@code true} when a negotiation packet was recognized and handled
   */
  private boolean tryProcessAuthAnonReply(
      byte[] buf, int offset, int length, PeerNode pn, Peer peer) {
    BlockCipher authKey = (BlockCipher) pn.handshake().anonymousInitiatorSetupCipher();
    // Does the packet match IV E( H(data) data ) ?
    int ivLength = PCFBMode.lengthIV(authKey);
    int digestLength = HASH_LENGTH;
    if (length < digestLength + ivLength + 5) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Anon auth reply packet too short (initiator): {} should be at least {}",
            length,
            digestLength + ivLength + 5);
      return false;
    }
    // IV at the beginning
    PCFBMode pcfb = PCFBMode.create(authKey, buf, offset);
    // Then the hash, then the data
    // => Data starts at ivLength + digestLength
    // Decrypt the hash
    byte[] hash = Arrays.copyOfRange(buf, offset + ivLength, offset + ivLength + digestLength);
    pcfb.blockDecipher(hash, 0, hash.length);

    int dataStart = ivLength + digestLength + offset + 2;

    int byte1 = (pcfb.decipher(buf[dataStart - 2]) & 0xff);
    int byte2 = (pcfb.decipher(buf[dataStart - 1]) & 0xff);
    int dataLength = (byte1 << 8) + byte2;
    if (LOG.isTraceEnabled())
      LOG.trace(
          "Anon auth reply " + DATA_LENGTH_PREFIX + "{}" + ONE_EQ_STR + "{}" + TWO_EQ_STR + "{})",
          dataLength,
          byte1,
          byte2);
    if (dataLength > length - (ivLength + hash.length + 2)) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Anon auth reply invalid data length: {} (max={})",
            dataLength,
            length - (ivLength + hash.length + 2));
      return false;
    }
    // Decrypt the data
    byte[] payload = Arrays.copyOfRange(buf, dataStart, dataStart + dataLength);
    pcfb.blockDecipher(payload, 0, payload.length);

    byte[] realHash = SHA256.digest(payload);

    if (MessageDigest.isEqual(realHash, hash)) {
      // Got one
      processDecryptedAuthAnonReply(payload, peer, pn);
      return true;
    } else {
      if (LOG.isDebugEnabled())
        LOG.debug(
            """
            Anon auth reply hash mismatch for {} (length={}, hashLen={})
            """,
            peer,
            dataLength,
            realHash.length);
      return false;
    }
  }

  // Anonymous-initiator setup types
  /** Connect to a node hoping it will act as a seednode for us */
  static final byte SETUP_OPENNET_SEEDNODE = 1;

  /**
   * Process an anonymous-initiator connection setup packet. For a normal setup (see {@link
   * #processDecryptedAuth(byte[], PeerNode, Peer, boolean)}), we know the node trying to contact
   * us. But in this case, we don't know the node yet, and we are doing a special-purpose connection
   * setup. At the moment the only type supported is for a new node connecting to a seednode to
   * announce. In the future, nodes may support other anonymous-initiator connection types such as
   * when a node (which is certain of its connectivity) issues one-time invites which allow a new
   * node to connect to it.
   *
   * @param payload The decrypted payload of the packet.
   * @param replyTo The address the packet came in from.
   */
  private void processDecryptedAuthAnon(final byte[] payload, final Peer replyTo) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Anon auth responder packet decrypted from {}" + LENGTH_STR + "{}",
          replyTo,
          payload.length);

    /* Protocol version. Should be 1. */
    final int version = payload[0];
    /*
     * Negotiation type. Common to anonymous-initiator auth and normal setup. 2 = JFK. 3 = JFK,
     * reuse PacketTracker Other types might indicate other DH variants or even non-DH-based
     * algorithms such as password-based key setup.
     */
    final int negType = payload[1];
    /* Packet phase. */
    final int packetType = payload[2];
    /*
     * Setup type. This is specific to anonymous-initiator setup and specifies the purpose of the
     * connection. At the moment it is SETUP_OPENNET_SEEDNODE to indicate we are connecting to a
     * seednode (which doesn't know us). Invites might require a different setupType.
     */
    final int setupType = payload[3];

    if (LOG.isDebugEnabled())
      LOG.debug(
          "Received anonymous auth reply packet (phase={}, v={}"
              + NT_STR
              + "{}, setup type={}"
              + RIGHT_PAREN_FROM
              + "{}",
          packetType,
          version,
          negType,
          setupType,
          replyTo);

    if (version != 1) {
      LOG.error("Anon auth responder: invalid protocol version {}", version);
      return;
    }
    if (negType != 10) {
      if (negType > 10) LOG.error("Unknown neg type in anon reply: {}", negType);
      else
        LOG.warn(
            "Received anon reply setup packet with unsupported obsolete neg type: {}", negType);
      return;
    }

    // Known setup types
    if (setupType != SETUP_OPENNET_SEEDNODE) {
      LOG.error("Anon reply: unknown setup type (negType={})", negType);
      return;
    }

    // We are the RESPONDER.
    // Therefore, we can only get packets of phases 1 and 3 here.

    if (packetType == 0 || packetType == 2) {
      // avoid redundant condition warnings
      this.authHandlingThread.execute(
          () -> {
            JfkNegotiationParams negotiation = new JfkNegotiationParams(true, setupType, negType);
            if (packetType == 0) {
              // Phase 1
              processJFKMessage1(payload, 4, null, replyTo, negotiation);
            } else {
              // Phase 3
              processJFKMessage3(payload, 4, new J3Ctx(null, replyTo), false, negotiation);
            }
          });
    } else {
      LOG.error("Anon-initiator responder invalid phase {} from {}", packetType, replyTo);
    }
  }

  private void processDecryptedAuthAnonReply(
      final byte[] payload, final Peer replyTo, final PeerNode pn) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Anon auth initiator packet decrypted from {}" + FOR_STR + "{}" + LENGTH_STR + "{}",
          replyTo,
          pn,
          payload.length);

    /* Protocol version. Should be 1. */
    final int version = payload[0];
    /*
     * Negotiation type. 2 = JFK. 3 = JFK, reuse PacketTracker Other types might indicate other DH
     * variants or even non-DH-based algorithms such as password-based key setup.
     */
    final int negType = payload[1];
    /* Packet phase. */
    final int packetType = payload[2];
    /* Setup type. See above. */
    final int setupType = payload[3];

    if (LOG.isDebugEnabled())
      LOG.debug(
          "Received anonymous auth packet (phase={}, v={}"
              + NT_STR
              + "{}, setup type={}"
              + RIGHT_PAREN_FROM
              + "{}",
          packetType,
          version,
          negType,
          setupType,
          replyTo);

    if (version != 1) {
      LOG.error("Anon auth initiator: invalid protocol version {}", version);
      return;
    }
    if (negType != 10) {
      if (negType > 10) LOG.error("Unknown neg type in anon request: {}", negType);
      else
        LOG.warn(
            "Received anon request setup packet with unsupported obsolete neg type: {}", negType);
      return;
    }

    // Known setup types
    if (setupType != SETUP_OPENNET_SEEDNODE) {
      LOG.error("Anon request: unknown setup type (negType={})", negType);
      return;
    }

    // We are the INITIATOR.
    // Therefore, we can only get packets of phases 2 and 4 here.

    if (packetType == 1 || packetType == 3) {
      // avoid redundant condition warnings
      authHandlingThread.execute(
          () -> {
            JfkNegotiationParams negotiation = new JfkNegotiationParams(true, setupType, negType);
            if (packetType == 1) {
              // Phase 2
              processJFKMessage2(payload, 4, pn, replyTo, negotiation);
            } else {
              // Phase 4
              processJFKMessage4(payload, 4, pn, replyTo, false, negType);
            }
          });

    } else {
      LOG.error("Anon-initiator initiator invalid phase {} from {}", packetType, replyTo);
    }
  }

  private final SerialExecutor authHandlingThread =
      new SerialExecutor(NativeThread.PriorityLevel.HIGH_PRIORITY.value, 1000);

  /**
   * Process a decrypted, authenticated auth packet.
   *
   * @param payload The packet payload, after it has been decrypted.
   */
  private void processDecryptedAuth(
      final byte[] payload, final PeerNode pn, final Peer replyTo, final boolean oldOpennetPeer) {
    if (LOG.isDebugEnabled())
      LOG.debug("Auth packet decrypted from {}" + FOR_STR + "{}", replyTo, pn);
    if (pn.isDisabled()) {
      if (LOG.isDebugEnabled()) LOG.debug("Won't connect to a disabled peer ({})", pn);
      return; // We don't connect to disabled peers
    }

    final int negType = payload[1];
    final int packetType = payload[2];
    final int version = payload[0];

    if (LOG.isDebugEnabled()) {
      long now = System.currentTimeMillis();
      long last = pn.lastSentPacketTime();
      String delta = "never";
      if (last > 0) {
        delta = TimeUtil.formatTime(now - last, 2, true) + " ago";
      }
      LOG.debug(
          "Received auth packet for {} (phase={}, v={}"
              + NT_STR
              + "{}) (last sent {}"
              + RIGHT_PAREN_FROM
              + "{}",
          pn.getPeer(),
          packetType,
          version,
          negType,
          delta,
          replyTo);
    }

    /* Format:
     * 1 byte - version number (1)
     * 1 byte - negotiation type (0 = simple DH, will not be supported when implement JFKi || 1 = StS)
     * 1 byte - packet type (0-3)
     */
    if (version != 1) {
      LOG.error("Auth packet: invalid protocol version {}", version);
      return;
    }

    handleNegTypePacket(negType, packetType, payload, pn, replyTo, oldOpennetPeer);
  }

  private void handleNegTypePacket(
      int negType,
      int packetType,
      byte[] payload,
      PeerNode pn,
      Peer replyTo,
      boolean oldOpennetPeer) {
    if (negType >= 0 && negType < 10) {
      LOG.warn("Obsolete neg type {} not supported", negType);
      return;
    }
    if (negType == 10) {
      if (packetType < 0 || packetType > 3) {
        LOG.error("Unknown packetType {} from {} from {}", packetType, replyTo, pn);
        return;
      }
      JfkNegotiationParams negotiation = new JfkNegotiationParams(false, -1, negType);
      authHandlingThread.execute(
          () -> {
            switch (packetType) {
              case 0 -> processJFKMessage1(payload, 3, pn, replyTo, negotiation);
              case 1 -> processJFKMessage2(payload, 3, pn, replyTo, negotiation);
              case 2 ->
                  processJFKMessage3(
                      payload, 3, new J3Ctx(pn, replyTo), oldOpennetPeer, negotiation);
              default -> // packetType == 3 (validated above)
                  processJFKMessage4(payload, 3, pn, replyTo, oldOpennetPeer, negType);
            }
          });
      return;
    }
    LOG.error(
        "Decrypted auth packet but unknown negotiation type {}"
            + FROM_STR
            + "{}"
            + POSSIBLY_FROM_STR
            + "{}",
        negType,
        replyTo,
        pn);
  }

  /**
   * Validates that the decrypted JFK(3) payload is at least the expected length. On failure, logs a
   * concise error including the peer and context.
   */
  private boolean hasExpectedLength(byte[] payload, int expectedLength, PeerNode pn) {
    if (payload.length >= expectedLength) return true;
    LOG.error(
        "event=jfk3_packet_too_short from {}: {} bytes, expected at least {}",
        pn,
        payload.length,
        expectedLength);
    return false;
  }

  private boolean verifyJFK3Authenticator(
      long t1, byte[] authenticator, ReplayFields replayFields, Peer replyTo) {
    boolean ok =
        HMAC.verifyWithSHA256(
            getTransientKey(),
            assembleJFKAuthenticator(
                replayFields.responderExponential,
                replayFields.initiatorExponential,
                replayFields.nonceResponder,
                replayFields.nonceInitiatorHashed,
                replyTo.getAddress().getAddress()),
            authenticator);
    if (ok) return true;
    if (shouldLogErrorInHandshake(t1)) {
      if (LOG.isTraceEnabled())
        LOG.debug("Received JFK(3) authenticator HMAC (len={})", authenticator.length);
      if (LOG.isTraceEnabled())
        LOG.trace(
            "Initiator nonce hash received (len={})", replayFields.nonceInitiatorHashed.length);
      LOG.info(
          "The HMAC doesn't match; let's discard the packet (either we rekeyed or we are victim of"
              + " forgery) - JFK3 - {}",
          replyTo);
    }
    return false;
  }

  private boolean tryReplayMessage4(
      JfkNegotiationParams negotiation,
      PeerNode pn,
      Peer replyTo,
      byte[] authenticator,
      ReplayFields rf) {
    Object message4;
    synchronized (authenticatorCache) {
      message4 = authenticatorCache.get(new ByteArrayWrapper(authenticator));
    }
    if (message4 == null) {
      if (LOG.isDebugEnabled())
        LOG.debug(
            "No message4 found for authenticator (len={}) responderExponential {}"
                + " initiatorExponential {} nonceResponder {} nonceInitiator {} addressLen {}",
            authenticator.length,
            Fields.hashCode(rf.responderExponential),
            Fields.hashCode(rf.initiatorExponential),
            Fields.hashCode(rf.nonceResponder),
            Fields.hashCode(rf.nonceInitiatorHashed),
            replyTo.getAddress().getAddress().length);
      return false;
    }
    LOG.info("Replayed message4 from cache - {}", pn);
    if (negotiation.unknownInitiator()) {
      sendAnonAuthPacket(
          negotiation.negType(),
          3,
          negotiation.setupType(),
          (byte[]) message4,
          null,
          replyTo,
          crypto.getAnonSetupCipher());
    } else {
      sendAuthPacket(negotiation.negType(), 3, (byte[]) message4, pn, replyTo);
    }
    return true;
  }

  // Removed validateECDHContext(): inlined specific logging at call sites to simplify flow.

  /**
   * Validates the inner HMAC for a JFK message. Returns {@code true} when the HMAC is invalid
   * (failure) and logs a concise error; returns {@code false} when valid.
   */
  private boolean isInnerHmacInvalid(
      byte[] ka, byte[] decypheredPayload, byte[] hmac, PeerNode pn, String where) {
    if (HMAC.verifyWithSHA256(ka, decypheredPayload, hmac)) return false;
    LOG.error("Inner HMAC mismatch; discard packet {} - {}", where, pn);
    return true;
  }

  private boolean validatePeerNode(PeerNode pn, boolean unknownInitiator) {
    if (pn != null) return true;
    if (unknownInitiator) LOG.info("Rejecting; unable to construct PeerNode");
    else LOG.error("PeerNode is null and unknownInitiator is false");
    return false;
  }

  /**
   * Verifies the ECDSA signature for JFK(3) using the peer's public key. Logs a clear error on
   * failure with context.
   */
  private boolean verifyECDSASignature(PeerNode pn, byte[] sig, byte[] toVerify) {
    if (ECDSA.verify(Curves.P256, pn.peerECDSAPubKey, sig, toVerify)) return true;
    LOG.error("ECDSA signature verification fails {} - {}", JFK3_STR, pn.getPeer());
    return false;
  }

  private void logGotJfk3Message(PeerNode pn) {
    if (LOG.isDebugEnabled()) LOG.debug("JFK(3) inbound: processing handshake payload - {}", pn);
  }

  private void traceReceivingNi(byte[] nonceInitiator) {
    if (LOG.isTraceEnabled()) LOG.trace("Receiving Ni (len={})", nonceInitiator.length);
  }

  private void debugInitialMessageIds(int theirInitialMsgID, int ourInitialMsgID) {
    if (LOG.isDebugEnabled())
      LOG.debug(
          "JFK(2) initial message IDs: theirs={} ours={}", theirInitialMsgID, ourInitialMsgID);
  }

  private boolean handleOldOpennetPromotion(boolean oldOpennetPeer, PeerNode pn) {
    boolean dontWant = false;
    if (oldOpennetPeer && pn instanceof OpennetPeerNode opn /* true */) {
      OpennetManager opennet = node.network().opennet();
      if (opennet == null) {
        LOG.info("Drop incoming old-opennet peer; opennet disabled: {}.", pn);
        return true; // signal caller to stop further work
      }
      if (!opennet.wantPeer(opn, false, false, true, ConnectionType.RECONNECT)) {
        LOG.info("No longer want peer {}; drop after connecting", pn);
        dontWant = true;
        opennet.purgeOldOpennetPeer(opn);
      }
    }
    return dontWant;
  }

  private boolean computeDontWantForDuplicateIP(boolean dontWant, PeerNode pn, Peer replyTo) {
    if (!dontWant && !crypto.allowConnection(pn, replyTo.getFreenetAddress())) {
      if (pn instanceof DarknetPeerNode peerNode) {
        LOG.error("Drop peer {} due to existing connections on the same IP address", pn);
        LOG.warn(
            "Disconnecting permanently from your friend \"{}\" because other peers use the same IP"
                + " address",
            peerNode.getName());
      }
      LOG.info("Reject connection; duplicate IP in use");
      return true;
    }
    return dontWant;
  }

  private void postHandshakeActions(
      long newTrackerID, long trackerID, Jfk4Params params, boolean dontWant) {
    if (newTrackerID <= 0) {
      LOG.error("Handshake failure with {}", params.pn.getPeer());
      return; // Don't send the JFK(4). We have not successfully connected.
    }
    params.newTrackerID = newTrackerID;
    params.sameAsOldTrackerID = (newTrackerID == trackerID);
    sendJFKMessage4(params);

    if (dontWant) {
      node.network().peers().messenger().disconnectAndRemove(params.pn, true, true, true);
    } else {
      params.pn.maybeSendInitialMessages();
    }
  }

  private static BlockCipher newRijndael() {
    try {
      return new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      throw new IllegalStateException(e);
    }
  }

  /*
   * Initiator Method: Message1
   * Process Message1: receive the initiator nonce and Diffie–Hellman exponential.
   *
   * format:
   *   Ni'
   *   g^i
   *   *IDr'
   *
   * Reference: http://www.wisdom.weizmann.ac.il/~reingold/publications/jfk-tissec.pdf
   *   "Just Fast Keying: Key Agreement In A Hostile Internet" — Aiello, Bellovin, Blaze, Canetti,
   *   Ioannidis, Keromytis, Reingold. ACM TISSEC 7 (2), May 2004, pp. 1–30.
   *
   * @param payload the decrypted payload buffer
   * @param offset start offset into payload
   * @param pn the peer node we are talking to; may be {@code null} for anonymous initiator (we are
   *     the responder)
   * @param replyTo the peer to which any reply should be sent
   * @param negotiation parameters for the handshake
   */
  private void processJFKMessage1(
      byte[] payload, int offset, PeerNode pn, Peer replyTo, JfkNegotiationParams negotiation) {
    long t1 = System.currentTimeMillis();
    int modulusLength = getModulusLength();
    // Pre negtype 9 we were sending Ni as opposed to Ni'
    int nonceSizeHashed = HASH_LENGTH;
    boolean unknownInitiator = negotiation.unknownInitiator();
    if (LOG.isDebugEnabled()) LOG.debug("JFK(1) inbound: processing initiator packet - {}", pn);
    // Note: The spec mentions sending IDr'; the current implementation omits it.
    if (payload.length
        < nonceSizeHashed
            + modulusLength
            + 3
            + (unknownInitiator ? NodeCrypto.IDENTITY_LENGTH : 0)) {
      LOG.error(
          "event=jfk1_packet_too_short from {}: {} bytes, expected at least {}",
          pn,
          payload.length,
          nonceSizeHashed + modulusLength);
      return;
    }
    // get Ni'
    byte[] nonceInitiator = new byte[nonceSizeHashed];
    System.arraycopy(payload, offset, nonceInitiator, 0, nonceSizeHashed);
    offset += nonceSizeHashed;

    // get g^i
    byte[] hisExponential = Arrays.copyOfRange(payload, offset, offset + modulusLength);
    if (unknownInitiator) {
      // Check IDr'
      offset += modulusLength;
      byte[] expectedIdentityHash =
          Arrays.copyOfRange(payload, offset, offset + NodeCrypto.IDENTITY_LENGTH);
      if (!MessageDigest.isEqual(expectedIdentityHash, crypto.getIdentityHash())) {
        if (LOG.isErrorEnabled()) {
          LOG.error(
              "Invalid unknown-initiator JFK(1), IDr' is {} should be {}",
              HexUtil.bytesToHex(expectedIdentityHash),
              HexUtil.bytesToHex(crypto.getIdentityHash()));
        }
        return;
      }
    }

    if (throttleRekey(pn, replyTo)) return;

    try {
      sendJFKMessage2(nonceInitiator, hisExponential, pn, replyTo, negotiation);
    } catch (NoContextsException _) {
      handleNoContextsException(NoContextsException.CONTEXT.REPLYING);
      return;
    }

    long t2 = System.currentTimeMillis();
    if ((t2 - t1) > 500) {
      LOG.error("event=jfk1_processing_slow (>500 ms) for {}", pn);
    }
  }

  private long lastLoggedNoContexts = -1;
  private static final long LOG_NO_CONTEXTS_INTERVAL = MINUTES.toMillis(1);

  private void handleNoContextsException(FNPPacketMangler.NoContextsException.CONTEXT context) {
    if (node.network().uptime() < SECONDS.toMillis(30)) {
      LOG.warn("No contexts available; cannot handle or send packet ({}) on {}", context, this);
      return;
    }
    // Log it immediately.
    LOG.warn("No contexts available {}; entropy low or CPU saturated?", context);
    // More loudly periodically.
    long now = System.currentTimeMillis();
    synchronized (this) {
      if (now < lastLoggedNoContexts + LOG_NO_CONTEXTS_INTERVAL) return;
      lastLoggedNoContexts = now;
    }
    logLoudErrorNoContexts();
  }

  private void logLoudErrorNoContexts() {
    // If this is happening regularly post-startup, then it's unlikely that reading the disk will
    // help.
    // Note: Consider localization and a user alert here.
    // RNG exhaustion shouldn't happen for Windows users at all and may not happen on Linux
    // depending on the JVM version, so let's leave it for now.
    LOG.error(
        "Crypta cannot establish connections: CPU overloaded or random number generator is slow");
    LOG.error("If the problem is CPU usage, shut down high-CPU applications.");
    if (FileUtil.detectedOS.isUnix) {
      File f = new File(System.getProperty("crypta.hwrng.path", "/dev/hwrng"));
      if (f.exists()) LOG.error("Installing \"rngd\" might help (e.g. apt-get install rng-tools).");
      LOG.error(
          "The best solution is to install a hardware random number generator, or use turbid or"
              + " similar software to take random data from an unconnected sound card.");
      LOG.error(
          "The quick workaround is to add"
              + " \"wrapper.java.additional.4=-Djava.security.egd=file:///dev/urandom\" to your"
              + " wrapper.conf.");
    }
  }

  private final LRUMap<InetAddress, Long> throttleRekeysByIP =
      LRUMap.createSafeMap(InetAddressComparator.COMPARATOR);

  private static final int REKEY_BY_IP_TABLE_SIZE = 1024;

  private boolean throttleRekey(PeerNode pn, Peer replyTo) {
    if (pn != null) {
      return pn.throttleRekey();
    }
    long now = System.currentTimeMillis();
    InetAddress addr = replyTo.getAddress();
    synchronized (throttleRekeysByIP) {
      Long l = throttleRekeysByIP.get(addr);
      if (l == null || now > l) throttleRekeysByIP.push(addr, now);
      // Trim to max size
      while (throttleRekeysByIP.size() > REKEY_BY_IP_TABLE_SIZE) throttleRekeysByIP.popKey();
      // Drop stale entries older than the throttle window; guard against null values to avoid NPE
      while (!throttleRekeysByIP.isEmpty()) {
        Long head = throttleRekeysByIP.peekValue();
        if (head == null || head >= now - PeerNode.THROTTLE_REKEY) break;
        throttleRekeysByIP.popKey();
      }
      if (l != null && now - l < PeerNode.THROTTLE_REKEY) {
        LOG.error("Two JFK(1)'s initiated by same IP within " + PeerNode.THROTTLE_REKEY + "ms");
        return true;
      }
    }
    return false;
  }

  private static final int MAX_NONCES_PER_PEER = 10;

  /*
   * format:
   * Ni',g^i
   * We send IDr' only if unknownInitiator is set.
   * @param pn The node to encrypt the message to. Cannot be null, because we are the initiator, and we
   *     know the responder in all cases.
   * @param replyTo The peer to send the actual packet to.
   * @param negotiation handshake negotiation parameters
   */
  private void sendJFKMessage1(PeerNode pn, Peer replyTo, JfkNegotiationParams negotiation)
      throws NoContextsException {
    if (LOG.isDebugEnabled())
      LOG.debug("Send JFK(1) init to {}" + FOR_STR + "{}", replyTo, pn.getPeer());
    final long now = System.currentTimeMillis();
    int modulusLength = getModulusLength();
    // Pre negtype 9 we were sending Ni as opposed to Ni'
    boolean unknownInitiator = negotiation.unknownInitiator();
    int setupType = negotiation.setupType();
    int negType = negotiation.negType();

    KeyAgreementSchemeContext ctx =
        (KeyAgreementSchemeContext) pn.handshake().getKeyAgreementSchemeContext();
    if (!(ctx instanceof ECDHLightContext)
        || ((pn.jfkContextLifetime + DH_GENERATION_INTERVAL * DH_CONTEXT_BUFFER_SIZE) < now)) {
      pn.jfkContextLifetime = now;
      KeyAgreementSchemeContext newCtx = getECDHLightContext();
      ctx = newCtx;
      pn.handshake().setKeyAgreementSchemeContext(newCtx);
    }

    int offset = 0;
    byte[] nonce = new byte[NONCE_SIZE];
    byte[] myExponential = ctx.getPublicKeyNetworkFormat();
    node.bootstrap().random().nextBytes(nonce);

    pn.rememberJfkNonce(nonce, MAX_NONCES_PER_PEER);

    int nonceSizeHashed = HASH_LENGTH;
    byte[] message1 =
        new byte
            [nonceSizeHashed + modulusLength + (unknownInitiator ? NodeCrypto.IDENTITY_LENGTH : 0)];

    System.arraycopy(SHA256.digest(nonce), 0, message1, offset, nonceSizeHashed);
    offset += nonceSizeHashed;
    System.arraycopy(myExponential, 0, message1, offset, modulusLength);

    if (unknownInitiator) {
      offset += modulusLength;
      System.arraycopy(pn.identityHash, 0, message1, offset, pn.identityHash.length);
      sendAnonAuthPacket(
          negType,
          0,
          setupType,
          message1,
          pn,
          replyTo,
          (BlockCipher) pn.handshake().anonymousInitiatorSetupCipher());
    } else {
      sendAuthPacket(negType, 0, message1, pn, replyTo);
    }
    long t2 = System.currentTimeMillis();
    if ((t2 - now) > 500) {
      LOG.error("event=jfk1_send_slow (>500 ms) for {}", pn.getPeer());
    }
  }

  /*
   * format:
   * Ni',Nr,g^r
   * Signature[g^r,grpInfo(r)]
   * Hashed JFKAuthenticator : HMAC{Hkr}[g^r, g^i, Nr, Ni', IPi]
   *
   * NB: we don't send IDr nor groupinfo as we know them: even if the responder doesn't know the initiator,
   * the initiator ALWAYS knows the responder.
   * @param pn The node to encrypt the message for. CAN BE NULL if anonymous-initiator.
   * @param replyTo The peer to send the packet to.
   * @param negotiation handshake negotiation parameters
   */
  private void sendJFKMessage2(
      byte[] nonceInitator,
      byte[] hisExponential,
      PeerNode pn,
      Peer replyTo,
      JfkNegotiationParams negotiation)
      throws NoContextsException {
    if (LOG.isDebugEnabled()) LOG.debug("Send JFK(2) response to {}", pn);
    int modulusLength = getModulusLength();
    int nonceSize = NONCE_SIZE;
    boolean unknownInitiator = negotiation.unknownInitiator();
    int setupType = negotiation.setupType();
    int negType = negotiation.negType();
    // g^r
    // Neg type 8 and later use ECDH for generating the keys.
    KeyAgreementSchemeContext ctx = getECDHLightContext();

    // Nr
    byte[] myNonce = new byte[nonceSize];
    node.bootstrap().random().nextBytes(myNonce);
    byte[] myExponential = ctx.getPublicKeyNetworkFormat();
    // Neg type 9 and later use ECDSA signature.
    byte[] sig = ctx.getECDSASignature();
    if (sig.length != getSignatureLength())
      throw new IllegalStateException(
          "This shouldn't happen: please report! We are attempting to send "
              + sig.length
              + " bytes of signature in JFK2! "
              + pn.getPeer());
    byte[] authenticator =
        HMAC.macWithSHA256(
            getTransientKey(),
            assembleJFKAuthenticator(
                myExponential,
                hisExponential,
                myNonce,
                nonceInitator,
                replyTo.getAddress().getAddress()));
    if (LOG.isTraceEnabled()) LOG.trace("Using HMAC (len={})", authenticator.length);
    if (LOG.isTraceEnabled()) LOG.trace("Nonce initiator hash (len={})", nonceInitator.length);
    byte[] message2 =
        new byte[nonceInitator.length + nonceSize + modulusLength + sig.length + HASH_LENGTH];

    int offset = 0;
    System.arraycopy(nonceInitator, 0, message2, offset, nonceInitator.length);
    offset += nonceInitator.length;
    System.arraycopy(myNonce, 0, message2, offset, myNonce.length);
    offset += myNonce.length;
    System.arraycopy(myExponential, 0, message2, offset, modulusLength);
    offset += modulusLength;

    System.arraycopy(sig, 0, message2, offset, sig.length);
    offset += sig.length;

    System.arraycopy(authenticator, 0, message2, offset, HASH_LENGTH);

    if (unknownInitiator) {
      sendAnonAuthPacket(negType, 1, setupType, message2, pn, replyTo, crypto.getAnonSetupCipher());
    } else {
      sendAuthPacket(negType, 1, message2, pn, replyTo);
    }
  }

  /*
   * Assemble what will be the jfk-Authenticator:
   * computed over the Responder exponentials and the Nonces and
   * used by the responder to verify that the round-trip has been done
   *
   */
  private byte[] assembleJFKAuthenticator(
      byte[] gR, byte[] gI, byte[] nR, byte[] nI, byte[] address) {
    byte[] authData = new byte[gR.length + gI.length + nR.length + nI.length + address.length];
    int offset = 0;

    System.arraycopy(gR, 0, authData, offset, gR.length);
    offset += gR.length;
    System.arraycopy(gI, 0, authData, offset, gI.length);
    offset += gI.length;
    System.arraycopy(nR, 0, authData, offset, nR.length);
    offset += nR.length;
    System.arraycopy(nI, 0, authData, offset, nI.length);
    offset += nI.length;
    System.arraycopy(address, 0, authData, offset, address.length);

    return authData;
  }

  /*
   * Initiator Method: Message2
   * See {@link #sendJFKMessage2(byte[], byte[], PeerNode, Peer, JfkNegotiationParams)} for the packet
   * format. This packet is the same for known and unknown initiators.
   *
   * @param payload the buffer containing the decrypted auth packet
   * @param inputOffset the offset in the buffer at which the packet starts
   * @param replyTo the peer to which we need to send the packet
   * @param pn the peer node we are talking to; cannot be {@code null} as we are the initiator
   * @param negotiation handshake negotiation parameters
   */
  private void processJFKMessage2(
      byte[] payload,
      int inputOffset,
      PeerNode pn,
      Peer replyTo,
      JfkNegotiationParams negotiation) {
    long t1 = System.currentTimeMillis();
    int modulusLength = getModulusLength();
    // Pre negtype 9 we were sending Ni as opposed to Ni'
    int nonceSize = NONCE_SIZE;
    int nonceSizeHashed = HASH_LENGTH;
    int negType = negotiation.negType();

    if (LOG.isDebugEnabled())
      LOG.debug("JFK(2) inbound: processing responder packet - {}", pn.getPeer());
    // Note: The spec suggests sending IDr'; the current code omits it.
    int sigLength = getSignatureLength();
    int expectedLength = nonceSizeHashed + nonceSize + modulusLength + sigLength + HASH_LENGTH;
    if (payload.length < inputOffset + expectedLength) {
      LOG.error(
          "event=jfk2_packet_too_short from {}: {} bytes, expected at least {}",
          pn.getPeer(),
          payload.length,
          inputOffset + expectedLength);
      return;
    }

    byte[] nonceInitiator = new byte[nonceSizeHashed];
    System.arraycopy(payload, inputOffset, nonceInitiator, 0, nonceSizeHashed);
    inputOffset += nonceSizeHashed;
    byte[] nonceResponder = new byte[nonceSize];
    System.arraycopy(payload, inputOffset, nonceResponder, 0, nonceSize);
    inputOffset += nonceSize;

    byte[] hisExponential = Arrays.copyOfRange(payload, inputOffset, inputOffset + modulusLength);
    inputOffset += modulusLength;

    // sigLength already computed for payload length validation.
    byte[] sig = new byte[sigLength];
    System.arraycopy(payload, inputOffset, sig, 0, sigLength);
    inputOffset += sigLength;

    byte[] authenticator = Arrays.copyOfRange(payload, inputOffset, inputOffset + HASH_LENGTH);

    // Check try to find the authenticator in the cache.
    // If authenticator is already present, indicates duplicate/replayed message2
    // Now simply transmit the corresponding message3
    Object message3;
    synchronized (authenticatorCache) {
      message3 = authenticatorCache.get(new ByteArrayWrapper(authenticator));
    }
    if (message3 != null) {
      LOG.info("We replayed a message from the cache (shouldn't happen often) - {}", pn.getPeer());
      sendAuthPacket(negType, 3, (byte[]) message3, pn, replyTo);
      return;
    }

    // sanity check
    byte[] myNi = pn.findOriginalJfkNonceByHash(nonceInitiator);
    if (myNi == null || myNi.length != NONCE_SIZE) {
      if (shouldLogErrorInHandshake(t1)) {
        LOG.info(
            "event=jfk2_invalid_nonce_length from {} (since added={}, last receive={}) len={}"
                + " expected={}",
            pn.getPeer(),
            pn.timeSinceAddedOrRestarted(),
            pn.lastReceivedPacketTime(),
            lengthOrNegOne(myNi),
            NONCE_SIZE);
      }
      return;
    }

    // Verify the ECDSA signature; We are assuming that it's the curve we expect
    if (!ECDSA.verify(Curves.P256, pn.peerECDSAPubKey, sig, hisExponential)) {
      if (pn.peerECDSAPubKeyHash == null) {
        // Note: legacy DSA support path; keep until removal.
        // Caused by nodes running broken early versions of negType9.
        LOG.atError()
            .addArgument(negType)
            .addArgument(pn::userToString)
            .log("Peer attempting negType {} with ECDSA but no ECDSA key known: {}");
        return;
      }
      LOG.error("ECDSA signature verification fails in JFK(2) {}", pn.getPeer());
      if (LOG.isDebugEnabled())
        LOG.debug(
            "Expected signature on {} with {} signature {}",
            HexUtil.bytesToHex(hisExponential),
            HexUtil.bytesToHex(pn.peerECDSAPubKeyHash),
            HexUtil.bytesToHex(sig));
      return;
    }

    // At this point we know it's from the peer, so we can report a packet received.
    pn.receivedPacket(true, false);

    Jfk3Params j3 = new Jfk3Params();
    j3.negotiation = negotiation;
    j3.nonceInitiator = myNi;
    j3.nonceResponder = nonceResponder;
    j3.hisExponential = hisExponential;
    j3.authenticator = authenticator;
    j3.pn = pn;
    j3.replyTo = replyTo;
    sendJFKMessage3(j3);

    long t2 = System.currentTimeMillis();
    if ((t2 - t1) > 500) {
      LOG.error("event=jfk2_processing_slow (>500 ms) for {}", pn.getPeer());
    }
  }

  /*
   * Initiator Method: Message3
   * Process Message3
   * Send the Initiator nonce,Responder nonce and DiffieHellman Exponential of the responder
   * and initiator in the clear.(unVerifiedData)
   * Send the authenticator which allows the responder to verify that a roundtrip occured
   * Compute the signature of the unVerifiedData and encrypt it using a shared key
   * which is derived from DHExponentials and the nonces; add a HMAC to protect it
   *
   * Format:
   * Ni, Nr, g^i, g^r
   * Authenticator - HMAC{Hkr}[g^r, g^i, Nr, Ni', IPi]
   * HMAC{Ka}(cyphertext)
   * IV + E{KE}[S{i}[Ni',Nr,g^i,g^r,idR, bootID, znoderefI], bootID, znoderefI*]
   *
   * * Noderef is sent whether unknownInitiator is true, however, if it is, it will
   * be a *full* noderef, otherwise it will exclude the pubkey etc.
   *
   * @param payload is The buffer containing the decrypted auth packet.
   * @param replyTo The peer to which we need to send the packet.
   * @param pn The PeerNode we are talking to. CAN BE NULL in the case of anonymous initiator since we are the
   * responder.
   * @param negotiation handshake negotiation parameters
   * @return byte Message3
   */
  private void processJFKMessage3(
      byte[] payload,
      int inputOffset,
      J3Ctx ctx,
      boolean oldOpennetPeer,
      JfkNegotiationParams negotiation) {
    final long t1 = System.currentTimeMillis();
    int modulusLength = getModulusLength();
    int nonceSize = NONCE_SIZE;
    boolean unknownInitiator = negotiation.unknownInitiator();
    int setupType = negotiation.setupType();
    int negType = negotiation.negType();
    logGotJfk3Message(ctx.pn);
    PeerNode pnLocal = ctx.pn;

    BlockCipher c = newRijndael();

    final int expectedLength =
        nonceSize * 2
            + // Ni, Nr
            modulusLength * 2
            + // g^i, g^r
            HASH_LENGTH
            + // authenticator
            HASH_LENGTH
            + // HMAC of the cyphertext
            (c.getBlockSize() >> 3)
            + // IV
            HASH_LENGTH
            + // it's at least a signature
            8
            + // a bootid
            8
            + // packet tracker ID
            1; // znoderefI* is at least 1 byte long

    if (!hasExpectedLength(payload, expectedLength + 3, ctx.pn)) return;

    // Ni
    byte[] nonceInitiator = new byte[nonceSize];
    System.arraycopy(payload, inputOffset, nonceInitiator, 0, nonceSize);
    inputOffset += nonceSize;
    traceReceivingNi(nonceInitiator);
    // Before negtype 9 we didn't hash it!
    byte[] nonceInitiatorHashed = SHA256.digest(nonceInitiator);

    // Nr
    byte[] nonceResponder = new byte[nonceSize];
    System.arraycopy(payload, inputOffset, nonceResponder, 0, nonceSize);
    inputOffset += nonceSize;
    // g^i
    byte[] initiatorExponential =
        Arrays.copyOfRange(payload, inputOffset, inputOffset + modulusLength);
    inputOffset += modulusLength;
    // g^r
    byte[] responderExponential =
        Arrays.copyOfRange(payload, inputOffset, inputOffset + modulusLength);
    inputOffset += modulusLength;

    byte[] authenticator = Arrays.copyOfRange(payload, inputOffset, inputOffset + HASH_LENGTH);
    inputOffset += HASH_LENGTH;

    // Validate authenticator and handle potential replay in one step
    ReplayFields replayFields =
        new ReplayFields(
            responderExponential, initiatorExponential, nonceResponder, nonceInitiatorHashed);
    if (!shouldProceedAfterAuthenticator(t1, authenticator, replayFields, negotiation, ctx)) return;

    byte[] hmac = Arrays.copyOfRange(payload, inputOffset, inputOffset + HASH_LENGTH);
    inputOffset += HASH_LENGTH;

    byte[] computedExponential =
        deriveSharedExponential(initiatorExponential, responderExponential, ctx);
    if (computedExponential.length == 0) return;

    if (LOG.isDebugEnabled())
      LOG.debug(
          "event=jfk2_shared_secret_derived len={} peer={}", computedExponential.length, ctx.pn);

    /* 0 is the outgoing key for the initiator, 7 for the responder */
    byte[] outgoingKey =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "7");
    byte[] incommingKey =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "0");
    byte[] ke = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "1");
    byte[] ka = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "2");

    byte[] hmacKey =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "3");
    byte[] ivKey =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "4");
    byte[] ivNonce =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "5");

    /* Bytes 1-4: Initial sequence number for the initiator
     * Bytes 5-8: Initial sequence number for the responder
     * Bytes 9-12: Initial message id for the initiator
     * Bytes 13-16: Initial message id for the responder
     * Note that we are the responder */
    byte[] sharedData =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "6");
    Arrays.fill(computedExponential, (byte) 0);
    int theirInitialSeqNum =
        ((sharedData[0] & 0xFF) << 24)
            | ((sharedData[1] & 0xFF) << 16)
            | ((sharedData[2] & 0xFF) << 8)
            | (sharedData[3] & 0xFF);
    int ourInitialSeqNum =
        ((sharedData[4] & 0xFF) << 24)
            | ((sharedData[5] & 0xFF) << 16)
            | ((sharedData[6] & 0xFF) << 8)
            | (sharedData[7] & 0xFF);
    int theirInitialMsgID;
    int ourInitialMsgID;

    theirInitialMsgID =
        unknownInitiator
            ? getInitialMessageID(crypto.getMyIdentity())
            : getInitialMessageID(pnLocal.identity, crypto.getMyIdentity());
    ourInitialMsgID =
        unknownInitiator
            ? getInitialMessageID(crypto.getMyIdentity())
            : getInitialMessageID(crypto.getMyIdentity(), pnLocal.identity);

    debugInitialMessageIds(theirInitialMsgID, ourInitialMsgID);

    c.initialize(ke);
    int ivLength = PCFBMode.lengthIV(c);
    int decypheredPayloadOffset = 0;
    // We compute the HMAC of ("I"+cyphertext): the cyphertext includes the IV!
    byte[] decypheredPayload =
        Arrays.copyOf(
            JFK_PREFIX_INITIATOR, JFK_PREFIX_INITIATOR.length + payload.length - inputOffset);
    decypheredPayloadOffset += JFK_PREFIX_INITIATOR.length;
    System.arraycopy(
        payload,
        inputOffset,
        decypheredPayload,
        decypheredPayloadOffset,
        decypheredPayload.length - decypheredPayloadOffset);
    if (isInnerHmacInvalid(ka, decypheredPayload, hmac, ctx.pn, JFK3_STR)) return;

    final PCFBMode pk = PCFBMode.create(c, decypheredPayload, decypheredPayloadOffset);
    // Get the IV
    decypheredPayloadOffset += ivLength;
    // Decrypt the payload
    pk.blockDecipher(
        decypheredPayload,
        decypheredPayloadOffset,
        decypheredPayload.length - decypheredPayloadOffset);
    /*
     * DecipheredData Format:
     * Signature
     * Node Data (starting with BootID)
     */
    int sigLength = getSignatureLength();
    byte[] sig = new byte[sigLength];
    System.arraycopy(decypheredPayload, decypheredPayloadOffset, sig, 0, sigLength);
    decypheredPayloadOffset += sigLength;
    byte[] data = new byte[decypheredPayload.length - decypheredPayloadOffset];
    System.arraycopy(
        decypheredPayload,
        decypheredPayloadOffset,
        data,
        0,
        decypheredPayload.length - decypheredPayloadOffset);
    int ptr = 0;
    long trackerID = normalizeTrackerId(Fields.bytesToLong(data, ptr));
    ptr += 8;
    long bootID = Fields.bytesToLong(data, ptr);
    ptr += 8;
    byte[] hisRef = Arrays.copyOfRange(data, ptr, data.length);

    // Resolve (when anonymous initiator) and validate peernode
    pnLocal = resolveAndValidatePeerNode(unknownInitiator, setupType, hisRef, pnLocal, ctx.replyTo);
    if (pnLocal == null) return;

    // verify the signature
    byte[] toVerify =
        assembleDHParams(
            nonceInitiatorHashed,
            nonceResponder,
            initiatorExponential,
            responderExponential,
            crypto.getIdentity(negType),
            data);
    if (!verifyECDSASignature(pnLocal, sig, toVerify)) return;

    // At this point we know it's from the peer, so we can report a packet received.
    pnLocal.receivedPacket(true, false);

    BlockCipher outgoingCipher;
    BlockCipher incommingCipher;
    BlockCipher ivCipher;
    try {
      outgoingCipher = new Rijndael(256, 256);
      incommingCipher = new Rijndael(256, 256);
      ivCipher = new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      throw new IllegalStateException(e);
    }
    outgoingCipher.initialize(outgoingKey);
    incommingCipher.initialize(incommingKey);
    ivCipher.initialize(ivKey);

    // Promote if necessary and check for duplicate IPs
    boolean dontWant = handleOldOpennetPromotion(oldOpennetPeer, pnLocal);
    dontWant = computeDontWantForDuplicateIP(dontWant, pnLocal, ctx.replyTo);

    HandshakeCompletionParams handshakeParams = new HandshakeCompletionParams();
    handshakeParams.thisBootID = bootID;
    handshakeParams.data = hisRef;
    handshakeParams.length = hisRef.length;
    handshakeParams.outgoingCipher = outgoingCipher;
    handshakeParams.outgoingKey = outgoingKey;
    handshakeParams.incommingCipher = incommingCipher;
    handshakeParams.incommingKey = incommingKey;
    handshakeParams.replyTo = ctx.replyTo;
    handshakeParams.unverified = true;
    handshakeParams.negType = negType;
    handshakeParams.trackerID = trackerID;
    handshakeParams.isJFK4 = false;
    handshakeParams.jfk4SameAsOld = false;
    handshakeParams.hmacKey = hmacKey;
    handshakeParams.ivCipher = ivCipher;
    handshakeParams.ivNonce = ivNonce;
    handshakeParams.ourInitialSeqNum = ourInitialSeqNum;
    handshakeParams.theirInitialSeqNum = theirInitialSeqNum;
    handshakeParams.ourInitialMsgID = ourInitialMsgID;
    handshakeParams.theirInitialMsgID = theirInitialMsgID;
    long newTrackerID = pnLocal.handshake().completedHandshake(handshakeParams);

    Jfk4Params params = new Jfk4Params();
    params.negotiation = negotiation;
    params.nonceInitiatorHashed = nonceInitiatorHashed;
    params.nonceResponder = nonceResponder;
    params.initiatorExponential = initiatorExponential;
    params.responderExponential = responderExponential;
    params.c = c;
    params.ka = ka;
    params.authenticator = authenticator;
    params.hisRef = hisRef;
    params.pn = pnLocal;
    params.replyTo = ctx.replyTo;
    postHandshakeActions(newTrackerID, trackerID, params, dontWant);

    if (LOG.isDebugEnabled()) LOG.debug("Seed client connected with negtype {}", negType);

    logIfSlow(t1, pnLocal);
  }

  private boolean shouldProceedAfterAuthenticator(
      long t1,
      byte[] authenticator,
      ReplayFields replayFields,
      JfkNegotiationParams negotiation,
      J3Ctx ctx) {
    // We want to check the HMAC before any cache lookup
    if (!verifyJFK3Authenticator(t1, authenticator, replayFields, ctx.replyTo)) return false;

    // Replay handling: if present, we transmit the cached message4 and stop.
    return !tryReplayMessage4(negotiation, ctx.pn, ctx.replyTo, authenticator, replayFields);
  }

  private byte[] deriveSharedExponential(
      byte[] initiatorExponential, byte[] responderExponential, J3Ctx ctx) {
    ECPublicKey initiatorKey = ECDH.getPublicKey(initiatorExponential, ecdhCurveToUse);
    ECPublicKey responderKey = ECDH.getPublicKey(responderExponential, ecdhCurveToUse);
    if (initiatorKey == null) {
      LOG.error("Invalid initiator ECDH public key - {}", JFK3_STR);
      return EMPTY_BYTES;
    }
    ECDHLightContext lctx = findECDHContextByPubKey(responderKey);
    if (lctx == null) {
      LOG.error("HMAC verified but no matching ECDH context for public key - JFK3 - {}", ctx.pn);
      return EMPTY_BYTES;
    }
    return lctx.getHMACKey(initiatorKey);
  }

  private long normalizeTrackerId(long id) {
    return (id < 0) ? -1 : id;
  }

  private PeerNode resolveAndValidatePeerNode(
      boolean unknownInitiator, int setupType, byte[] hisRef, PeerNode pnLocal, Peer replyTo) {
    PeerNode out = pnLocal;
    if (unknownInitiator) {
      out = getPeerNodeFromUnknownInitiator(hisRef, setupType, pnLocal, replyTo);
    }
    return validatePeerNode(out, unknownInitiator) ? out : null;
  }

  private void logIfSlow(long t1, PeerNode pn) {
    final long t2 = System.currentTimeMillis();
    if ((t2 - t1) > 500) {
      LOG.atError()
          .addArgument(pn::getPeer)
          .addArgument(() -> TimeUtil.formatTime(t2 - t1, 3, true))
          .log("Message3 Processing packet for {} took {}");
    }
  }

  private PeerNode getPeerNodeFromUnknownInitiator(
      byte[] hisRef, int setupType, PeerNode pn, Peer from) {
    if (setupType == SETUP_OPENNET_SEEDNODE) {
      OpennetManager om = node.network().opennet();
      if (om == null) {
        LOG.error("Opennet disabled; ignore seednode connect attempt");
        // Note: consider sending an explicit rejection message.
        return null;
      }
      SimpleFieldSet ref = OpennetNoderefValidator.validateNoderef(hisRef, null, true);
      if (ref == null) {
        LOG.error("Invalid noderef");
        return null;
      }
      PeerNode seed = createSeedClientPeer(ref, from);
      if (seed == null) return null;
      if (seed.equals(pn)) {
        LOG.info("Already connected to seednode");
        return pn;
      }
      node.network().peers().addPeer(seed);
      return seed;
    } else {
      LOG.error("Unknown anonymous setup type in unknown-initiator flow");
      return null;
    }
  }

  private PeerNode createSeedClientPeer(SimpleFieldSet ref, Peer from) {
    try {
      return new SeedClientPeerNode(ref, node, crypto, node.network().peers());
    } catch (FSParseException
        | PeerParseException
        | ReferenceSignatureVerificationException
        | PeerTooOldException e) {
      LOG.error("Invalid seed client noderef: {}" + FROM_STR + "{}", e, from, e);
      return null;
    }
  }

  private boolean isReplayMessage4AndRecord(byte[] hmac, long t1, PeerNode pn) {
    byte[] message4Timestamp;
    boolean replay;
    synchronized (authenticatorCache) {
      ByteArrayWrapper hmacBAW = new ByteArrayWrapper(hmac);
      byte[] inserted = Fields.longToBytes(t1);
      byte[] existing = authenticatorCache.computeIfAbsent(hmacBAW, _ -> inserted);
      message4Timestamp = existing;
      replay = existing != inserted; // true when mapping already existed
    }
    if (replay) {
      LOG.atInfo()
          .addArgument(() -> TimeUtil.formatTime(t1 - Fields.bytesToLong(message4Timestamp)))
          .addArgument(pn)
          .log("Replayed message4 (first handled at {}) from - {}");
      return true;
    }
    return false;
  }

  private boolean verifyECDSAJFK4(
      PeerNode pn, byte[] sig, byte[] locallyGeneratedText, byte[] hisRef, long bootID) {
    if (ECDSA.verify(Curves.P256, pn.peerECDSAPubKey, sig, locallyGeneratedText)) return true;
    LOG.error(
        "ECDSA signature verification fails JFK(4) - {}"
            + LENGTH_STR
            + "{} hisRef {}"
            + HASH_STR
            + "{} myRef {}"
            + HASH_STR
            + "{} boot ID {}",
        pn.getPeer(),
        locallyGeneratedText.length,
        hisRef.length,
        Fields.hashCode(hisRef),
        pn.jfkMyRef.length,
        Fields.hashCode(pn.jfkMyRef),
        bootID);
    return false;
  }

  private void postHandshakeActionsJFK4(long newTrackerID, boolean dontWant, PeerNode pn) {
    if (newTrackerID >= 0) {
      if (dontWant) {
        node.network().peers().messenger().disconnectAndRemove(pn, true, true, true);
      } else {
        pn.maybeSendInitialMessages();
      }
    } else {
      LOG.error("Handshake failed");
    }
  }

  /*
   * Responder Method:Message4
   * Process Message4
   *
   * Format:
   * HMAC{Ka}[cyphertext]
   * IV + E{Ke}[S{R}[Ni', Nr, g^i, g^r, IDi, bootID, znoderefR, znoderefI], bootID, znoderefR]
   *
   * @param payload The decrypted auth packet.
   * @param pn The PeerNode we are talking to. Cannot be null as we are the initiator.
   * @param replyTo The Peer we are replying to.
   */
  @SuppressWarnings("UnusedReturnValue")
  private boolean processJFKMessage4(
      byte[] payload,
      int inputOffset,
      PeerNode pn,
      Peer replyTo,
      boolean oldOpennetPeer,
      int negType) {
    final long t1 = System.currentTimeMillis();
    int signLength = getSignatureLength();
    maybeLogJfk4Processing(pn);
    maybeLogMissingMyRef(pn);
    BlockCipher c;
    try {
      c = new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      throw new IllegalStateException(e);
    }

    Stage1Result s1 = jfk4Stage1(payload, inputOffset, pn, c, signLength, negType, t1);
    if (s1.status == Stage1Result.Status.INVALID) return false;
    if (s1.status == Stage1Result.Status.HANDLED || s1.status == Stage1Result.Status.REPLAYED)
      return true;

    // Promote if necessary and handle duplicate IP
    boolean dontWant = handleOldOpennetPromotion(oldOpennetPeer, pn);
    dontWant = computeDontWantForDuplicateIP(dontWant, pn, replyTo);

    // We change the key
    BlockCipher ivCipher;
    BlockCipher outgoingCipher;
    BlockCipher incommingCipher;
    try {
      ivCipher = new Rijndael(256, 256);
      outgoingCipher = new Rijndael(256, 256);
      incommingCipher = new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      throw new IllegalStateException(e);
    }

    outgoingCipher.initialize(pn.outgoingKey);
    incommingCipher.initialize(pn.incommingKey);
    ivCipher.initialize(pn.ivKey);

    HandshakeCompletionParams handshakeParams = new HandshakeCompletionParams();
    handshakeParams.thisBootID = s1.bootID;
    handshakeParams.data = s1.hisRef;
    handshakeParams.length = s1.hisRef.length;
    handshakeParams.outgoingCipher = outgoingCipher;
    handshakeParams.outgoingKey = pn.outgoingKey;
    handshakeParams.incommingCipher = incommingCipher;
    handshakeParams.incommingKey = pn.incommingKey;
    handshakeParams.replyTo = replyTo;
    handshakeParams.unverified = false;
    handshakeParams.negType = negType;
    handshakeParams.trackerID = s1.trackerID;
    handshakeParams.isJFK4 = true;
    handshakeParams.jfk4SameAsOld = s1.reusedTracker;
    handshakeParams.hmacKey = pn.hmacKey;
    handshakeParams.ivCipher = ivCipher;
    handshakeParams.ivNonce = pn.ivNonce;
    handshakeParams.ourInitialSeqNum = pn.ourInitialSeqNum;
    handshakeParams.theirInitialSeqNum = pn.theirInitialSeqNum;
    handshakeParams.ourInitialMsgID = pn.ourInitialMsgID;
    handshakeParams.theirInitialMsgID = pn.theirInitialMsgID;
    long newTrackerID = pn.handshake().completedHandshake(handshakeParams);
    postHandshakeActionsJFK4(newTrackerID, dontWant, pn);

    // cleanup
    // Note: Consider zeroing/garbling this buffer before letting GC reclaim it.
    pn.setJFKBuffer(null);
    pn.jfkKa = null;
    pn.jfkKe = null;
    pn.outgoingKey = null;
    pn.incommingKey = null;
    pn.hmacKey = null;
    pn.ivKey = null;
    pn.ivNonce = null;
    pn.ourInitialSeqNum = 0;
    pn.theirInitialSeqNum = 0;
    pn.ourInitialMsgID = 0;
    pn.theirInitialMsgID = 0;
    // We want to clear it here so that new handshake requests
    // will be sent with a different DH pair
    pn.handshake().clearKeyAgreementSchemeContext();
    // Note: TRUE MULTI-HOMING: winner-takes-all, kill all other connection attempts since we
    // can't deal with multiple active connections. Also avoids leaking.
    pn.clearJfkNoncesSent();

    final long t2 = System.currentTimeMillis();
    logMessage4TimeoutIfSlow(t1, t2, pn);
    return true;
  }

  private void maybeLogJfk4Processing(PeerNode pn) {
    if (LOG.isDebugEnabled())
      LOG.debug("JFK(4) inbound: processing finalization packet - {}", pn.getPeer());
  }

  private void maybeLogMissingMyRef(PeerNode pn) {
    if (pn.jfkMyRef == null) {
      String error = "Got a JFK(4) message but no pn.jfkMyRef for " + pn;
      if (node.network().uptime() < SECONDS.toMillis(60)) {
        LOG.debug(error);
      } else {
        LOG.error(error);
      }
    }
  }

  private void logMessage4TimeoutIfSlow(long t1, long t2, PeerNode pn) {
    if ((t2 - t1) > 500) LOG.error("event=jfk4_processing_slow (>500 ms) from {}", pn.getPeer());
  }

  /*
   * Format:
   * Ni, Nr, g^i, g^r
   * Authenticator - HMAC{Hkr}[g^r, g^i, Nr, Ni', IPi]
   * HMAC{Ka}(cyphertext)
   * IV + E{KE}[S{i}[Ni',Nr,g^i,g^r,idR, bootID, znoderefI], bootID, znoderefI]
   *
   * @param pn The PeerNode to encrypt the message for. Cannot be null as we are the initiator.
   * @param replyTo The Peer to send the packet to.
   */

  private void sendJFKMessage3(Jfk3Params p) {
    if (LOG.isDebugEnabled()) LOG.debug("Send JFK(3) handshake to {}", p.pn.getPeer());
    int modulusLength = getModulusLength();
    int signLength = getSignatureLength();
    // Pre negtype 9 we were sending Ni as opposed to Ni'
    byte[] nonceInitiatorHashed = SHA256.digest(p.nonceInitiator);

    long t1 = System.currentTimeMillis();
    BlockCipher c;
    try {
      c = new Rijndael(256, 256);
    } catch (UnsupportedCipherException e) {
      throw new IllegalStateException(e);
    }
    KeyAgreementSchemeContext ctx =
        (KeyAgreementSchemeContext) p.pn.handshake().getKeyAgreementSchemeContext();
    if (ctx == null) return;
    byte[] ourExponential = ctx.getPublicKeyNetworkFormat();
    p.pn.jfkMyRef =
        p.negotiation.unknownInitiator()
            ? crypto.myCompressedHeavySetupRef()
            : crypto.myCompressedSetupRef();
    byte[] data = new byte[8 + 8 + p.pn.jfkMyRef.length];
    int ptr = 0;
    long trackerID;
    trackerID = p.pn.getReusableTrackerID();
    System.arraycopy(Fields.longToBytes(trackerID), 0, data, ptr, 8);
    ptr += 8;
    if (LOG.isDebugEnabled()) LOG.debug("Sending tracker ID {} in JFK(3)", trackerID);
    System.arraycopy(Fields.longToBytes(p.pn.getOutgoingBootID()), 0, data, ptr, 8);
    ptr += 8;
    System.arraycopy(p.pn.jfkMyRef, 0, data, ptr, p.pn.jfkMyRef.length);
    if (!isValidJfk3HeaderLengths(
        p.nonceInitiator,
        p.nonceResponder,
        ourExponential,
        p.hisExponential,
        p.authenticator,
        modulusLength)) {
      if (shouldLogErrorInHandshake(t1)) {
        LOG.error(
            "event=jfk3_invalid_header peer={} niLen={} nrLen={} giLen={} grLen={} authLen={}"
                + " modLen={}",
            p.pn.getPeer(),
            lengthOrNegOne(p.nonceInitiator),
            lengthOrNegOne(p.nonceResponder),
            lengthOrNegOne(ourExponential),
            lengthOrNegOne(p.hisExponential),
            lengthOrNegOne(p.authenticator),
            modulusLength);
      } else if (LOG.isDebugEnabled()) {
        LOG.debug(
            "event=jfk3_invalid_header peer={} niLen={} nrLen={} giLen={} grLen={} authLen={}"
                + " modLen={}",
            p.pn.getPeer(),
            lengthOrNegOne(p.nonceInitiator),
            lengthOrNegOne(p.nonceResponder),
            lengthOrNegOne(ourExponential),
            lengthOrNegOne(p.hisExponential),
            lengthOrNegOne(p.authenticator),
            modulusLength);
      }
      return;
    }

    final byte[] message3 =
        new byte
            [NONCE_SIZE * 2
                + // nI, nR
                modulusLength * 2
                + // g^i, g^r
                HASH_LENGTH
                + // authenticator
                HASH_LENGTH
                + // HMAC(cyphertext)
                (c.getBlockSize() >> 3)
                + // IV
                signLength
                + // Signature
                data.length]; // The bootid+noderef
    int offset =
        writeMessage3Header(
            message3,
            p.nonceInitiator,
            p.nonceResponder,
            ourExponential,
            p.hisExponential,
            p.authenticator);
    /*
     * Digital Signature of the message with the private key belonging to the initiator/responder
     * It is assumed to be non-message recovering
     */
    byte[] sig =
        signJFK3AndCacheBuffer(
            p.pn,
            nonceInitiatorHashed,
            p.nonceResponder,
            ourExponential,
            p.hisExponential,
            p.pn.getPubKeyHash(),
            data);

    byte[] computedExponential =
        ((ECDHLightContext) ctx).getHMACKey(ECDH.getPublicKey(p.hisExponential, ecdhCurveToUse));

    if (LOG.isDebugEnabled())
      LOG.debug("event=jfk3_shared_secret_sent len={} peer={}", computedExponential.length, p.pn);
    /* 0 is the outgoing key for the initiator, 7 for the responder */
    deriveKeysAndInit(
        p.pn,
        (ECDHLightContext) ctx,
        p.hisExponential,
        nonceInitiatorHashed,
        p.nonceResponder,
        p.negotiation.unknownInitiator());

    c.initialize(p.pn.jfkKe);
    int ivLength = PCFBMode.lengthIV(c);
    appendEncryptedPayloadAndHmacForJFK3(p.pn, c, sig, data, message3, offset, ivLength);

    // cache the message
    synchronized (authenticatorCache) {
      if (!maybeResetTransientKey())
        authenticatorCache.put(new ByteArrayWrapper(p.authenticator), message3);
    }
    final long timeSent = System.currentTimeMillis();
    if (p.negotiation.unknownInitiator()) {
      sendAnonAuthPacket(
          p.negotiation.negType(),
          2,
          p.negotiation.setupType(),
          message3,
          p.pn,
          p.replyTo,
          (BlockCipher) p.pn.handshake().anonymousInitiatorSetupCipher());
    } else {
      sendAuthPacket(p.negotiation.negType(), 2, message3, p.pn, p.replyTo);
    }
    scheduleJFK3ResendIfNoReply(p.pn, p.replyTo, p.negotiation, message3, timeSent);
    long t2 = System.currentTimeMillis();
    if ((t2 - t1) > 500L) LOG.error("event=jfk3_send_slow (>500 ms) for {}", p.pn.getPeer());
  }

  private int getInitialMessageID(byte[] identity) {
    MessageDigest md = SHA256.getMessageDigest();
    md.update(identity);
    // Similar to JFK keygen, should be safe enough.
    md.update("INITIAL0".getBytes(StandardCharsets.UTF_8));
    byte[] hashed = md.digest();
    return Fields.bytesToInt(hashed, 0);
  }

  private int getInitialMessageID(byte[] identity, byte[] otherIdentity) {
    MessageDigest md = SHA256.getMessageDigest();
    md.update(identity);
    md.update(otherIdentity);
    // Similar to JFK keygen, should be safe enough.
    md.update("INITIAL1".getBytes(StandardCharsets.UTF_8));
    byte[] hashed = md.digest();
    return Fields.bytesToInt(hashed, 0);
  }

  /*
   * Format:
   * HMAC{Ka}(cyphertext)
   * IV, E{Ke}[S{R}[Ni',Nr,g^i,g^r,idI, bootID, znoderefR, znoderefI],bootID,znoderefR]
   *
   * @param replyTo The Peer we are replying to.
   * @param pn The PeerNode to encrypt the auth packet to. Cannot be null, because even in anonymous initiator,
   * we will have created one before calling this method.
   */
  private void sendJFKMessage4(Jfk4Params p) {
    if (LOG.isDebugEnabled()) LOG.debug("Send JFK(4) finalization to {}", p.pn.getPeer());
    long t1 = System.currentTimeMillis();

    byte[] myRef = crypto.myCompressedSetupRef();
    byte[] data = new byte[9 + 8 + myRef.length + p.hisRef.length];
    int ptr = 0;
    System.arraycopy(Fields.longToBytes(p.newTrackerID), 0, data, ptr, 8);
    ptr += 8;
    data[ptr++] = (byte) (p.sameAsOldTrackerID ? 1 : 0);

    System.arraycopy(Fields.longToBytes(p.pn.getOutgoingBootID()), 0, data, ptr, 8);
    ptr += 8;
    System.arraycopy(myRef, 0, data, ptr, myRef.length);
    ptr += myRef.length;
    System.arraycopy(p.hisRef, 0, data, ptr, p.hisRef.length);

    byte[] params =
        assembleDHParams(
            p.nonceInitiatorHashed,
            p.nonceResponder,
            p.initiatorExponential,
            p.responderExponential,
            p.pn.getPubKeyHash(),
            data);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Message length {} myRef: {}" + HASH_STR + "{} hisRef: {}" + HASH_STR + "{} boot ID {}",
          params.length,
          myRef.length,
          Fields.hashCode(myRef),
          p.hisRef.length,
          Fields.hashCode(p.hisRef),
          node.getBootId());
    byte[] sig = crypto.ecdsaSign(params);

    int ivLength = PCFBMode.lengthIV(p.c);
    byte[] iv = new byte[ivLength];
    node.bootstrap().random().nextBytes(iv);
    PCFBMode pk = PCFBMode.create(p.c, iv);
    // Don't include the last bit
    int dataLength = data.length - p.hisRef.length;
    byte[] cyphertext = new byte[JFK_PREFIX_RESPONDER.length + ivLength + sig.length + dataLength];
    int cleartextOffset = 0;
    System.arraycopy(
        JFK_PREFIX_RESPONDER, 0, cyphertext, cleartextOffset, JFK_PREFIX_RESPONDER.length);
    cleartextOffset += JFK_PREFIX_RESPONDER.length;
    System.arraycopy(iv, 0, cyphertext, cleartextOffset, ivLength);
    cleartextOffset += ivLength;
    System.arraycopy(sig, 0, cyphertext, cleartextOffset, sig.length);
    cleartextOffset += sig.length;
    System.arraycopy(data, 0, cyphertext, cleartextOffset, dataLength);
    // no need to update further; not used beyond this point
    // Now encrypt the cleartext[Signature]
    int cleartextToEncypherOffset = JFK_PREFIX_RESPONDER.length + ivLength;
    pk.blockEncipher(
        cyphertext, cleartextToEncypherOffset, cyphertext.length - cleartextToEncypherOffset);

    // We compute the HMAC of (prefix + iv + signature)
    byte[] hmac = HMAC.macWithSHA256(p.ka, cyphertext);

    // Message4 = hmac + IV + encryptedSignature
    byte[] message4 =
        new byte[HASH_LENGTH + ivLength + (cyphertext.length - cleartextToEncypherOffset)];
    int offset = 0;
    System.arraycopy(hmac, 0, message4, offset, HASH_LENGTH);
    offset += HASH_LENGTH;
    System.arraycopy(iv, 0, message4, offset, ivLength);
    offset += ivLength;
    System.arraycopy(
        cyphertext,
        cleartextToEncypherOffset,
        message4,
        offset,
        cyphertext.length - cleartextToEncypherOffset);

    // cache the message
    synchronized (authenticatorCache) {
      if (!maybeResetTransientKey())
        authenticatorCache.put(new ByteArrayWrapper(p.authenticator), message4);
      if (LOG.isTraceEnabled())
        LOG.trace("Storing JFK(4) authenticator (len={})", p.authenticator.length);
    }

    if (p.negotiation.unknownInitiator()) {
      sendAnonAuthPacket(
          p.negotiation.negType(),
          3,
          p.negotiation.setupType(),
          message4,
          p.pn,
          p.replyTo,
          crypto.getAnonSetupCipher());
    } else {
      sendAuthPacket(p.negotiation.negType(), 3, message4, p.pn, p.replyTo);
    }
    long t2 = System.currentTimeMillis();
    if ((t2 - t1) > 500) LOG.error("event=jfk4_send_slow (>500 ms) for {}", p.pn.getPeer());
  }

  private record JfkNegotiationParams(boolean unknownInitiator, int setupType, int negType) {}

  private static final class Jfk4Params {
    JfkNegotiationParams negotiation;
    byte[] nonceInitiatorHashed;
    byte[] nonceResponder;
    byte[] initiatorExponential;
    byte[] responderExponential;
    BlockCipher c;
    byte[] ka;
    byte[] authenticator;
    byte[] hisRef;
    PeerNode pn;
    Peer replyTo;
    long newTrackerID;
    boolean sameAsOldTrackerID;
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class SigData {
    final byte[] sig;
    final byte[] data;

    SigData(byte[] sig, byte[] data) {
      this.sig = sig;
      this.data = data;
    }
  }

  private static final class Jfk3Params {
    JfkNegotiationParams negotiation;
    byte[] nonceInitiator;
    byte[] nonceResponder;
    byte[] hisExponential;
    byte[] authenticator;
    PeerNode pn;
    Peer replyTo;
  }

  @SuppressWarnings("ClassCanBeRecord")
  private static final class Stage1Result {
    enum Status {
      OK,
      REPLAYED,
      INVALID,
      HANDLED
    }

    final Status status;
    final long trackerID;
    final boolean reusedTracker;
    final long bootID;
    final byte[] hisRef;

    Stage1Result(Status status) {
      this(status, -1, false, -1, null);
    }

    Stage1Result(Status status, long trackerID, boolean reusedTracker, long bootID, byte[] hisRef) {
      this.status = status;
      this.trackerID = trackerID;
      this.reusedTracker = reusedTracker;
      this.bootID = bootID;
      this.hisRef = hisRef;
    }
  }

  private record J3Ctx(PeerNode pn, Peer replyTo) {}

  @SuppressWarnings("ClassCanBeRecord")
  private static final class ReplayFields {
    final byte[] responderExponential;
    final byte[] initiatorExponential;
    final byte[] nonceResponder;
    final byte[] nonceInitiatorHashed;

    ReplayFields(
        byte[] responderExponential,
        byte[] initiatorExponential,
        byte[] nonceResponder,
        byte[] nonceInitiatorHashed) {
      this.responderExponential = responderExponential;
      this.initiatorExponential = initiatorExponential;
      this.nonceResponder = nonceResponder;
      this.nonceInitiatorHashed = nonceInitiatorHashed;
    }
  }

  private int writeMessage3Header(
      byte[] message3,
      byte[] nonceInitiator,
      byte[] nonceResponder,
      byte[] ourExponential,
      byte[] hisExponential,
      byte[] authenticator) {
    int offset = 0;
    int nonceSize = NONCE_SIZE;
    System.arraycopy(nonceInitiator, 0, message3, offset, nonceSize);
    offset += nonceSize;
    if (LOG.isTraceEnabled()) LOG.trace("Sending Ni (len={})", nonceInitiator.length);
    System.arraycopy(nonceResponder, 0, message3, offset, nonceSize);
    offset += nonceSize;
    System.arraycopy(ourExponential, 0, message3, offset, ourExponential.length);
    offset += ourExponential.length;
    System.arraycopy(hisExponential, 0, message3, offset, hisExponential.length);
    offset += hisExponential.length;
    System.arraycopy(authenticator, 0, message3, offset, HASH_LENGTH);
    offset += HASH_LENGTH;
    return offset;
  }

  static boolean isValidJfk3HeaderLengths(
      byte[] nonceInitiator,
      byte[] nonceResponder,
      byte[] ourExponential,
      byte[] hisExponential,
      byte[] authenticator,
      int modulusLength) {
    return nonceInitiator != null
        && nonceInitiator.length == NONCE_SIZE
        && nonceResponder != null
        && nonceResponder.length == NONCE_SIZE
        && ourExponential != null
        && ourExponential.length == modulusLength
        && hisExponential != null
        && hisExponential.length == modulusLength
        && authenticator != null
        && authenticator.length == HASH_LENGTH;
  }

  private static int lengthOrNegOne(byte[] data) {
    return data == null ? -1 : data.length;
  }

  private byte[] signJFK3AndCacheBuffer(
      PeerNode pn,
      byte[] nonceInitiatorHashed,
      byte[] nonceResponder,
      byte[] ourExponential,
      byte[] hisExponential,
      byte[] pubKeyHash,
      byte[] data) {
    byte[] toSign =
        assembleDHParams(
            nonceInitiatorHashed, nonceResponder, ourExponential, hisExponential, pubKeyHash, data);
    pn.setJFKBuffer(toSign);
    return crypto.ecdsaSign(toSign);
  }

  private void deriveKeysAndInit(
      PeerNode pn,
      ECDHLightContext ctx,
      byte[] hisExponential,
      byte[] nonceInitiatorHashed,
      byte[] nonceResponder,
      boolean unknownInitiator) {
    byte[] computedExponential = ctx.getHMACKey(ECDH.getPublicKey(hisExponential, ecdhCurveToUse));
    if (LOG.isDebugEnabled())
      LOG.debug("event=jfk3_keys_derived len={} peer={}", computedExponential.length, pn);
    pn.outgoingKey =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "0");
    pn.incommingKey =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "7");
    pn.jfkKe = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "1");
    pn.jfkKa = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "2");
    pn.hmacKey =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "3");
    pn.ivKey = computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "4");
    pn.ivNonce =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "5");
    byte[] sharedData =
        computeJFKSharedKey(computedExponential, nonceInitiatorHashed, nonceResponder, "6");
    Arrays.fill(computedExponential, (byte) 0);
    pn.ourInitialSeqNum =
        ((sharedData[0] & 0xFF) << 24)
            | ((sharedData[1] & 0xFF) << 16)
            | ((sharedData[2] & 0xFF) << 8)
            | (sharedData[3] & 0xFF);
    pn.theirInitialSeqNum =
        ((sharedData[4] & 0xFF) << 24)
            | ((sharedData[5] & 0xFF) << 16)
            | ((sharedData[6] & 0xFF) << 8)
            | (sharedData[7] & 0xFF);
    pn.theirInitialMsgID =
        unknownInitiator
            ? getInitialMessageID(pn.identity)
            : getInitialMessageID(pn.identity, crypto.getMyIdentity());
    pn.ourInitialMsgID =
        unknownInitiator
            ? getInitialMessageID(pn.identity)
            : getInitialMessageID(crypto.getMyIdentity(), pn.identity);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "JFK(3) derived message IDs: theirs={} ours={}",
          pn.theirInitialMsgID,
          pn.ourInitialMsgID);
  }

  private void appendEncryptedPayloadAndHmacForJFK3(
      PeerNode pn,
      BlockCipher c,
      byte[] sig,
      byte[] data,
      byte[] message3,
      int offset,
      int ivLength) {
    byte[] iv = new byte[ivLength];
    node.bootstrap().random().nextBytes(iv);
    PCFBMode pcfb = PCFBMode.create(c, iv);
    int cleartextOffset = 0;
    byte[] cleartext = new byte[JFK_PREFIX_INITIATOR.length + ivLength + sig.length + data.length];
    System.arraycopy(
        JFK_PREFIX_INITIATOR, 0, cleartext, cleartextOffset, JFK_PREFIX_INITIATOR.length);
    cleartextOffset += JFK_PREFIX_INITIATOR.length;
    System.arraycopy(iv, 0, cleartext, cleartextOffset, ivLength);
    cleartextOffset += ivLength;
    System.arraycopy(sig, 0, cleartext, cleartextOffset, sig.length);
    cleartextOffset += sig.length;
    System.arraycopy(data, 0, cleartext, cleartextOffset, data.length);
    // no need to update further; not used beyond this point
    int cleartextToEncypherOffset = JFK_PREFIX_INITIATOR.length + ivLength;
    pcfb.blockEncipher(
        cleartext, cleartextToEncypherOffset, cleartext.length - cleartextToEncypherOffset);
    byte[] hmac = HMAC.macWithSHA256(pn.jfkKa, cleartext);
    System.arraycopy(hmac, 0, message3, offset, HASH_LENGTH);
    offset += HASH_LENGTH;
    System.arraycopy(iv, 0, message3, offset, ivLength);
    offset += ivLength;
    System.arraycopy(
        cleartext,
        cleartextToEncypherOffset,
        message3,
        offset,
        cleartext.length - cleartextToEncypherOffset);
  }

  private void scheduleJFK3ResendIfNoReply(
      final PeerNode pn,
      final Peer replyTo,
      final JfkNegotiationParams negotiation,
      final byte[] message3,
      final long timeSent) {
    node.network()
        .ticker()
        .queueTimedJob(
            () -> {
              if (pn.timeLastConnectionCompleted() < timeSent) {
                if (LOG.isDebugEnabled())
                  LOG.debug(
                      "Resending JFK(3) to {}" + FOR_STR + "{}",
                      pn,
                      node.network().darknetPortNumber());
                if (negotiation.unknownInitiator()) {
                  sendAnonAuthPacket(
                      negotiation.negType(),
                      2,
                      negotiation.setupType(),
                      message3,
                      pn,
                      replyTo,
                      (BlockCipher) pn.handshake().anonymousInitiatorSetupCipher());
                } else {
                  sendAuthPacket(negotiation.negType(), 2, message3, pn, replyTo);
                }
              }
            },
            SECONDS.toMillis(5));
  }

  private Stage1Result jfk4Stage1(
      byte[] payload,
      int inputOffset,
      PeerNode pn,
      BlockCipher c,
      int signLength,
      int negType,
      long t1) {
    final int expectedLength = expectedLengthJFK4(c, signLength);
    java.util.Optional<byte[]> jfkBufferOpt =
        validateLengthAndGetJfkBuffer(payload, inputOffset, pn, expectedLength);
    if (jfkBufferOpt.isEmpty()) return new Stage1Result(Stage1Result.Status.INVALID);
    byte[] jfkBuffer = jfkBufferOpt.get();

    byte[] hmac = Arrays.copyOfRange(payload, inputOffset, inputOffset + HASH_LENGTH);
    int ofs = inputOffset + HASH_LENGTH;

    c.initialize(pn.jfkKe);
    int ivLength = PCFBMode.lengthIV(c);
    int decOffset = 0;
    byte[] dec =
        Arrays.copyOf(JFK_PREFIX_RESPONDER, JFK_PREFIX_RESPONDER.length + payload.length - ofs);
    decOffset += JFK_PREFIX_RESPONDER.length;
    System.arraycopy(payload, ofs, dec, decOffset, payload.length - ofs);
    if (isInnerHmacInvalid(pn.jfkKa, dec, hmac, pn, "JFK(4)"))
      return new Stage1Result(Stage1Result.Status.INVALID);

    if (isReplayMessage4AndRecord(hmac, t1, pn))
      return new Stage1Result(Stage1Result.Status.REPLAYED);

    final PCFBMode pk = PCFBMode.create(c, dec, decOffset);
    decOffset += ivLength;
    pk.blockDecipher(dec, decOffset, dec.length - decOffset);

    SigData sd = extractSigAndDataFromDecrypted(dec, decOffset, signLength);
    byte[] sig = sd.sig;
    byte[] data = sd.data;

    int ptr = 0;
    long trackerID = Fields.bytesToLong(data, ptr);
    ptr += 8;
    boolean reusedTracker = data[ptr++] != 0;
    long bootID = Fields.bytesToLong(data, ptr);
    ptr += 8;
    byte[] hisRef = Arrays.copyOfRange(data, ptr, data.length);

    int dataLen = hisRef.length + 8 + 9;
    byte[] identity = crypto.getIdentity(negType);
    int modulusLengthLocal = getModulusLength();
    byte[] toVerify =
        buildJFK4VerifyText(jfkBuffer, identity, modulusLengthLocal, data, dataLen, pn.jfkMyRef);
    if (!verifyECDSAJFK4(pn, sig, toVerify, hisRef, bootID))
      return new Stage1Result(Stage1Result.Status.HANDLED);

    pn.receivedPacket(true, false);
    return new Stage1Result(Stage1Result.Status.OK, trackerID, reusedTracker, bootID, hisRef);
  }

  private SigData extractSigAndDataFromDecrypted(
      byte[] decypheredPayload, int decypheredPayloadOffset, int signLength) {
    byte[] sig = new byte[signLength];
    System.arraycopy(decypheredPayload, decypheredPayloadOffset, sig, 0, signLength);
    int next = decypheredPayloadOffset + signLength;
    byte[] data = new byte[decypheredPayload.length - next];
    System.arraycopy(decypheredPayload, next, data, 0, data.length);
    return new SigData(sig, data);
  }

  private int expectedLengthJFK4(BlockCipher c, int signLength) {
    return HASH_LENGTH
        + (c.getBlockSize() >> 3) // IV
        + signLength // signature
        + 9 // ID of packet tracker, plus boolean byte
        + 8 // bootID
        + 1; // znoderefR
  }

  private java.util.Optional<byte[]> validateLengthAndGetJfkBuffer(
      byte[] payload, int inputOffset, PeerNode pn, int expectedLength) {
    if (payload.length - inputOffset < expectedLength + 3) {
      LOG.error(
          "event=jfk4_packet_too_short from {}: {} bytes, expected at least {}",
          pn.getPeer(),
          payload.length,
          expectedLength + 3);
      return java.util.Optional.empty();
    }
    byte[] jfkBuffer = pn.getJFKBuffer();
    if (jfkBuffer == null) {
      LOG.info("We have already handled this message... might be a replay or a bug - {}", pn);
      return java.util.Optional.empty();
    }
    return java.util.Optional.of(jfkBuffer);
  }

  private byte[] buildJFK4VerifyText(
      byte[] jfkBuffer,
      byte[] identity,
      int modulusLength,
      byte[] data,
      int dataLen,
      byte[] myRef) {
    int nonceSize = NONCE_SIZE;
    int nonceSizeHashed = HASH_LENGTH;
    byte[] locallyGeneratedText =
        new byte
            [nonceSizeHashed
                + nonceSize
                + modulusLength * 2
                + identity.length
                + dataLen
                + myRef.length];
    int bufferOffset = nonceSizeHashed + nonceSize + modulusLength * 2;
    System.arraycopy(jfkBuffer, 0, locallyGeneratedText, 0, bufferOffset);
    System.arraycopy(identity, 0, locallyGeneratedText, bufferOffset, identity.length);
    bufferOffset += identity.length;
    System.arraycopy(data, 0, locallyGeneratedText, bufferOffset, dataLen);
    bufferOffset += dataLen;
    System.arraycopy(myRef, 0, locallyGeneratedText, bufferOffset, myRef.length);
    return locallyGeneratedText;
  }

  /** Send an auth packet. */
  private void sendAuthPacket(int negType, int phase, byte[] data, PeerNode pn, Peer replyTo) {
    if (pn == null) throw new IllegalArgumentException("pn shouldn't be null here!");
    byte[] output = new byte[data.length + 3];
    output[0] = (byte) 1; // version is always 1
    output[1] = (byte) negType;
    output[2] = (byte) phase;
    System.arraycopy(data, 0, output, 3, data.length);
    if (LOG.isDebugEnabled()) {
      long now = System.currentTimeMillis();
      long last = pn.lastSentPacketTime();
      String delta = TimeUtil.formatTime(now - last, 2, true) + " ago";
      LOG.debug(
          "Sending auth packet for {} (phase={}, ver=1"
              + NT_STR
              + "{}) (last sent {} to {}) data.length={} (dest={})",
          pn.getPeer(),
          phase,
          negType,
          delta,
          replyTo,
          data.length,
          replyTo);
    }
    sendAuthPacket(output, (BlockCipher) pn.handshake().outgoingSetupCipher(), pn, replyTo, false);
  }

  /**
   * Send an anonymous‑initiator auth packet.
   *
   * @param negType negotiation type identifier
   * @param phase packet phase (0–3)
   * @param setupType anonymous‑initiator setup type (e.g., {@link #SETUP_OPENNET_SEEDNODE})
   * @param data payload to send (unencrypted body)
   * @param pn may be {@code null}; when non‑null, used for details such as anti‑firewall handling
   * @param replyTo destination peer
   * @param cipher outer cipher used to protect the packet
   */
  private void sendAnonAuthPacket(
      int negType,
      int phase,
      int setupType,
      byte[] data,
      PeerNode pn,
      Peer replyTo,
      BlockCipher cipher) {
    byte[] output = new byte[data.length + 4];
    output[0] = (byte) 1; // version is always 1
    output[1] = (byte) negType;
    output[2] = (byte) phase;
    output[3] = (byte) setupType;
    System.arraycopy(data, 0, output, 4, data.length);
    if (LOG.isDebugEnabled())
      LOG.debug(
          "Sending anon auth packet (phase={}, ver=" + 1 + NT_STR + "{}, setup={}) data.length={}",
          phase,
          negType,
          setupType,
          data.length);
    sendAuthPacket(output, cipher, pn, replyTo, true);
  }

  /** Send an auth packet (we have constructed the payload, now hash it, pad it, encrypt it). */
  private void sendAuthPacket(
      byte[] output, BlockCipher cipher, PeerNode pn, Peer replyTo, boolean anonAuth) {
    int length = output.length;
    if (length > sock.getMaxPacketSize()) {
      throw new IllegalStateException("Cannot send auth packet: too long: " + length);
    }
    byte[] iv = new byte[PCFBMode.lengthIV(cipher)];
    node.bootstrap().random().nextBytes(iv);
    byte[] hash = SHA256.digest(output);
    if (LOG.isTraceEnabled()) LOG.trace("Data hash computed (len={})", hash.length);
    int prePaddingLength = iv.length + hash.length + 2 /* length */ + output.length;
    int maxPacketSize = sock.getMaxPacketSize();
    int paddingLength;
    if (prePaddingLength < maxPacketSize) {
      paddingLength =
          node.bootstrap()
              .fastWeakRandom()
              .nextInt(Math.min(100, maxPacketSize - prePaddingLength));
    } else {
      paddingLength =
          0; // Avoid oversize packets if at all possible, the MTU is an estimate and may be wrong,
      // and fragmented packets are often dropped by firewalls.
      // Tell the devs, this shouldn't happen.
      LOG.error("Oversize auth packet (anonAuth={}) of {} bytes", anonAuth, prePaddingLength);
    }
    byte[] data = new byte[prePaddingLength + paddingLength];
    PCFBMode pcfb = PCFBMode.create(cipher, iv);
    System.arraycopy(iv, 0, data, 0, iv.length);
    pcfb.blockEncipher(hash, 0, hash.length);
    System.arraycopy(hash, 0, data, iv.length, hash.length);
    if (LOG.isDebugEnabled()) LOG.debug("Payload length: {} padded length {}", length, data.length);
    data[hash.length + iv.length] = (byte) pcfb.encipher((byte) (length >> 8));
    data[hash.length + iv.length + 1] = (byte) pcfb.encipher((byte) length);
    pcfb.blockEncipher(output, 0, output.length);
    System.arraycopy(output, 0, data, hash.length + iv.length + 2, output.length);

    Util.randomBytes(
        node.bootstrap().fastWeakRandom(),
        data,
        hash.length + iv.length + 2 + output.length,
        paddingLength);
    try {
      sendPacket(data, replyTo, pn);
      node.network().stats().reportAuthBytes(data.length + sock.getHeadersLength(replyTo));
    } catch (LocalAddressException _) {
      LOG.warn(
          "Tried to send auth packet to local address: {}"
              + FOR_STR
              + "{} - maybe set allowLocalAddresses for this peer?",
          replyTo,
          pn);
    }
  }

  private void sendPacket(byte[] data, Peer replyTo, PeerNode pn) throws LocalAddressException {
    if (pn != null && pn.isIgnoreSource()) {
      Peer p = pn.getPeer();
      if (p != null) replyTo = p;
    }
    sock.sendPacket(
        data,
        replyTo,
        pn == null ? crypto.getConfig().alwaysAllowLocalAddresses() : pn.allowLocalAddresses());
    if (pn != null) pn.reportOutgoingBytes(data.length);
    if (PeerNodeAddressManager.shouldThrottle(replyTo, node)) {
      node.network().outputThrottle().forceGrab(data.length);
    }
  }

  /**
   * Should we log an error for an event that could easily be caused by a handshake across a restart
   * boundary?
   */
  private boolean shouldLogErrorInHandshake(long now) {
    return now - node.getStartupTime() >= Node.HANDSHAKE_TIMEOUT * 2L;
  }

  /**
   * Sends an initial JFK handshake to a peer.
   *
   * <p>Selects a supported negotiation type, resolves the target {@link Peer} address, and emits a
   * JFK(1) message. When no common negotiation type exists, a random supported type is chosen.
   *
   * @param pn target peer node (must be non-null)
   * @param notRegistered whether the peer is not yet registered with the node
   */
  @Override
  public void sendHandshake(PeerNode pn, boolean notRegistered) {
    int negType = pn.selectNegType(this);
    if (negType == -1) {
      // Pick a random negType from what I do support
      int[] negTypes = supportedNegTypes(true);
      negType = negTypes[node.bootstrap().random().nextInt(negTypes.length)];
      LOG.info(
          "Cannot send handshake to {} because no common negTypes; choosing random negType {}",
          pn,
          negType);
    }
    if (LOG.isDebugEnabled()) LOG.debug("Possibly send handshake to {} (negType={})", pn, negType);

    Peer peer = pn.getHandshakeIP();
    if (peer == null) {
      pn.couldNotSendHandshake(notRegistered);
      return;
    }
    Peer oldPeer = peer;
    peer = peer.dropHostName();
    if (peer == null) {
      LOG.error("No address for peer {} so cannot send handshake", oldPeer);
      pn.couldNotSendHandshake(notRegistered);
      return;
    }
    try {
      JfkNegotiationParams negotiation =
          new JfkNegotiationParams(
              pn.handshakeUnknownInitiator(), pn.handshakeSetupType(), negType);
      sendJFKMessage1(pn, peer, negotiation);
    } catch (NoContextsException _) {
      handleNoContextsException(NoContextsException.CONTEXT.SENDING);
      return;
    }
    if (LOG.isDebugEnabled()) LOG.debug("Sending handshake to {}" + FOR_STR + "{}", peer, pn);
    pn.sentHandshake(notRegistered);
  }

  /**
   * Reports whether the supplied context represents a disconnected peer.
   *
   * @param context peer context (nullable)
   * @return {@code true} if {@code context} is non-null and not connected; otherwise {@code false}
   */
  @Override
  public boolean isDisconnected(PeerContext context) {
    if (context == null) return false;
    return !context.isConnected();
  }

  /**
   * Lists supported negotiation types.
   *
   * @param forPublic when {@code true}, returns the types advertised to the public network
   * @return an array of supported negotiation type identifiers
   */
  @Override
  public int[] supportedNegTypes(boolean forPublic) {
    return new int[] {10};
  }

  /**
   * Returns the active socket handler used to send and receive packets.
   *
   * @return the {@link SocketHandler} instance for this mangler
   */
  @Override
  public SocketHandler getSocketHandler() {
    return sock;
  }

  /**
   * Provides the detected primary IP addresses for the local node.
   *
   * @return an array of primary {@link Peer} addresses
   */
  @Override
  public Peer[] getPrimaryIPAddress() {
    return crypto.getDetector().getPrimaryPeers();
  }

  /**
   * Returns the compressed node reference for this node.
   *
   * @return a byte array with the compressed noderef
   */
  @Override
  public byte[] getCompressedNoderef() {
    return crypto.myCompressedFullRef();
  }

  /**
   * Indicates whether local addresses are always allowed for outgoing packets.
   *
   * @return {@code true} when local addresses are permitted without additional checks
   */
  @Override
  public boolean alwaysAllowLocalAddresses() {
    return crypto.getConfig().alwaysAllowLocalAddresses();
  }

  private ECDHLightContext genECDHLightContext() {
    final ECDHLightContext ctx = new ECDHLightContext(ecdhCurveToUse);
    ctx.setECDSASignature(crypto.ecdsaSign(ctx.getPublicKeyNetworkFormat()));
    if (LOG.isDebugEnabled())
      LOG.debug(
          "ECDSA signature: {}" + FOR_STR + "{}",
          HexUtil.bytesToHex(ctx.getECDSASignature()),
          HexUtil.bytesToHex(ctx.getPublicKeyNetworkFormat()));
    return ctx;
  }

  private void fillJfkEcdhFifoOffThread() {
    // do it off-thread
    node.network()
        .executor()
        .execute(
            new PrioRunnable() {
              @Override
              public void run() {
                fillJfkEcdhFifo();
              }

              @Override
              public int getPriority() {
                return NativeThread.PriorityLevel.MIN_PRIORITY.value;
              }
            },
            "ECDH exponential signing");
  }

  private void fillJfkEcdhFifo() {
    synchronized (ecdhContextFIFO) {
      int size = ecdhContextFIFO.size();
      if ((size + 1 > DH_CONTEXT_BUFFER_SIZE)) {
        ECDHLightContext result = null;
        long oldestSeen = Long.MAX_VALUE;

        for (ECDHLightContext tmp : ecdhContextFIFO) {
          if (tmp.lifetime < oldestSeen) {
            oldestSeen = tmp.lifetime;
            result = tmp;
          }
        }
        ecdhContextToBePrunned = result;
        ecdhContextFIFO.remove(ecdhContextToBePrunned);
      }

      ecdhContextFIFO.addLast(genECDHLightContext());
    }
  }

  /**
   * Change the ECDH key regularly but at most once every 30sec.
   *
   * @return {@link ECDHLightContext} currently selected for use
   * @throws NoContextsException when no pre-generated ECDH contexts are available in the FIFO and a
   *     new one cannot be provided synchronously
   */
  private ECDHLightContext getECDHLightContext() throws NoContextsException {
    final long now = System.currentTimeMillis();
    ECDHLightContext result;

    synchronized (ecdhContextFIFO) {
      result = ecdhContextFIFO.pollFirst();

      // Shall we replace one element of the queue?
      if ((jfkECDHLastGenerationTimestamp + DH_GENERATION_INTERVAL) < now) {
        jfkECDHLastGenerationTimestamp = now;
        fillJfkEcdhFifoOffThread();
      }

      // Don't generate on-thread as it might block.
      if (result == null) throw new NoContextsException();

      ecdhContextFIFO.addLast(result);
    }

    if (LOG.isDebugEnabled()) LOG.debug("getECDHLightContext() serves {}", result.hashCode());
    return result;
  }

  private static class NoContextsException extends Exception {

    private enum CONTEXT {
      SENDING,
      REPLYING
    }
  }

  /**
   * Used in processJFK[3|4]. This is O(n) over the small FIFO and is called only once a round-trip
   * has completed.
   *
   * @param exponential the ECDH public key to look up
   * @return the corresponding {@link ECDHLightContext} that owns the provided public key, or {@code
   *     null} if no match is found
   */
  private ECDHLightContext findECDHContextByPubKey(ECPublicKey exponential) {
    synchronized (ecdhContextFIFO) {
      for (ECDHLightContext result : ecdhContextFIFO) {
        if (exponential.equals(result.getPublicKey())) {
          return result;
        }
      }

      if (ecdhContextToBePrunned != null
          && ecdhContextToBePrunned.getPublicKey().equals(exponential))
        return ecdhContextToBePrunned;
    }
    return null;
  }

  /*
   * Prepare DH parameters of message2 for them to be signed (useful in message3 to check the sig)
   */
  private byte[] assembleDHParams(
      byte[] nonceInitiator,
      byte[] nonceResponder,
      byte[] initiatorExponential,
      byte[] responderExponential,
      byte[] id,
      byte[] sa) {
    byte[] result =
        new byte
            [nonceInitiator.length
                + nonceResponder.length
                + initiatorExponential.length
                + responderExponential.length
                + id.length
                + sa.length];
    int offset = 0;

    System.arraycopy(nonceInitiator, 0, result, offset, nonceInitiator.length);
    offset += nonceInitiator.length;
    System.arraycopy(nonceResponder, 0, result, offset, nonceResponder.length);
    offset += nonceResponder.length;
    System.arraycopy(initiatorExponential, 0, result, offset, initiatorExponential.length);
    offset += initiatorExponential.length;
    System.arraycopy(responderExponential, 0, result, offset, responderExponential.length);
    offset += responderExponential.length;
    System.arraycopy(id, 0, result, offset, id.length);
    offset += id.length;
    System.arraycopy(sa, 0, result, offset, sa.length);

    return result;
  }

  private byte[] getTransientKey() {
    synchronized (authenticatorCache) {
      return transientKey;
    }
  }

  // This is our Key Derivation Function for JFK.
  // Consider moving it to freenet/crypt/.
  private byte[] computeJFKSharedKey(byte[] exponential, byte[] ni, byte[] nr, String what) {
    assert ("0".equals(what)
        || "1".equals(what)
        || "2".equals(what)
        || "3".equals(what)
        || "4".equals(what)
        || "5".equals(what)
        || "6".equals(what)
        || "7".equals(what));

    byte[] number = what.getBytes(StandardCharsets.UTF_8);

    byte[] toHash = new byte[ni.length + nr.length + number.length];
    int offset = 0;
    System.arraycopy(ni, 0, toHash, offset, ni.length);
    offset += ni.length;
    System.arraycopy(nr, 0, toHash, offset, nr.length);
    offset += nr.length;
    System.arraycopy(number, 0, toHash, offset, number.length);

    return HMAC.macWithSHA256(exponential, toHash);
  }

  private long timeLastReset = -1;

  /**
   * How big can the authenticator cache get before we flush it ? n * 40 bytes (32 for the
   * authenticator and 8 for the timestamp)
   *
   * <p>We push to it until we reach the cap where we rekey, or we reach the PFS interval
   */
  private int getAuthenticatorCacheSize() {
    if (crypto.isOpennet() && node.network().wantAnonAuth(true)) { // seednodes
      return 5000; // 200kB
    } else {
      return 250; // 10kB
    }
  }

  /**
   * Change the transient key used by JFK.
   *
   * <p>It will determine the PFS interval, hence we call it at least once every 30 mins.
   *
   * @return True if we reset the transient key and therefore the authenticator cache.
   */
  private boolean maybeResetTransientKey() {
    long now = System.currentTimeMillis();
    boolean isCacheTooBig = true;
    int authenticatorCacheSize;
    int authenticatorCacheCap = getAuthenticatorCacheSize();
    synchronized (authenticatorCache) {
      authenticatorCacheSize = authenticatorCache.size();
      if (authenticatorCacheSize < authenticatorCacheCap) {
        isCacheTooBig = false;
        if (now - timeLastReset < TRANSIENT_KEY_REKEYING_MIN_INTERVAL) return false;
      }
      timeLastReset = now;

      node.bootstrap().random().nextBytes(transientKey);

      // reset the authenticator cache
      authenticatorCache.clear();
    }
    node.network()
        .ticker()
        .queueTimedJob(
            transientKeyRekeyer,
            "JFKmaybeResetTransientKey" + now,
            TRANSIENT_KEY_REKEYING_MIN_INTERVAL,
            false,
            false);
    LOG.info(
        "JFK transientKey rotated; message cache flushed because {} on {}",
        isCacheTooBig
            ? ("the cache is oversized (" + authenticatorCacheSize + ')')
            : "it's time to rekey",
        this);
    return true;
  }

  /**
   * Returns the current best-known external connectivity status.
   *
   * <p>Result is cached for ~3 minutes to minimize expensive probing.
   *
   * @return a {@link AddressTracker.Status} value describing NAT/connectivity observations
   */
  @Override
  public AddressTracker.Status getConnectivityStatus() {
    long now = System.currentTimeMillis();
    if (now - lastConnectivityStatusUpdate < MINUTES.toMillis(3)) return lastConnectivityStatus;

    AddressTracker.Status value;
    if (crypto.getConfig().alwaysHandshakeAggressively())
      value = AddressTracker.Status.DEFINITELY_NATED;
    else value = sock.getDetectedConnectivityStatus();

    lastConnectivityStatusUpdate = now;

    lastConnectivityStatus = value;
    return lastConnectivityStatus;
  }

  /**
   * Checks whether a connection to the given address is allowed.
   *
   * @param pn peer node (nullable)
   * @param addr address under evaluation
   * @return {@code true} if connections to {@code addr} are permitted
   */
  @Override
  public boolean allowConnection(PeerNode pn, FreenetInetAddress addr) {
    return crypto.allowConnection(pn, addr);
  }

  /**
   * Marks the environment as having broken or unavailable port forwarding.
   *
   * <p>Downstream components may adapt handshake and NAT traversal strategies accordingly.
   */
  @Override
  public void setPortForwardingBroken() {
    crypto.setPortForwardingBroken();
  }

  /**
   * Returns the modulus length in bytes for the current negotiation curve.
   *
   * @return the modulus length in bytes for the negotiated curve
   */
  private int getModulusLength() {
    return ecdhCurveToUse.modulusSize;
  }

  private int getSignatureLength() {
    return ECDSA.Curves.P256.maxSigSize;
  }

  // getNonceSize(int) returned a constant; usages have been replaced by NONCE_SIZE.
}
