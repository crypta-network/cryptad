package network.crypta.node;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.DSAPublicKey;
import network.crypta.crypt.ECDSA;
import network.crypta.crypt.ECDSA.Curves;
import network.crypta.crypt.Global;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.keys.ClientSSK;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.USK;
import network.crypta.node.PeerNode.IdentityValues;
import network.crypta.support.Base64;
import network.crypta.support.Fields;
import network.crypta.support.HexUtil;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.TimeUtil;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import network.crypta.support.transport.ip.IPUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Helper that owns noderef parsing, identity validation, and setup key derivation for {@link
 * PeerNode}.
 */
final class PeerNodeReferenceSupport {
  private static final Logger LOG = LoggerFactory.getLogger(PeerNodeReferenceSupport.class);

  private final PeerNode peer;

  PeerNodeReferenceSupport(PeerNode peer) {
    this.peer = peer;
  }

  ECPublicKey readPeerEcdsaKeyReturn(SimpleFieldSet fs)
      throws FSParseException, PeerTooOldException {
    SimpleFieldSet sfs = fs.subset("ecdsa.P256");
    if (sfs == null) {
      GregorianCalendar gc = new GregorianCalendar(2013, Calendar.JULY, 20);
      gc.setTimeZone(TimeZone.getTimeZone("GMT"));
      throw new PeerTooOldException("No ECC support", 1449, gc.getTime());
    }
    byte[] pub;
    try {
      pub = Base64.decode(sfs.get("pub"));
    } catch (IllegalBase64Exception e) {
      throw new FSParseException("Invalid base64 in ecdsa.P256.pub", e);
    }
    if (pub.length > Curves.P256.modulusSize)
      throw new FSParseException("ecdsa.P256.pub is not the right size!");
    ECPublicKey key = ECDSA.getPublicKey(pub, Curves.P256);
    if (key == null) throw new FSParseException("ecdsa.P256.pub is invalid!");
    return key;
  }

  void verifySignatureIfPresent(SimpleFieldSet fs, boolean noSig)
      throws ReferenceSignatureVerificationException {
    if (noSig) {
      peer.setSignatureVerificationSuccessfull(true);
      return;
    }
    // When present, verifyReferenceSignature() sets the flag and may throw on failure.
    verifyReferenceSignature(fs);
  }

  IdentityValues readIdentityValues(SimpleFieldSet fs) throws FSParseException, PeerParseException {
    String identityString = fs.get(PeerNode.SFS_KEY_IDENTITY);
    if (identityString == null && peer.isDarknet()) throw new PeerParseException("No identity!");
    try {
      byte[] id;
      if (identityString != null) {
        id = Base64.decode(identityString);
      } else {
        // We might be talking to a pre-1471 node
        // We need to generate it from the DSA key
        SimpleFieldSet sfs = fs.subset("dsaPubKey");
        id = SHA256.digest(DSAPublicKey.create(sfs, Global.DSAgroupBigA).asBytes());
      }
      if (id == null) throw new FSParseException("No identity");
      String b64 = Base64.encode(id);
      byte[] idHash = SHA256.digest(id);
      byte[] idHashHash = SHA256.digest(idHash);
      long swapId = Fields.bytesToLong(idHashHash);
      int hc = Fields.hashCode(peer.peerECDSAPubKeyHash);
      return new IdentityValues(id, b64, idHash, idHashHash, swapId, hc);
    } catch (NumberFormatException | IllegalBase64Exception e) {
      throw new FSParseException(e);
    }
  }

  byte[] computeIncomingSetupKey(NodeCrypto crypto, byte[] identityHashHash) {
    byte[] nodeKey = crypto.getIdentityHash();
    int digestLength = SHA256.getDigestLength();
    byte[] key = new byte[digestLength];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (nodeKey[i] ^ identityHashHash[i]);
    return key;
  }

  byte[] computeOutgoingSetupKey(NodeCrypto crypto, byte[] identityHash) {
    byte[] nodeKeyHash = crypto.getIdentityHashHash();
    int digestLength = SHA256.getDigestLength();
    byte[] key = new byte[digestLength];
    for (int i = 0; i < key.length; i++) key[i] = (byte) (nodeKeyHash[i] ^ identityHash[i]);
    return key;
  }

  BlockCipher buildRijndaelCipher(byte[] keyBytes) {
    try {
      BlockCipher c = new Rijndael(256, 256);
      c.initialize(keyBytes);
      return c;
    } catch (UnsupportedCipherException e1) {
      throw new IllegalStateException("Failed to initialize Rijndael(256,256)", e1);
    }
  }

  byte[] computePeerPublicKeyHash(ECPublicKey key) {
    return SHA256.digest(key.getEncoded());
  }

  List<Peer> parsePeerEntryCompat(String phys, boolean fromLocal) {
    ArrayList<Peer> out = new ArrayList<>(2);
    try {
      out.add(new Peer(phys, true, true));
      return out;
    } catch (HostnameSyntaxException | PeerParseException | UnknownHostException _) {
      // Try compatibility forms only if a comma appears.
      if (phys.indexOf(',') >= 0) {
        // Pattern: A,B,C:port -> apply trailing port to each host
        int lastColon = phys.lastIndexOf(':');
        if (lastColon > 0 && lastColon < phys.length() - 1) {
          String portStr = phys.substring(lastColon + 1);
          boolean portOk = true;
          try {
            int p = Integer.parseInt(portStr);
            if (p < 0 || p > 65535) portOk = false;
          } catch (NumberFormatException _) {
            portOk = false;
          }
          if (portOk) {
            String hostList = phys.substring(0, lastColon);
            String[] hosts = hostList.split(",");
            for (String h : hosts) {
              String cand = h.trim() + ":" + portStr;
              try {
                out.add(new Peer(cand, true, true));
              } catch (Exception _) {
                // try next
              }
            }
          }
        }
        // Additionally try: split by comma and parse each token as-is (covers A:port,B:port)
        for (String token : phys.split(",")) {
          String cand = token.trim();
          if (cand.isEmpty()) continue;
          try {
            Peer parsed = new Peer(cand, true, true);
            if (!out.contains(parsed)) out.add(parsed);
          } catch (Exception _) {
            // continue
          }
        }
        if (!out.isEmpty()) {
          LOG.info("Parsed {} into {} peer(s) via compatibility split", phys, out.size());
          return out;
        }
      }
      if (fromLocal) {
        LOG.error(
            "Invalid hostname or IP Address syntax error while parsing peer reference in local"
                + " peers list: {}",
            phys);
      } else {
        LOG.warn(
            "Invalid hostname or IP Address syntax error while parsing peer reference: {}", phys);
      }
      return out;
    }
  }

  Peer tryParsePeer(String phys) {
    try {
      return new Peer(phys, true, true);
    } catch (UnknownHostException _) {
      // Host appears syntactically valid but cannot be resolved here (e.g., link-local scope name
      // not present on this host). Lower severity to INFO to avoid noisy logs.
      LOG.info(
          PeerNode.STR_INVALID_HOST_OR_IP_WHILE_PARSING
              + "{} (unresolvable here; likely host-local scope or transient DNS)",
          phys);
      return null;
    } catch (HostnameSyntaxException | PeerParseException _) {
      // True syntax issues: keep ERROR to surface malformed noderefs.
      LOG.error(PeerNode.STR_INVALID_HOST_OR_IP_WHILE_PARSING + "{}", phys);
      return null;
    }
  }

  void checkTestnetAndOpennet(SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    if (!forDiffNodeRef && (fs.getBoolean(PeerNode.SFS_KEY_TESTNET, false))) {
      String err = "Preventing connection to node " + peer.getPeer() + " - testnet is enabled!";
      LOG.error(err);
      throw new FSParseException(err);
    }
    String s = fs.get(PeerNode.SFS_KEY_OPENNET);
    if (s == null && forFullNodeRef) throw new FSParseException("No opennet ref");
    else if (s != null) {
      try {
        boolean b = Fields.stringToBool(s);
        if (b != peer.isOpennetForNoderef())
          throw new FSParseException(
              "Changed opennet status?!?!?!? expected="
                  + peer.isOpennetForNoderef()
                  + " but got "
                  + b
                  + " ("
                  + s
                  + PeerNode.STR_ON
                  + peer);
      } catch (NumberFormatException e) {
        throw new FSParseException("Cannot parse opennet=\"" + s + "\"", e);
      }
    }
  }

  void validateIdentity(SimpleFieldSet fs, boolean forDiffNodeRef, boolean forFullNodeRef)
      throws FSParseException {
    String identityString = fs.get(PeerNode.SFS_KEY_IDENTITY);
    if (identityString != null) {
      try {
        byte[] id = Base64.decode(identityString);
        if (!Arrays.equals(id, peer.identity)) throw new FSParseException("Changing the identity");
      } catch (NumberFormatException | IllegalBase64Exception e) {
        throw new FSParseException(e);
      }
      return;
    }
    // Missing identity is allowed for differential or partial noderefs (e.g., during handshake).
    // Only full noderefs must include identity.
    if (forFullNodeRef && !forDiffNodeRef) {
      if (peer.isDarknet()) throw new FSParseException("No identity!");
      else if (LOG.isDebugEnabled())
        LOG.debug("didn't send an identity; let's assume it's pre-1471");
    }
  }

  void parseEcdsaFields(SimpleFieldSet fs) throws FSParseException {
    /* Read the ECDSA key material for the peer */
    SimpleFieldSet sfs = fs.subset("ecdsa.P256");
    if (sfs != null) {
      byte[] pub;
      try {
        pub = Base64.decode(sfs.get("pub"));
      } catch (IllegalBase64Exception e) {
        throw new FSParseException("Invalid base64 in ecdsa.P256.pub", e);
      }
      if (pub.length > ECDSA.Curves.P256.modulusSize)
        throw new FSParseException("ecdsa.P256.pub is not the right size!");
      ECPublicKey key = ECDSA.getPublicKey(pub, ECDSA.Curves.P256);
      if (key == null) throw new FSParseException("ecdsa.P256.pub is invalid!");
      if (!key.equals(peer.peerECDSAPubKey)) {
        LOG.atError()
            .addArgument(peer::userToString)
            .log("Tried to change ECDSA key on {} - did neighbour try to downgrade? Rejecting...");
        throw new FSParseException("Changing ECDSA key not allowed!");
      }
    }
  }

  void putEcdsaFields(SimpleFieldSet fs, ECPublicKey key) {
    fs.put("ecdsa", Curves.P256.getSFS(key));
  }

  @SuppressWarnings("UnusedReturnValue")
  boolean verifyReferenceSignature(SimpleFieldSet fs)
      throws ReferenceSignatureVerificationException {
    // Assume we failed at validating
    boolean failed;
    String signatureP256 = fs.get(PeerNode.SFS_KEY_SIG_P256);
    try {
      // If we have:
      // - the new P256 signature AND the P256 pubkey
      // OR
      // - the old DSA signature the pubkey and the groups
      // THEN
      // verify the signatures
      fs.removeValue("sig");
      fs.removeValue(PeerNode.SFS_KEY_SIG_P256);
      byte[] toVerifyECDSA = fs.toOrderedString().getBytes(StandardCharsets.UTF_8);

      boolean isECDSAsigPresent = (signatureP256 != null && peer.peerECDSAPubKey != null);
      boolean verifyECDSA = false; // assume it failed.

      // Is there a new ECDSA sig?
      if (isECDSAsigPresent) {
        fs.putSingle(PeerNode.SFS_KEY_SIG_P256, signatureP256);
        verifyECDSA =
            ECDSA.verify(
                Curves.P256, peer.peerECDSAPubKey, Base64.decode(signatureP256), toVerifyECDSA);
      }

      // If there is no signature, FAIL
      // If there is an ECDSA signature, and it doesn't verify, FAIL
      boolean hasNoSignature = (!isECDSAsigPresent);
      boolean isECDSAsigInvalid = (isECDSAsigPresent && !verifyECDSA);
      failed = hasNoSignature || isECDSAsigInvalid;
      if (failed) {
        String errCause = "";
        if (hasNoSignature) errCause += " (No signature)";
        if (isECDSAsigInvalid) errCause += " (ECDSA signature is invalid)";
        errCause += " (VERIFICATION FAILED)";
        LOG.atError()
            .addArgument(errCause)
            .addArgument(fs::toOrderedString)
            .log("The integrity of the reference has been compromised!{} fs was\n{}");
        peer.setSignatureVerificationSuccessfull(false);
        throw new ReferenceSignatureVerificationException(
            "The integrity of the reference has been compromised!" + errCause);
      } else {
        peer.setSignatureVerificationSuccessfull(true);
        if (!peer.dontKeepFullFieldSet()) peer.fullFieldSet = fs;
      }
    } catch (IllegalBase64Exception e) {
      LOG.error("Invalid reference: {}", e, e);
      throw new ReferenceSignatureVerificationException(
          "The node reference you added is invalid: It does not have a valid ECDSA signature.");
    }
    return true;
  }

  String formatPeerKeyHash(byte[] hash) {
    return HexUtil.bytesToHex(hash);
  }

  String formatDuration(long millis) {
    return TimeUtil.formatTime(millis);
  }

  static SimpleFieldSet compressedNoderefToFieldSet(byte[] data, int offset, int length)
      throws FSParseException {
    if (length <= 5) throw new FSParseException("Too short");
    int firstByte = data[offset];
    offset++;
    length--;
    if ((firstByte & 0x2) == 2) { // DSAcompressed group; legacy
      offset++;
      length--;
    }
    // Is it compressed?
    if ((firstByte & 1) == 1) {
      Inflater inflater = new Inflater();
      try {
        inflater.setInput(data, offset, length);
        // We shouldn't ever need 4096 bytes long ref!
        byte[] output = new byte[4096];
        length = inflater.inflate(output, 0, output.length);
        // Finished
        data = output;
        offset = 0;
        if (LOG.isDebugEnabled())
          LOG.debug("We have decompressed a {} bytes big reference.", length);
      } catch (DataFormatException _) {
        throw new FSParseException("Invalid compressed data");
      } finally {
        inflater.end();
      }
    }
    if (LOG.isDebugEnabled())
      LOG.debug("Reference: {}({})", HexUtil.bytesToHex(data, offset, length), length);

    // Now decode it
    ByteArrayInputStream bais = new ByteArrayInputStream(data, offset, length);
    InputStreamReader isr = new InputStreamReader(bais, StandardCharsets.UTF_8);
    BufferedReader br = new BufferedReader(isr);
    try {
      return new SimpleFieldSet(br, false, true);
    } catch (IOException e) {
      throw new FSParseException("Impossible: " + e, e);
    }
  }

  static boolean isValidAddress(InetAddress addr) {
    return IPUtil.isValidAddress(addr, false);
  }

  static String[] splitVersionComponents(String versionStr) {
    if (versionStr == null) {
      return new String[0];
    }
    String[] raw = versionStr.split(",");
    ArrayList<String> components = new ArrayList<>(raw.length);
    for (String token : raw) {
      String trimmed = token.trim();
      if (!trimmed.isEmpty()) {
        components.add(trimmed);
      }
    }
    return components.toArray(new String[0]);
  }

  static USK computeArk(
      PeerNode peer, SimpleFieldSet fs, boolean onStartup, boolean forDiffNodeRef, USK currentArk) {
    try {
      String arkPubKey = fs.get(PeerNode.SFS_KEY_ARK_PUBURI);
      long arkNo = fs.getLong(PeerNode.SFS_KEY_ARK_NUMBER, -1);
      if (arkPubKey == null && arkNo <= -1) return null; // pair is optional
      if (arkPubKey != null && arkNo > -1) {
        if (onStartup) arkNo++;
        FreenetURI uri = new FreenetURI(arkPubKey);
        ClientSSK ssk = new ClientSSK(uri);
        return new USK(ssk, arkNo);
      }
      if (forDiffNodeRef && arkPubKey == null && currentArk != null) {
        return currentArk.copy(arkNo);
      }
      if (forDiffNodeRef && arkPubKey != null && currentArk != null) {
        LOG.error(
            "Got a differential node reference from {} with an arkPubKey but no ARK edition", peer);
        return null;
      }
    } catch (MalformedURLException | NumberFormatException e) {
      LOG.error("Couldn't parse ARK info for {}: {}", peer, e, e);
    }
    return null;
  }
}
