package network.crypta.node;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.ArrayList;
import java.util.zip.DeflaterOutputStream;
import network.crypta.crypt.BlockCipher;
import network.crypta.crypt.ECDSA;
import network.crypta.crypt.ECDSA.Curves;
import network.crypta.crypt.RandomSource;
import network.crypta.crypt.SHA256;
import network.crypta.crypt.UnsupportedCipherException;
import network.crypta.crypt.ciphers.Rijndael;
import network.crypta.io.AddressTracker.Status;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.IncomingPacketFilterImpl;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.keys.FreenetURI;
import network.crypta.keys.InsertableClientSSK;
import network.crypta.support.Base64;
import network.crypta.support.IllegalBase64Exception;
import network.crypta.support.SimpleFieldSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages the node's cryptographic identity and UDP transport parameters.
 *
 * <p>This component owns the long‑lived identity (random {@code identity} bytes and their hashes),
 * the ECDSA P‑256 key pair used for signatures, the Address Resolution Key (ARK) used for updatable
 * references, and the UDP socket / packet mangler used by the FNP transport. It also builds, signs,
 * and compresses noderefs that peers consume during handshake.
 *
 * <p>Construction binds a UDP port (deterministic or random) and wires the packet pipeline, but the
 * I/O threads only start after a call to {@link #start()}.
 *
 * @author toad
 */
public class NodeCrypto {
  private static final Logger LOG = LoggerFactory.getLogger(NodeCrypto.class);
  private static final String LOG_CAUGHT_PREFIX = "Caught ";
  private static final String SFS_KEY_ECDSA = "ecdsa";

  /** Length of a node identity */
  public static final int IDENTITY_LENGTH = 32;

  final Node node;

  private final boolean isOpennet;

  final RandomSource random;

  /**
   * UDP socket handler for this node. Reads/writes the configured port and feeds raw packets to the
   * packet mangler.
   */
  private final UdpSocketHandler socket;

  private final FNPPacketMangler packetMangler;

  // Consider abstracting address handling to a NodeReference-like component.
  private final int portNumber;

  /**
   * @see PeerNode#identity
   */
  private byte[] myIdentity;

  /** Hash of identity. Used as setup key. */
  private byte[] identityHash;

  /** Hash of hash of identity i.e. hash of setup key. */
  private byte[] identityHashHash;

  /** Nonce used to generate ?secureid= for fproxy etc */
  byte[] clientNonce;

  /** My ECDSA/P256 keypair and context */
  private ECDSA ecdsaP256;

  private byte[] ecdsaPubKeyHash;

  /** My ARK SSK private key */
  private InsertableClientSSK myARK;

  /** My ARK sequence number */
  private long myARKNumber;

  private final NodeCryptoConfig config;

  private final NodeIPPortDetector detector;

  private final BlockCipher anonSetupCipher;

  // Noderef related
  /** An ordered version of the noderef FieldSet, without the signature */
  private String mySignedReference = null;

  /** The ECDSA/P256 signature of the above fieldset */
  private String myReferenceECDSASignature = null;

  /** A synchronization object used while signing the reference fieldset */
  private final Object referenceSync = new Object();

  /**
   * Constructs the crypto/transport context and binds the UDP socket.
   *
   * <p>Reads the desired port and bind address from {@code config}. When the configured port is
   * {@code -1}, a random available port in the ephemeral range is selected. The chosen port is
   * written back to the config. Initializes the packet mangler and connectivity detector.
   *
   * @param node owning node instance; used for RNG, collectors, versioning, and peer access
   * @param isOpennet whether this node is configured for opennet
   * @param config source of port/bind settings and feature toggles
   * @param startupTime process start time used for metrics
   * @param enableARKs whether ARK-related features are enabled
   * @throws NodeInitException if the socket cannot be created or bound
   * @throws IllegalStateException if the configured cipher cannot be initialized
   */
  @SuppressWarnings("java:S1181")
  public NodeCrypto(
      final Node node,
      final boolean isOpennet,
      NodeCryptoConfig config,
      long startupTime,
      boolean enableARKs)
      throws NodeInitException {

    this.node = node;
    this.config = config;
    random = node.getRandom();
    this.isOpennet = isOpennet;

    config.starting(this);

    try {

      int configuredPort = config.getPort();
      FreenetInetAddress bindto = config.getBindTo();

      UdpSocketHandler u = createAndBindSocket(configuredPort, bindto, startupTime);
      socket = u;

      int actualPort = u.getPortNumber();
      LOG.info("FNP UDP port bound on {}:{}", bindto, actualPort);
      portNumber = actualPort;
      config.setPort(actualPort);

      socket.setDropProbability(config.getDropProbability());

      packetMangler = new FNPPacketMangler(node, this, socket);

      detector = new NodeIPPortDetector(node, node.getIpDetector(), this, enableARKs);

      anonSetupCipher = new Rijndael(256, 256);

    } catch (NodeInitException | Error | RuntimeException e) {
      config.stopping();
      throw e;
    } catch (UnsupportedCipherException e) {
      config.stopping();
      throw new IllegalStateException(e);
    } finally {
      config.maybeStarted();
    }
  }

  private UdpSocketHandler createAndBindSocket(
      int port, FreenetInetAddress bindto, long startupTime) throws NodeInitException {
    if (port > 65535) {
      throw new NodeInitException(
          NodeInitException.EXIT_IMPOSSIBLE_USM_PORT, "Impossible port number: " + port);
    }

    if (port == -1) {
      // Pick a random port
      for (int i = 0; i < 200000; i++) {
        int portNo = 1024 + random.nextInt(65535 - 1024);
        try {
          return new UdpSocketHandler(
              portNo,
              bindto.getAddress(),
              node,
              startupTime,
              getTitle(portNo),
              node.getCollector());
        } catch (Exception e) {
          LOG.info("Bind {}:{} throws {}", bindto, portNo, e, e);
        }
      }
      throw new NodeInitException(
          NodeInitException.EXIT_NO_AVAILABLE_UDP_PORTS,
          "Could not find an available UDP port number for FNP (none specified)");
    }

    try {
      return new UdpSocketHandler(
          port, bindto.getAddress(), node, startupTime, getTitle(port), node.getCollector());
    } catch (Exception e) {
      LOG.error(LOG_CAUGHT_PREFIX + "{}", e, e);
      throw new NodeInitException(
          NodeInitException.EXIT_IMPOSSIBLE_USM_PORT,
          "Could not bind to port: " + port + " (node already running?)");
    }
  }

  private String getTitle(int port) {
    // Title text only; localization handled by higher layers.
    return "UDP " + (isOpennet ? "Opennet " : "Darknet ") + "port " + port;
  }

  /**
   * Reads cryptographic identity and related fields from a noderef.
   *
   * <p>Expected keys include {@code identity}, {@code ecdsa.P256}, optional ARK fields, and an
   * optional {@code clientNonce}. Derived hashes are computed and the anonymous setup cipher is
   * initialized from {@code identity}.
   *
   * @param fs ordered noderef {@link SimpleFieldSet}
   * @throws IOException if a required field is missing or malformed
   */
  public void readCrypto(SimpleFieldSet fs) throws IOException {
    parseIdentity(fs);
    parseECDSA(fs);
    parseARK(fs);
    parseClientNonce(fs);
  }

  private void parseIdentity(SimpleFieldSet fs) throws IOException {
    String identity = fs.get("identity");
    if (identity == null) throw new IOException();
    try {
      myIdentity = Base64.decode(identity);
    } catch (IllegalBase64Exception _) {
      throw new IOException();
    }
    identityHash = SHA256.digest(myIdentity);
    anonSetupCipher.initialize(identityHash);
    identityHashHash = SHA256.digest(identityHash);
  }

  private void parseECDSA(SimpleFieldSet fs) throws IOException {
    try {
      SimpleFieldSet ecdsaSFS = fs.subset(SFS_KEY_ECDSA);
      if (ecdsaSFS != null)
        ecdsaP256 = new ECDSA(ecdsaSFS.subset(ECDSA.Curves.P256.name()), Curves.P256);
    } catch (FSParseException e) {
      throw new IOException(
          "Failed to parse ECDSA (P256) information from noderef SimpleFieldSet", e);
    }
    if (ecdsaP256 == null) {
      // No keypair present in the noderef; generate a fresh one.
      LOG.info("Missing ecdsa.P256 in noderef; generating new key");
      ecdsaP256 = new ECDSA(Curves.P256);
    }
    ecdsaPubKeyHash = SHA256.digest(ecdsaP256.getPublicKey().getEncoded());
  }

  private void parseARK(SimpleFieldSet fs) {
    InsertableClientSSK ark = null;
    String s = fs.get("ark.number");
    String privARK = fs.get("ark.privURI");
    try {
      if (privARK != null) {
        FreenetURI uri = new FreenetURI(privARK);
        ark = InsertableClientSSK.create(uri);
        if (s == null) {
          ark = null;
          myARKNumber = 0;
        } else {
          Long parsed = safeParseLong(s);
          if (parsed == null) {
            myARKNumber = 0;
            ark = null;
          } else {
            myARKNumber = parsed;
          }
        }
      }
    } catch (MalformedURLException e) {
      LOG.debug(LOG_CAUGHT_PREFIX + "{}", e, e);
    }
    if (ark == null) {
      ark = InsertableClientSSK.createRandom(random, "ark");
      myARKNumber = 0;
    }
    myARK = ark;
  }

  private static Long safeParseLong(String value) {
    try {
      return Long.parseLong(value);
    } catch (NumberFormatException _) {
      return null;
    }
  }

  private void parseClientNonce(SimpleFieldSet fs) throws IOException {
    String cn = fs.get("clientNonce");
    if (cn != null) {
      try {
        clientNonce = Base64.decode(cn);
      } catch (IllegalBase64Exception e) {
        throw new IOException("Invalid clientNonce field: " + e);
      }
    } else {
      clientNonce = new byte[32];
      node.getRandom().nextBytes(clientNonce);
    }
  }

  /** Creates a fresh identity, ECDSA key pair, ARK, and client nonce. */
  public void initCrypto() {
    ecdsaP256 = new ECDSA(ECDSA.Curves.P256);
    ecdsaPubKeyHash = SHA256.digest(ecdsaP256.getPublicKey().getEncoded());
    myARK = InsertableClientSSK.createRandom(random, "ark");
    myARKNumber = 0;
    clientNonce = new byte[32];
    node.getRandom().nextBytes(clientNonce);
    myIdentity = new byte[IDENTITY_LENGTH];
    node.getRandom().nextBytes(myIdentity);
    identityHash = SHA256.digest(myIdentity);
    identityHashHash = SHA256.digest(identityHash);
    anonSetupCipher.initialize(identityHash);
  }

  /**
   * Starts I/O: configures filters, then starts the packet mangler and UDP socket threads.
   *
   * <p>Call once after construction and identity initialization.
   */
  public void start() {
    socket.calculateMaxPacketSize();
    socket.setLowLevelFilter(new IncomingPacketFilterImpl(packetMangler, node, this));
    packetMangler.start();
    socket.start();
  }

  /**
   * Exports a full noderef including private material.
   *
   * <p>Includes the private ECDSA fields and ARK insert URI. Intended for local persistence, not
   * for sharing with peers.
   *
   * @return a {@link SimpleFieldSet} with both public and private fields
   */
  public SimpleFieldSet exportPrivateFieldSet() {
    SimpleFieldSet fs = exportPublicFieldSet(false, false, false);
    addPrivateFields(fs);
    return fs;
  }

  /**
   * Exports a public noderef that peers can use to connect.
   *
   * <p>Contains only public information (no private keys). See {@link
   * #exportPublicFieldSet(boolean, boolean, boolean)} for flags that tailor the contents for
   * setup/initiator phases.
   *
   * @return ordered {@link SimpleFieldSet} containing public fields
   */
  public SimpleFieldSet exportPublicFieldSet() {
    return exportPublicFieldSet(false, false, false);
  }

  /**
   * Export my reference so that another node can connect to me.
   *
   * @param forSetup If true, strip out everything that isn't needed for the references exchanged
   *     immediately after connection setup. I.e. strip out everything that is invariant, or that
   *     can safely be exchanged later.
   * @param forAnonInitiator If true, we are adding a node from an anonymous initiator noderef
   *     exchange. Minimal noderef which we can construct a PeerNode from. Short-lived so no ARK
   *     etc. Already signed so dump the signature.
   */
  SimpleFieldSet exportPublicFieldSet(boolean forSetup, boolean forAnonInitiator, boolean forARK) {
    SimpleFieldSet fs = exportPublicCryptoFieldSet(forSetup || forARK, forAnonInitiator);
    maybeAppendIPs(fs, forSetup, forAnonInitiator);
    maybeAddLocation(fs, forARK, forSetup, forAnonInitiator);
    addVersionFields(fs, forAnonInitiator);
    maybeAddName(fs, forSetup, forARK);
    maybeSignReference(fs, forAnonInitiator);

    if (LOG.isDebugEnabled()) LOG.debug("My reference: {}", fs.toOrderedString());
    return fs;
  }

  SimpleFieldSet exportPublicCryptoFieldSet(boolean forSetup, boolean forAnonInitiator) {
    SimpleFieldSet fs = new SimpleFieldSet(true);
    int[] negTypes = packetMangler.supportedNegTypes(true);
    if (!forSetup) {
      // These are invariant. They cannot change on connection setup. They can safely be excluded.
      fs.put(SFS_KEY_ECDSA, ecdsaP256.asFieldSet(false));
      fs.putSingle("identity", Base64.encode(myIdentity));
    }
    if (!forAnonInitiator) {
      // Short-lived connections don't need ARK and don't need negTypes either.
      fs.put("auth.negTypes", negTypes);
      if (!forSetup) {
        fs.put("ark.number", myARKNumber); // Can be changed on setup
        fs.putSingle(
            "ark.pubURI", myARK.getURI().toString(false, false)); // Can be changed on setup
      }
    }
    return fs;
  }

  private String ecdsaSignRef(String mySignedReference) throws NodeInitException {
    if (LOG.isDebugEnabled()) LOG.debug("Signing reference:\n{}", mySignedReference);

    byte[] ref = mySignedReference.getBytes(StandardCharsets.UTF_8);

    // We don't need a padded signature here
    byte[] sig = ecdsaP256.sign(ref);
    if (LOG.isDebugEnabled() && !ECDSA.verify(Curves.P256, getECDSAP256Pubkey(), sig, ref))
      throw new NodeInitException(NodeInitException.EXIT_EXCEPTION_TO_DEBUG, mySignedReference);
    return Base64.encode(sig);
  }

  private byte[] myCompressedRef(boolean setup, boolean heavySetup) {
    SimpleFieldSet fs = exportPublicFieldSet(setup, heavySetup, false);

    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    try (DeflaterOutputStream gis = new DeflaterOutputStream(baos)) {
      fs.writeTo(gis);
    } catch (IOException e) {
      LOG.error("I/O error: {}", e.getMessage(), e);
    }

    byte[] buf = baos.toByteArray();
    if (buf.length >= 4096)
      throw new IllegalStateException(
          "We are attempting to send a " + buf.length + " bytes big reference!");
    byte[] obuf = new byte[buf.length + 1];
    int offset = 0;
    obuf[offset++] = 0x01; // compressed noderef
    System.arraycopy(buf, 0, obuf, offset, buf.length);
    if (LOG.isDebugEnabled())
      LOG.debug("myCompressedRef({},{}) returning {} bytes", setup, heavySetup, obuf.length);
    return obuf;
  }

  /**
   * Returns the setup-phase noderef, compressed with DEFLATE and tagged with prefix {@code 0x01}.
   *
   * @return compressed bytes for the lightweight setup exchange
   */
  public byte[] myCompressedSetupRef() {
    return myCompressedRef(true, false);
  }

  /**
   * Returns the heavy setup noderef (for unknown peers), compressed and tagged with {@code 0x01}.
   *
   * @return compressed bytes used when we do not already know the peer
   */
  public byte[] myCompressedHeavySetupRef() {
    return myCompressedRef(false, true);
  }

  /**
   * Returns the full noderef, compressed and tagged with {@code 0x01}.
   *
   * @return compressed bytes for the complete noderef
   */
  public byte[] myCompressedFullRef() {
    return myCompressedRef(false, false);
  }

  void addPrivateFields(SimpleFieldSet fs) {
    // Let's not add it twice
    fs.removeSubset(SFS_KEY_ECDSA);
    fs.put(SFS_KEY_ECDSA, ecdsaP256.asFieldSet(true));

    fs.putSingle("ark.privURI", myARK.getInsertURI().toString(false, false));
    fs.putSingle("clientNonce", Base64.encode(clientNonce));
  }

  private void maybeAppendIPs(SimpleFieldSet fs, boolean forSetup, boolean forAnonInitiator) {
    if ((!forAnonInitiator) && (!forSetup)) {
      Peer[] ips = detector.detectPrimaryPeers();
      if (ips != null) {
        for (Peer ip : ips) {
          java.net.InetAddress a = ip.getFreenetAddress().getAddress();
          String host = network.crypta.support.transport.ip.HostnameUtil.toNoderefHost(a);
          String value =
              (host != null ? host : ip.getFreenetAddress().toString()) + ':' + ip.getPort();
          fs.putAppend("physical.udp", value);
        }
      }
    }
  }

  private void maybeAddLocation(
      SimpleFieldSet fs, boolean forARK, boolean forSetup, boolean forAnonInitiator) {
    if (!(forARK || forSetup || forAnonInitiator)) {
      fs.put("location", node.getLocationManager().getLocation());
    }
  }

  private void addVersionFields(SimpleFieldSet fs, boolean forAnonInitiator) {
    fs.putSingle("version", Version.getVersionString());
    if (!forAnonInitiator) {
      fs.putSingle("lastGoodVersion", Version.getMinAcceptableVersionString());
    }
    if (Node.isTestnetEnabled()) {
      fs.put("testnet", true);
    }
  }

  private void maybeAddName(SimpleFieldSet fs, boolean forSetup, boolean forARK) {
    if ((!isOpennet) && (!forSetup) && (!forARK)) {
      fs.putSingle("myName", node.getMyName());
    }
  }

  private void maybeSignReference(SimpleFieldSet fs, boolean forAnonInitiator) {
    if (forAnonInitiator) return;
    fs.put("opennet", isOpennet);
    synchronized (referenceSync) {
      if (myReferenceECDSASignature == null
          || mySignedReference == null
          || !mySignedReference.equals(fs.toOrderedString())) {
        mySignedReference = fs.toOrderedString();
        try {
          myReferenceECDSASignature = ecdsaSignRef(mySignedReference);
          fs.putSingle("sigP256", myReferenceECDSASignature);
          mySignedReference = fs.toOrderedString();
        } catch (NodeInitException e) {
          node.exit(e.exitCode);
        }
      }
    }
  }

  /**
   * Sign data with the node's ECDSA key. The data does not need to be hashed, the signing code will
   * handle that for us, using an algorithm appropriate for the keysize.
   */
  byte[] ecdsaSign(byte[]... data) {
    return ecdsaP256.signToNetworkFormat(data);
  }

  /**
   * Returns the node's ECDSA P‑256 public key.
   *
   * @return immutable {@link ECPublicKey} instance
   */
  public ECPublicKey getECDSAP256Pubkey() {
    return ecdsaP256.getPublicKey();
  }

  /**
   * Updates the UDP packet drop probability on the active socket.
   *
   * @param val probability in the configured units (implementation-defined)
   */
  public void onSetDropProbability(int val) {
    synchronized (this) {
      if (socket == null) return;
    }
    socket.setDropProbability(val);
  }

  /** Stops I/O and closes the UDP socket. Safe to call during shutdown. */
  public void stop() {
    config.stopping();
    socket.close();
  }

  /**
   * Returns the current peer list of this node.
   *
   * @return an array of peers, or {@code null} when the peer manager is unavailable
   */
  @SuppressWarnings("java:S1168")
  public PeerNode[] getPeerNodes() {
    if (node.getPeers() == null) return null;
    if (isOpennet) return node.getPeers().roster().getOpennetAndSeedServerPeers();
    else return node.getPeers().roster().getDarknetPeers();
  }

  /**
   * Determines whether we should attempt a handshake to the given address for the peer.
   *
   * <p>Implements the one-connection-per-address policy when enabled and excludes self-addresses
   * detected by {@link #getDetector()}.
   *
   * @param pn target peer
   * @param addr candidate network address
   * @return {@code true} to proceed with a handshake; {@code false} to skip
   */
  public boolean allowConnection(PeerNode pn, FreenetInetAddress addr) {
    // Disallow multiple connections to the same address.
    // For IPv6, a configurable same-/64 subnet rule may be more appropriate than exact match.
    if (config.oneConnectionPerAddress()
        && node.getPeers().roster().anyConnectedPeerHasAddress(addr, pn)
        && !detector.includes(addr)
        && addr.isRealInternetAddress(false, false, false)) {
      LOG.info("Skip handshake packets to {} for {}: same IP address as another node", addr, pn);
      return false;
    }
    return true;
  }

  /*
   * If oneConnectionPerAddress is not set, but there are peers with the same IP for which it is
   * set, disconnect them.
   */
  /**
   * Disconnects existing peers that violate one-connection-per-address for the given address.
   *
   * @param peerNode the incoming/considered peer
   * @param address the address shared by multiple peers
   */
  public void maybeBootConnection(PeerNode peerNode, FreenetInetAddress address) {
    if (detector.includes(address)) return;
    if (!address.isRealInternetAddress(false, false, false)) return;
    java.util.List<PeerNode> possibleMatches =
        node.getPeers().roster().getAllConnectedByAddress(address, true);
    if (possibleMatches == null) return;
    for (PeerNode pn : possibleMatches) {
      if (pn == peerNode || pn.equals(peerNode)) continue;
      maybeDisconnectForSameIP(peerNode, address, pn);
    }
  }

  private void maybeDisconnectForSameIP(
      PeerNode incomingPeer, FreenetInetAddress address, PeerNode existingPeer) {
    if (!existingPeer.crypto.getConfig().oneConnectionPerAddress()) return;
    if (existingPeer instanceof DarknetPeerNode darknetPeerNode) {
      if (!(incomingPeer instanceof DarknetPeerNode)) {
        // Darknet is only affected by other darknet peers.
        // Opennet peers with the same IP will NOT cause darknet peers to be dropped, even if
        // one connection per IP is set for darknet, and even if it isn't set for opennet.
        // (Which would be a perverse configuration anyway!)
        // Consider: FOAFs should not boot darknet connections.
        return;
      }
      LOG.error("Drop peer {} due to existing connection on same IP address", existingPeer);
      LOG.info(
          "Disconnect permanently from friend \"{}\" because friend \"{}\" uses the same IP address"
              + " {}",
          darknetPeerNode.getName(),
          ((DarknetPeerNode) incomingPeer).getName(),
          address);
    }
    node.getPeers()
        .messenger()
        .disconnectAndRemove(existingPeer, true, true, existingPeer.isOpennet());
  }

  /**
   * Returns the cipher used for anonymous setup with unknown initiators.
   *
   * @return initialized {@link BlockCipher}
   */
  public BlockCipher getAnonSetupCipher() {
    return anonSetupCipher;
  }

  /**
   * Returns peers that are using this packet mangler for unknown-initiator handshakes.
   *
   * @return array of peers suitable for anonymous setup
   */
  public PeerNode[] getAnonSetupPeerNodes() {
    ArrayList<PeerNode> v = new ArrayList<>();
    for (PeerNode pn : node.getPeers().myPeers()) {
      if (pn.handshakeUnknownInitiator() && pn.getOutgoingMangler() == packetMangler) v.add(pn);
    }
    return v.toArray(new PeerNode[0]);
  }

  void setPortForwardingBroken() {
    this.socket.getAddressTracker().setBroken();
  }

  /**
   * Returns the stable identity bytes advertised to peers.
   *
   * <p>The current implementation returns the SHA‑256 of the encoded ECDSA P‑256 public key. The
   * {@code negType} parameter is accepted for signature compatibility and logging.
   *
   * @param negType negotiation type (currently informational)
   * @return 32‑byte hash identifying this node
   */
  public byte[] getIdentity(int negType) {
    if (LOG.isTraceEnabled()) {
      LOG.trace("getIdentity(negType={})", negType);
    }
    return ecdsaPubKeyHash;
  }

  /** Returns whether connectivity testing confirms definite port forwarding. */
  public boolean definitelyPortForwarded() {
    return socket.getDetectedConnectivityStatus() == Status.DEFINITELY_PORT_FORWARDED;
  }

  /** Returns the last detected connectivity status for the UDP socket. */
  public Status getDetectedConnectivityStatus() {
    return socket.getDetectedConnectivityStatus();
  }

  /** Returns the configured bind address. */
  public FreenetInetAddress getBindTo() {
    return config.getBindTo();
  }

  /** Whether anonymous authentication is desired for this node kind. */
  public boolean wantAnonAuth() {
    return node.wantAnonAuth(isOpennet);
  }

  /** Whether anonymous authentication should allow IP change for this node kind. */
  public boolean wantAnonAuthChangeIP() {
    return node.wantAnonAuthChangeIP(isOpennet);
  }

  /** Returns the packet mangler handling encryption/negotiation for this node. */
  public FNPPacketMangler getPacketMangler() {
    return packetMangler;
  }

  /** Returns {@code true} when this node operates in opennet mode. */
  public boolean isOpennet() {
    return isOpennet;
  }

  /** Returns the UDP socket handler bound for this node. */
  public UdpSocketHandler getSocket() {
    return socket;
  }

  /** Returns the bound UDP port number. */
  public int getPortNumber() {
    return portNumber;
  }

  /** Returns the raw 32‑byte random identity generated for this node. */
  public byte[] getMyIdentity() {
    return myIdentity;
  }

  /** Returns SHA‑256 of {@link #getMyIdentity()}. */
  public byte[] getIdentityHash() {
    return identityHash;
  }

  /** Returns SHA‑256 of {@link #getIdentityHash()}. */
  public byte[] getIdentityHashHash() {
    return identityHashHash;
  }

  /** Returns SHA‑256 of the encoded ECDSA P‑256 public key. */
  public byte[] getEcdsaPubKeyHash() {
    return ecdsaPubKeyHash;
  }

  /** Returns the ARK private key used for updatable references. */
  public InsertableClientSSK getMyARK() {
    return myARK;
  }

  /** Returns the current ARK sequence number. */
  public long getMyARKNumber() {
    return myARKNumber;
  }

  /** Sets the ARK sequence number. */
  public void setMyARKNumber(long myARKNumber) {
    this.myARKNumber = myARKNumber;
  }

  /** Returns the immutable crypto configuration view. */
  public NodeCryptoConfig getConfig() {
    return config;
  }

  /** Returns the IP/port detector used to discover externally reachable addresses. */
  public NodeIPPortDetector getDetector() {
    return detector;
  }
}
