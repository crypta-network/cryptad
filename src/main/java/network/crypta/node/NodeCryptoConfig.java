package network.crypta.node;

import java.net.UnknownHostException;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.StringCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Holds network/crypto runtime configuration for a {@link NodeCrypto} instance.
 *
 * <p>The configuration can be read and updated before the underlying {@code NodeCrypto} is started.
 * Some values are intentionally immutable at runtime (for example, {@code listenPort} and {@code
 * bindTo}); attempts to change them on the fly result in validation errors and require a restart to
 * take effect. Values are sourced from {@link SubConfig} and exposed via synchronized accessors
 * where relevant.
 *
 * <p>Key settings include: - {@code listenPort}: {@code -1} selects a random available port on
 * activation; any explicit value must be in {@code [1, 65535]}. - {@code bindTo}: local address to
 * bind; {@code 0.0.0.0} binds all interfaces. - {@code testingDropPacketsEvery}: test hook; when
 * {@code > 0}, approximately one in N packets is dropped to simulate lossy links. - {@code
 * oneConnectionPerIP}: avoids multiple simultaneous connections to the same peer IP. - {@code
 * alwaysAllowLocalAddresses}: permits local/LAN addresses irrespective of per-peer flags. - {@code
 * assumeNATed}: enables aggressive handshakes typical for NAT traversal. - {@code
 * includeLocalAddressesInNoderefs}: includes local addresses in exported noderefs. - {@code
 * paddDataPackets}: pads data packets to obscure size; authentication packets are unaffected.
 *
 * <p>Thread-safety: mutators and most accessors synchronize on {@code this} (or the class where
 * noted). Callers may use the getters from any thread after construction.
 *
 * @author toad
 */
public class NodeCryptoConfig {
  private static final Logger LOG = LoggerFactory.getLogger(NodeCryptoConfig.class);
  private static final String KEY_BIND_TO = "bindTo";

  /** Port number; {@code -1} selects a random available port at activation time. */
  private int portNumber;

  /** Bind address; {@code 0.0.0.0} binds all local interfaces. */
  private final FreenetInetAddress bindTo;

  /**
   * Test hook for simulated loss. When {@code > 0}, roughly one in {@code dropProbability} packets
   * is dropped by the UDP handler to emulate lossy networks.
   */
  private int dropProbability;

  /** The current {@link NodeCrypto} instance, when started; {@code null} otherwise. */
  private NodeCrypto crypto;

  /**
   * Prevents maintaining multiple simultaneous connections to the same peer IP address. Typically
   * enabled for opennet and disabled for darknet.
   */
  private boolean oneConnectionPerAddress;

  /**
   * When true, allows connecting to peers via local/LAN IP addresses regardless of per‑peer flags.
   */
  private boolean alwaysAllowLocalAddresses;

  /**
   * When true, assumes the node is behind NAT and enables aggressive handshake behavior
   * (approximately every 10–30 seconds).
   */
  private boolean assumeNATed;

  /** When true, includes local addresses in exported noderefs. */
  private boolean includeLocalAddressesInNoderefs;

  /**
   * When true, pads data packets to reduce length leakage; authentication packets are not padded.
   */
  private boolean paddDataPackets;

  public NodeCryptoConfig(
      SubConfig config, int sortOrder, boolean isOpennet, SecurityLevels securityLevels)
      throws NodeInitException {
    sortOrder = registerListenPort(config, sortOrder, isOpennet);
    initializePortNumber(config);

    sortOrder = registerBindTo(config, sortOrder);
    this.bindTo = parseBindTo(config);

    sortOrder = registerTestingDropPacketsEvery(config, sortOrder);
    initializeDropProbability(config);

    sortOrder = registerOneConnectionPerIP(config, sortOrder, isOpennet);
    initializeOneConnectionPerAddress(config);
    maybeRegisterOpennetThreatListener(isOpennet, securityLevels);

    sortOrder = registerAlwaysAllowLocalAddresses(config, sortOrder, isOpennet);
    initializeAlwaysAllowLocalAddresses(config);

    sortOrder = registerAssumeNATed(config, sortOrder);
    initializeAssumeNATed(config);

    sortOrder = registerIncludeLocalAddressesInNoderefs(config, sortOrder, isOpennet);
    initializeIncludeLocalAddressesInNoderefs(config);

    registerPaddDataPackets(config, sortOrder);
    initializePaddDataPackets(config);
  }

  private int registerListenPort(SubConfig config, int sortOrder, boolean isOpennet) {
    config.register(
        "listenPort",
        -1 /* means random */,
        new Option.Meta(
            sortOrder++,
            true,
            true,
            isOpennet ? "Node.opennetPort" : "Node.port",
            isOpennet ? "Node.opennetPortLong" : "Node.portLong"),
        new IntCallback() {
          @Override
          public Integer get() {
            synchronized (NodeCryptoConfig.class) {
              if (crypto != null) portNumber = crypto.getPortNumber();
              return portNumber;
            }
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (val < -1 || val == 0 || val > 65535) {
              throw new InvalidConfigValueException("Invalid port number");
            }

            synchronized (NodeCryptoConfig.class) {
              if (portNumber == val) return;
              // On-the-fly listenPort changes are not supported.
              // Note that this sort of thing should be the exception rather than the rule!
              if (crypto != null)
                throw new InvalidConfigValueException(
                    "Switching listenPort on the fly not yet supported");
              portNumber = val;
            }
          }

          @Override
          public boolean isReadOnly() {
            return true;
          }
        },
        false);
    return sortOrder;
  }

  private void initializePortNumber(SubConfig config) {
    try {
      portNumber = config.getInt("listenPort");
    } catch (Exception e) {
      // Keep default (-1) on failure and log the reason.
      LOG.error("Read listenPort from config failed; keeping default -1 (reason={})", e, e);
      portNumber = -1;
    }
  }

  private int registerBindTo(SubConfig config, int sortOrder) {
    config.register(
        KEY_BIND_TO,
        "0.0.0.0",
        new Option.Meta(sortOrder++, true, true, "Node.bindTo", "Node.bindToLong"),
        new NodeBindtoCallback());
    return sortOrder;
  }

  private FreenetInetAddress parseBindTo(SubConfig config) throws NodeInitException {
    try {
      return new FreenetInetAddress(config.getString(KEY_BIND_TO), false);
    } catch (UnknownHostException _) {
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_BIND_USM,
          "Invalid bindTo: " + config.getString(KEY_BIND_TO));
    }
  }

  private int registerTestingDropPacketsEvery(SubConfig config, int sortOrder) {
    config.register(
        "testingDropPacketsEvery",
        0,
        new Option.Meta(
            sortOrder++, true, false, "Node.dropPacketEvery", "Node.dropPacketEveryLong"),
        new IntCallback() {
          @Override
          public Integer get() {
            synchronized (NodeCryptoConfig.this) {
              return dropProbability;
            }
          }

          @Override
          public void set(Integer val) throws InvalidConfigValueException {
            if (val < 0)
              throw new InvalidConfigValueException("testingDropPacketsEvery must not be negative");
            synchronized (NodeCryptoConfig.this) {
              if (val == dropProbability) return;
              dropProbability = val;
              if (crypto == null) return;
            }
            crypto.onSetDropProbability(val);
          }
        },
        false);
    return sortOrder;
  }

  private void initializeDropProbability(SubConfig config) {
    dropProbability = config.getInt("testingDropPacketsEvery");
  }

  private int registerOneConnectionPerIP(SubConfig config, int sortOrder, boolean isOpennet) {
    config.register(
        "oneConnectionPerIP",
        isOpennet,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            (isOpennet ? "OpennetManager" : "Node") + ".oneConnectionPerIP",
            (isOpennet ? "OpennetManager" : "Node") + ".oneConnectionPerIPLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            synchronized (NodeCryptoConfig.this) {
              return oneConnectionPerAddress;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (NodeCryptoConfig.this) {
              oneConnectionPerAddress = val;
            }
          }
        });
    return sortOrder;
  }

  private void initializeOneConnectionPerAddress(SubConfig config) {
    oneConnectionPerAddress = config.getBoolean("oneConnectionPerIP");
  }

  private void maybeRegisterOpennetThreatListener(
      boolean isOpennet, SecurityLevels securityLevels) {
    if (isOpennet) {
      securityLevels.addNetworkThreatLevelListener(
          (oldLevel, newLevel) -> {
            if (newLevel == NETWORK_THREAT_LEVEL.LOW) {
              oneConnectionPerAddress = false;
            }
            if (oldLevel == NETWORK_THREAT_LEVEL.LOW) {
              oneConnectionPerAddress = true;
            }
          });
    }
  }

  private int registerAlwaysAllowLocalAddresses(
      SubConfig config, int sortOrder, boolean isOpennet) {
    config.register(
        "alwaysAllowLocalAddresses",
        !isOpennet,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "Node.alwaysAllowLocalAddresses",
            "Node.alwaysAllowLocalAddressesLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            synchronized (NodeCryptoConfig.this) {
              return alwaysAllowLocalAddresses;
            }
          }

          @Override
          public void set(Boolean val) {
            synchronized (NodeCryptoConfig.this) {
              alwaysAllowLocalAddresses = val;
            }
          }
        });
    return sortOrder;
  }

  private void initializeAlwaysAllowLocalAddresses(SubConfig config) {
    alwaysAllowLocalAddresses = config.getBoolean("alwaysAllowLocalAddresses");
  }

  private int registerAssumeNATed(SubConfig config, int sortOrder) {
    config.register(
        "assumeNATed",
        true,
        new Option.Meta(sortOrder++, true, true, "Node.assumeNATed", "Node.assumeNATedLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return assumeNATed;
          }

          @Override
          public void set(Boolean val) {
            assumeNATed = val;
          }
        });
    return sortOrder;
  }

  private void initializeAssumeNATed(SubConfig config) {
    assumeNATed = config.getBoolean("assumeNATed");
  }

  private int registerIncludeLocalAddressesInNoderefs(
      SubConfig config, int sortOrder, boolean isOpennet) {
    // Include local IP addresses in the exported noderef file.
    config.register(
        "includeLocalAddressesInNoderefs",
        !isOpennet,
        new Option.Meta(
            sortOrder++,
            true,
            false,
            "NodeIPDectector.inclLocalAddress",
            "NodeIPDectector.inclLocalAddressLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return includeLocalAddressesInNoderefs;
          }

          @Override
          public void set(Boolean val) {
            includeLocalAddressesInNoderefs = val;
          }
        });
    return sortOrder;
  }

  private void initializeIncludeLocalAddressesInNoderefs(SubConfig config) {
    includeLocalAddressesInNoderefs = config.getBoolean("includeLocalAddressesInNoderefs");
  }

  private void registerPaddDataPackets(SubConfig config, int sortOrder) {
    // Toggle padding of outgoing data packets (authentication packets remain unpadded).
    config.register(
        "paddDataPackets",
        true,
        new Option.Meta(sortOrder, true, false, "Node.paddDataPackets", "Node.paddDataPacketsLong"),
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return paddDataPackets;
          }

          @Override
          public void set(Boolean val) {
            if (val.equals(get())) return;
            paddDataPackets = val;
          }
        });
  }

  private void initializePaddDataPackets(SubConfig config) {
    paddDataPackets = config.getBoolean("paddDataPackets");
  }

  /** Number of config options; amount to increment {@code sortOrder} by. */
  public static final int OPTION_COUNT = 3;

  synchronized void starting(NodeCrypto crypto2) {
    if (crypto != null)
      throw new IllegalStateException(
          "Replacing existing NodeCrypto " + crypto + " with " + crypto2);
    crypto = crypto2;
  }

  @SuppressWarnings("unused")
  synchronized void started(NodeCrypto crypto2) {
    if (crypto != null)
      throw new IllegalStateException(
          "Replacing existing NodeCrypto " + crypto + " with " + crypto2);
  }

  synchronized void maybeStarted() {
    // Lifecycle hook invoked after start attempts; intentionally no-op here.
  }

  synchronized void stopping() {
    crypto = null;
  }

  /**
   * Returns the configured listen port.
   *
   * <p>A return value of {@code -1} indicates that a random available port will be chosen when the
   * transport activates.
   *
   * @return the port number, or {@code -1} as a sentinel for random selection
   */
  public synchronized int getPort() {
    return portNumber;
  }

  class NodeBindtoCallback extends StringCallback {

    @Override
    public String get() {
      return bindTo.toString();
    }

    @Override
    public void set(String val) throws InvalidConfigValueException {
      if (val.equals(get())) return;
      // Changing bindTo at runtime is not supported; requires restart.
      throw new InvalidConfigValueException("Cannot be updated on the fly");
    }

    @Override
    public boolean isReadOnly() {
      return true;
    }
  }

  /**
   * Returns the configured bind address.
   *
   * <p>The textual {@code 0.0.0.0} value represents all local interfaces.
   *
   * @return the bind address used by the transport
   */
  public synchronized FreenetInetAddress getBindTo() {
    return bindTo;
  }

  /**
   * Sets the stored listen port value.
   *
   * <p>This method updates configuration state only; socket binding is performed elsewhere during
   * activation.
   *
   * @param port the desired port number, or {@code -1} to select a random port at activation
   */
  public synchronized void setPort(int port) {
    portNumber = port;
  }

  /**
   * Returns the packet drop interval used for loss simulation.
   *
   * <p>When {@code > 0}, approximately one in {@code N} packets is dropped. {@code 0} disables the
   * simulation.
   *
   * @return the interval {@code N}; {@code 0} to disable
   */
  public synchronized int getDropProbability() {
    return dropProbability;
  }

  /**
   * Indicates whether only a single connection per peer IP address is allowed.
   *
   * @return {@code true} when multiple connections to the same IP are disallowed
   */
  public synchronized boolean oneConnectionPerAddress() {
    return oneConnectionPerAddress;
  }

  /**
   * Indicates whether local/LAN peer addresses are always permitted.
   *
   * @return {@code true} when local addresses are allowed irrespective of per‑peer settings
   */
  public synchronized boolean alwaysAllowLocalAddresses() {
    return alwaysAllowLocalAddresses;
  }

  /**
   * Indicates whether aggressive handshake behavior is enabled (as if behind NAT).
   *
   * @return {@code true} when aggressive handshakes are used
   */
  public boolean alwaysHandshakeAggressively() {
    return assumeNATed;
  }

  /**
   * Indicates whether local IP addresses are included in exported noderefs.
   *
   * @return {@code true} when local addresses are included
   */
  public boolean includeLocalAddressesInNoderefs() {
    return includeLocalAddressesInNoderefs;
  }

  /**
   * Indicates whether data packet padding is enabled.
   *
   * @return {@code true} when padding is applied to data packets
   */
  public boolean paddDataPackets() {
    return paddDataPackets;
  }
}
