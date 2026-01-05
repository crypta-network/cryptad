package network.crypta.node.subsystem;

import static java.util.concurrent.TimeUnit.SECONDS;

import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import network.crypta.client.FetchContext;
import network.crypta.config.Dimension;
import network.crypta.config.EnumerableOptionCallback;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.io.comm.DMT;
import network.crypta.io.comm.DisconnectedException;
import network.crypta.io.comm.FreenetInetAddress;
import network.crypta.io.comm.IOStatisticCollector;
import network.crypta.io.comm.Message;
import network.crypta.io.comm.MessageCore;
import network.crypta.io.comm.MessageFilter;
import network.crypta.io.comm.Peer;
import network.crypta.io.comm.PeerParseException;
import network.crypta.io.comm.ReferenceSignatureVerificationException;
import network.crypta.io.comm.UdpSocketHandler;
import network.crypta.l10n.NodeL10n;
import network.crypta.node.BandwidthManager;
import network.crypta.node.DNSRequester;
import network.crypta.node.DarknetPeerNode;
import network.crypta.node.FSParseException;
import network.crypta.node.LocationManager;
import network.crypta.node.Node;
import network.crypta.node.NodeCrypto;
import network.crypta.node.NodeCryptoConfig;
import network.crypta.node.NodeDispatcher;
import network.crypta.node.NodeIPDetector;
import network.crypta.node.NodeInitException;
import network.crypta.node.NodeStats;
import network.crypta.node.NodeStatsConfig;
import network.crypta.node.OpennetDisabledException;
import network.crypta.node.OpennetManager;
import network.crypta.node.OpennetPeerNode;
import network.crypta.node.PacketSender;
import network.crypta.node.PeerManager;
import network.crypta.node.PeerNode;
import network.crypta.node.PeerTooOldException;
import network.crypta.node.SeedServerTestPeerNode;
import network.crypta.node.SemiOrderedShutdownHook;
import network.crypta.node.UptimeEstimator;
import network.crypta.node.probe.Listener;
import network.crypta.node.probe.Type;
import network.crypta.node.useralerts.SimpleUserAlert;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.pluginmanager.ForwardPort;
import network.crypta.support.OutputThrottle;
import network.crypta.support.PooledExecutor;
import network.crypta.support.PrioritizedTicker;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.ShortBuffer;
import network.crypta.support.SimpleFieldSet;
import network.crypta.support.Ticker;
import network.crypta.support.api.BooleanCallback;
import network.crypta.support.api.IntCallback;
import network.crypta.support.api.LongCallback;
import network.crypta.support.api.StringCallback;
import network.crypta.support.transport.ip.HostnameSyntaxException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Network subsystem facade (peers, dispatcher, sockets). */
public final class NodeNetworkSubsystem {
  private static final Logger LOG = LoggerFactory.getLogger(NodeNetworkSubsystem.class);

  private final Node node;
  private FetchContext arkFetcherContext;
  private NodeStats nodeStats;
  private LocationManager locationManager;
  private PeerManager peers;
  private MessageCore usm;
  private NodeIPDetector ipDetector;
  private IOStatisticCollector collector;
  private PacketSender packetSender;
  private PrioritizedTicker ticker;
  private DNSRequester dnsRequester;
  private NodeDispatcher dispatcher;
  private UptimeEstimator uptimeEstimator;
  private OutputThrottle outputThrottle;
  private network.crypta.io.comm.TrafficClass trafficClass;
  private NodeCrypto darknetCrypto;
  private OpennetManager opennet;
  private NodeCryptoConfig opennetCryptoConfig;
  private FreenetInetAddress freenetLocalhostAddress;
  private java.net.InetAddress localhostAddress;
  private int maxOpennetPeers;
  private boolean acceptSeedConnections;
  private boolean isAllowedToConnectToSeednodes;
  private boolean passOpennetRefsThroughDarknet;
  private int maxPacketSize;
  private boolean throttleLocalData;
  private int outputBandwidthLimit;
  private int inputBandwidthLimit;
  private boolean inputLimitDefault;
  private long amountOfDataToCheckCompressionRatio;
  private int minimumCompressionPercentage;
  private boolean connectionSpeedDetection;

  public NodeNetworkSubsystem(Node node) {
    this.node = node;
  }

  public int initNodeStats(PersistentConfig config, int sortOrder) throws NodeInitException {
    NodeStatsConfig nodeStatsConfig = new NodeStatsConfig(config.createSubConfig("node.load"));
    nodeStats = new NodeStats(node, sortOrder, nodeStatsConfig);
    return sortOrder;
  }

  public void startStats() {
    if (nodeStats != null) nodeStats.start();
  }

  public void startDispatcher() {
    dispatcher.start(nodeStats);
  }

  public void startPacketSender() {
    packetSender.start(nodeStats);
  }

  public SimpleFieldSet exportVolatileFieldSet() {
    return nodeStats.exportVolatileFieldSet();
  }

  public boolean enableNewLoadManagement(boolean realTimeFlag) {
    if (nodeStats == null) {
      LOG.error(
          "Calling enableNewLoadManagement before Node constructor completes! FIX THIS!",
          new Exception("error"));
      return false;
    }
    return nodeStats.enableNewLoadManagement(realTimeFlag);
  }

  public void initLocationManager() {
    locationManager = new LocationManager(node.bootstrap().random(), node);
  }

  public void startLocationManager() {
    locationManager.start();
  }

  public void initMessagingCore(PriorityAwareExecutor executor) {
    usm = new MessageCore(executor);
    ipDetector = new NodeIPDetector(node);
  }

  public int registerIpDetectorConfigs(SubConfig nodeConfig, int sortOrder) {
    return ipDetector.registerConfigs(nodeConfig, sortOrder);
  }

  public void setOldIPAddress(FreenetInetAddress address) {
    ipDetector.setOldIPAddress(address);
  }

  public int minimumDetectedMtu() {
    if (ipDetector == null) return Integer.MAX_VALUE;
    return ipDetector.getMinimumDetectedMTU();
  }

  public void startIpDetector() {
    ipDetector.start();
  }

  public void initCollector() {
    collector = new IOStatisticCollector();
  }

  public void initLocalhost() {
    try {
      localhostAddress = java.net.InetAddress.getByName("127.0.0.1");
    } catch (java.net.UnknownHostException e3) {
      throw new IllegalStateException(e3);
    }
    freenetLocalhostAddress = new FreenetInetAddress(localhostAddress);
  }

  public int initTrafficClass(SubConfig nodeConfig, int sortOrder) {
    class TrafficClassCallback extends StringCallback implements EnumerableOptionCallback {
      @Override
      public String get() {
        return trafficClass.name();
      }

      @Override
      public void set(String tcName) throws InvalidConfigValueException, NodeNeedRestartException {
        try {
          trafficClass = network.crypta.io.comm.TrafficClass.fromNameOrValue(tcName);
        } catch (IllegalArgumentException e) {
          throw new InvalidConfigValueException(e);
        }
        throw new NodeNeedRestartException("TrafficClass cannot change on the fly");
      }

      @Override
      public String[] getPossibleValues() {
        ArrayList<String> array = new ArrayList<>();
        for (network.crypta.io.comm.TrafficClass tc : network.crypta.io.comm.TrafficClass.values())
          array.add(tc.name());
        return array.toArray(new String[0]);
      }
    }
    nodeConfig.register(
        "trafficClass",
        network.crypta.io.comm.TrafficClass.getDefault().name(),
        sortOrder++,
        true,
        false,
        "Node.trafficClass",
        "Node.trafficClassLong",
        new TrafficClassCallback());
    String trafficClassValue = nodeConfig.getString("trafficClass");
    try {
      trafficClass = network.crypta.io.comm.TrafficClass.fromNameOrValue(trafficClassValue);
    } catch (IllegalArgumentException e) {
      LOG.error("Invalid trafficClass:{} resetting the value to default.", trafficClassValue, e);
      trafficClass = network.crypta.io.comm.TrafficClass.getDefault();
    }
    return sortOrder;
  }

  public int initCryptoAndTransport(
      SubConfig nodeConfig,
      SimpleFieldSet oldConfig,
      int sortOrder,
      PriorityAwareExecutor executor,
      SemiOrderedShutdownHook shutdownHook,
      network.crypta.node.SecurityLevels securityLevels,
      long startupTime,
      boolean enableARKs)
      throws NodeInitException {
    if (oldConfig != null && "-1".equals(oldConfig.get("node.listenPort")))
      throw new NodeInitException(
          NodeInitException.EXIT_COULD_NOT_BIND_USM,
          "Your freenet.ini file is corrupted! 'listenPort=-1'");
    NodeCryptoConfig darknetConfig =
        new NodeCryptoConfig(nodeConfig, sortOrder, false, securityLevels);
    sortOrder += NodeCryptoConfig.OPTION_COUNT;

    darknetCrypto = new NodeCrypto(node, false, darknetConfig, startupTime, enableARKs);
    dnsRequester = new DNSRequester(node);
    packetSender = new PacketSender(node);
    ticker = new PrioritizedTicker(executor, darknetCrypto.getPortNumber());
    if (executor instanceof PooledExecutor pooledExecutor) pooledExecutor.setTicker(ticker);

    LOG.info("Creating node...");

    shutdownHook.addEarlyJob(
        new Thread(
            () -> {
              if (opennet != null) opennet.stop(false);
            }));

    shutdownHook.addEarlyJob(new Thread(darknetCrypto::stop));

    return sortOrder;
  }

  public int initBandwidthConfig(SubConfig nodeConfig, int sortOrder, int minimumBandwidth)
      throws NodeInitException {
    nodeConfig.register(
        "outputBandwidthLimit",
        "15K",
        sortOrder++,
        false,
        true,
        "Node.outBWLimit",
        "Node.outBWLimitLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return outputBandwidthLimit;
          }

          @Override
          public void set(Integer obwLimit) throws InvalidConfigValueException {
            BandwidthManager.checkOutputBandwidthLimit(obwLimit);
            try {
              outputThrottle.changeNanosAndBucketSize(SECONDS.toNanos(1) / obwLimit, obwLimit / 2);
            } catch (IllegalArgumentException e) {
              throw new InvalidConfigValueException(e);
            }
            outputBandwidthLimit = obwLimit;
          }
        });

    int obwLimit = nodeConfig.getInt("outputBandwidthLimit");
    if (obwLimit < minimumBandwidth) {
      obwLimit = minimumBandwidth;
      LOG.info(
          "Output bandwidth was lower than minimum bandwidth. Increased to minimum bandwidth.");
    }

    outputBandwidthLimit = obwLimit;
    try {
      BandwidthManager.checkOutputBandwidthLimit(outputBandwidthLimit);
    } catch (InvalidConfigValueException e) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
    }

    int bucketSize = obwLimit / 2;
    try {
      outputThrottle = new OutputThrottle(bucketSize, SECONDS.toNanos(1) / obwLimit, obwLimit / 2);
    } catch (IllegalArgumentException e) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
    }

    nodeConfig.register(
        "inputBandwidthLimit",
        "-1",
        sortOrder++,
        false,
        true,
        "Node.inBWLimit",
        "Node.inBWLimitLong",
        new IntCallback() {
          @Override
          public Integer get() {
            if (inputLimitDefault) return -1;
            return inputBandwidthLimit;
          }

          @Override
          public void set(Integer ibwLimit) throws InvalidConfigValueException {
            BandwidthManager.checkInputBandwidthLimit(ibwLimit);
            if (ibwLimit == -1) {
              inputLimitDefault = true;
              ibwLimit = outputBandwidthLimit * 4;
            } else {
              inputLimitDefault = false;
            }
            inputBandwidthLimit = ibwLimit;
          }
        });

    int ibwLimit = nodeConfig.getInt("inputBandwidthLimit");
    if (ibwLimit == -1) {
      inputLimitDefault = true;
      ibwLimit = obwLimit * 4;
    } else if (ibwLimit < minimumBandwidth) {
      ibwLimit = minimumBandwidth;
      LOG.info("Input bandwidth was lower than minimum bandwidth. Increased to minimum bandwidth.");
    }
    inputBandwidthLimit = ibwLimit;
    try {
      BandwidthManager.checkInputBandwidthLimit(inputBandwidthLimit);
    } catch (InvalidConfigValueException e) {
      throw new NodeInitException(NodeInitException.EXIT_BAD_BWLIMIT, e.getMessage());
    }

    nodeConfig.register(
        "amountOfDataToCheckCompressionRatio",
        "8MiB",
        sortOrder++,
        true,
        true,
        "Node.amountOfDataToCheckCompressionRatio",
        "Node.amountOfDataToCheckCompressionRatioLong",
        new LongCallback() {
          @Override
          public Long get() {
            return amountOfDataToCheckCompressionRatio;
          }

          @Override
          public void set(Long amountOfDataToCheckCompressionRatio) {
            if (amountOfDataToCheckCompressionRatio < 0
                || amountOfDataToCheckCompressionRatio > 100 * 1024 * 1024) {
              LOG.info(
                  "Amount of data to check for compression should be 100 MiB max, {} bytes"
                      + " selected",
                  amountOfDataToCheckCompressionRatio);
              return;
            }
            NodeNetworkSubsystem.this.amountOfDataToCheckCompressionRatio =
                amountOfDataToCheckCompressionRatio;
          }
        },
        true);

    amountOfDataToCheckCompressionRatio = nodeConfig.getLong("amountOfDataToCheckCompressionRatio");

    nodeConfig.register(
        "minimumCompressionPercentage",
        "10",
        sortOrder++,
        true,
        true,
        "Node.minimumCompressionPercentage",
        "Node.minimumCompressionPercentageLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return minimumCompressionPercentage;
          }

          @Override
          public void set(Integer minimumCompressionPercentage) {
            if (minimumCompressionPercentage < 0 || minimumCompressionPercentage > 100) {
              LOG.info(
                  "Wrong minimum compression percentage: must be between 0 and 100, but is {}",
                  minimumCompressionPercentage);
              return;
            }

            NodeNetworkSubsystem.this.minimumCompressionPercentage = minimumCompressionPercentage;
          }
        },
        Dimension.NOT);

    minimumCompressionPercentage = nodeConfig.getInt("minimumCompressionPercentage");

    nodeConfig.registerIgnoredOption("maxTimeForSingleCompressor");

    nodeConfig.register(
        "connectionSpeedDetection",
        true,
        sortOrder++,
        true,
        true,
        "Node.connectionSpeedDetection",
        "Node.connectionSpeedDetectionLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return connectionSpeedDetection;
          }

          @Override
          public void set(Boolean connectionSpeedDetection) {
            NodeNetworkSubsystem.this.connectionSpeedDetection = connectionSpeedDetection;
          }
        });

    connectionSpeedDetection = nodeConfig.getBoolean("connectionSpeedDetection");

    nodeConfig.register(
        "throttleLocalTraffic",
        false,
        sortOrder++,
        true,
        false,
        "Node.throttleLocalTraffic",
        "Node.throttleLocalTrafficLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return throttleLocalData;
          }

          @Override
          public void set(Boolean val) {
            throttleLocalData = val;
          }
        });

    throttleLocalData = nodeConfig.getBoolean("throttleLocalTraffic");

    return sortOrder;
  }

  public int initOpennet(PersistentConfig config, SubConfig nodeConfig, int sortOrder)
      throws NodeInitException {
    final SubConfig opennetConfig = config.createSubConfig("node.opennet");
    opennetConfig.register(
        "connectToSeednodes",
        true,
        0,
        true,
        false,
        "Node.withAnnouncement",
        "Node.withAnnouncementLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return isAllowedToConnectToSeednodes;
          }

          @Override
          public void set(Boolean val) throws NodeNeedRestartException {
            if (get().equals(val)) return;
            if (opennet != null)
              throw new NodeNeedRestartException(
                  l10n("connectToSeednodesCannotBeChangedMustDisableOpennetOrReboot"));
            isAllowedToConnectToSeednodes = val;
          }
        });
    isAllowedToConnectToSeednodes = opennetConfig.getBoolean("connectToSeednodes");

    opennetConfig.register(
        "enabled",
        false,
        0,
        true,
        true,
        "Node.opennetEnabled",
        "Node.opennetEnabledLong",
        new BooleanCallback() {
          @Override
          public Boolean get() {
            return opennet != null;
          }

          @Override
          public void set(Boolean val) throws InvalidConfigValueException {
            OpennetManager o;
            boolean enable = Boolean.TRUE.equals(val);
            if (enable == (opennet != null)) return;
            if (enable) {
              try {
                o =
                    opennet =
                        new OpennetManager(
                            node,
                            opennetCryptoConfig,
                            System.currentTimeMillis(),
                            isAllowedToConnectToSeednodes);
              } catch (NodeInitException e) {
                opennet = null;
                throw new InvalidConfigValueException(e.getMessage());
              }
            } else {
              o = opennet;
              opennet = null;
            }
            if (enable) o.start();
            else o.stop(true);
            ipDetector.notifyPortChange(publicInterfacePorts());
          }
        });
    boolean opennetEnabled = opennetConfig.getBoolean("enabled");

    opennetConfig.register(
        "maxOpennetPeers",
        OpennetManager.MAX_PEERS_FOR_SCALING,
        1,
        true,
        false,
        "Node.maxOpennetPeers",
        "Node.maxOpennetPeersLong",
        new IntCallback() {
          @Override
          public Integer get() {
            return maxOpennetPeers;
          }

          @Override
          public void set(Integer inputMaxOpennetPeers) throws InvalidConfigValueException {
            if (inputMaxOpennetPeers < 0)
              throw new InvalidConfigValueException(l10n("mustBePositive"));
            if (inputMaxOpennetPeers > OpennetManager.MAX_PEERS_FOR_SCALING)
              throw new InvalidConfigValueException(
                  l10n(
                      "maxOpennetPeersMustBeTwentyOrLess",
                      "maxpeers",
                      Integer.toString(OpennetManager.MAX_PEERS_FOR_SCALING)));
            maxOpennetPeers = inputMaxOpennetPeers;
          }
        },
        false);

    maxOpennetPeers = opennetConfig.getInt("maxOpennetPeers");
    if (maxOpennetPeers > OpennetManager.MAX_PEERS_FOR_SCALING) {
      LOG.error("maxOpennetPeers may not be over {}", OpennetManager.MAX_PEERS_FOR_SCALING);
      maxOpennetPeers = OpennetManager.MAX_PEERS_FOR_SCALING;
    }

    opennetCryptoConfig =
        new NodeCryptoConfig(opennetConfig, 2, true, node.services().securityLevels());

    if (opennetEnabled) {
      opennet =
          new OpennetManager(
              node, opennetCryptoConfig, System.currentTimeMillis(), isAllowedToConnectToSeednodes);
    } else {
      opennet = null;
    }

    node.services()
        .securityLevels()
        .addNetworkThreatLevelListener(
            (oldLevel, newLevel) -> {
              if (newLevel == network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL.HIGH
                  || newLevel == network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL.MAXIMUM) {
                OpennetManager om = opennet;
                if (om != null) {
                  opennet = null;
                  om.stop(true);
                  ipDetector.notifyPortChange(publicInterfacePorts());
                }
              } else if (newLevel == network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL
                  || newLevel == network.crypta.node.SecurityLevels.NETWORK_THREAT_LEVEL.LOW) {
                OpennetManager o = null;
                if (opennet == null) {
                  try {
                    o =
                        opennet =
                            new OpennetManager(
                                node,
                                opennetCryptoConfig,
                                System.currentTimeMillis(),
                                isAllowedToConnectToSeednodes);
                  } catch (NodeInitException e) {
                    opennet = null;
                    LOG.error("UNABLE TO ENABLE OPENNET: {}", e, e);
                    node.services()
                        .clientCore()
                        .getAlerts()
                        .register(
                            new SimpleUserAlert(
                                false,
                                l10n("enableOpennetFailedTitle"),
                                l10n("enableOpennetFailed", "message", e.getLocalizedMessage()),
                                l10n("enableOpennetFailed", "message", e.getLocalizedMessage()),
                                UserAlert.ERROR));
                  }
                }
                if (o != null) {
                  o.start();
                  ipDetector.notifyPortChange(publicInterfacePorts());
                }
              }
              node.getConfig().store();
            });

    opennetConfig.register(
        "acceptSeedConnections",
        false,
        2,
        true,
        true,
        "Node.acceptSeedConnectionsShort",
        "Node.acceptSeedConnections",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return acceptSeedConnections;
          }

          @Override
          public void set(Boolean val) {
            acceptSeedConnections = val;
          }
        });

    acceptSeedConnections = opennetConfig.getBoolean("acceptSeedConnections");

    if (acceptSeedConnections && opennet != null)
      opennet.getCrypto().getSocket().getAddressTracker().setHugeTracker();

    opennetConfig.finishedInitialization();

    nodeConfig.register(
        "passOpennetPeersThroughDarknet",
        true,
        sortOrder++,
        true,
        false,
        "Node.passOpennetPeersThroughDarknet",
        "Node.passOpennetPeersThroughDarknetLong",
        new BooleanCallback() {

          @Override
          public Boolean get() {
            return passOpennetRefsThroughDarknet;
          }

          @Override
          public void set(Boolean val) {
            passOpennetRefsThroughDarknet = val;
          }
        });

    passOpennetRefsThroughDarknet = nodeConfig.getBoolean("passOpennetPeersThroughDarknet");

    return sortOrder;
  }

  private String l10n(String key) {
    return NodeL10n.getBase().getString("Node." + key);
  }

  private String l10n(String key, String pattern, String value) {
    return NodeL10n.getBase().getString("Node." + key, pattern, value);
  }

  public void initPeers(SemiOrderedShutdownHook shutdownHook) {
    peers = new PeerManager(node, shutdownHook);
  }

  public void readPeers(network.crypta.node.ProgramDirectory nodeDir) {
    peers.tryReadPeers(
        nodeDir.file("peers-" + darknetPortNumber()).getPath(), darknetCrypto, null, false, false);
  }

  public void startPeers() {
    peers.start();
  }

  public void updatePeerManagerUserAlert() {
    peers.updatePMUserAlert();
  }

  public void readExtraPeerData() {
    peers.readExtraPeerData();
  }

  public boolean anyConnectedPeers() {
    return peers.anyConnectedPeers();
  }

  public String peerStatus() {
    return peers != null ? peers.getStatus() : "No peers yet";
  }

  public String tmciPeerList() {
    return peers != null ? peers.getTMCIPeerList() : "";
  }

  public void initDispatcher() {
    dispatcher = new NodeDispatcher(node);
    usm.setDispatcher(dispatcher);
  }

  public void initUptime(network.crypta.node.ProgramDirectory runDir) {
    uptimeEstimator = new UptimeEstimator(runDir, ticker, darknetCrypto.getIdentityHash());
  }

  public void setDispatcherHook(NodeDispatcher.NodeDispatcherCallback cb) {
    dispatcher.setHook(cb);
  }

  public void readDarknetCrypto(SimpleFieldSet fs) throws IOException {
    darknetCrypto.readCrypto(fs);
  }

  public void applyUdpFromFieldSet(SimpleFieldSet fs) throws IOException {
    String[] udp = fs.getAll("physical.udp");
    if (udp == null) return;
    for (String udpAddr : udp) {
      Peer p;
      try {
        p = new Peer(udpAddr, false, true);
      } catch (UnknownHostException _) {
        LOG.info(
            "Unknown host while parsing our darknet node reference: {} (likely host-local scope or"
                + " transient DNS)",
            udpAddr);
        p = null;
      } catch (HostnameSyntaxException _) {
        LOG.error(
            "Invalid hostname or IP Address syntax error while parsing our darknet node reference:"
                + " {}",
            udpAddr);
        p = null;
      } catch (PeerParseException e) {
        throw new IOException(e);
      }
      if (p != null && p.getPort() == darknetPortNumber()) {
        // DNSRequester doesn't deal with our own node
        setOldIPAddress(p.getFreenetAddress());
        return;
      }
    }
  }

  public void initDarknetCrypto() {
    darknetCrypto.initCrypto();
  }

  public byte[] darknetIdentityHashHash() {
    return darknetCrypto.getIdentityHashHash();
  }

  public void writeOpennetFile() {
    if (opennet != null) opennet.writeFile();
  }

  public void startNetworking() {
    dnsRequester.start();
    uptimeEstimator.start();
    darknetCrypto.start();
    if (opennet != null) opennet.start();
    ticker.start();
    usm.start(ticker);
  }

  public int unclaimedFifoSize() {
    return usm.getUnclaimedFIFOSize();
  }

  public PeerManager peers() {
    return peers;
  }

  public NodeStats stats() {
    return nodeStats;
  }

  public PriorityAwareExecutor executor() {
    return node.getExecutor();
  }

  public NodeCrypto darknetCrypto() {
    return darknetCrypto;
  }

  public PacketSender packetSender() {
    return packetSender;
  }

  public OutputThrottle outputThrottle() {
    return outputThrottle;
  }

  public IOStatisticCollector collector() {
    return collector;
  }

  public DNSRequester dnsRequester() {
    return dnsRequester;
  }

  public UptimeEstimator uptimeEstimator() {
    return uptimeEstimator;
  }

  public NodeDispatcher dispatcher() {
    return dispatcher;
  }

  public OpennetManager opennet() {
    return opennet;
  }

  public LocationManager locationManager() {
    return locationManager;
  }

  public MessageCore usm() {
    return usm;
  }

  public NodeIPDetector ipDetector() {
    return ipDetector;
  }

  public Ticker ticker() {
    return ticker;
  }

  public int darknetPortNumber() {
    return darknetCrypto.getPortNumber();
  }

  public FreenetInetAddress freenetLocalhostAddress() {
    return freenetLocalhostAddress;
  }

  public DarknetPeerNode[] darknetConnections() {
    return peers.roster().getDarknetPeers();
  }

  public PeerNode[] peerNodes() {
    return peers.myPeers();
  }

  public PeerNode[] connectedPeers() {
    return peers.connectedPeers();
  }

  public PeerNode getPeerNode(String nodeIdentifier) {
    for (PeerNode pn : peers.myPeers()) {
      Peer peer = pn.getPeer();
      String nodeIpAndPort = "";
      if (peer != null) {
        nodeIpAndPort = peer.toString();
      }
      String identity = pn.getIdentityString();
      if (pn instanceof DarknetPeerNode dpn) {
        String name = dpn.getName();
        if (identity.equals(nodeIdentifier)
            || nodeIpAndPort.equals(nodeIdentifier)
            || name.equals(nodeIdentifier)) {
          return pn;
        }
      } else {
        if (identity.equals(nodeIdentifier) || nodeIpAndPort.equals(nodeIdentifier)) {
          return pn;
        }
      }
    }
    return null;
  }

  public int routedPing(double loc2, byte[] pubKeyHash) {
    long uid = node.bootstrap().random().nextLong();
    int initialX = node.bootstrap().random().nextInt();
    Message m = DMT.createFNPRoutedPing(uid, loc2, node.maxHTL(), initialX, pubKeyHash);
    LOG.info("Message: {}", m);

    dispatcher().handleRouted(m, null);
    MessageFilter mf1 =
        MessageFilter.create().setField(DMT.UID, uid).setType(DMT.FNPRoutedPong).setTimeout(5000);
    try {
      m = usm().waitFor(mf1, null);
    } catch (DisconnectedException _) {
      LOG.info("Disconnected in waiting for pong");
      return -1;
    }
    if (m == null) return -1;
    if (m.getSpec() == DMT.FNPRoutedRejected) return -1;
    return m.getInt(DMT.COUNTER) - initialX;
  }

  public void broadcastDisconnect() {
    try {
      Message msg = DMT.createFNPDisconnect(false, false, -1, new ShortBuffer(new byte[0]));
      peers.messenger().localBroadcast(msg, true, false, peers.messenger().getDisconnCounter());
    } catch (Exception t) {
      try {
        LOG.error("Failed to tell peers we are going down: {}", t, t);
      } catch (Exception _) {
        // Ignore. We don't want to mess up the exit process!
      }
    }
  }

  public void setArkFetcherContext(FetchContext ctx) {
    this.arkFetcherContext = ctx;
  }

  public FetchContext arkFetcherContext() {
    return arkFetcherContext;
  }

  public int outputBandwidthLimit() {
    return outputBandwidthLimit;
  }

  public int inputBandwidthLimit() {
    return inputBandwidthLimit;
  }

  public boolean isThrottleLocalData() {
    return throttleLocalData;
  }

  public network.crypta.io.comm.TrafficClass trafficClass() {
    return trafficClass;
  }

  public double location() {
    return locationManager.getLocation();
  }

  public double locationChangeSession() {
    return locationManager.getLocChangeSession();
  }

  public int averageOutgoingSwapTime() {
    return locationManager.getAverageSwapTime();
  }

  public long sendSwapInterval() {
    return locationManager.getSendSwapInterval();
  }

  public int numberOfRemotePeerLocationsSeenInSwaps() {
    return locationManager.getNumberOfRemotePeerLocationsSeenInSwaps();
  }

  public void setLocation(double loc) {
    locationManager.setLocation(loc);
  }

  public int swaps() {
    return LocationManager.getSwaps();
  }

  public int noSwaps() {
    return LocationManager.getNoSwaps();
  }

  public int startedSwaps() {
    return LocationManager.getStartedSwaps();
  }

  public int swapsRejectedAlreadyLocked() {
    return LocationManager.getSwapsRejectedAlreadyLocked();
  }

  public int swapsRejectedNowhereToGo() {
    return LocationManager.getSwapsRejectedNowhereToGo();
  }

  public int swapsRejectedRateLimit() {
    return LocationManager.getSwapsRejectedRateLimit();
  }

  public int swapsRejectedRecognizedID() {
    return LocationManager.getSwapsRejectedRecognizedID();
  }

  public int maxOpennetPeers() {
    return maxOpennetPeers;
  }

  public int numArkFetchers() {
    int x = 0;
    for (PeerNode p : peers.myPeers()) {
      if (p.isFetchingARK()) x++;
    }
    return x;
  }

  public void startProbe(final byte htl, final long uid, final Type type, final Listener listener) {
    dispatcher.startProbe(htl, uid, type, listener);
  }

  public boolean addPeerConnection(PeerNode pn) {
    boolean retval = peers.addPeer(pn);
    peers.writePeersUrgent(pn.isOpennet());
    return retval;
  }

  public void removePeerConnection(PeerNode pn) {
    peers.messenger().disconnectAndRemove(pn, true, false, false);
  }

  public void onConnectedPeer() {
    if (ipDetector != null) ipDetector.onConnectedPeer();
  }

  public boolean isOutdated() {
    return peers.isOutdated();
  }

  public int fnpPort() {
    return darknetPortNumber();
  }

  public void connectToSeednode(SeedServerTestPeerNode node) {
    peers.addPeer(node, false, false);
  }

  public void connect(
      Node node, DarknetPeerNode.FRIEND_TRUST trust, DarknetPeerNode.FRIEND_VISIBILITY visibility)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    peers.connector().connect(node.network().exportDarknetPublicFieldSet(), trust, visibility);
  }

  public OpennetPeerNode createNewOpennetNode(SimpleFieldSet fs)
      throws FSParseException,
          OpennetDisabledException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    if (opennet() == null) throw new OpennetDisabledException("Opennet is not currently enabled");
    return new OpennetPeerNode(fs, node, opennet().getCrypto(), opennet(), false, peers);
  }

  public DarknetPeerNode createNewDarknetNode(
      SimpleFieldSet fs,
      DarknetPeerNode.FRIEND_TRUST trust,
      DarknetPeerNode.FRIEND_VISIBILITY visibility)
      throws FSParseException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    return new DarknetPeerNode(fs, node, darknetCrypto, false, trust, visibility, peers);
  }

  public SeedServerTestPeerNode createNewSeedServerTestPeerNode(SimpleFieldSet fs)
      throws FSParseException,
          OpennetDisabledException,
          PeerParseException,
          ReferenceSignatureVerificationException,
          PeerTooOldException {
    if (opennet() == null) throw new OpennetDisabledException("Opennet is not currently enabled");
    return new SeedServerTestPeerNode(fs, node, opennet().getCrypto(), true, peers);
  }

  public OpennetPeerNode addNewOpennetNode(
      SimpleFieldSet fs, OpennetManager.ConnectionType connectionType)
      throws FSParseException, PeerParseException, ReferenceSignatureVerificationException {
    if (opennet() == null) return null;
    return opennet().addNewOpennetNode(fs, connectionType, false);
  }

  public byte[] opennetPubKeyHash() {
    return opennet().getCrypto().getEcdsaPubKeyHash();
  }

  public byte[] darknetPubKeyHash() {
    return darknetCrypto.getEcdsaPubKeyHash();
  }

  public boolean isOpennetEnabled() {
    return opennet() != null;
  }

  public SimpleFieldSet exportDarknetPublicFieldSet() {
    return darknetCrypto.exportPublicFieldSet();
  }

  public SimpleFieldSet exportOpennetPublicFieldSet() {
    return opennet().getCrypto().exportPublicFieldSet();
  }

  public SimpleFieldSet exportDarknetPrivateFieldSet() {
    return darknetCrypto.exportPrivateFieldSet();
  }

  public SimpleFieldSet exportOpennetPrivateFieldSet() {
    return opennet().getCrypto().exportPrivateFieldSet();
  }

  public boolean dontDetect() {
    if (!darknetCrypto.getBindTo().isRealInternetAddress(false, true, false)) return false;
    if (opennet() != null) {
      return !opennet().getCrypto().getBindTo().isRealInternetAddress(false, true, false);
    }
    return true;
  }

  public int opennetFnpPort() {
    if (opennet() == null) return -1;
    return opennet().getCrypto().getPortNumber();
  }

  public boolean passOpennetRefsThroughDarknet() {
    return passOpennetRefsThroughDarknet;
  }

  public Set<ForwardPort> publicInterfacePorts() {
    HashSet<ForwardPort> set = new HashSet<>();
    set.add(
        new ForwardPort(
            "darknet", false, ForwardPort.PROTOCOL_UDP_IPV4, darknetCrypto.getPortNumber()));
    if (opennet() != null) {
      var crypto = opennet().getCrypto();
      if (crypto != null) {
        set.add(
            new ForwardPort(
                "opennet", false, ForwardPort.PROTOCOL_UDP_IPV4, crypto.getPortNumber()));
      }
    }
    return set;
  }

  public long uptime() {
    return System.currentTimeMillis() - usm().getStartedTime();
  }

  public UdpSocketHandler[] packetSocketHandlers() {
    if (opennet() != null) {
      return new UdpSocketHandler[] {darknetCrypto.getSocket(), opennet().getCrypto().getSocket()};
    }
    return new UdpSocketHandler[] {darknetCrypto.getSocket()};
  }

  public void onAddedValidIP() {
    OpennetManager om = opennet();
    if (om != null) {
      var announcer = om.getAnnouncer();
      if (announcer != null) {
        announcer.maybeSendAnnouncementOffThread();
      }
    }
  }

  public boolean isSeednode() {
    return acceptSeedConnections;
  }

  public boolean wantAnonAuth(boolean isOpennet) {
    if (isOpennet) return opennet() != null && acceptSeedConnections;
    else return false;
  }

  public boolean wantAnonAuthChangeIP(boolean isOpennet) {
    return !isOpennet;
  }

  public boolean opennetDefinitelyPortForwarded() {
    OpennetManager om = opennet();
    if (om == null) return false;
    var crypto = om.getCrypto();
    if (crypto == null) return false;
    return crypto.definitelyPortForwarded();
  }

  public boolean darknetDefinitelyPortForwarded() {
    var crypto = darknetCrypto;
    if (crypto == null) return false;
    return crypto.definitelyPortForwarded();
  }

  public void updateMTU() {
    darknetCrypto.getSocket().calculateMaxPacketSize();
    OpennetManager om = opennet();
    if (om != null) {
      om.getCrypto().getSocket().calculateMaxPacketSize();
    }
  }

  public void logFnpPort() {
    LOG.info("FNP port is on {}:{}", darknetCrypto.getBindTo(), darknetPortNumber());
  }

  public boolean updateIsUrgent() {
    if (opennet != null
        && opennet.getAnnouncer() != null
        && opennet.getAnnouncer().isWaitingForUpdater()) return true;
    return peers.getPeerNodeStatusSize(PeerManager.PEER_NODE_STATUS_TOO_NEW, true)
        > PeerManager.OUTDATED_MIN_TOO_NEW_DARKNET;
  }
}
