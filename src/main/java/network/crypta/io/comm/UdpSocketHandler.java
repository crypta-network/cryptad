package network.crypta.io.comm;

import com.sun.jna.LastErrorException;
import com.sun.jna.Native;
import com.sun.jna.Platform;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import java.io.IOException;
import java.lang.reflect.Field;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.channels.UnsupportedAddressTypeException;
import java.util.Random;
import network.crypta.io.AddressTracker;
import network.crypta.io.comm.Peer.LocalAddressException;
import network.crypta.node.Node;
import network.crypta.node.PrioRunnable;
import network.crypta.support.io.NativeThread;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handles UDP I/O for a node using a non-blocking {@link DatagramChannel}.
 *
 * <p>This handler binds to a specific local address/port, receives packets into an internal {@link
 * ByteBuffer}, and forwards them to a configured {@link IncomingPacketFilter}. Outgoing packets are
 * sent via {@link #sendPacket(byte[], Peer, boolean)}. Connectivity and basic traffic statistics
 * are recorded through {@link AddressTracker} and {@link IOStatisticCollector}.
 *
 * <p>Threading: instances are executed on the node's executor (see {@link Node#getExecutor()}). The
 * run loop continues while {@code active == true}. {@link #close()} stops the loop, closes the
 * channel, and waits for termination. This class is not intended to be used from multiple threads
 * concurrently except for the lifecycle methods and {@link #sendPacket(byte[], Peer, boolean)}.
 *
 * <p>Units: sizes are in bytes; times are in milliseconds since the epoch.
 */
public class UdpSocketHandler
    implements PrioRunnable, PacketSocketHandler, PortForwardSensitiveSocketHandler {

  private static final Logger LOG = LoggerFactory.getLogger(UdpSocketHandler.class);
  private static final String CAUGHT_PREFIX = "Caught ";

  private final ByteBuffer receiveBuffer = ByteBuffer.allocate(MAX_RECEIVE_SIZE);
  private final DatagramChannel datagramChannel;
  private final InetSocketAddress localAddress;
  private final AddressTracker tracker;
  private IncomingPacketFilter lowLevelFilter;

  /**
   * RNG for debugging, used with {@link #dropProbability}. Not cryptographically secure; do not use
   * for any security-sensitive purpose.
   */
  private final Random dropRandom;

  /**
   * If &gt; 0, there is a 1 in {@code dropProbability} chance to drop a packet (debugging only).
   */
  private int dropProbability;

  // Cross-layer reference to Node for configuration and scheduling.
  private final Node node;

  private boolean isDone;
  private volatile boolean active = true;
  private final String title;
  private boolean started;
  private long startTime;
  private final IOStatisticCollector ioStatistics;

  private static class SocketOptions {
    private static class SocketOptionsHolder {
      static {
        Native.register(Platform.C_LIBRARY_NAME);
      }

      private static native int setsockopt(
          int fd, int level, int optionName, Pointer optionValue, int optionLen)
          throws LastErrorException;
    }

    public enum SOCKET_level {
      IPPROTO_IPV6(0x29);

      final int linux;

      SOCKET_level(int linux) {
        this.linux = linux;
      }
    }

    public enum SOCKET_option_name {
      IPV6_ADDR_PREFERENCES(0x48); // rfc5014

      final int linux;

      SOCKET_option_name(int linux) {
        this.linux = linux;
      }
    }

    public enum SOCKET_ADDR_PREFERENCE {
      IPV6_PREFER_SRC_TMP(0x0001),
      IPV6_PREFER_SRC_PUBLIC(0x0002),
      IPV6_PREFER_SRC_PUBTMP_DEFAULT(0x0100),
      IPV6_PREFER_SRC_COA(0x0004),
      IPV6_PREFER_SRC_HOME(0x0400),
      IPV6_PREFER_SRC_CGA(0x0008),
      IPV6_PREFER_SRC_NONCGA(0x0800);

      final SOCKET_option_name optionName = SOCKET_option_name.IPV6_ADDR_PREFERENCES;
      final int linux;

      SOCKET_ADDR_PREFERENCE(int linux) {
        this.linux = linux;
      }
    }

    @SuppressWarnings("java:S3011")
    private static int getFd(DatagramChannel channel) {
      try {
        Field fdVal = channel.getClass().getDeclaredField("fdVal");
        if (!fdVal.canAccess(channel)) {
          // Reflective access: the JDK keeps this field private,
          // and we rely on it to set IPV6 address preferences on Linux.
          fdVal.setAccessible(true);
        }
        return fdVal.getInt(channel);
      } catch (NoSuchFieldException | IllegalAccessException | RuntimeException e) {
        LOG.warn(e.getMessage(), e);
        return -1;
      }
    }

    public static boolean setAddressPreference(DatagramChannel channel, SOCKET_ADDR_PREFERENCE p) {
      if (!Platform.isLinux()) {
        return false;
      }
      int fd = getFd(channel);
      if (fd <= 2) {
        return false;
      }
      try {
        int ret =
            SocketOptionsHolder.setsockopt(
                fd,
                SOCKET_level.IPPROTO_IPV6.linux,
                p.optionName.linux,
                new IntByReference(p.linux).getPointer(),
                Native.POINTER_SIZE);
        return ret == 0;
      } catch (Exception e) {
        LOG.info(e.getMessage(), e);
        return false;
      }
    }
  }

  /**
   * Creates a UDP socket handler bound to {@code bindToAddress:listenPort}.
   *
   * <p>The constructor binds a {@link DatagramChannel}, applies basic socket options (receive
   * buffer, {@code SO_REUSEADDR}, IP TOS/DSCP when supported), and initializes connectivity
   * tracking.
   *
   * @param listenPort Local UDP port to bind.
   * @param bindToAddress Local address to bind.
   * @param node Owning node used for configuration, scheduling, and randomness.
   * @param startupTime Milliseconds timestamp to mark the beginning of send tracking.
   * @param title Human-readable label for diagnostics.
   * @param ioStatistics Collector that receives per-address byte counters.
   * @throws IOException If the channel cannot be opened, configured, or bound.
   */
  public UdpSocketHandler(
      int listenPort,
      InetAddress bindToAddress,
      Node node,
      long startupTime,
      String title,
      IOStatisticCollector ioStatistics)
      throws IOException {
    this.node = node;
    this.ioStatistics = ioStatistics;
    this.title = title;
    localAddress = new InetSocketAddress(bindToAddress, listenPort);
    DatagramChannel tmp = DatagramChannel.open();
    boolean success = false;
    try {
      tmp.bind(localAddress);
      tmp.setOption(StandardSocketOptions.SO_RCVBUF, 65536);
      tmp.setOption(StandardSocketOptions.SO_REUSEADDR, true);
      datagramChannel = tmp;

      try {
        datagramChannel.setOption(
            StandardSocketOptions.IP_TOS, node.network().trafficClass().value);
      } catch (UnsupportedOperationException e) {
        LOG.error("Failed to set IP_TOS socket option", e);
      }

      boolean r =
          SocketOptions.setAddressPreference(
              datagramChannel, SocketOptions.SOCKET_ADDR_PREFERENCE.IPV6_PREFER_SRC_PUBLIC);
      if (LOG.isDebugEnabled()) {
        LOG.debug(
            "Setting IPV6_PREFER_SRC_PUBLIC for port {} is a {}",
            listenPort,
            r ? "success" : "failure");
      }

      // Only used for debugging, no need to seed from Yarrow
      dropRandom = node.bootstrap().fastWeakRandom();
      tracker = AddressTracker.create(node.getLastBootId(), node.runDir(), listenPort);
      tracker.startSend(startupTime);
      success = true;
    } finally {
      if (!success) {
        try {
          tmp.close();
        } catch (IOException e) {
          LOG.warn("Error closing DatagramChannel after constructor failure", e);
        }
      }
    }
  }

  /**
   * Sets the low-level filter used to process received packets.
   *
   * <p>Must be called before {@link #start()} (or any call that triggers {@link #run()}); otherwise
   * the receive path will dereference a {@code null} filter and fail.
   *
   * @param f The filter that decodes/dispatches incoming packets.
   */
  @Override
  public void setLowLevelFilter(IncomingPacketFilter f) {
    lowLevelFilter = f;
  }

  /**
   * Returns the local address this handler is bound to.
   *
   * @return The bound {@link InetAddress}.
   */
  public InetAddress getBindTo() {
    return localAddress.getAddress();
  }

  /**
   * Returns the diagnostic title supplied at construction.
   *
   * @return Human-readable label for this handler.
   */
  public String getTitle() {
    return title;
  }

  /**
   * Main receive loop. Continues to read from the channel and dispatch packets while active.
   *
   * <p>All unexpected throwables are logged with memory information to aid diagnostics.
   */
  @Override
  public void run() { // Listen for packets
    tracker.startReceive(System.currentTimeMillis());
    try {
      runLoop();
    } catch (Exception t) {
      // Catch-all guard to avoid silent thread death; log details for analysis.
      LOG.error("Unhandled throwable in run(): {}", t.getClass().getName());
      LOG.error("Unhandled throwable message: {}", t.getMessage());
      // Avoid forced GC calls; they are ineffective and can mask real memory issues
      Runtime r = Runtime.getRuntime();
      LOG.error("freeMemory={} totalMemory={}", r.freeMemory(), r.totalMemory());
      LOG.error("Unhandled exception in run()", t);
    } finally {
      LOG.error("run() exiting for UdpSocketHandler on port {}", localAddress.getPort());
      synchronized (this) {
        isDone = true;
        notifyAll();
      }
    }
  }

  private void runLoop() {
    while (active) {
      try {
        realRun();
      } catch (Exception t) {
        LOG.error(CAUGHT_PREFIX + "{}", t, t);
      }
    }
  }

  private void realRun() {
    InetSocketAddress remote = receive();
    long now = System.currentTimeMillis();
    if (remote != null) {
      handleRemote(remote, now);
    } else {
      if (LOG.isTraceEnabled()) LOG.trace("No packet received");
    }
  }

  @SuppressWarnings("java:S1181") // we really do want to catch Throwable here
  private void handleRemote(InetSocketAddress remote, long now) {
    long start = System.currentTimeMillis();
    Peer peer = new Peer(remote.getAddress(), remote.getPort());
    tracker.receivedPacketFrom(peer);
    long end = System.currentTimeMillis();
    logIfSlow("packet creation", start, end);

    try {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Processing packet of length {} from {}", receiveBuffer.limit(), peer);
      }
      start = System.currentTimeMillis();
      lowLevelFilter.process(receiveBuffer.array(), 0, receiveBuffer.limit(), peer, now);
      end = System.currentTimeMillis();
      logIfSlow("processing packet", start, end);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Successfully handled packet length {}", receiveBuffer.limit());
      }
    } catch (Throwable t) {
      LOG.error(CAUGHT_PREFIX + "{} from {}", t, lowLevelFilter, t);
    }
  }

  private static void logIfSlow(String what, long start, long end) {
    long duration = end - start;
    if (duration > 50) {
      if (duration > 3000) {
        LOG.error("{} took {}ms", what, duration);
      } else if (LOG.isDebugEnabled()) {
        LOG.debug("{} took {}ms", what, duration);
      }
    }
  }

  private static final int MAX_RECEIVE_SIZE = 1500;

  private InetSocketAddress receive() {
    try {
      receiveBuffer.clear();
      InetSocketAddress remote = (InetSocketAddress) datagramChannel.receive(receiveBuffer);
      receiveBuffer.flip();
      InetAddress address = remote.getAddress();
      // Account for transport overhead in statistics to approximate on-the-wire size.
      ioStatistics.reportReceivedBytes(address, getHeadersLength(address) + receiveBuffer.limit());
      return remote;
    } catch (SocketTimeoutException _) {
      return null;
    } catch (IOException e2) {
      if (!active) { // Channel closed during shutdown; return silently.
        return null;
      } else {
        throw new java.io.UncheckedIOException(e2);
      }
    }
  }

  /**
   * Sends an encoded UDP payload to a peer.
   *
   * <p>Normally the destination address is pre-resolved; if it is missing, this method attempts a
   * best-effort resolution via {@link Peer#getAddress(boolean, boolean)} and logs failures.
   *
   * @param blockToSend The UDP payload to transmit.
   * @param destination The peer target (address/port).
   * @param allowLocalAddresses Whether local/private addresses are permitted for this send.
   * @throws LocalAddressException If local addresses are disallowed and the peer resolves to one.
   */
  @Override
  public void sendPacket(byte[] blockToSend, Peer destination, boolean allowLocalAddresses)
      throws LocalAddressException {
    if (!active) {
      LOG.error("Trying to send packet but no longer active");
      // Do not send during shutdown to keep AddressTracker data accurate.
      return;
    }

    ByteBuffer packet = ByteBuffer.wrap(blockToSend);
    int port = destination.getPort();
    InetAddress address;
    // Address should be pre-resolved; fall back to resolution and log if we must.
    if ((address = destination.getAddress(false, allowLocalAddresses)) == null) {
      LOG.error(
          "Tried sending to destination without pre-looked up IP address(needs a real"
              + " Peer.getHostname()): null:{}",
          destination.getPort(),
          new Exception("error"));
      if ((address = destination.getAddress(true, allowLocalAddresses)) == null) {
        LOG.error(
            "Tried sending to bad destination address: null:{}",
            destination.getPort(),
            new Exception("error"));
        return;
      }
    }
    if (dropProbability > 0 && dropRandom.nextInt(dropProbability) == 0) {
      LOG.info("DROPPED: {} -> {}", localAddress.getPort(), destination.getPort());
      return;
    }

    try {
      datagramChannel.send(packet, new InetSocketAddress(address, port));
      tracker.sentPacketTo(destination);
      ioStatistics.reportSentBytes(address, getHeadersLength(address) + blockToSend.length);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Sent packet length {} to {}:{}", blockToSend.length, address, port);
      }
    } catch (IOException | UnsupportedAddressTypeException e) {
      if (address instanceof Inet6Address) {
        LOG.info("Error while sending packet to IPv6 address: {}: {}", destination, e, e);
      } else {
        LOG.error("Error while sending packet to {}: {}", destination, e, e);
      }
    }
  }

  // CompuServe use 1400 MTU; AOL claim 1450; DFN@home use 1448.
  // http://info.aol.co.uk/broadband/faqHomeNetworking.adp
  // http://www.compuserve.de/cso/hilfe/linux/hilfekategorien/installation/contentview.jsp?conid=385700
  // http://www.studenten-ins-netz.net/inhalt/service_faq.html
  // officially GRE is 1476 and PPPoE is 1492.
  // unofficially, PPPoE is often 1472 (seen in the wild). Also, PPPoATM is sometimes 1472.
  static final int MAX_ALLOWED_MTU = 1492;
  static int udpV4HeadersLength = 28;
  static int udpV6HeadersLength = 48;
  // conservative estimation when AF is not known
  public static final int UDP_HEADERS_LENGTH = udpV6HeadersLength;

  static final int MIN_IPV4_MTU = 576;
  // conservative estimation when AF is not known
  public static final int MIN_MTU = MIN_IPV4_MTU;

  private volatile int maxPacketSize = MAX_ALLOWED_MTU;

  /**
   * Returns the maximum payload size supported, excluding UDP/IP headers.
   *
   * @return Maximum number of payload bytes per packet.
   */
  @Override
  public int getMaxPacketSize() {
    return maxPacketSize;
  }

  /**
   * Recomputes and stores the maximum payload size based on the node's advertised minimum MTU.
   *
   * @return The newly computed maximum payload size in bytes.
   */
  public int calculateMaxPacketSize() {
    int oldSize = maxPacketSize;
    int newSize = innerCalculateMaxPacketSize();
    maxPacketSize = newSize;
    if (oldSize != newSize) LOG.info("Max packet size: {}", newSize);
    return maxPacketSize;
  }

  /** Recalculate the maximum packet size (internal helper). */
  int innerCalculateMaxPacketSize() { // Note: consider passing a peerNode and doing per-peer sizing
    // a per-peer basis? How? PMTU would require JNI, although it
    // might be worth it...
    final int minAdvertisedMTU = node.getMinimumMTU();
    maxPacketSize = Math.min(MAX_ALLOWED_MTU, minAdvertisedMTU) - UDP_HEADERS_LENGTH;
    return maxPacketSize;
  }

  /**
   * Returns a conservative payload size threshold used by senders to avoid fragmentation.
   *
   * @return {@code getMaxPacketSize() - 100}.
   */
  @Override
  public int getPacketSendThreshold() {
    return getMaxPacketSize() - 100;
  }

  /** Starts the receive loop on the node executor. No-op if already inactive. */
  public void start() {
    if (!active) return;
    synchronized (this) {
      started = true;
      startTime = System.currentTimeMillis();
    }
    node.network().executor().execute(this, "UdpSocketHandler for port " + localAddress.getPort());
  }

  /**
   * Stops the handler, closes the channel, waits for the run loop to exit, and persists tracker
   * data.
   */
  public void close() {
    LOG.info("Closing.");
    synchronized (this) {
      active = false;
      try {
        datagramChannel.close();
      } catch (IOException e) {
        LOG.error("Error closing DatagramChannel", e);
      }

      if (!started) return;
      while (!isDone) {
        try {
          wait(2000);
        } catch (InterruptedException e) {
          LOG.warn("Interrupted while waiting for UdpSocketHandler shutdown", e);
          Thread.currentThread().interrupt();
        }
      }
    }
    tracker.storeData(node.getBootId(), node.runDir(), localAddress.getPort());
  }

  /**
   * Returns the current debug drop probability parameter.
   *
   * @return The denominator of the 1/N drop chance, or zero to disable.
   */
  @SuppressWarnings("unused")
  public int getDropProbability() {
    return dropProbability;
  }

  /**
   * Sets the debug drop probability.
   *
   * @param dropProbability A value {@code N >= 0}. When {@code N > 0}, each send has a 1/N chance
   *     to be dropped locally for testing.
   */
  public void setDropProbability(int dropProbability) {
    this.dropProbability = dropProbability;
  }

  /**
   * Returns the local UDP port number.
   *
   * @return The bound port.
   */
  public int getPortNumber() {
    return localAddress.getPort();
  }

  /** Returns a string form of the bound local socket address. */
  @Override
  public String toString() {
    return localAddress.toString();
  }

  /**
   * Returns the assumed UDP/IP header length when address family is unknown.
   *
   * @return Header length in bytes (defaults to IPv6 size).
   */
  @Override
  public int getHeadersLength() {
    return UDP_HEADERS_LENGTH;
  }

  /**
   * Returns the UDP/IP header length for the peer's address family.
   *
   * @param peer Destination peer.
   * @return Header length in bytes for IPv4 or IPv6.
   */
  @Override
  public int getHeadersLength(Peer peer) {
    return getHeadersLength(peer.getAddress(false));
  }

  int getHeadersLength(InetAddress addr) {
    return addr == null || addr instanceof Inet6Address ? udpV6HeadersLength : udpV4HeadersLength;
  }

  /**
   * Exposes the connectivity tracker used by this handler.
   *
   * @return The {@link AddressTracker} instance.
   */
  public AddressTracker getAddressTracker() {
    return tracker;
  }

  /** Requests a re-scan of the port-forwarding status. */
  @Override
  public void rescanPortForward() {
    tracker.rescan();
  }

  /**
   * Returns the most recently detected connectivity status.
   *
   * @return Current {@link AddressTracker.Status}.
   */
  @Override
  public AddressTracker.Status getDetectedConnectivityStatus() {
    return tracker.getPortForwardStatus();
  }

  /** Returns the native thread priority to use when scheduling this runnable. */
  @Override
  public int getPriority() {
    return NativeThread.PriorityLevel.MAX_PRIORITY.value;
  }

  /**
   * Returns the {@code System.currentTimeMillis()} timestamp recorded at {@link #start()}.
   *
   * @return Start time in milliseconds since the epoch.
   */
  public long getStartTime() {
    return startTime;
  }
}
