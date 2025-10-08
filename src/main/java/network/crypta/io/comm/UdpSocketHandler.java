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

public class UdpSocketHandler
    implements PrioRunnable, PacketSocketHandler, PortForwardSensitiveSocketHandler {

  private static final Logger LOG = LoggerFactory.getLogger(UdpSocketHandler.class);

  private final ByteBuffer receiveBuffer = ByteBuffer.allocate(MAX_RECEIVE_SIZE);
  private final DatagramChannel datagramChannel;
  private final InetSocketAddress localAddress;
  private final AddressTracker tracker;
  private IncomingPacketFilter lowLevelFilter;

  /**
   * RNG for debugging, used with _dropProbability. NOT CRYPTO SAFE. DO NOT USE FOR THINGS THAT NEED
   * CRYPTO SAFE RNG!
   */
  private final Random dropRandom;

  /** If &gt;0, 1 in _dropProbability chance of dropping a packet; for debugging */
  private int _dropProbability;

  // Icky layer violation
  private final Node node;

  private boolean _isDone;
  private volatile boolean _active = true;
  private final String title;
  private boolean _started;
  private long startTime;
  private final IOStatisticCollector ioStatistics;

  static {
  }

  private static class socketOptions {
    private static class socketOptionsHolder {
      static {
        Native.register(Platform.C_LIBRARY_NAME);
      }

      private static native int setsockopt(
          int fd, int level, int option_name, Pointer option_value, int option_len)
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

      final SOCKET_option_name option_name = SOCKET_option_name.IPV6_ADDR_PREFERENCES;
      final int linux;

      SOCKET_ADDR_PREFERENCE(int linux) {
        this.linux = linux;
      }
    }

    private static int getFd(DatagramChannel channel) {
      try {
        Field fdVal = channel.getClass().getDeclaredField("fdVal");
        fdVal.setAccessible(true);
        return fdVal.getInt(channel);
      } catch (Exception e) {
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
            socketOptionsHolder.setsockopt(
                fd,
                SOCKET_level.IPPROTO_IPV6.linux,
                p.option_name.linux,
                new IntByReference(p.linux).getPointer(),
                Native.POINTER_SIZE);
        return ret == 0;
      } catch (Exception e) {
        LOG.info(e.getMessage(), e);
        return false;
      }
    }
  }

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
    datagramChannel =
        DatagramChannel.open()
            .bind(localAddress)
            .setOption(StandardSocketOptions.SO_RCVBUF, 65536)
            .setOption(StandardSocketOptions.SO_REUSEADDR, true);

    try {
      datagramChannel.setOption(StandardSocketOptions.IP_TOS, node.getTrafficClass().value);
    } catch (UnsupportedOperationException e) {
      LOG.error("Failed to set IP_TOS socket option", e);
    }

    boolean r =
        socketOptions.setAddressPreference(
            datagramChannel, socketOptions.SOCKET_ADDR_PREFERENCE.IPV6_PREFER_SRC_PUBLIC);
    if (LOG.isDebugEnabled()) {
      LOG.debug(
          "Setting IPV6_PREFER_SRC_PUBLIC for port "
              + listenPort
              + " is a "
              + (r ? "success" : "failure"));
    }

    // Only used for debugging, no need to seed from Yarrow
    dropRandom = node.getFastWeakRandom();
    tracker = AddressTracker.create(node.getLastBootId(), node.runDir(), listenPort);
    tracker.startSend(startupTime);
  }

  /** Must be called, or we will NPE in run() */
  @Override
  public void setLowLevelFilter(IncomingPacketFilter f) {
    lowLevelFilter = f;
  }

  public InetAddress getBindTo() {
    return localAddress.getAddress();
  }

  public String getTitle() {
    return title;
  }

  @Override
  public void run() { // Listen for packets
    tracker.startReceive(System.currentTimeMillis());
    try {
      runLoop();
    } catch (Throwable t) {
      // Impossible? It keeps on exiting. We get the below,
      // but not this...
      try {
        System.err.print(t.getClass().getName());
        System.err.println();
      } catch (Throwable tt) {
      }
      try {
        System.err.print(t.getMessage());
        System.err.println();
      } catch (Throwable tt) {
      }
      // Avoid forced GC calls; they are ineffective and can mask real memory issues
      try {
        Runtime r = Runtime.getRuntime();
        System.err.print(r.freeMemory());
        System.err.println();
        System.err.print(r.totalMemory());
        System.err.println();
      } catch (Throwable tt) {
      }
      try {
        t.printStackTrace();
      } catch (Throwable tt) {
      }
    } finally {
      System.err.println("run() exiting for UdpSocketHandler on port " + localAddress.getPort());
      LOG.error("run() exiting for UdpSocketHandler on port " + localAddress.getPort());
      synchronized (this) {
        _isDone = true;
        notifyAll();
      }
    }
  }

  private void runLoop() {
    while (_active) {
      try {
        realRun();
      } catch (Throwable t) {
        System.err.println("Caught " + t);
        t.printStackTrace(System.err);
        LOG.error("Caught " + t, t);
      }
    }
  }

  private void realRun() {
    InetSocketAddress remote = receive();
    long now = System.currentTimeMillis();
    if (remote != null) {
      long startTime = System.currentTimeMillis();
      Peer peer = new Peer(remote.getAddress(), remote.getPort());
      tracker.receivedPacketFrom(peer);
      long endTime = System.currentTimeMillis();
      if (endTime - startTime > 50) {
        if (endTime - startTime > 3000) {
          LOG.error("packet creation took " + (endTime - startTime) + "ms");
        } else {
          if (LOG.isDebugEnabled())
            LOG.debug("packet creation took " + (endTime - startTime) + "ms");
        }
      }

      try {
        if (LOG.isDebugEnabled()) {
          LOG.debug("Processing packet of length " + receiveBuffer.limit() + " from " + peer);
        }
        startTime = System.currentTimeMillis();
        lowLevelFilter.process(receiveBuffer.array(), 0, receiveBuffer.limit(), peer, now);
        endTime = System.currentTimeMillis();
        if (endTime - startTime > 50) {
          if (endTime - startTime > 3000) {
            LOG.error("processing packet took " + (endTime - startTime) + "ms");
          } else {
            if (LOG.isDebugEnabled())
              LOG.debug("processing packet took " + (endTime - startTime) + "ms");
          }
        }
        if (LOG.isDebugEnabled()) {
          LOG.debug("Successfully handled packet length " + receiveBuffer.limit());
        }
      } catch (Throwable t) {
        LOG.error("Caught " + t + " from " + lowLevelFilter, t);
      }
    } else {
      if (LOG.isTraceEnabled()) LOG.trace("No packet received");
    }
  }

  private static final int MAX_RECEIVE_SIZE = 1500;

  private InetSocketAddress receive() {
    try {
      receiveBuffer.clear();
      InetSocketAddress remote = (InetSocketAddress) datagramChannel.receive(receiveBuffer);
      receiveBuffer.flip();
      InetAddress address = remote.getAddress();
      ioStatistics.reportReceivedBytes(address, getHeadersLength(address) + receiveBuffer.limit());
      return remote;
    } catch (SocketTimeoutException e1) {
      return null;
    } catch (IOException e2) {
      if (!_active) { // closed, just return silently
        return null;
      } else {
        throw new RuntimeException(e2);
      }
    }
  }

  /**
   * Send a block of encoded bytes to a peer. This is called by send, and by
   * IncomingPacketFilter.processOutgoing(..).
   *
   * @param blockToSend The data block to send.
   * @param destination The peer to send it to.
   */
  @Override
  public void sendPacket(byte[] blockToSend, Peer destination, boolean allowLocalAddresses)
      throws LocalAddressException {
    if (!_active) {
      LOG.error("Trying to send packet but no longer active");
      // It is essential that for recording accurate AddressTracker data that we don't send any more
      // packets after shutdown.
      return;
    }

    ByteBuffer packet = ByteBuffer.wrap(blockToSend);
    int port = destination.getPort();
    InetAddress address;
    // there should be no DNS needed here, but go ahead if we can, but complain doing it
    if ((address = destination.getAddress(false, allowLocalAddresses)) == null) {
      LOG.error(
          "Tried sending to destination without pre-looked up IP address(needs a real"
              + " Peer.getHostname()): null:"
              + destination.getPort(),
          new Exception("error"));
      if ((address = destination.getAddress(true, allowLocalAddresses)) == null) {
        LOG.error(
            "Tried sending to bad destination address: null:" + destination.getPort(),
            new Exception("error"));
        return;
      }
    }
    if (_dropProbability > 0) {
      if (dropRandom.nextInt() % _dropProbability == 0) {
        LOG.info("DROPPED: " + localAddress.getPort() + " -> " + destination.getPort());
        return;
      }
    }

    try {
      datagramChannel.send(packet, new InetSocketAddress(address, port));
      tracker.sentPacketTo(destination);
      ioStatistics.reportSentBytes(address, getHeadersLength(address) + blockToSend.length);
      if (LOG.isDebugEnabled()) {
        LOG.debug("Sent packet length " + blockToSend.length + " to " + address + ':' + port);
      }
    } catch (IOException | UnsupportedAddressTypeException e) {
      if (address instanceof Inet6Address) {
        LOG.info("Error while sending packet to IPv6 address: " + destination + ": " + e);
      } else {
        LOG.error("Error while sending packet to " + destination + ": " + e, e);
      }
    }
  }

  // CompuServe use 1400 MTU; AOL claim 1450; DFN@home use 1448.
  // http://info.aol.co.uk/broadband/faqHomeNetworking.adp
  // http://www.compuserve.de/cso/hilfe/linux/hilfekategorien/installation/contentview.jsp?conid=385700
  // http://www.studenten-ins-netz.net/inhalt/service_faq.html
  // officially GRE is 1476 and PPPoE is 1492.
  // unofficially, PPPoE is often 1472 (seen in the wild). Also PPPoATM is sometimes 1472.
  static final int MAX_ALLOWED_MTU = 1492;
  static final int UDPv4_HEADERS_LENGTH = 28;
  static final int UDPv6_HEADERS_LENGTH = 48;
  // conservative estimation when AF is not known
  public static final int UDP_HEADERS_LENGTH = UDPv6_HEADERS_LENGTH;

  static final int MIN_IPv4_MTU = 576;
  static final int MIN_IPv6_MTU = 1280;
  // conservative estimation when AF is not known
  public static final int MIN_MTU = MIN_IPv4_MTU;

  private volatile int maxPacketSize = MAX_ALLOWED_MTU;

  /**
   * @return The maximum packet size supported by this SocketManager, not including transport
   *     (UDP/IP) headers.
   */
  @Override
  public int getMaxPacketSize() {
    return maxPacketSize;
  }

  public int calculateMaxPacketSize() {
    int oldSize = maxPacketSize;
    int newSize = innerCalculateMaxPacketSize();
    maxPacketSize = newSize;
    if (oldSize != newSize) System.out.println("Max packet size: " + newSize);
    return maxPacketSize;
  }

  /** Recalculate the maximum packet size */
  int innerCalculateMaxPacketSize() { // FIXME: what about passing a peerNode though and doing it on
    // a per-peer basis? How? PMTU would require JNI, although it
    // might be worth it...
    final int minAdvertisedMTU = node.getMinimumMTU();
    return maxPacketSize = Math.min(MAX_ALLOWED_MTU, minAdvertisedMTU) - UDP_HEADERS_LENGTH;
  }

  @Override
  public int getPacketSendThreshold() {
    return getMaxPacketSize() - 100;
  }

  public void start() {
    if (!_active) return;
    synchronized (this) {
      _started = true;
      startTime = System.currentTimeMillis();
    }
    node.getExecutor().execute(this, "UdpSocketHandler for port " + localAddress.getPort());
  }

  public void close() {
    LOG.info("Closing.", new Exception("error"));
    synchronized (this) {
      _active = false;
      try {
        datagramChannel.close();
      } catch (IOException e) {
        LOG.error("Error closing DatagramChannel", e);
      }

      if (!_started) return;
      while (!_isDone) {
        try {
          wait(2000);
        } catch (InterruptedException e) {
          e.printStackTrace();
        }
      }
    }
    tracker.storeData(node.getBootId(), node.runDir(), localAddress.getPort());
  }

  public int getDropProbability() {
    return _dropProbability;
  }

  public void setDropProbability(int dropProbability) {
    _dropProbability = dropProbability;
  }

  public int getPortNumber() {
    return localAddress.getPort();
  }

  @Override
  public String toString() {
    return localAddress.toString();
  }

  @Override
  public int getHeadersLength() {
    return UDP_HEADERS_LENGTH;
  }

  @Override
  public int getHeadersLength(Peer peer) {
    return getHeadersLength(peer.getAddress(false));
  }

  int getHeadersLength(InetAddress addr) {
    return addr == null || addr instanceof Inet6Address
        ? UDPv6_HEADERS_LENGTH
        : UDPv4_HEADERS_LENGTH;
  }

  public AddressTracker getAddressTracker() {
    return tracker;
  }

  @Override
  public void rescanPortForward() {
    tracker.rescan();
  }

  @Override
  public AddressTracker.Status getDetectedConnectivityStatus() {
    return tracker.getPortForwardStatus();
  }

  @Override
  public int getPriority() {
    return NativeThread.PriorityLevel.MAX_PRIORITY.value;
  }

  public long getStartTime() {
    return startTime;
  }
}
