package network.crypta.io.comm;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import network.crypta.io.AddressTracker;
import network.crypta.io.AddressTracker.Status;
import network.crypta.node.Node;
import network.crypta.node.ProgramDirectory;
import network.crypta.support.PriorityAwareExecutor;
import network.crypta.support.io.NativeThread;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@SuppressWarnings("java:S100") // Allow method names of the form method_whenCondition_expectOutcome
class UdpSocketHandlerTest {

  private static final String LOOPBACK_V6 = "::1";

  private Node node;
  private IOStatisticCollector ioStats;
  private AddressTracker tracker;
  private UdpSocketHandler handler;

  @TempDir Path tempDir;

  @BeforeEach
  void setUp() throws Exception {
    node = Mockito.mock(Node.class, org.mockito.Answers.RETURNS_DEEP_STUBS);
    ProgramDirectory runDir = new ProgramDirectory();
    // Ensure ProgramDirectory has a backing filesystem path.
    runDir.move(tempDir.toString());
    ioStats = new IOStatisticCollector();
    tracker = Mockito.mock(AddressTracker.class);

    network.crypta.node.subsystem.NodeNetworkSubsystem network =
        Mockito.mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(network);
    when(network.trafficClass()).thenReturn(TrafficClass.DSCP_CS1);
    when(node.bootstrap().fastWeakRandom()).thenReturn(new java.security.SecureRandom());
    when(node.getLastBootId()).thenReturn(42L);
    when(node.getBootId()).thenReturn(43L);
    when(node.runDir()).thenReturn(runDir);
    when(node.getMinimumMTU()).thenReturn(1492);
    when(network.executor()).thenReturn(new NewThreadExecutor());

    // Default: AddressTracker.create(...) returns our tracker instance for predictable behavior.
    try (MockedStatic<AddressTracker> mocked = Mockito.mockStatic(AddressTracker.class)) {
      mocked
          .when(() -> AddressTracker.create(Mockito.anyLong(), Mockito.any(), Mockito.anyInt()))
          .thenReturn(tracker);
      handler =
          new UdpSocketHandler(
              /* listenPort= */ 0,
              InetAddress.getLoopbackAddress(),
              node,
              /* startupTime= */ System.currentTimeMillis(),
              /* title= */ "test-udp",
              ioStats);
    }
  }

  @AfterEach
  void tearDown() {
    if (handler != null) {
      handler.close();
    }
  }

  @Test
  void calculateMaxPacketSize_whenMinMtuUnderCap_expectMinMinusHeaders() {
    when(node.getMinimumMTU()).thenReturn(1400);
    int size = handler.calculateMaxPacketSize();
    int expected =
        Math.min(UdpSocketHandler.MAX_ALLOWED_MTU, 1400) - UdpSocketHandler.UDP_HEADERS_LENGTH;
    assertEquals(expected, size);
    assertEquals(size - 100, handler.getPacketSendThreshold());
    assertEquals(UdpSocketHandler.UDP_HEADERS_LENGTH, handler.getHeadersLength());
  }

  @Test
  void getHeadersLength_whenIPv4AndIPv6AndNull_expectCorrectValues() throws Exception {
    InetAddress ipv4 = InetAddress.getByName("203.0.113.1"); // RFC 5737 TEST-NET-3
    byte[] loopbackV6 = new byte[16];
    loopbackV6[15] = 1;
    InetAddress ipv6 = InetAddress.getByAddress(LOOPBACK_V6, loopbackV6);
    assertEquals(UdpSocketHandler.udpV4HeadersLength, handler.getHeadersLength(ipv4));
    // Sanity check type in test to ensure we're actually passing IPv6
    assertInstanceOf(Inet6Address.class, ipv6);
    assertEquals(UdpSocketHandler.udpV6HeadersLength, handler.getHeadersLength(ipv6));
    assertEquals(UdpSocketHandler.udpV6HeadersLength, handler.getHeadersLength((InetAddress) null));
  }

  @Test
  void sendPacket_whenDropProbabilityOne_expectTrackerNotUpdated() throws Exception {
    handler.setDropProbability(1); // 1 in 1 chance → always drop

    byte[] payload = "ignored".getBytes(StandardCharsets.UTF_8);
    Peer dest = new Peer(InetAddress.getLoopbackAddress(), 54321);

    handler.sendPacket(payload, dest, /* allowLocalAddresses= */ true);

    // Because we dropped, no send accounting or tracker call should happen.
    verify(tracker, never()).sentPacketTo(any(Peer.class));
  }

  @Test
  void sendPacket_whenUnknownHost_expectNoThrowAndNoSend() throws Exception {
    byte[] payload = "ignored".getBytes(StandardCharsets.UTF_8);
    // allowUnknown=true lets us construct the Peer without resolution; actual send path will try
    // and fail when forcing a lookup.
    Peer dest = new Peer("does-not-exist.invalid-tld:31337", /* allowUnknown= */ true);

    assertDoesNotThrow(() -> handler.sendPacket(payload, dest, /* allowLocalAddresses= */ true));
    verify(tracker, never()).sentPacketTo(any(Peer.class));
  }

  @Test
  void getBindTo_getTitle_getPriority_expectConsistentValues() {
    assertEquals(InetAddress.getLoopbackAddress(), handler.getBindTo());
    assertEquals("test-udp", handler.getTitle());
    assertEquals(NativeThread.PriorityLevel.MAX_PRIORITY.value, handler.getPriority());
  }

  @Test
  void startAndReceive_whenPacketArrives_filterInvoked_andTrackerUpdated() throws Exception {
    // Prepare filter and wire it into the handler before starting the thread.
    IncomingPacketFilter filter = Mockito.mock(IncomingPacketFilter.class);
    when(filter.process(any(byte[].class), anyInt(), anyInt(), any(Peer.class), anyLong()))
        .thenReturn(IncomingPacketFilter.DECODED.DECODED);
    // Build a fresh handler bound to a specific free UDP port to avoid reflection.
    if (handler != null) handler.close();
    int freePort = findFreeUdpPort();
    try (MockedStatic<AddressTracker> mocked = Mockito.mockStatic(AddressTracker.class)) {
      mocked
          .when(() -> AddressTracker.create(Mockito.anyLong(), Mockito.any(), Mockito.anyInt()))
          .thenReturn(tracker);
      handler =
          new UdpSocketHandler(
              freePort,
              InetAddress.getLoopbackAddress(),
              node,
              System.currentTimeMillis(),
              "rx-test",
              ioStats);
    }
    handler.setLowLevelFilter(filter);
    handler.start();
    // Do not assert startReceive() immediately: on CI under heavy load the
    // receiver thread can be scheduled with noticeable delay, which makes a
    // short timeout here flaky. Instead, we assert receipt/processing first
    // (which can only occur after startReceive()), then verify startReceive().

    // Send a small UDP packet to the handler's bound address.
    InetSocketAddress bound = new InetSocketAddress(InetAddress.getLoopbackAddress(), freePort);
    try (DatagramChannel sender = DatagramChannel.open()) {
      sender.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
      int bytes = sender.send(ByteBuffer.wrap("hello".getBytes(StandardCharsets.UTF_8)), bound);
      assertEquals(5, bytes);
    }

    // The filter should be invoked once with some peer and the correct length.
    ArgumentCaptor<Peer> peerCaptor = ArgumentCaptor.forClass(Peer.class);
    ArgumentCaptor<Integer> lenCaptor = ArgumentCaptor.forClass(Integer.class);
    verify(filter, timeout(10000))
        .process(any(byte[].class), eq(0), lenCaptor.capture(), peerCaptor.capture(), anyLong());
    assertEquals(5, lenCaptor.getValue());

    // The tracker should record a receive from the sender's address/port.
    verify(tracker, atLeastOnce()).receivedPacketFrom(any(Peer.class));

    // By the time processing has happened, the run loop has already called
    // startReceive(); verifying without a timeout avoids racy failures.
    verify(tracker, atLeastOnce()).startReceive(anyLong());

    // Cleanup so the receive loop exits.
    handler.close();
  }

  @Test
  void rescanAndStatus_whenInvoked_delegateToTracker() {
    when(tracker.getPortForwardStatus()).thenReturn(Status.MAYBE_PORT_FORWARDED);
    assertEquals(Status.MAYBE_PORT_FORWARDED, handler.getDetectedConnectivityStatus());
    handler.rescanPortForward();
    verify(tracker, atLeastOnce()).rescan();
  }

  @Test
  void close_whenNotStarted_doesNotWaitAndSkipsStore() {
    // Create a fresh handler but don't start it, then close immediately.
    UdpSocketHandler localHandler;
    try (MockedStatic<AddressTracker> mocked = Mockito.mockStatic(AddressTracker.class)) {
      mocked
          .when(() -> AddressTracker.create(Mockito.anyLong(), Mockito.any(), Mockito.anyInt()))
          .thenReturn(tracker);
      localHandler =
          new UdpSocketHandler(
              0,
              InetAddress.getLoopbackAddress(),
              node,
              System.currentTimeMillis(),
              "no-start",
              new IOStatisticCollector());
    } catch (Exception e) {
      throw new AssertionError("Handler construction failed", e);
    }

    // Not started → close should not block and should NOT write a snapshot.
    localHandler.close();
    verify(tracker, never()).storeData(anyLong(), any(ProgramDirectory.class), anyInt());
  }

  private static int findFreeUdpPort() throws java.io.IOException {
    try (DatagramChannel dc = DatagramChannel.open()) {
      dc.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0));
      return ((InetSocketAddress) dc.getLocalAddress()).getPort();
    }
  }

  /** Simple executor that runs tasks on a new thread to avoid blocking the caller. */
  private static final class NewThreadExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NotNull Runnable job) {
      new Thread(job, "test-exec").start();
    }

    @Override
    public void execute(Runnable job, String jobName) {
      new Thread(job, jobName == null ? "test-exec" : jobName).start();
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      execute(job, jobName);
    }

    @Override
    public int[] waitingThreads() {
      return new int[] {0};
    }

    @Override
    public int[] runningThreads() {
      return new int[] {0};
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }
}
