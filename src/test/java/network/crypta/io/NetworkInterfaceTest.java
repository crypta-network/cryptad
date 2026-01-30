package network.crypta.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import network.crypta.support.PriorityAwareExecutor;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@SuppressWarnings("java:S100") // Follow method_whenCondition_expectOutcome naming
class NetworkInterfaceTest {

  private TestNetworkInterface iface;

  @BeforeEach
  void setUp() {
    TestExecutor executor = new TestExecutor();
    iface = new TestNetworkInterface(55555, "127.0.0.1", executor);
  }

  @AfterEach
  void tearDown() throws Exception {
    iface.close();
  }

  @Test
  @DisplayName("setSoTimeout before bind applies to new acceptors")
  void setSoTimeout_beforeBind_appliesToNewAcceptors() throws Exception {
    iface.setSoTimeout(200);

    String[] failed = iface.setBindTo("127.0.0.1", false);
    assertNull(failed, "Binding to IPv4 loopback should succeed");

    TestServerSocket server = iface.findServerSocketByHost("127.0.0.1");
    assertNotNull(server, "Server socket for 127.0.0.1 should exist");
    assertEquals(
        200, server.getSoTimeoutMs(), "Acceptor timeout should propagate to server socket");
    assertTrue(server.isReuseEnabled(), "Server socket reuse should be enabled");
  }

  @Test
  @DisplayName("IPv6 bind failure ignored when flag set")
  void setBindTo_whenIPv6BindFailsAndIgnoreTrue_excludesFromBrokenList() {
    iface.setFailIPv6Bind(true);
    String[] failed = iface.setBindTo("::1,127.0.0.1", true);

    // IPv6 failure should be ignored; IPv4 should bind fine
    assertNull(failed, "IPv6 bind failure should be ignored when flag is true");
    assertTrue(iface.isBound(), "Interface should be considered bound after successful IPv4 bind");
    assertNotNull(iface.findServerSocketByHost("127.0.0.1"));
  }

  @Test
  @DisplayName("IPv6 bind failure returned when ignore flag is false")
  void setBindTo_whenIPv6BindFailsAndIgnoreFalse_returnsBrokenList() {
    iface.setFailIPv6Bind(true);
    String[] failed = iface.setBindTo("::1,127.0.0.1", false);

    assertNotNull(failed, "Broken list should not be null when IPv6 bind fails and ignore=false");
    assertArrayEquals(
        new String[] {"::1"}, failed, "Only the IPv6 address should be reported broken");
    assertNotNull(iface.findServerSocketByHost("127.0.0.1"), "IPv4 bind should still succeed");
  }

  @Test
  @DisplayName("IPv6 bind succeeds when failure flag is false")
  void setBindTo_whenIPv6BindSucceeds_returnsNoBrokenList() {
    iface.setFailIPv6Bind(false);
    String ip6Full = "0:0:0:0:0:0:0:1";
    String[] failed = iface.setBindTo(ip6Full, false);
    assertNull(failed, "IPv6 bind should succeed when failure flag is false");
    assertNotNull(
        iface.findServerSocketByHost(ip6Full),
        "Server socket for IPv6 address should be present when bind succeeds");
  }

  @Test
  @DisplayName("accept returns null immediately when not bound")
  void accept_whenNoAcceptors_returnsNull() {
    // new interface without calling setBindTo()
    Socket s = iface.accept();
    assertNull(s, "Accept should return null if no acceptors are bound");
  }

  @Test
  @DisplayName("Allowed client is accepted and returned by accept()")
  void accept_whenAllowedClient_returnsSocket() throws Exception {
    // Small timeout on acceptor to avoid indefinite waits in the background loop
    iface.setSoTimeout(50);
    String[] failed = iface.setBindTo("127.0.0.1", false);
    assertNull(failed);

    TestServerSocket srv = iface.findServerSocketByHost("127.0.0.1");
    assertNotNull(srv);

    // Enqueue a client that matches AllowedHosts (127.0.0.1)
    srv.enqueue(new TestSocket(InetAddress.getAllByName("127.0.0.1")[0]));

    Socket accepted = iface.accept();
    assertNotNull(accepted, "Expected a socket to be accepted");
    // Same instance that acceptor added
    assertEquals(TestSocket.class, accepted.getClass());
    assertEquals("127.0.0.1", accepted.getInetAddress().getHostAddress());
  }

  @Test
  @DisplayName("Disallowed client is closed and not queued; accept() unblocks on close")
  void accept_whenDisallowedClient_unblocksOnClose() throws Exception {
    // Restrict allowed hosts to loopback only
    iface.setAllowedHosts("127.0.0.1");
    iface.setSoTimeout(25); // propagate to acceptors created below
    String[] failed = iface.setBindTo("127.0.0.1", false);
    assertNull(failed);

    TestServerSocket srv = iface.findServerSocketByHost("127.0.0.1");
    assertNotNull(srv);

    // Enqueue a client from a different address; should be denied by acceptor
    TestSocket disallowed = new TestSocket(InetAddress.getAllByName("10.0.0.15")[0]);
    srv.enqueue(disallowed);

    // Kick off accept() which will wait for a signal; we'll close the interface to signal.
    final Socket[] result = new Socket[1];
    Thread t = new Thread(() -> result[0] = iface.accept(), "test-accept-thread");
    t.setDaemon(true);
    t.start();

    // Wait up to ~500ms for the disallowed connection to be rejected (socket closed by acceptor)
    long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(500);
    while (!disallowed.isClosedFlag() && System.nanoTime() < deadline) {
      Thread.onSpinWait();
    }
    assertTrue(disallowed.isClosedFlag(), "Acceptor should close disallowed client socket");

    // Now close the interface to wake accept() and make it return null
    iface.close();
    t.join(1000);
    assertNull(result[0], "No socket should be accepted when only disallowed clients were offered");
  }

  // -------------------------
  // Test scaffolding
  // -------------------------

  private static final class TestExecutor implements PriorityAwareExecutor {
    @Override
    public void execute(@NotNull Runnable job) {
      Thread t = new Thread(job, "test-exec");
      t.setDaemon(true);
      t.start();
    }

    @Override
    public void execute(Runnable job, String jobName) {
      Thread t = new Thread(job, jobName == null ? "test-exec-labeled" : jobName);
      t.setDaemon(true);
      t.start();
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

  private static final class TestNetworkInterface extends NetworkInterface {
    private final List<TestServerSocket> sockets = Collections.synchronizedList(new ArrayList<>());
    private volatile boolean failIPv6Bind = false;

    TestNetworkInterface(int port, String allowedHosts, PriorityAwareExecutor executor) {
      super(port, allowedHosts, executor);
    }

    void setFailIPv6Bind(boolean fail) {
      this.failIPv6Bind = fail;
    }

    @Override
    protected ServerSocket createServerSocket() throws IOException {
      TestServerSocket s = new TestServerSocket(this);
      sockets.add(s);
      return s;
    }

    TestServerSocket findServerSocketByHost(String host) {
      synchronized (sockets) {
        for (TestServerSocket s : sockets) {
          InetSocketAddress bound = s.getBoundAddress();
          if (bound != null && Objects.equals(bound.getHostString(), host)) return s;
        }
      }
      return null;
    }
  }

  private static final class TestServerSocket extends ServerSocket {
    private final TestNetworkInterface owner;
    private volatile InetSocketAddress boundAddress;
    private volatile boolean reuse;
    private volatile int soTimeoutMs;
    private volatile boolean closed;
    private final BlockingQueue<Socket> queue = new LinkedBlockingQueue<>();

    TestServerSocket(TestNetworkInterface owner) throws IOException {
      super();
      this.owner = owner;
    }

    int getSoTimeoutMs() {
      return soTimeoutMs;
    }

    InetSocketAddress getBoundAddress() {
      return boundAddress;
    }

    void enqueue(Socket s) {
      queue.add(s);
    }

    @Override
    public void setReuseAddress(boolean on) {
      this.reuse = on;
    }

    boolean isReuseEnabled() {
      return reuse;
    }

    @Override
    public void bind(SocketAddress endpoint) throws IOException {
      InetSocketAddress isa = (InetSocketAddress) endpoint;
      InetAddress addr = isa.getAddress();
      if (owner.failIPv6Bind && addr instanceof Inet6Address) {
        throw new SocketException("IPv6 bind not supported in test environment");
      }
      this.boundAddress = isa;
      this.closed = false;
    }

    @Override
    public void setSoTimeout(int timeout) {
      this.soTimeoutMs = timeout;
    }

    @Override
    public Socket accept() throws IOException {
      if (closed) throw new SocketException("closed");
      try {
        int wait = soTimeoutMs > 0 ? soTimeoutMs : 50; // avoid indefinite waits
        Socket s = queue.poll(wait, TimeUnit.MILLISECONDS);
        if (s == null) throw new SocketTimeoutException("timeout");
        return s;
      } catch (InterruptedException _) {
        Thread.currentThread().interrupt();
        throw new SocketException("interrupted");
      }
    }

    @Override
    public void close() {
      this.closed = true;
    }
  }

  private static final class TestSocket extends Socket {
    private final InetAddress inetAddress;
    private volatile boolean closed;

    TestSocket(InetAddress inetAddress) {
      this.inetAddress = inetAddress;
    }

    @Override
    public InetAddress getInetAddress() {
      return inetAddress;
    }

    @Override
    public synchronized void close() {
      this.closed = true;
    }

    boolean isClosedFlag() {
      return closed;
    }
  }
}
