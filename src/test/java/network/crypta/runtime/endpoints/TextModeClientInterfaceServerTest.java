package network.crypta.runtime.endpoints;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.PrintStream;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import javax.net.ServerSocketFactory;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.SubConfig;
import network.crypta.crypt.RandomSource;
import network.crypta.io.NetworkInterface;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.subsystem.NodeNetworkSubsystem;
import network.crypta.runtime.bootstrap.NodeBootstrap;
import network.crypta.runtime.core.SSL;
import network.crypta.support.PriorityAwareExecutor;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class TextModeClientInterfaceServerTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeBootstrap bootstrap;
  @Mock private NodeNetworkSubsystem network;

  @Mock private NodeClientCore core;
  @Mock private ClientEndpoints endpoints;

  @TempDir File tempDir;

  private static void setStaticField(Class<?> type, String name, Object value) throws Exception {
    Field f = type.getDeclaredField(name);
    f.setAccessible(true);
    f.set(null, value);
  }

  @BeforeEach
  void resetStatics() throws Exception {
    // Ensure SSL.available() returns false by default for tests that rely on it.
    setStaticField(SSL.class, "ssf", null);
    // Reset the TMCI SSL flag to a known state.
    setStaticField(TextModeClientInterfaceServer.class, "ssl", false);
    Mockito.lenient().when(core.getEndpoints()).thenReturn(endpoints);
  }

  @Test
  void maybeCreate_whenDirectEnabled_returnsDirectTMCI() {
    Config cfg = Mockito.mock(Config.class);
    SubConfig sub = Mockito.mock(SubConfig.class);
    Mockito.when(cfg.createSubConfig("console")).thenReturn(sub);
    // Configuration values: TMCI disabled, direct enabled.
    Mockito.when(sub.getBoolean("enabled")).thenReturn(false);
    Mockito.when(sub.getInt("port")).thenReturn(0);
    Mockito.when(sub.getString("bindTo")).thenReturn(NetworkInterface.DEFAULT_BIND_TO);
    Mockito.when(sub.getString("allowedHosts")).thenReturn(NetworkInterface.DEFAULT_BIND_TO);
    Mockito.when(sub.getBoolean("directEnabled")).thenReturn(true);

    // Node + core wiring
    Mockito.when(core.getDownloadsDir()).thenReturn(tempDir);
    Mockito.when(core.makeClient(Mockito.anyShort(), Mockito.eq(true), Mockito.eq(false)))
        .thenReturn(Mockito.mock(network.crypta.client.HighLevelSimpleClient.class));

    TextModeClientInterfaceServer.InitResult init =
        TextModeClientInterfaceServer.maybeCreate(node, core, cfg);

    // TMCI is disabled in config, so no server instance is created.
    assertNull(init.server());

    // Direct TMCI should be created for later registration/start.
    assertNotNull(init.directTMCI());

    // Sub-config should be finalized.
    Mockito.verify(sub).finishedInitialization();
  }

  @Test
  void start_whenCalled_logsAndSchedulesRunnable() throws Exception {
    // Arrange a minimal node/core for constructor wiring.
    Mockito.when(node.services().clientCore()).thenReturn(core);
    Mockito.when(node.bootstrap()).thenReturn(bootstrap);
    Mockito.when(bootstrap.random()).thenReturn(Mockito.mock(RandomSource.class));
    Mockito.when(core.getDownloadsDir()).thenReturn(tempDir);

    CapturingExecutor exec = new CapturingExecutor();
    Mockito.when(node.network()).thenReturn(network);
    Mockito.when(network.executor()).thenReturn(exec);

    TextModeClientInterfaceServer tmci =
        new TextModeClientInterfaceServer(
            node, core, 0, NetworkInterface.DEFAULT_BIND_TO, NetworkInterface.DEFAULT_BIND_TO);

    // Capture stdout
    ByteArrayOutputStream bout = new ByteArrayOutputStream();
    PrintStream originalOut = System.out;
    System.setOut(new PrintStream(bout, false, StandardCharsets.UTF_8));
    try {
      // Act
      tmci.start();

      // Assert
      String out = bout.toString(StandardCharsets.UTF_8).trim();
      String expectedPrefix = "TMCI started on " + tmci.networkInterface.getAllowedHosts() + ':';
      assertTrue(out.startsWith(expectedPrefix));
      // Runnable scheduled should be the server itself
      assertEquals(tmci, exec.lastRunnable);
      assertEquals("Text mode client interface", exec.lastJobName);
    } finally {
      System.setOut(originalOut);
      // Clean up bound sockets promptly to avoid port leakage during tests.
      tmci.networkInterface.close();
    }
  }

  @Test
  void TMCIEnabledCallback_getAndSet_behaviour() {
    TextModeClientInterfaceServer serverMock = Mockito.mock(TextModeClientInterfaceServer.class);
    Mockito.when(endpoints.getTextModeClientInterface()).thenReturn(serverMock);
    TextModeClientInterfaceServer.TMCIEnabledCallback cb =
        new TextModeClientInterfaceServer.TMCIEnabledCallback(core);

    // First get(): server present -> true
    assertTrue(cb.get());
    // set(equal) -> no exception
    assertDoesNotThrow(() -> cb.set(true));
    // set(different) -> throws
    assertThrows(InvalidConfigValueException.class, () -> cb.set(false));

    // Now with no server
    Mockito.when(endpoints.getTextModeClientInterface()).thenReturn(null);
    assertFalse(cb.get());
    assertDoesNotThrow(() -> cb.set(false));
    assertThrows(InvalidConfigValueException.class, () -> cb.set(true));
  }

  @Test
  void TMCIDirectEnabledCallback_getAndSet_behaviour() {
    // Direct TMCI present
    Mockito.when(endpoints.getDirectTMCI()).thenReturn(Mockito.mock(TextModeClientInterface.class));
    TextModeClientInterfaceServer.TMCIDirectEnabledCallback cb =
        new TextModeClientInterfaceServer.TMCIDirectEnabledCallback(core);

    assertTrue(cb.get());
    assertDoesNotThrow(() -> cb.set(true));
    assertThrows(InvalidConfigValueException.class, () -> cb.set(false));

    Mockito.when(endpoints.getDirectTMCI()).thenReturn(null);
    assertFalse(cb.get());
    assertDoesNotThrow(() -> cb.set(false));
    assertThrows(InvalidConfigValueException.class, () -> cb.set(true));
  }

  @Test
  void TMCISSLCallback_set_whenSSLUnavailable_throwsAndDoesNotChange() {
    TextModeClientInterfaceServer.TMCISSLCallback cb =
        new TextModeClientInterfaceServer.TMCISSLCallback();
    assertFalse(cb.get());
    InvalidConfigValueException ex =
        assertThrows(InvalidConfigValueException.class, () -> cb.set(true));
    assertTrue(ex.getMessage().contains("Enable SSL support"));
    assertFalse(cb.get());
  }

  @Test
  void TMCISSLCallback_set_whenSSLAvailable_setsThenThrows() throws Exception {
    // Make SSL.available() return true by setting the ServerSocketFactory.
    setStaticField(SSL.class, "ssf", ServerSocketFactory.getDefault());
    TextModeClientInterfaceServer.TMCISSLCallback cb =
        new TextModeClientInterfaceServer.TMCISSLCallback();
    assertFalse(cb.get());
    InvalidConfigValueException ex =
        assertThrows(InvalidConfigValueException.class, () -> cb.set(true));
    assertTrue(ex.getMessage().contains("Cannot change SSL on the fly"));
    // Value has been applied despite the exception.
    assertTrue(cb.get());
  }

  @Test
  void TMCIBindtoCallback_getDefaultsAndSetNoopWhenEqual() {
    // No server -> get() returns default
    Mockito.when(endpoints.getTextModeClientInterface()).thenReturn(null);
    TextModeClientInterfaceServer.TMCIBindtoCallback cb =
        new TextModeClientInterfaceServer.TMCIBindtoCallback(core);

    assertEquals(NetworkInterface.DEFAULT_BIND_TO, cb.get());
    // set(equal) should be a no-op (and not throw) even when the server is null.
    assertDoesNotThrow(() -> cb.set(NetworkInterface.DEFAULT_BIND_TO));
  }

  @Test
  void TMCIAllowedHostsCallback_getDefaultsAndSetWhenDisabled_throws() {
    Mockito.when(endpoints.getTextModeClientInterface()).thenReturn(null);
    TextModeClientInterfaceServer.TMCIAllowedHostsCallback cb =
        new TextModeClientInterfaceServer.TMCIAllowedHostsCallback(core);

    assertEquals(NetworkInterface.DEFAULT_BIND_TO, cb.get());
    InvalidConfigValueException ex =
        assertThrows(InvalidConfigValueException.class, () -> cb.set("127.0.0.1"));
    assertTrue(ex.getMessage().contains("TMCI is disabled"));
  }

  @Test
  void TCMIPortNumberCallback_getDefaultAndSetDelegates() throws InvalidConfigValueException {
    // With no server, get() returns default 2323
    Mockito.when(endpoints.getTextModeClientInterface()).thenReturn(null);
    TextModeClientInterfaceServer.TCMIPortNumberCallback cb =
        new TextModeClientInterfaceServer.TCMIPortNumberCallback(core);
    assertEquals(2323, cb.get());

    // With a server present, set() delegates to setPort()
    TextModeClientInterfaceServer serverMock = Mockito.mock(TextModeClientInterfaceServer.class);
    Mockito.when(endpoints.getTextModeClientInterface()).thenReturn(serverMock);
    cb.set(12345);
    Mockito.verify(serverMock).setPort(12345);
  }

  // Minimal executor used to capture tasks submitted by start().
  private static final class CapturingExecutor implements PriorityAwareExecutor {
    Runnable lastRunnable;
    String lastJobName;

    @Override
    public void execute(@NotNull Runnable job) {
      this.lastRunnable = job;
      this.lastJobName = null;
    }

    @Override
    public void execute(Runnable job, String jobName) {
      this.lastRunnable = job;
      this.lastJobName = jobName;
    }

    @Override
    public void execute(Runnable job, String jobName, boolean fromTicker) {
      this.lastRunnable = job;
      this.lastJobName = jobName;
    }

    @Override
    public int[] waitingThreads() {
      return new int[0];
    }

    @Override
    public int[] runningThreads() {
      return new int[0];
    }

    @Override
    public int getWaitingThreadsCount() {
      return 0;
    }
  }
}
