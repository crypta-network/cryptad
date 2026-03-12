package network.crypta.io;

import java.io.IOException;
import java.lang.reflect.Field;
import javax.net.ServerSocketFactory;
import javax.net.ssl.SSLServerSocket;
import network.crypta.crypt.SSL;
import network.crypta.support.PriorityAwareExecutor;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // test method naming with underscores
class SSLNetworkInterfaceTest {

  private Object originalFactory;

  @BeforeEach
  void saveOriginalFactory() throws Exception {
    originalFactory = getSslServerSocketFactory();
  }

  @AfterEach
  void restoreOriginalFactory() throws Exception {
    setSslServerSocketFactory(originalFactory);
  }

  @Test
  @DisplayName("createServerSocket sets flags and enables only allowed cipher suites present")
  void createServerSocket_whenSupportedIncludesAllowed_expectOnlyAllowedEnabled() throws Exception {
    // Arrange
    SSLServerSocket mockSslServerSocket = mock(SSLServerSocket.class);
    when(mockSslServerSocket.getSupportedCipherSuites())
        .thenReturn(
            new String[] {
              // allowed
              "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
              // not allowed
              "TLS_FAKE_UNSUPPORTED",
              // allowed
              "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
              // allowed (SCSV)
              "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
            });

    // Provide a factory returning our mock without initializing the heavy SSL subsystem.
    setSslServerSocketFactory(new StubServerSocketFactory(mockSslServerSocket));

    PriorityAwareExecutor exec = mock(PriorityAwareExecutor.class);
    try (TestableSSLNetworkInterface iface = new TestableSSLNetworkInterface(12345, "*", exec)) {
      // Act
      SSLServerSocket created = (SSLServerSocket) iface.newServerSocket();

      // Assert
      assertNotNull(created);
      assertSame(mockSslServerSocket, created);
      // Supported cipher query should happen first
      verify(mockSslServerSocket).getSupportedCipherSuites();
      // Socket mode flags
      verify(mockSslServerSocket).setNeedClientAuth(false);
      verify(mockSslServerSocket).setUseClientMode(false);
      verify(mockSslServerSocket).setWantClientAuth(false);
      // Cipher suite filtering preserves order of supported list for allowed entries only
      org.mockito.ArgumentCaptor<String[]> enabledCaptor =
          org.mockito.ArgumentCaptor.forClass(String[].class);
      verify(mockSslServerSocket).setEnabledCipherSuites(enabledCaptor.capture());
      assertArrayEquals(
          new String[] {
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
          },
          enabledCaptor.getValue());
      verifyNoMoreInteractions(mockSslServerSocket);
    }
  }

  @Test
  @DisplayName("createServerSocket enables empty ciphers when none are allowed")
  void createServerSocket_whenNoAllowedCiphers_expectEmptyEnabled() throws Exception {
    // Arrange
    SSLServerSocket mockSslServerSocket = mock(SSLServerSocket.class);
    when(mockSslServerSocket.getSupportedCipherSuites())
        .thenReturn(new String[] {"TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"});

    setSslServerSocketFactory(new StubServerSocketFactory(mockSslServerSocket));

    PriorityAwareExecutor exec = mock(PriorityAwareExecutor.class);
    try (TestableSSLNetworkInterface iface = new TestableSSLNetworkInterface(12345, "*", exec)) {
      // Act
      SSLServerSocket created = (SSLServerSocket) iface.newServerSocket();

      // Assert
      assertSame(mockSslServerSocket, created);

      // Supported cipher query should happen
      verify(mockSslServerSocket).getSupportedCipherSuites();
      // Verify flags always set
      verify(mockSslServerSocket).setNeedClientAuth(false);
      verify(mockSslServerSocket).setUseClientMode(false);
      verify(mockSslServerSocket).setWantClientAuth(false);
      // No supported cipher matches allowed list → empty enable set
      org.mockito.ArgumentCaptor<String[]> enabledCaptor =
          org.mockito.ArgumentCaptor.forClass(String[].class);
      verify(mockSslServerSocket).setEnabledCipherSuites(enabledCaptor.capture());
      assertArrayEquals(new String[0], enabledCaptor.getValue());
      verifyNoMoreInteractions(mockSslServerSocket);
    }
  }

  @Test
  @DisplayName("createServerSocket propagates IOException from underlying SSL factory")
  void createServerSocket_whenFactoryThrowsIOException_expectPropagate() throws Exception {
    // Arrange
    setSslServerSocketFactory(new ThrowingServerSocketFactory(new IOException("boom")));
    PriorityAwareExecutor exec = mock(PriorityAwareExecutor.class);
    try (TestableSSLNetworkInterface iface = new TestableSSLNetworkInterface(12345, "*", exec)) {
      // Act + Assert
      assertThrows(IOException.class, iface::newServerSocket);
    }
  }

  // --- Test scaffolding helpers ---

  private static Object getSslServerSocketFactory() throws Exception {
    Field f = SSL.class.getDeclaredField("ssf");
    f.setAccessible(true);
    return f.get(null);
  }

  private static void setSslServerSocketFactory(Object factory) throws Exception {
    Field f = SSL.class.getDeclaredField("ssf");
    f.setAccessible(true);
    f.set(null, factory);
  }

  /** Exposes {@code createServerSocket()} to tests while executing the real implementation. */
  private static class TestableSSLNetworkInterface extends SSLNetworkInterface {
    TestableSSLNetworkInterface(int port, String allowedHosts, PriorityAwareExecutor executor) {
      super(port, allowedHosts, executor);
    }

    /** Calls the real {@code super.createServerSocket()} implementation. */
    public java.net.ServerSocket newServerSocket() throws IOException {
      return super.createServerSocket();
    }
  }

  /** A simple {@link ServerSocketFactory} that returns a preconfigured {@link SSLServerSocket}. */
  private static final class StubServerSocketFactory extends ServerSocketFactory {
    private final SSLServerSocket toReturn;

    StubServerSocketFactory(SSLServerSocket toReturn) {
      this.toReturn = toReturn;
    }

    @Override
    public java.net.ServerSocket createServerSocket() {
      return toReturn;
    }

    @Override
    public java.net.ServerSocket createServerSocket(int port) {
      throw new UnsupportedOperationException();
    }

    @Override
    public java.net.ServerSocket createServerSocket(int port, int backlog) {
      throw new UnsupportedOperationException();
    }

    @Override
    public java.net.ServerSocket createServerSocket(
        int port, int backlog, java.net.InetAddress ifAddress) {
      throw new UnsupportedOperationException();
    }
  }

  /** A {@link ServerSocketFactory} that always throws the provided {@link IOException}. */
  private static final class ThrowingServerSocketFactory extends ServerSocketFactory {
    private final IOException toThrow;

    ThrowingServerSocketFactory(IOException toThrow) {
      this.toThrow = toThrow;
    }

    @Override
    public java.net.ServerSocket createServerSocket() throws IOException {
      throw toThrow;
    }

    @Override
    public java.net.ServerSocket createServerSocket(int port) throws IOException {
      throw toThrow;
    }

    @Override
    public java.net.ServerSocket createServerSocket(int port, int backlog) throws IOException {
      throw toThrow;
    }

    @Override
    public java.net.ServerSocket createServerSocket(
        int port, int backlog, java.net.InetAddress ifAddress) throws IOException {
      throw toThrow;
    }
  }
}
