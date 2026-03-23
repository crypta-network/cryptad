package network.crypta.crypt;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.Provider;
import network.crypta.config.Config;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.config.SubConfig;
import network.crypta.node.runtime.SSL;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100") // method naming with underscores for clarity
class SSLTest {

  private SubConfig sslConfig;
  private Path keystorePath;
  // SubConfig option keys (avoid duplicated literals per Sonar rules)
  private static final String OPT_ENABLE = "sslEnable";
  private static final String OPT_KEYSTORE = "sslKeyStore";
  private static final String OPT_KEYPASS = "sslKeyPass";
  private static final String OPT_HSTS = "sslHSTS";
  // JCE property key to control BC loading (keep local to tests)
  private static final String PROP_USE_BC = "crypta.jce.use.BC.I.know.what.I.am.doing";

  @TempDir Path tmpDir;

  @BeforeEach
  void setUp() throws Exception {
    // Ensure BC provider is loaded for tests that enable SSL and generate keys.
    // Set property before touching JceLoader to influence static initialization.
    System.setProperty(PROP_USE_BC, "true");
    Provider bc = JceLoader.getBouncyCastle();
    assertNotNull(bc, "BouncyCastle provider must be available for SSL tests");

    // Fresh SubConfig for each test; SSL holds static state so we drive it via callbacks.
    Config cfg = new Config();
    sslConfig = cfg.createSubConfig("ssl");
    SSL.init(sslConfig);

    // Use a per-test keystore location under a temp directory to avoid touching the repo tree.
    keystorePath = tmpDir.resolve("keystore-" + System.nanoTime() + ".p12");
    // Change keystore path while SSL is disabled – this does not perform I/O per implementation.
    sslConfig.set(OPT_KEYSTORE, keystorePath.toString());

    // Best-effort reset: force-disable to clear any previous factory if a prior test enabled it.
    // If already disabled this is a no-op.
    try {
      sslConfig.set(OPT_ENABLE, false);
    } catch (InvalidConfigValueException | NodeNeedRestartException _) {
      // Ignore: we only need SSL disabled; failures here would surface in assertions anyway.
    }
  }

  @AfterEach
  void tearDown() {
    // Return SSL to a disabled state so tests are independent.
    try {
      sslConfig.set(OPT_ENABLE, false);
    } catch (InvalidConfigValueException | NodeNeedRestartException _) {
      // Ignore on cleanup
    }
  }

  @Test
  void available_whenNotEnabled_expectFalse() {
    assertFalse(SSL.available(), "SSL should not be available when disabled");
  }

  @Test
  void createServerSocket_whenNotInitialized_expectIOException() {
    assertThrows(IOException.class, SSL::createServerSocket, "Should throw when SSL not set up");
  }

  @Test
  void enable_whenKeystoreMissing_createsKeystoreAndAllowsServerSocket() throws Exception {
    // Arrange
    File ksFile = keystorePath.toFile();
    assertFalse(ksFile.exists(), "Keystore should not exist before enabling");

    // Act: enabling with a missing keystore should create a self-signed cert and SSL context.
    sslConfig.set(OPT_ENABLE, true);

    // Assert
    assertTrue(SSL.available(), "SSL should be available after enabling");
    assertTrue(
        ksFile.exists() && ksFile.length() > 0, "Keystore file should be created and non-empty");

    // Creating a socket should succeed and return a non-null instance; close immediately.
    try (java.net.ServerSocket s = SSL.createServerSocket()) {
      assertNotNull(s);
    }
  }

  @Test
  void getHSTSHeader_whenDisabledOrZero_expectEmpty() throws Exception {
    // Disabled + positive HSTS should still yield empty header
    sslConfig.set(OPT_HSTS, "60");
    assertEquals("", SSL.getHSTSHeader());

    // Enable but HSTS=0 → still empty
    sslConfig.set(OPT_HSTS, "0");
    sslConfig.set(OPT_ENABLE, true);
    assertEquals("", SSL.getHSTSHeader());
  }

  @Test
  void getHSTSHeader_whenEnabledAndPositive_expectValue() throws Exception {
    sslConfig.set(OPT_ENABLE, true);
    sslConfig.set(OPT_HSTS, "86400");
    assertEquals("max-age=86400", SSL.getHSTSHeader());
  }

  @Test
  void setHSTS_whenNegative_expectInvalidConfigValueException() {
    assertThrows(
        InvalidConfigValueException.class,
        () -> sslConfig.set(OPT_HSTS, "-1"),
        "Negative HSTS max-age should be rejected");
  }

  @Test
  void changeKeyPass_whenNoEntry_expectInvalidConfigValueException() {
    // SSL disabled, empty keystore → changing key password should fail via the callback
    assertThrows(
        InvalidConfigValueException.class,
        () -> sslConfig.set(OPT_KEYPASS, "newpass"),
        "Changing key password without a key entry should be rejected");
  }

  @Test
  void changeKeyPass_whenEnabled_expectContextRemainsUsable() throws Exception {
    // Arrange: enable to create a key entry in the keystore
    sslConfig.set(OPT_ENABLE, true);
    assertTrue(SSL.available());

    // Act: change the key password; should succeed and refresh SSL context
    assertDoesNotThrow(() -> sslConfig.set(OPT_KEYPASS, "newSecret"));

    // Assert: we can still create a server socket
    try (java.net.ServerSocket s = SSL.createServerSocket()) {
      assertNotNull(s);
    }
  }
}
