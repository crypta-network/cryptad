package network.crypta.node;

import java.util.concurrent.atomic.AtomicReference;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.Option;
import network.crypta.config.SubConfig;
import network.crypta.io.comm.FreenetInetAddress;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeCryptoConfigTest {

  @Mock SecurityLevels securityLevels;

  private static class TestConfigHarness {
    final network.crypta.config.Config root = new network.crypta.config.Config();
    final SubConfig sub = root.createSubConfig("node");
  }

  @Test
  void constructor_darknetDefaults_expectSaneInitialValues() throws Exception {
    // Arrange
    TestConfigHarness h = new TestConfigHarness();

    // Act
    NodeCryptoConfig cfg = new NodeCryptoConfig(h.sub, 0, false, securityLevels);

    // Assert
    assertEquals(-1, cfg.getPort(), "default listenPort should be -1 (random)");
    FreenetInetAddress bind = cfg.getBindTo();
    assertNotNull(bind, "bindTo should be initialized");
    assertEquals("0.0.0.0", bind.toString(), "bindTo default should be 0.0.0.0");
    assertEquals(0, cfg.getDropProbability(), "dropProbability default");
    assertFalse(cfg.oneConnectionPerAddress(), "oneConnectionPerIP default (darknet)");
    assertTrue(cfg.alwaysAllowLocalAddresses(), "alwaysAllowLocalAddresses default");
    assertTrue(cfg.alwaysHandshakeAggressively(), "assumeNATed default");
    assertTrue(
        cfg.includeLocalAddressesInNoderefs(), "includeLocalAddressesInNoderefs default (darknet)");
    assertTrue(cfg.paddDataPackets(), "paddDataPackets default");

    // For darknet, no listener is registered
    verifyNoMoreInteractions(securityLevels);
  }

  @Test
  void constructor_opennet_registersThreatListener_andTogglesOneConnection() throws Exception {
    // Arrange
    TestConfigHarness h = new TestConfigHarness();
    AtomicReference<SecurityLevelListener<SecurityLevels.NETWORK_THREAT_LEVEL>> listenerRef =
        new AtomicReference<>();
    org.mockito.Mockito.doAnswer(
            inv -> {
              SecurityLevelListener<SecurityLevels.NETWORK_THREAT_LEVEL> l = inv.getArgument(0);
              listenerRef.set(l);
              return null;
            })
        .when(securityLevels)
        .addNetworkThreatLevelListener(org.mockito.ArgumentMatchers.any());

    // Act
    NodeCryptoConfig cfg = new NodeCryptoConfig(h.sub, 0, true, securityLevels);

    // Assert initial default for opennet
    assertTrue(cfg.oneConnectionPerAddress(), "opennet defaults to oneConnectionPerIP=true");

    // Verify registration and drive the captured listener
    verify(securityLevels, times(1))
        .addNetworkThreatLevelListener(org.mockito.ArgumentMatchers.any());
    SecurityLevelListener<SecurityLevels.NETWORK_THREAT_LEVEL> listener = listenerRef.get();

    // When entering LOW → disable oneConnectionPerAddress
    listener.onChange(
        SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL, SecurityLevels.NETWORK_THREAT_LEVEL.LOW);
    assertFalse(cfg.oneConnectionPerAddress());

    // When leaving LOW → enable oneConnectionPerAddress
    listener.onChange(
        SecurityLevels.NETWORK_THREAT_LEVEL.LOW, SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL);
    assertTrue(cfg.oneConnectionPerAddress());
  }

  @Test
  void listenPort_optionSet_whenCryptoNull_updatesPort() throws Exception {
    // Arrange
    TestConfigHarness h = new TestConfigHarness();
    NodeCryptoConfig cfg = new NodeCryptoConfig(h.sub, 0, false, securityLevels);
    Option<?> opt = h.sub.getOption("listenPort");

    // Act
    opt.setValue("12345");

    // Assert
    assertEquals(12345, cfg.getPort());
  }

  @Test
  void listenPort_optionSet_whenCryptoPresent_throwsAndKeepsOldPort() throws Exception {
    // Arrange
    TestConfigHarness h = new TestConfigHarness();
    NodeCryptoConfig cfg = new NodeCryptoConfig(h.sub, 0, false, securityLevels);
    Option<?> opt = h.sub.getOption("listenPort");
    opt.setValue("12345");
    NodeCrypto crypto = mock(NodeCrypto.class);
    cfg.starting(crypto); // set non-null crypto

    // Act + Assert
    InvalidConfigValueException ex =
        assertThrows(InvalidConfigValueException.class, () -> opt.setValue("23456"));
    assertTrue(ex.getMessage().contains("Switching listenPort on the fly not yet supported"));
    assertEquals(12345, cfg.getPort(), "port should remain unchanged after failed update");
  }

  @Test
  void dropProbability_setNegative_throws_andDoesNotChangeValue() throws Exception {
    // Arrange
    TestConfigHarness h = new TestConfigHarness();
    NodeCryptoConfig cfg = new NodeCryptoConfig(h.sub, 0, false, securityLevels);
    Option<?> opt = h.sub.getOption("testingDropPacketsEvery");

    // Act + Assert
    InvalidConfigValueException ex =
        assertThrows(InvalidConfigValueException.class, () -> opt.setValue("-1"));
    assertTrue(ex.getMessage().contains("must not be negative"));
    assertEquals(0, cfg.getDropProbability());
  }

  @Test
  void dropProbability_setPositive_invokesCryptoCallback_whenPresent() throws Exception {
    // Arrange
    TestConfigHarness h = new TestConfigHarness();
    NodeCryptoConfig cfg = new NodeCryptoConfig(h.sub, 0, false, securityLevels);
    NodeCrypto crypto = mock(NodeCrypto.class);
    cfg.starting(crypto);
    Option<?> opt = h.sub.getOption("testingDropPacketsEvery");

    // Act
    opt.setValue("7");

    // Assert
    assertEquals(7, cfg.getDropProbability());
    verify(crypto, times(1)).onSetDropProbability(7);
  }

  @Test
  void bindTo_default_isValidInetAddressString() throws Exception {
    // Arrange
    TestConfigHarness h = new TestConfigHarness();

    // Act
    NodeCryptoConfig cfg = new NodeCryptoConfig(h.sub, 0, false, securityLevels);

    // Assert
    FreenetInetAddress addr = cfg.getBindTo();
    assertNotNull(addr);
    assertEquals("0.0.0.0", addr.toString());
  }

  @Test
  void nodeBindtoCallback_setDifferent_throwsInvalidConfigValueException() throws Exception {
    // Arrange
    TestConfigHarness h = new TestConfigHarness();
    NodeCryptoConfig cfg = new NodeCryptoConfig(h.sub, 0, false, securityLevels);
    NodeCryptoConfig.NodeBindtoCallback cb = cfg.new NodeBindtoCallback();

    // Act + Assert
    // Equal value: noop
    cb.set("0.0.0.0");
    // Different value: should throw
    assertThrows(InvalidConfigValueException.class, () -> cb.set("1.2.3.4"));
  }

  @Test
  void booleanOptions_toggleViaSubConfig_callbacksReflectInGetters() throws Exception {
    // Arrange
    TestConfigHarness h = new TestConfigHarness();
    NodeCryptoConfig cfg = new NodeCryptoConfig(h.sub, 0, true, securityLevels);

    // oneConnectionPerIP: default true for opennet → set to false
    h.sub.getOption("oneConnectionPerIP").setValue("false");
    assertFalse(cfg.oneConnectionPerAddress());

    // alwaysAllowLocalAddresses: default false for opennet → set to true
    h.sub.getOption("alwaysAllowLocalAddresses").setValue("true");
    assertTrue(cfg.alwaysAllowLocalAddresses());

    // assumeNATed: default true → set to false
    h.sub.getOption("assumeNATed").setValue("false");
    assertFalse(cfg.alwaysHandshakeAggressively());

    // includeLocalAddressesInNoderefs: default false for opennet → set to true
    h.sub.getOption("includeLocalAddressesInNoderefs").setValue("true");
    assertTrue(cfg.includeLocalAddressesInNoderefs());

    // paddDataPackets: default true → set to false
    h.sub.getOption("paddDataPackets").setValue("false");
    assertFalse(cfg.paddDataPackets());
  }
}
