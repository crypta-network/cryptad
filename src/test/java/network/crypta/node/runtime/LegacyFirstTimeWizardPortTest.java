package network.crypta.node.runtime;

import java.util.Locale;
import network.crypta.clients.http.wizardsteps.BandwidthDetectionUnavailableException;
import network.crypta.clients.http.wizardsteps.BandwidthLimit;
import network.crypta.clients.http.wizardsteps.BandwidthManipulator;
import network.crypta.clients.http.wizardsteps.DatastoreSize;
import network.crypta.compat.BandwidthIndicator;
import network.crypta.config.Config;
import network.crypta.config.Option;
import network.crypta.config.PersistentConfig;
import network.crypta.config.SubConfig;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeIPDetector;
import network.crypta.node.SecurityLevels;
import network.crypta.node.subsystem.NodeServicesSubsystem;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardSubmission;
import network.crypta.support.Fields;
import network.crypta.support.io.DatastoreUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class LegacyFirstTimeWizardPortTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeClientCore core;
  @Mock private PersistentConfig config;
  @Mock private SubConfig nodeSubConfig;
  @Mock private SubConfig fproxySubConfig;
  @Mock private SecurityLevels securityLevels;
  @Mock private NodeStorageSubsystem storage;

  @Test
  void snapshot_whenDaemonStateAvailable_returnsDetachedDefaultsAndSuggestions() {
    Option<Long> storeSize = mockLongOption();
    Option<Long> clientCache = mockLongOption();
    Option<Long> slashdotCache = mockLongOption();
    BandwidthIndicator bandwidthIndicator = mock(BandwidthIndicator.class);
    NodeIPDetector ipDetector = mock(NodeIPDetector.class);
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    network.crypta.node.subsystem.NodeNetworkSubsystem networkSubsystem =
        mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);

    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(node.network()).thenReturn(networkSubsystem);
    when(networkSubsystem.ipDetector()).thenReturn(ipDetector);
    when(ipDetector.getBandwidthIndicator()).thenReturn(bandwidthIndicator);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    when(storeSize.isDefault()).thenReturn(false);
    when(storeSize.getValue()).thenReturn(2L * DatastoreUtil.ONE_GIB);
    when(clientCache.getValue()).thenReturn(0L);
    when(slashdotCache.getValue()).thenReturn(0L);

    try (MockedStatic<Config> configStatic = mockStatic(Config.class);
        MockedStatic<DatastoreUtil> datastore = mockStatic(DatastoreUtil.class);
        MockedStatic<BandwidthManipulator> bandwidth = mockStatic(BandwidthManipulator.class)) {
      configStatic.when(() -> Config.longOption(nodeSubConfig, "storeSize")).thenReturn(storeSize);
      configStatic
          .when(() -> Config.longOption(nodeSubConfig, "clientCacheSize"))
          .thenReturn(clientCache);
      configStatic
          .when(() -> Config.longOption(nodeSubConfig, "slashdotCacheSize"))
          .thenReturn(slashdotCache);
      datastore.when(DatastoreUtil::maxDatastoreSize).thenReturn(10L * DatastoreUtil.ONE_GIB);
      bandwidth
          .when(() -> BandwidthManipulator.detectBandwidthLimits(bandwidthIndicator))
          .thenReturn(new BandwidthLimit(2097152L, 1048576L, "desc", false));

      LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

      FirstTimeWizardSnapshot snapshot = port.snapshot();

      assertTrue(snapshot.passwordAlreadySet());
      assertEquals("2.00", snapshot.initialStorageLimitGiB());
      assertEquals(
          String.format(
              Locale.ENGLISH,
              "%.2f",
              (float) (NodeStorageSubsystem.MIN_STORE_SIZE * 5 / 4) / DatastoreUtil.ONE_GIB),
          snapshot.minStorageLimitGiB());
      assertEquals(NodeStorageSubsystem.MIN_STORE_SIZE * 5 / 4, snapshot.minStorageLimitBytes());
      assertEquals("10.00", snapshot.maxStorageLimitGiB());
      assertEquals(10L * DatastoreUtil.ONE_GIB, snapshot.maxStorageLimitBytes());
      assertEquals(Node.getMinimumBandwidth() / 1024L, snapshot.minBandwidthKiB());
      assertEquals(SECONDS.toNanos(1) / 1024L, snapshot.maxUploadLimitKiB());
      assertEquals(
          String.format(Locale.ENGLISH, "%.2f", BandwidthLimit.MIN_MONTHLY_LIMIT),
          snapshot.minBandwidthMonthlyLimitGiB());
      assertEquals("1024", snapshot.detectedDownloadLimitKiB());
      assertEquals("512", snapshot.detectedUploadLimitKiB());
    }
  }

  @Test
  void snapshot_whenAutodetectAndDetectionUnavailable_returnsFallbackAndEmptySuggestions() {
    Option<Long> storeSize = mockLongOption();
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);

    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);

    try (MockedStatic<Config> configStatic = mockStatic(Config.class);
        MockedStatic<DatastoreUtil> datastore = mockStatic(DatastoreUtil.class);
        MockedStatic<BandwidthManipulator> bandwidth = mockStatic(BandwidthManipulator.class)) {
      configStatic.when(() -> Config.longOption(nodeSubConfig, "storeSize")).thenReturn(storeSize);
      when(storeSize.isDefault()).thenReturn(true);
      datastore.when(() -> DatastoreUtil.autodetectDatastoreSize(core, config)).thenReturn(0L);
      datastore.when(DatastoreUtil::maxDatastoreSize).thenReturn(10L * DatastoreUtil.ONE_GIB);
      bandwidth
          .when(
              () ->
                  BandwidthManipulator.detectBandwidthLimits(
                      node.network().ipDetector().getBandwidthIndicator()))
          .thenThrow(new BandwidthDetectionUnavailableException("none"));

      LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

      FirstTimeWizardSnapshot snapshot = port.snapshot();

      assertFalse(snapshot.passwordAlreadySet());
      assertEquals("100.00", snapshot.initialStorageLimitGiB());
      assertEquals("", snapshot.detectedDownloadLimitKiB());
      assertEquals("", snapshot.detectedUploadLimitKiB());
    }
  }

  @Test
  void snapshot_whenStorageCapNeedsRounding_preservesExactStorageBytes() {
    Option<Long> storeSize = mockLongOption();
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    long roundedUpMaxStorageLimitBytes = Fields.parseLong("1.235GiB");

    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);

    try (MockedStatic<Config> configStatic = mockStatic(Config.class);
        MockedStatic<DatastoreUtil> datastore = mockStatic(DatastoreUtil.class);
        MockedStatic<BandwidthManipulator> bandwidth = mockStatic(BandwidthManipulator.class)) {
      configStatic.when(() -> Config.longOption(nodeSubConfig, "storeSize")).thenReturn(storeSize);
      when(storeSize.isDefault()).thenReturn(true);
      datastore.when(() -> DatastoreUtil.autodetectDatastoreSize(core, config)).thenReturn(0L);
      datastore.when(DatastoreUtil::maxDatastoreSize).thenReturn(roundedUpMaxStorageLimitBytes);
      bandwidth
          .when(
              () ->
                  BandwidthManipulator.detectBandwidthLimits(
                      node.network().ipDetector().getBandwidthIndicator()))
          .thenThrow(new BandwidthDetectionUnavailableException("none"));

      LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

      FirstTimeWizardSnapshot snapshot = port.snapshot();

      assertEquals("1.24", snapshot.maxStorageLimitGiB());
      assertEquals(roundedUpMaxStorageLimitBytes, snapshot.maxStorageLimitBytes());
    }
  }

  @Test
  void applySubmission_whenDirectLimitsWithoutPassword_writesDaemonStateAndPersists()
      throws Exception {
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(config.get("fproxy")).thenReturn(fproxySubConfig);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(node.storage()).thenReturn(storage);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);

    try (MockedStatic<DatastoreSize> datastoreSize = mockStatic(DatastoreSize.class)) {
      LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

      port.applySubmission(
          new FirstTimeWizardSubmission(true, false, false, "20000", "10000", "", "2", false, ""));

      verify(securityLevels).setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.HIGH);
      verify(nodeSubConfig).set("inputBandwidthLimit", "20000KiB");
      verify(nodeSubConfig).set("outputBandwidthLimit", "10000KiB");
      datastoreSize.verify(() -> DatastoreSize.setDatastoreSize("2GiB", config), times(1));
      verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
      verify(storage).changeMasterPassword("", "", true);
      verify(fproxySubConfig).set("hasCompletedWizard", true);
      verify(core).storeConfig();
    }
  }

  @Test
  void applySubmission_whenMonthlyLimitAndPasswordRequested_derivesBandwidthAndSetsPassword()
      throws Exception {
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(config.get("fproxy")).thenReturn(fproxySubConfig);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(node.storage()).thenReturn(storage);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);

    try (MockedStatic<DatastoreSize> datastoreSize = mockStatic(DatastoreSize.class)) {
      LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

      port.applySubmission(
          new FirstTimeWizardSubmission(false, true, true, "", "", "500", "3", true, "secret"));

      BandwidthLimit bandwidth = new BandwidthLimit(Fields.parseLong("500GiB"));
      verify(securityLevels).setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL);
      verify(nodeSubConfig).set("inputBandwidthLimit", Long.toString(bandwidth.downBytes));
      verify(nodeSubConfig).set("outputBandwidthLimit", Long.toString(bandwidth.upBytes));
      datastoreSize.verify(() -> DatastoreSize.setDatastoreSize("3GiB", config), times(1));
      verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
      verify(storage).changeMasterPassword("", "secret", true);
      verify(fproxySubConfig).set("hasCompletedWizard", true);
      verify(core).storeConfig();
    }
  }

  @Test
  void applySubmission_whenMonthlyLimitCannotBeParsed_throwsAndDoesNotCompleteWizard()
      throws Exception {
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.getConfig()).thenReturn(config);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);

    try (MockedStatic<DatastoreSize> datastoreSize = mockStatic(DatastoreSize.class)) {
      LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);
      FirstTimeWizardSubmission invalidSubmission =
          new FirstTimeWizardSubmission(false, true, true, "", "", "1e8", "3", true, "secret");

      assertThrows(NumberFormatException.class, () -> port.applySubmission(invalidSubmission));

      verify(securityLevels).setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL);
      verify(fproxySubConfig, never()).set("hasCompletedWizard", true);
      verify(core, never()).storeConfig();
      verify(storage, never()).changeMasterPassword("", "secret", true);
      datastoreSize.verifyNoInteractions();
    }
  }

  @Test
  void applySubmission_whenDatastoreSizingFails_throwsAndDoesNotCompleteWizard() throws Exception {
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);

    try (MockedStatic<DatastoreSize> datastoreSize = mockStatic(DatastoreSize.class)) {
      datastoreSize
          .when(() -> DatastoreSize.setDatastoreSize("3GiB", config))
          .thenThrow(new IllegalArgumentException("too big"));
      LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);
      FirstTimeWizardSubmission invalidSubmission =
          new FirstTimeWizardSubmission(
              false, true, false, "20000", "10000", "", "3", true, "secret");

      assertThrows(IllegalArgumentException.class, () -> port.applySubmission(invalidSubmission));

      verify(securityLevels).setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL);
      verify(nodeSubConfig).set("inputBandwidthLimit", "20000KiB");
      verify(nodeSubConfig).set("outputBandwidthLimit", "10000KiB");
      verify(fproxySubConfig, never()).set("hasCompletedWizard", true);
      verify(core, never()).storeConfig();
      verify(storage, never()).changeMasterPassword("", "secret", true);
    }
  }

  @Test
  void applySubmission_whenPasswordAlreadySet_skipsPasswordMutation() throws Exception {
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(config.get("fproxy")).thenReturn(fproxySubConfig);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);

    try (MockedStatic<DatastoreSize> datastoreSize = mockStatic(DatastoreSize.class)) {
      LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

      port.applySubmission(
          new FirstTimeWizardSubmission(
              false, false, false, "20000", "10000", "", "2", true, "secret"));

      verify(nodeSubConfig).set("inputBandwidthLimit", "20000KiB");
      verify(nodeSubConfig).set("outputBandwidthLimit", "10000KiB");
      datastoreSize.verify(() -> DatastoreSize.setDatastoreSize("2GiB", config), times(1));
      verify(securityLevels, never()).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
      verify(node, never()).storage();
      verify(core).storeConfig();
    }
  }

  private static Option<Long> mockLongOption() {
    @SuppressWarnings("unchecked")
    Option<Long> option = (Option<Long>) mock(Option.class);
    return option;
  }
}
