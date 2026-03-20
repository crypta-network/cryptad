package network.crypta.node.runtime;

import java.io.File;
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
import network.crypta.node.MasterKeysFileSizeException;
import network.crypta.node.MasterKeysWrongPasswordException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeIPDetector;
import network.crypta.node.SecurityLevels;
import network.crypta.node.subsystem.NodeServicesSubsystem;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.runtime.spi.FirstTimeWizardCurrentBandwidthLimits;
import network.crypta.runtime.spi.FirstTimeWizardSnapshot;
import network.crypta.runtime.spi.FirstTimeWizardSubmission;
import network.crypta.runtime.spi.MasterPasswordMutationStatus;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.support.Fields;
import network.crypta.support.io.DatastoreUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static java.util.concurrent.TimeUnit.SECONDS;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
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

  @TempDir File tempDir;

  @Test
  void snapshot_whenDaemonStateAvailable_returnsDetachedDefaultsAndSuggestions() {
    Option<Long> storeSize = mockLongOption();
    Option<Long> clientCache = mockLongOption();
    Option<Long> slashdotCache = mockLongOption();
    Option<?> outputBandwidthLimit = mockOption();
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
    when(networkSubsystem.inputBandwidthLimit()).thenReturn(2048);
    when(networkSubsystem.outputBandwidthLimit()).thenReturn(1024);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    doReturn(outputBandwidthLimit).when(nodeSubConfig).getOption("outputBandwidthLimit");
    when(outputBandwidthLimit.isDefault()).thenReturn(false);
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
      datastore
          .when(() -> DatastoreUtil.maxDatastoreSize(node))
          .thenReturn(8L * DatastoreUtil.ONE_GIB);
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
      assertEquals(8L * DatastoreUtil.ONE_GIB, snapshot.legacyMaxStorageLimitBytes());
      assertEquals(Node.getMinimumBandwidth() / 1024L, snapshot.minBandwidthKiB());
      assertEquals(SECONDS.toNanos(1) / 1024L, snapshot.maxUploadLimitKiB());
      assertEquals(
          String.format(
              Locale.ENGLISH,
              "%.2f",
              BandwidthLimit.minimumMonthlyLimitGiB(Node.getMinimumBandwidth())),
          snapshot.minBandwidthMonthlyLimitGiB());
      assertEquals("1024", snapshot.detectedDownloadLimitKiB());
      assertEquals("512", snapshot.detectedUploadLimitKiB());
      FirstTimeWizardCurrentBandwidthLimits currentBandwidthLimits =
          snapshot.currentBandwidthLimits();
      assertNotNull(currentBandwidthLimits);
      assertEquals(2048L, currentBandwidthLimits.downloadBytes());
      assertEquals(1024L, currentBandwidthLimits.uploadBytes());
      assertEquals(-1L, snapshot.autodetectedStorageLimitBytes());
    }
  }

  @Test
  void snapshot_whenAutodetectAndDetectionUnavailable_returnsFallbackAndEmptySuggestions() {
    Option<Long> storeSize = mockLongOption();
    Option<?> outputBandwidthLimit = mockOption();
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);

    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    doReturn(outputBandwidthLimit).when(nodeSubConfig).getOption("outputBandwidthLimit");
    when(outputBandwidthLimit.isDefault()).thenReturn(true);

    try (MockedStatic<Config> configStatic = mockStatic(Config.class);
        MockedStatic<DatastoreUtil> datastore = mockStatic(DatastoreUtil.class);
        MockedStatic<BandwidthManipulator> bandwidth = mockStatic(BandwidthManipulator.class)) {
      configStatic.when(() -> Config.longOption(nodeSubConfig, "storeSize")).thenReturn(storeSize);
      when(storeSize.isDefault()).thenReturn(true);
      datastore.when(() -> DatastoreUtil.autodetectDatastoreSize(core, config)).thenReturn(0L);
      datastore.when(DatastoreUtil::maxDatastoreSize).thenReturn(10L * DatastoreUtil.ONE_GIB);
      datastore
          .when(() -> DatastoreUtil.maxDatastoreSize(node))
          .thenReturn(9L * DatastoreUtil.ONE_GIB);
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
      assertEquals(9L * DatastoreUtil.ONE_GIB, snapshot.legacyMaxStorageLimitBytes());
      assertNull(snapshot.currentBandwidthLimits());
      assertEquals(-1L, snapshot.autodetectedStorageLimitBytes());
    }
  }

  @Test
  void snapshot_whenIpDetectorNotInitialized_returnsStorageSuggestionAndEmptyBandwidthHints() {
    Option<Long> storeSize = mockLongOption();
    Option<?> outputBandwidthLimit = mockOption();
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    network.crypta.node.subsystem.NodeNetworkSubsystem networkSubsystem =
        mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    long autodetectedStorageLimitBytes = 3L * DatastoreUtil.ONE_GIB;

    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    when(node.network()).thenReturn(networkSubsystem);
    when(networkSubsystem.ipDetector()).thenReturn(null);
    doReturn(outputBandwidthLimit).when(nodeSubConfig).getOption("outputBandwidthLimit");
    when(outputBandwidthLimit.isDefault()).thenReturn(true);

    try (MockedStatic<Config> configStatic = mockStatic(Config.class);
        MockedStatic<DatastoreUtil> datastore = mockStatic(DatastoreUtil.class)) {
      configStatic.when(() -> Config.longOption(nodeSubConfig, "storeSize")).thenReturn(storeSize);
      when(storeSize.isDefault()).thenReturn(true);
      datastore
          .when(() -> DatastoreUtil.autodetectDatastoreSize(core, config))
          .thenReturn(autodetectedStorageLimitBytes);
      datastore.when(DatastoreUtil::maxDatastoreSize).thenReturn(10L * DatastoreUtil.ONE_GIB);
      datastore
          .when(() -> DatastoreUtil.maxDatastoreSize(node))
          .thenReturn(6L * DatastoreUtil.ONE_GIB);

      LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

      FirstTimeWizardSnapshot snapshot = port.snapshot();

      assertEquals("3.00", snapshot.initialStorageLimitGiB());
      assertEquals("", snapshot.detectedDownloadLimitKiB());
      assertEquals("", snapshot.detectedUploadLimitKiB());
      assertEquals(6L * DatastoreUtil.ONE_GIB, snapshot.legacyMaxStorageLimitBytes());
      assertNull(snapshot.currentBandwidthLimits());
      assertEquals(autodetectedStorageLimitBytes, snapshot.autodetectedStorageLimitBytes());
    }
  }

  @Test
  void snapshot_whenStorageCapNeedsRounding_preservesExactStorageBytes() {
    Option<Long> storeSize = mockLongOption();
    Option<?> outputBandwidthLimit = mockOption();
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    long roundedUpMaxStorageLimitBytes = Fields.parseLong("1.235GiB");

    when(node.getConfig()).thenReturn(config);
    when(config.get("node")).thenReturn(nodeSubConfig);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    doReturn(outputBandwidthLimit).when(nodeSubConfig).getOption("outputBandwidthLimit");
    when(outputBandwidthLimit.isDefault()).thenReturn(true);

    try (MockedStatic<Config> configStatic = mockStatic(Config.class);
        MockedStatic<DatastoreUtil> datastore = mockStatic(DatastoreUtil.class);
        MockedStatic<BandwidthManipulator> bandwidth = mockStatic(BandwidthManipulator.class)) {
      configStatic.when(() -> Config.longOption(nodeSubConfig, "storeSize")).thenReturn(storeSize);
      when(storeSize.isDefault()).thenReturn(true);
      datastore.when(() -> DatastoreUtil.autodetectDatastoreSize(core, config)).thenReturn(0L);
      datastore.when(DatastoreUtil::maxDatastoreSize).thenReturn(roundedUpMaxStorageLimitBytes);
      datastore
          .when(() -> DatastoreUtil.maxDatastoreSize(node))
          .thenReturn(5L * DatastoreUtil.ONE_GIB);
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
      assertEquals(5L * DatastoreUtil.ONE_GIB, snapshot.legacyMaxStorageLimitBytes());
      assertNull(snapshot.currentBandwidthLimits());
    }
  }

  @Test
  void isOpennetEnabled_whenRuntimeReportsEnabled_returnsTrue() {
    network.crypta.node.subsystem.NodeNetworkSubsystem networkSubsystem =
        mock(network.crypta.node.subsystem.NodeNetworkSubsystem.class);
    when(node.network()).thenReturn(networkSubsystem);
    when(networkSubsystem.isOpennetEnabled()).thenReturn(true);

    LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

    assertTrue(port.isOpennetEnabled());
  }

  @Test
  void securitySnapshot_whenDaemonStateAvailable_returnsDetachedSecurityState() throws Exception {
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    File masterKeysFile = new File(tempDir, "master.keys");
    assertTrue(masterKeysFile.createNewFile());

    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getNetworkThreatLevel())
        .thenReturn(SecurityLevels.NETWORK_THREAT_LEVEL.HIGH);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.MAXIMUM);
    when(node.storage()).thenReturn(storage);
    when(storage.getMasterKeysFile()).thenReturn(masterKeysFile);
    when(node.hasDatabase()).thenReturn(true);

    LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

    SecurityLevelsSnapshot snapshot = port.securitySnapshot();

    assertEquals(SecurityNetworkThreatLevel.HIGH, snapshot.networkThreatLevel());
    assertEquals(SecurityPhysicalThreatLevel.MAXIMUM, snapshot.physicalThreatLevel());
    assertTrue(snapshot.hasDatabase());
    assertTrue(snapshot.masterPasswordFileExists());
    assertEquals(masterKeysFile.getPath(), snapshot.masterPasswordFilePath());
  }

  @Test
  void setNetworkThreatLevel_whenCalled_updatesSecurityLevelsAndPersistsConfig() {
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);

    LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

    port.setNetworkThreatLevel(SecurityNetworkThreatLevel.LOW);

    verify(securityLevels).setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.LOW);
    verify(core).storeConfig();
  }

  @Test
  void setPhysicalThreatLevel_whenCalled_updatesSecurityLevelsPersistsAndInitializesDatabase() {
    NodeServicesSubsystem services = mock(NodeServicesSubsystem.class);
    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(node.storage()).thenReturn(storage);

    LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

    port.setPhysicalThreatLevel(SecurityPhysicalThreatLevel.MAXIMUM);

    verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.MAXIMUM);
    verify(core).storeConfig();
    verify(storage).lateSetupDatabase(null);
  }

  @Test
  void changeMasterPassword_whenSuccessful_usesFirstTimeWizardStoragePath() throws Exception {
    when(node.storage()).thenReturn(storage);

    LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

    MasterPasswordMutationStatus status = port.changeMasterPassword("old", "new");

    assertEquals(MasterPasswordMutationStatus.SUCCESS, status);
    verify(storage).changeMasterPassword("old", "new", true);
  }

  @Test
  void changeMasterPassword_whenWrongPassword_returnsWrongPassword() throws Exception {
    when(node.storage()).thenReturn(storage);
    doThrow(new MasterKeysWrongPasswordException())
        .when(storage)
        .changeMasterPassword("old", "new", true);

    LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

    MasterPasswordMutationStatus status = port.changeMasterPassword("old", "new");

    assertEquals(MasterPasswordMutationStatus.WRONG_PASSWORD, status);
  }

  @Test
  void setMasterPassword_whenCorruptedFile_returnsCorruptedFile() throws Exception {
    when(node.storage()).thenReturn(storage);
    doThrow(new MasterKeysFileSizeException(false)).when(storage).setMasterPassword("secret", true);

    LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

    MasterPasswordMutationStatus status = port.setMasterPassword("secret");

    assertEquals(MasterPasswordMutationStatus.CORRUPTED_FILE, status);
  }

  @Test
  void deleteMasterPasswordFile_whenCalled_delegatesToStorage() throws Exception {
    when(node.storage()).thenReturn(storage);

    LegacyFirstTimeWizardPort port = new LegacyFirstTimeWizardPort(node, core);

    port.deleteMasterPasswordFile();

    verify(storage).killMasterKeysFile();
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

      BandwidthLimit bandwidth =
          BandwidthLimit.fromMonthlyBudget(Fields.parseLong("500GiB"), Node.getMinimumBandwidth());
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

  private static Option<?> mockOption() {
    return mock(Option.class);
  }
}
