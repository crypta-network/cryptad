package network.crypta.node.subsystem;

import java.io.File;
import java.lang.reflect.Field;
import java.security.SecureRandom;
import network.crypta.clients.http.PasswordFormOptions;
import network.crypta.clients.http.SecurityLevelsToadlet;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.keys.CHKBlock;
import network.crypta.node.DatabaseKey;
import network.crypta.node.MasterKeys;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeInitException;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.SecurityLevels;
import network.crypta.runtime.alerts.UserAlert;
import network.crypta.runtime.alerts.UserAlertManager;
import network.crypta.runtime.bootstrap.NodeBootstrap;
import network.crypta.runtime.endpoints.ClientEndpoints;
import network.crypta.runtime.http.HttpShellContainer;
import network.crypta.runtime.services.NodeServicesSubsystem;
import network.crypta.store.CHKStore;
import network.crypta.store.FreenetStore;
import network.crypta.store.saltedhash.SaltedHashFreenetStore;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class NodeStorageSubsystemTest {
  @Mock private Node node;
  @Mock private NodeServicesSubsystem services;
  @Mock private NodeClientCore clientCore;
  @Mock private UserAlertManager alerts;

  private NodeStorageSubsystem subsystem;

  @BeforeEach
  void setUp() {
    subsystem = new NodeStorageSubsystem(node);
  }

  @Test
  void constructor_whenCreated_initializesPubKey() {
    assertNotNull(subsystem.getPubKey());
  }

  @Test
  void setStoreUseSlotFilters_whenCalled_updatesValueAndThrowsRestart() {
    NodeNeedRestartException ex =
        assertThrows(NodeNeedRestartException.class, () -> subsystem.setStoreUseSlotFilters(true));

    assertTrue(subsystem.isStoreUseSlotFilters());
    assertTrue(ex.getMessage().contains("storeUseSlotFilters"));
  }

  @Test
  void initializeStoreUseSlotFilters_whenCalled_setsValue() {
    subsystem.initializeStoreUseSlotFilters(true);

    assertTrue(subsystem.isStoreUseSlotFilters());
  }

  @Test
  void setStoreSaltHashSlotFilterPersistenceTime_whenTooLow_throwsInvalidConfigValueException() {
    assertThrows(
        InvalidConfigValueException.class,
        () -> subsystem.setStoreSaltHashSlotFilterPersistenceTime(-2));
  }

  @ParameterizedTest
  @CsvSource({"-1", "0", "5"})
  void setStoreSaltHashSlotFilterPersistenceTime_whenValid_setsValue(int value) throws Exception {
    subsystem.setStoreSaltHashSlotFilterPersistenceTime(value);

    assertEquals(value, subsystem.getStoreSaltHashSlotFilterPersistenceTime());
  }

  @Test
  void initializeStoreSaltHashSlotFilterPersistenceTime_whenCalled_setsValue() {
    subsystem.initializeStoreSaltHashSlotFilterPersistenceTime(12);

    assertEquals(12, subsystem.getStoreSaltHashSlotFilterPersistenceTime());
  }

  @Test
  void initializeDatastoreSize_whenTooSmallAndNotSpecialType_throwsNodeInitException() {
    subsystem.setStoreType("custom");

    NodeInitException ex =
        assertThrows(
            NodeInitException.class,
            () -> subsystem.initializeDatastoreSize(NodeStorageSubsystem.MIN_STORE_SIZE - 1));

    assertEquals(NodeInitException.EXIT_INVALID_STORE_SIZE, ex.exitCode);
  }

  @Test
  void initializeDatastoreSize_whenRamTypeAndSmall_setsSizeAndKeys() throws Exception {
    subsystem.setStoreType("ram");

    subsystem.initializeDatastoreSize(1L);

    assertEquals(1L, subsystem.getDatastoreSize());
    assertEquals(0L, subsystem.getMaxTotalKeys());
  }

  @Test
  void initializeClientCacheSize_whenNegative_throwsNodeInitException() {
    NodeInitException ex =
        assertThrows(NodeInitException.class, () -> subsystem.initializeClientCacheSize(-1));

    assertEquals(NodeInitException.EXIT_INVALID_STORE_SIZE, ex.exitCode);
  }

  @Test
  void initializeClientCacheSize_whenZero_setsSize() throws Exception {
    subsystem.initializeClientCacheSize(0);

    assertEquals(0L, subsystem.getClientCacheSize());
  }

  @Test
  void setCachingFreenetStoreMaxSize_whenNegative_throwsInvalidConfigValueException() {
    assertThrows(
        InvalidConfigValueException.class, () -> subsystem.setCachingFreenetStoreMaxSize(-1));
  }

  @Test
  void setCachingFreenetStoreMaxSize_whenValid_setsValueAndThrowsRestart() {
    assertThrows(NodeNeedRestartException.class, () -> subsystem.setCachingFreenetStoreMaxSize(42));

    assertEquals(42L, subsystem.getCachingFreenetStoreMaxSize());
  }

  @Test
  void initializeCachingFreenetStoreMaxSize_whenNegative_throwsNodeInitException() {
    NodeInitException ex =
        assertThrows(
            NodeInitException.class, () -> subsystem.initializeCachingFreenetStoreMaxSize(-1));

    assertEquals(NodeInitException.EXIT_BAD_CONFIG, ex.exitCode);
  }

  @Test
  void initializeCachingFreenetStoreMaxSize_whenValid_setsValue() throws Exception {
    subsystem.initializeCachingFreenetStoreMaxSize(512);

    assertEquals(512L, subsystem.getCachingFreenetStoreMaxSize());
  }

  @Test
  void setCachingFreenetStorePeriod_whenCalled_setsValueAndThrowsRestart() {
    assertThrows(NodeNeedRestartException.class, () -> subsystem.setCachingFreenetStorePeriod(10));

    assertEquals(10L, subsystem.getCachingFreenetStorePeriod());
  }

  @Test
  void initializeCachingFreenetStorePeriod_whenCalled_setsValue() {
    subsystem.initializeCachingFreenetStorePeriod(99L);

    assertEquals(99L, subsystem.getCachingFreenetStorePeriod());
  }

  @Test
  void setStoreDir_whenProvided_exposesProgramDirectoryAndDirFile() {
    ProgramDirectory programDirectory = org.mockito.Mockito.mock(ProgramDirectory.class);
    File dir = new File("/tmp/store");
    when(programDirectory.dir()).thenReturn(dir);
    subsystem.setStoreDir(programDirectory);

    assertSame(programDirectory, subsystem.getStoreProgramDir());
    assertSame(dir, subsystem.getStoreDir());
  }

  @Test
  void setClientCacheAwaitingPassword_whenCalled_setsFlagAndRegistersAlert() {
    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);

    subsystem.setClientCacheAwaitingPassword();

    assertTrue(subsystem.isClientCacheAwaitingPassword());
    verify(alerts).register(org.mockito.Mockito.any(UserAlert.class));
  }

  @Test
  void clearAwaitingPasswords_whenCalled_resetsFlags() {
    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(clientCore);
    when(clientCore.getAlerts()).thenReturn(alerts);
    subsystem.setDatabaseAwaitingPassword();
    subsystem.setClientCacheAwaitingPassword();

    subsystem.clearAwaitingPasswords();

    assertFalse(subsystem.isDatabaseAwaitingPassword());
    assertFalse(subsystem.isClientCacheAwaitingPassword());
  }

  @Test
  void masterPasswordUserAlert_getHTMLText_whenRendered_matchesLegacyPasswordForm()
      throws Exception {
    HttpShellContainer container = org.mockito.Mockito.mock(HttpShellContainer.class);
    when(container.addFormChild(any(HTMLNode.class), anyString(), anyString()))
        .thenAnswer(
            invocation -> {
              HTMLNode parent = invocation.getArgument(0);
              String target = invocation.getArgument(1);
              String id = invocation.getArgument(2);
              HTMLNode form = parent.addChild("form");
              form.addAttribute("target", target);
              form.addAttribute("id", id);
              return form;
            });
    when(node.services()).thenReturn(services);
    when(services.clientCore()).thenReturn(clientCore);
    when(clientCore.getEndpoints()).thenReturn(new ClientEndpoints(null, null, container));

    HTMLNode expectedContent = new HTMLNode("div");
    SecurityLevelsToadlet.generatePasswordFormPage(
        new PasswordFormOptions(false, false, false, false, null, null),
        container,
        expectedContent);

    HTMLNode renderedContent = getMasterPasswordUserAlert(subsystem).getHTMLText();

    assertEquals(expectedContent.generate(), renderedContent.generate());
  }

  @Test
  void setStorePreallocate_whenSaltHashBeforeStoresInitialized_doesNotThrow() {
    subsystem.setStoreType(Node.TYPE_SALT_HASH);

    assertDoesNotThrow(() -> subsystem.setStorePreallocate(true));
    assertTrue(subsystem.isStorePreallocate());
  }

  @Test
  void setStorePreallocate_whenStoreIsWrapped_appliesToUnderlyingSaltedHashStore()
      throws Exception {
    subsystem.setStoreType(Node.TYPE_SALT_HASH);

    CHKStore chkDatastore = new CHKStore();
    @SuppressWarnings("unchecked")
    FreenetStore<CHKBlock> wrapperStore = org.mockito.Mockito.mock(FreenetStore.class);
    @SuppressWarnings("unchecked")
    SaltedHashFreenetStore<CHKBlock> saltedHashStore =
        org.mockito.Mockito.mock(SaltedHashFreenetStore.class);

    when(wrapperStore.getUnderlyingStore()).thenReturn(saltedHashStore);
    chkDatastore.setStore(wrapperStore);

    setChkDatastore(subsystem, chkDatastore);

    subsystem.setStorePreallocate(true);

    verify(saltedHashStore).setPreallocate(true);
  }

  @Test
  void changeMasterPassword_whenKeysUnavailableAndMasterKeysFileExists_loadsKeysAndChangesPassword()
      throws Exception {
    File masterKeysFile = File.createTempFile("master-keys", ".tmp");
    masterKeysFile.deleteOnExit();
    subsystem.setMasterKeysFile(masterKeysFile);

    MasterKeys loadedKeys = org.mockito.Mockito.mock(MasterKeys.class);
    DatabaseKey loadedDatabaseKey = org.mockito.Mockito.mock(DatabaseKey.class);
    SecurityLevels securityLevels = org.mockito.Mockito.mock(SecurityLevels.class);
    NodeBootstrap bootstrap = org.mockito.Mockito.mock(NodeBootstrap.class);
    SecureRandom secureRandom = new SecureRandom();

    when(node.services()).thenReturn(services);
    when(services.securityLevels()).thenReturn(securityLevels);
    when(services.clientCore()).thenReturn(clientCore);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    when(node.bootstrap()).thenReturn(bootstrap);
    when(bootstrap.secureRandom()).thenReturn(secureRandom);
    when(loadedKeys.createDatabaseKey()).thenReturn(loadedDatabaseKey);

    try (MockedStatic<MasterKeys> masterKeysStatic = mockStatic(MasterKeys.class)) {
      masterKeysStatic
          .when(() -> MasterKeys.read(masterKeysFile, secureRandom, "old-password"))
          .thenReturn(loadedKeys);

      subsystem.changeMasterPassword("old-password", "new-password", true);

      masterKeysStatic.verify(() -> MasterKeys.read(masterKeysFile, secureRandom, "old-password"));
    }

    verify(loadedKeys).changePassword(masterKeysFile, "new-password", secureRandom);
    assertSame(loadedKeys, subsystem.getKeys());
    assertSame(loadedDatabaseKey, subsystem.getDatabaseKey());
  }

  private static void setChkDatastore(NodeStorageSubsystem target, CHKStore value)
      throws ReflectiveOperationException {
    Field field = target.getClass().getDeclaredField("chkDatastore");
    field.setAccessible(true);
    field.set(target, value);
  }

  private static UserAlert getMasterPasswordUserAlert(NodeStorageSubsystem target)
      throws ReflectiveOperationException {
    Field field = target.getClass().getDeclaredField("masterPasswordUserAlert");
    field.setAccessible(true);
    return (UserAlert) field.get(target);
  }
}
