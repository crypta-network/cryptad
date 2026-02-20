package network.crypta.node.subsystem;

import java.io.File;
import java.lang.reflect.Field;
import network.crypta.config.InvalidConfigValueException;
import network.crypta.config.NodeNeedRestartException;
import network.crypta.keys.CHKBlock;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.NodeInitException;
import network.crypta.node.ProgramDirectory;
import network.crypta.node.useralerts.UserAlert;
import network.crypta.node.useralerts.UserAlertManager;
import network.crypta.store.CHKStore;
import network.crypta.store.FreenetStore;
import network.crypta.store.saltedhash.SaltedHashFreenetStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

    setPrivateField(subsystem, "chkDatastore", chkDatastore);

    subsystem.setStorePreallocate(true);

    verify(saltedHashStore).setPreallocate(true);
  }

  private static void setPrivateField(Object target, String fieldName, Object value)
      throws ReflectiveOperationException {
    Field field = target.getClass().getDeclaredField(fieldName);
    field.setAccessible(true);
    field.set(target, value);
  }
}
