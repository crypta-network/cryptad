package network.crypta.clients.http.wizardsteps;

import java.io.File;
import java.io.IOException;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.clients.http.SecurityLevelsToadlet;
import network.crypta.node.MasterKeysFileSizeException;
import network.crypta.node.MasterKeysWrongPasswordException;
import network.crypta.node.Node;
import network.crypta.node.NodeClientCore;
import network.crypta.node.SecurityLevels;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
@ExtendWith(MockitoExtension.class)
class SecurityPhysicalTest {

  private static final String PHYSICAL_THREAT_LEVEL_PART = "security-levels.physicalThreatLevel";
  private static final String BACK_TO_MAIN_PART = "backToMain";
  private static final String MASTER_KEYS_FILENAME = "master.keys";
  private static final String NEW_SECRET = "newPass";
  private static final String OLD_SECRET = "oldPass";

  @Mock private NodeClientCore core;

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private NodeStorageSubsystem storage;
  @Mock private SecurityLevels securityLevels;
  @Mock private HTTPRequest request;

  @TempDir File tempDir;

  @Test
  void getCurrentLevel_whenCalled_returnsLevelFromNodeSecurityLevels() {
    when(core.getNode()).thenReturn(node);
    when(node.services().securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);

    SecurityPhysical subject = new SecurityPhysical(core);

    SecurityLevels.PHYSICAL_THREAT_LEVEL current = subject.getCurrentLevel();

    assertEquals(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL, current);
  }

  @Test
  void postStep_whenThreatLevelMissing_returnsPhysicalStepName() throws Exception {
    stubOldThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    stubPasswordParts("pw", "pw");
    when(request.getPartAsStringFailsafe(PHYSICAL_THREAT_LEVEL_PART, 128)).thenReturn("HIGH");
    when(request.isPartSet(PHYSICAL_THREAT_LEVEL_PART)).thenReturn(false);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name(), next);
  }

  @Test
  void postStep_whenBackToMainSet_returnsPhysicalStepName() throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL, SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    stubPasswordParts("pw", "pw");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(true);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name(), next);
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenThreatLevelUnparseable_returnsPhysicalStepName() throws Exception {
    stubOldThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    stubPasswordParts("pw", "pw");
    when(request.getPartAsStringFailsafe(PHYSICAL_THREAT_LEVEL_PART, 128))
        .thenReturn("NOT_A_LEVEL");

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name(), next);
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenUpgradeToHighWithBlankPassword_promptsSetBlank() throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL, SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    stubPasswordParts("", "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
            + "&error=pass&newThreatLevel=HIGH&type=SET_BLANK",
        next);
    verify(storage, never()).changeMasterPassword(anyString(), anyString(), anyBoolean());
    verify(storage, never()).setMasterPassword(anyString(), anyBoolean());
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenUpgradeToHighWithMismatchPassword_promptsSetNoMatch() throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL, SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    stubPasswordParts("pw1", "pw2");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
            + "&error=pass&newThreatLevel=HIGH&type=SET_NO_MATCH",
        next);
    verify(storage, never()).changeMasterPassword(anyString(), anyString(), anyBoolean());
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenUpgradeToHighFromNormal_changesFromBlankPasswordThenAdvances()
      throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL, SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    stubPasswordParts(NEW_SECRET, NEW_SECRET);
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(node.storage()).thenReturn(storage);
    doNothing().when(storage).changeMasterPassword("", NEW_SECRET, true);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);

    InOrder inOrder = inOrder(storage, securityLevels, core);
    inOrder.verify(storage).changeMasterPassword("", NEW_SECRET, true);
    inOrder.verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    inOrder.verify(core).storeConfig();
    inOrder.verify(storage).lateSetupDatabase(null);
    inOrder.verifyNoMoreInteractions();
  }

  @Test
  void postStep_whenUpgradeToHighFromMaximum_setsMasterPasswordThenAdvances() throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.MAXIMUM, SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    stubPasswordParts(NEW_SECRET, NEW_SECRET);
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(node.storage()).thenReturn(storage);
    doNothing().when(storage).setMasterPassword(NEW_SECRET, true);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    verify(storage).setMasterPassword(NEW_SECRET, true);
    verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    verify(core).storeConfig();
    verify(storage).lateSetupDatabase(null);
  }

  @Test
  void postStep_whenUpgradeToHighAlreadyHasPassword_ignoresAlreadySetExceptionAndAdvances()
      throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL, SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    stubPasswordParts(NEW_SECRET, NEW_SECRET);
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    doThrow(new Node.AlreadySetPasswordException())
        .when(storage)
        .changeMasterPassword("", NEW_SECRET, true);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
  }

  @Test
  void postStep_whenUpgradeToHighWrongPassword_throwsIOException() throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL, SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    stubPasswordParts(NEW_SECRET, NEW_SECRET);
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    doThrow(new MasterKeysWrongPasswordException())
        .when(storage)
        .changeMasterPassword("", NEW_SECRET, true);

    SecurityPhysical subject = new SecurityPhysical(core);

    IOException thrown = assertThrows(IOException.class, () -> subject.postStep(request));

    assertInstanceOf(MasterKeysWrongPasswordException.class, thrown.getCause());
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenUpgradeToHighMasterKeysFileSizeException_returnsCorruptError()
      throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL, SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);
    stubPasswordParts(NEW_SECRET, NEW_SECRET);
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    doThrow(new MasterKeysFileSizeException(false))
        .when(storage)
        .changeMasterPassword("", NEW_SECRET, true);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL + "&error=corrupt", next);
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenDowngradeFromHighBlankPassword_promptsDecryptBlank() throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH, SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    stubPasswordParts("", "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
            + "&error=pass&newThreatLevel=NORMAL&type=DECRYPT_BLANK",
        next);
    verify(storage, never()).changeMasterPassword(anyString(), anyString(), anyBoolean());
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenDowngradeFromHighWrongPassword_promptsDecryptWrong() throws Exception {
    File masterKeys = new File(tempDir, MASTER_KEYS_FILENAME);
    assertFalse(masterKeys.exists());
    assertTrue(masterKeys.createNewFile());

    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH, SecurityLevels.PHYSICAL_THREAT_LEVEL.LOW);
    stubPasswordParts(OLD_SECRET, "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(storage.getMasterKeysFile()).thenReturn(masterKeys);
    doThrow(new MasterKeysWrongPasswordException())
        .when(storage)
        .changeMasterPassword(OLD_SECRET, "", true);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
            + "&error=pass&newThreatLevel=LOW&type=DECRYPT_WRONG",
        next);
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenDowngradeFromHighFileSizeException_returnsCorruptError() throws Exception {
    File masterKeys = new File(tempDir, MASTER_KEYS_FILENAME);
    assertTrue(masterKeys.createNewFile());

    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH, SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    stubPasswordParts(OLD_SECRET, "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(storage.getMasterKeysFile()).thenReturn(masterKeys);
    doThrow(new MasterKeysFileSizeException(true))
        .when(storage)
        .changeMasterPassword(OLD_SECRET, "", true);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL + "&error=corrupt", next);
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenDowngradeFromHighIoFailureAndFileExists_throwsIOException() throws Exception {
    File masterKeys = new File(tempDir, MASTER_KEYS_FILENAME);
    assertTrue(masterKeys.createNewFile());

    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH, SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    stubPasswordParts(OLD_SECRET, "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(storage.getMasterKeysFile()).thenReturn(masterKeys);

    IOException lowLevel = new IOException("disk full");
    doThrow(lowLevel).when(storage).changeMasterPassword(OLD_SECRET, "", true);

    SecurityPhysical subject = new SecurityPhysical(core);

    IOException thrown = assertThrows(IOException.class, () -> subject.postStep(request));

    assertEquals("cantWriteNewMasterKeysFile", thrown.getMessage());
    assertSame(lowLevel, thrown.getCause());
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenDowngradeFromHighIoFailureButFileDeleted_advances() throws Exception {
    File masterKeys = new File(tempDir, MASTER_KEYS_FILENAME);
    assertTrue(masterKeys.createNewFile());

    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH, SecurityLevels.PHYSICAL_THREAT_LEVEL.LOW);
    stubPasswordParts(OLD_SECRET, "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(storage.getMasterKeysFile()).thenReturn(masterKeys);

    doAnswer(
            invocation -> {
              assertTrue(masterKeys.delete());
              throw new IOException("write failed");
            })
        .when(storage)
        .changeMasterPassword(OLD_SECRET, "", true);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.LOW);
  }

  @Test
  void postStep_whenDowngradeFromHighWithoutMasterKeysFile_advances() throws Exception {
    File masterKeys = new File(tempDir, MASTER_KEYS_FILENAME);
    assertFalse(masterKeys.exists());

    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH, SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    stubPasswordParts(OLD_SECRET, "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(storage.getMasterKeysFile()).thenReturn(masterKeys);

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    verify(storage, never()).changeMasterPassword(anyString(), anyString(), anyBoolean());
    verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
  }

  @Test
  void postStep_whenMaximumThreatLevelDeleteFails_returnsDeleteError() throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL, SecurityLevels.PHYSICAL_THREAT_LEVEL.MAXIMUM);
    stubPasswordParts("pw", "pw");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    doThrow(new IOException("no permission")).when(storage).killMasterKeysFile();

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
            + "&error=delete&newThreatLevel=MAXIMUM",
        next);
    verify(securityLevels, never()).setThreatLevel(any(SecurityLevels.PHYSICAL_THREAT_LEVEL.class));
  }

  @Test
  void postStep_whenMaximumThreatLevelDeleteSucceeds_advancesAndStoresThreatLevel()
      throws Exception {
    stubThreatLevels(
        SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL, SecurityLevels.PHYSICAL_THREAT_LEVEL.MAXIMUM);
    stubPasswordParts("pw", "pw");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    doNothing().when(storage).killMasterKeysFile();

    SecurityPhysical subject = new SecurityPhysical(core);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    verify(storage).killMasterKeysFile();
    verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.MAXIMUM);
    verify(core).storeConfig();
    verify(storage).lateSetupDatabase(null);
  }

  @Test
  void setThreatLevel_whenNullThreatLevel_throwsNullPointerException() {
    when(core.getNode()).thenReturn(node);
    when(node.services().securityLevels()).thenReturn(securityLevels);
    when(node.storage()).thenReturn(storage);
    doThrow(new NullPointerException())
        .when(securityLevels)
        .setThreatLevel((SecurityLevels.PHYSICAL_THREAT_LEVEL) null);
    SecurityPhysical subject = new SecurityPhysical(core);

    assertThrows(NullPointerException.class, () -> subject.setThreatLevel(null));

    verify(securityLevels).setThreatLevel((SecurityLevels.PHYSICAL_THREAT_LEVEL) null);
    verify(core, never()).storeConfig();
    verify(storage, never()).lateSetupDatabase(any());
  }

  @Test
  void setThreatLevel_whenValidThreatLevel_updatesSecurityLevelsStoresConfigAndLateInitsDatabase() {
    when(core.getNode()).thenReturn(node);
    when(node.services().securityLevels()).thenReturn(securityLevels);
    when(node.storage()).thenReturn(storage);

    SecurityPhysical subject = new SecurityPhysical(core);

    subject.setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);

    InOrder inOrder = inOrder(securityLevels, core, storage);
    inOrder.verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.NORMAL);
    inOrder.verify(core).storeConfig();
    inOrder.verify(storage).lateSetupDatabase(null);
    inOrder.verifyNoMoreInteractions();
  }

  private void stubPasswordParts(String masterPassword, String confirmPassword) {
    when(request.getPartAsStringFailsafe(
            "masterPassword", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH))
        .thenReturn(masterPassword);
    when(request.getPartAsStringFailsafe(
            "confirmMasterPassword", SecurityLevelsToadlet.MAX_PASSWORD_LENGTH))
        .thenReturn(confirmPassword);
  }

  private void stubThreatLevels(
      SecurityLevels.PHYSICAL_THREAT_LEVEL oldThreatLevel,
      SecurityLevels.PHYSICAL_THREAT_LEVEL newThreatLevel) {
    when(request.getPartAsStringFailsafe(PHYSICAL_THREAT_LEVEL_PART, 128))
        .thenReturn(newThreatLevel.name());
    when(request.isPartSet(PHYSICAL_THREAT_LEVEL_PART)).thenReturn(true);
    stubOldThreatLevel(oldThreatLevel);
  }

  private void stubOldThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL oldThreatLevel) {
    when(core.getNode()).thenReturn(node);
    when(node.services().securityLevels()).thenReturn(securityLevels);
    when(node.storage()).thenReturn(storage);
    when(securityLevels.getPhysicalThreatLevel()).thenReturn(oldThreatLevel);
  }
}
