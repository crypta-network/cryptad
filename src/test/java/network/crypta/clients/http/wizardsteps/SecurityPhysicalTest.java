package network.crypta.clients.http.wizardsteps;

import java.io.File;
import java.io.IOException;
import network.crypta.clients.http.FirstTimeWizardToadlet;
import network.crypta.clients.http.SecurityLevelsToadlet;
import network.crypta.runtime.spi.FirstTimeWizardPort;
import network.crypta.runtime.spi.MasterPasswordMutationStatus;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.support.api.HTTPRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
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

  @Mock private FirstTimeWizardPort wizardPort;
  @Mock private HTTPRequest request;

  @TempDir File tempDir;

  @Test
  void getCurrentLevel_whenCalled_returnsLevelFromSnapshot() {
    when(wizardPort.securitySnapshot())
        .thenReturn(snapshot(SecurityPhysicalThreatLevel.NORMAL, false, ""));

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    SecurityPhysicalThreatLevel current = subject.getCurrentLevel();

    assertEquals(SecurityPhysicalThreatLevel.NORMAL, current);
  }

  @Test
  void postStep_whenThreatLevelMissing_returnsPhysicalStepName() throws Exception {
    stubOldThreatLevel(SecurityPhysicalThreatLevel.NORMAL);
    stubPasswordParts("pw", "pw");
    when(request.getPartAsStringFailsafe(PHYSICAL_THREAT_LEVEL_PART, 128)).thenReturn("HIGH");
    when(request.isPartSet(PHYSICAL_THREAT_LEVEL_PART)).thenReturn(false);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name(), next);
  }

  @Test
  void postStep_whenBackToMainSet_returnsPhysicalStepName() throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.NORMAL, SecurityPhysicalThreatLevel.HIGH);
    stubPasswordParts("pw", "pw");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(true);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name(), next);
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenThreatLevelUnparseable_returnsPhysicalStepName() throws Exception {
    stubOldThreatLevel(SecurityPhysicalThreatLevel.NORMAL);
    stubPasswordParts("pw", "pw");
    when(request.getPartAsStringFailsafe(PHYSICAL_THREAT_LEVEL_PART, 128))
        .thenReturn("NOT_A_LEVEL");

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL.name(), next);
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenUpgradeToHighWithBlankPassword_promptsSetBlank() throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.NORMAL, SecurityPhysicalThreatLevel.HIGH);
    stubPasswordParts("", "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
            + "&error=pass&newThreatLevel=HIGH&type=SET_BLANK",
        next);
    verify(wizardPort, never()).changeMasterPassword(anyString(), anyString());
    verify(wizardPort, never()).setMasterPassword(anyString());
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenUpgradeToHighWithMismatchPassword_promptsSetNoMatch() throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.NORMAL, SecurityPhysicalThreatLevel.HIGH);
    stubPasswordParts("pw1", "pw2");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
            + "&error=pass&newThreatLevel=HIGH&type=SET_NO_MATCH",
        next);
    verify(wizardPort, never()).changeMasterPassword(anyString(), anyString());
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenUpgradeToHighFromNormal_changesFromBlankPasswordThenAdvances()
      throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.NORMAL, SecurityPhysicalThreatLevel.HIGH);
    stubPasswordParts(NEW_SECRET, NEW_SECRET);
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(wizardPort.changeMasterPassword("", NEW_SECRET))
        .thenReturn(MasterPasswordMutationStatus.SUCCESS);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    InOrder inOrder = inOrder(wizardPort);
    inOrder.verify(wizardPort).changeMasterPassword("", NEW_SECRET);
    inOrder.verify(wizardPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.HIGH);
    inOrder.verifyNoMoreInteractions();
  }

  @Test
  void postStep_whenUpgradeToHighFromMaximum_setsMasterPasswordThenAdvances() throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.MAXIMUM, SecurityPhysicalThreatLevel.HIGH);
    stubPasswordParts(NEW_SECRET, NEW_SECRET);
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(wizardPort.setMasterPassword(NEW_SECRET)).thenReturn(MasterPasswordMutationStatus.SUCCESS);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    InOrder inOrder = inOrder(wizardPort);
    inOrder.verify(wizardPort).setMasterPassword(NEW_SECRET);
    inOrder.verify(wizardPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.HIGH);
    inOrder.verifyNoMoreInteractions();
  }

  @Test
  void postStep_whenUpgradeToHighAlreadyHasPassword_ignoresAlreadySetAndAdvances()
      throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.NORMAL, SecurityPhysicalThreatLevel.HIGH);
    stubPasswordParts(NEW_SECRET, NEW_SECRET);
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(wizardPort.changeMasterPassword("", NEW_SECRET))
        .thenReturn(MasterPasswordMutationStatus.ALREADY_SET);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    verify(wizardPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.HIGH);
  }

  @Test
  void postStep_whenUpgradeToHighWrongPassword_throwsIOException() throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.NORMAL, SecurityPhysicalThreatLevel.HIGH);
    stubPasswordParts(NEW_SECRET, NEW_SECRET);
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(wizardPort.changeMasterPassword("", NEW_SECRET))
        .thenReturn(MasterPasswordMutationStatus.WRONG_PASSWORD);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    IOException thrown = assertThrows(IOException.class, () -> subject.postStep(request));

    assertEquals(
        "Incorrect password when changing from another level to high", thrown.getMessage());
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenUpgradeToHighCorruptedFile_returnsCorruptError() throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.NORMAL, SecurityPhysicalThreatLevel.HIGH);
    stubPasswordParts(NEW_SECRET, NEW_SECRET);
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(wizardPort.changeMasterPassword("", NEW_SECRET))
        .thenReturn(MasterPasswordMutationStatus.CORRUPTED_FILE);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL + "&error=corrupt", next);
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenDowngradeFromHighBlankPassword_promptsDecryptBlank() throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.HIGH, SecurityPhysicalThreatLevel.NORMAL);
    stubPasswordParts("", "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
            + "&error=pass&newThreatLevel=NORMAL&type=DECRYPT_BLANK",
        next);
    verify(wizardPort, never()).changeMasterPassword(anyString(), anyString());
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenDowngradeFromHighWrongPassword_promptsDecryptWrong() throws Exception {
    File masterKeys = new File(tempDir, MASTER_KEYS_FILENAME);
    assertFalse(masterKeys.exists());
    assertTrue(masterKeys.createNewFile());

    stubThreatLevelsFromHigh(SecurityPhysicalThreatLevel.LOW, masterKeys);
    stubPasswordParts(OLD_SECRET, "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(wizardPort.changeMasterPassword(OLD_SECRET, ""))
        .thenReturn(MasterPasswordMutationStatus.WRONG_PASSWORD);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
            + "&error=pass&newThreatLevel=LOW&type=DECRYPT_WRONG",
        next);
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenDowngradeFromHighCorruptedFile_returnsCorruptError() throws Exception {
    File masterKeys = new File(tempDir, MASTER_KEYS_FILENAME);
    assertTrue(masterKeys.createNewFile());

    stubThreatLevelsFromHigh(SecurityPhysicalThreatLevel.NORMAL, masterKeys);
    stubPasswordParts(OLD_SECRET, "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    when(wizardPort.changeMasterPassword(OLD_SECRET, ""))
        .thenReturn(MasterPasswordMutationStatus.CORRUPTED_FILE);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL + "&error=corrupt", next);
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenDowngradeFromHighIoFailureAndFileExists_throwsIOException() throws Exception {
    File masterKeys = new File(tempDir, MASTER_KEYS_FILENAME);
    assertTrue(masterKeys.createNewFile());

    stubThreatLevelsFromHigh(SecurityPhysicalThreatLevel.NORMAL, masterKeys);
    stubPasswordParts(OLD_SECRET, "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);

    IOException lowLevel = new IOException("disk full");
    when(wizardPort.changeMasterPassword(OLD_SECRET, "")).thenThrow(lowLevel);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    IOException thrown = assertThrows(IOException.class, () -> subject.postStep(request));

    assertEquals("cantWriteNewMasterKeysFile", thrown.getMessage());
    assertSame(lowLevel, thrown.getCause());
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenDowngradeFromHighIoFailureButFileDeleted_advances() throws Exception {
    File masterKeys = new File(tempDir, MASTER_KEYS_FILENAME);
    assertTrue(masterKeys.createNewFile());

    when(wizardPort.securitySnapshot())
        .thenAnswer(
            _ ->
                snapshot(
                    SecurityPhysicalThreatLevel.HIGH, masterKeys.exists(), masterKeys.getPath()));
    when(request.getPartAsStringFailsafe(PHYSICAL_THREAT_LEVEL_PART, 128)).thenReturn("LOW");
    when(request.isPartSet(PHYSICAL_THREAT_LEVEL_PART)).thenReturn(true);
    stubPasswordParts(OLD_SECRET, "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);

    doAnswer(
            _ -> {
              assertTrue(masterKeys.delete());
              throw new IOException("write failed");
            })
        .when(wizardPort)
        .changeMasterPassword(OLD_SECRET, "");

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    verify(wizardPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.LOW);
  }

  @Test
  void postStep_whenDowngradeFromHighWithoutMasterKeysFile_advances() throws Exception {
    File masterKeys = new File(tempDir, MASTER_KEYS_FILENAME);
    assertFalse(masterKeys.exists());

    stubThreatLevelsFromHigh(SecurityPhysicalThreatLevel.NORMAL, masterKeys);
    stubPasswordParts(OLD_SECRET, "");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    verify(wizardPort, never()).changeMasterPassword(anyString(), anyString());
    verify(wizardPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.NORMAL);
  }

  @Test
  void postStep_whenMaximumThreatLevelDeleteFails_returnsDeleteError() throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.NORMAL, SecurityPhysicalThreatLevel.MAXIMUM);
    stubPasswordParts("pw", "pw");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);
    doThrow(new IOException("no permission")).when(wizardPort).deleteMasterPasswordFile();

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(
        FirstTimeWizardToadlet.WIZARD_STEP.SECURITY_PHYSICAL
            + "&error=delete&newThreatLevel=MAXIMUM",
        next);
    verify(wizardPort, never()).setPhysicalThreatLevel(any(SecurityPhysicalThreatLevel.class));
  }

  @Test
  void postStep_whenMaximumThreatLevelDeleteSucceeds_advancesAndStoresThreatLevel()
      throws Exception {
    stubThreatLevels(SecurityPhysicalThreatLevel.NORMAL, SecurityPhysicalThreatLevel.MAXIMUM);
    stubPasswordParts("pw", "pw");
    when(request.isPartSet(BACK_TO_MAIN_PART)).thenReturn(false);

    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    String next = subject.postStep(request);

    assertEquals(FirstTimeWizardToadlet.WIZARD_STEP.NAME_SELECTION.name(), next);
    InOrder inOrder = inOrder(wizardPort);
    inOrder.verify(wizardPort).deleteMasterPasswordFile();
    inOrder.verify(wizardPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.MAXIMUM);
    inOrder.verifyNoMoreInteractions();
  }

  @Test
  void setThreatLevel_whenNullThreatLevel_throwsNullPointerException() {
    doThrow(new NullPointerException()).when(wizardPort).setPhysicalThreatLevel(null);
    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    assertThrows(NullPointerException.class, () -> subject.setThreatLevel(null));

    verify(wizardPort).setPhysicalThreatLevel(null);
  }

  @Test
  void setThreatLevel_whenValidThreatLevel_delegatesToWizardPort() {
    SecurityPhysical subject = new SecurityPhysical(wizardPort);

    subject.setThreatLevel(SecurityPhysicalThreatLevel.NORMAL);

    verify(wizardPort).setPhysicalThreatLevel(SecurityPhysicalThreatLevel.NORMAL);
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
      SecurityPhysicalThreatLevel oldThreatLevel, SecurityPhysicalThreatLevel newThreatLevel) {
    when(request.getPartAsStringFailsafe(PHYSICAL_THREAT_LEVEL_PART, 128))
        .thenReturn(newThreatLevel.name());
    when(request.isPartSet(PHYSICAL_THREAT_LEVEL_PART)).thenReturn(true);
    stubOldThreatLevel(oldThreatLevel);
  }

  private void stubThreatLevelsFromHigh(
      SecurityPhysicalThreatLevel newThreatLevel, File masterKeysFile) {
    when(request.getPartAsStringFailsafe(PHYSICAL_THREAT_LEVEL_PART, 128))
        .thenReturn(newThreatLevel.name());
    when(request.isPartSet(PHYSICAL_THREAT_LEVEL_PART)).thenReturn(true);
    when(wizardPort.securitySnapshot())
        .thenReturn(
            snapshot(
                SecurityPhysicalThreatLevel.HIGH,
                masterKeysFile.exists(),
                masterKeysFile.getPath()));
  }

  private void stubOldThreatLevel(SecurityPhysicalThreatLevel oldThreatLevel) {
    when(wizardPort.securitySnapshot()).thenReturn(snapshot(oldThreatLevel, false, ""));
  }

  private SecurityLevelsSnapshot snapshot(
      SecurityPhysicalThreatLevel physicalThreatLevel,
      boolean masterPasswordFileExists,
      String masterPasswordFilePath) {
    return new SecurityLevelsSnapshot(
        SecurityNetworkThreatLevel.NORMAL,
        physicalThreatLevel,
        true,
        masterPasswordFileExists,
        masterPasswordFilePath);
  }
}
