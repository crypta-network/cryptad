package network.crypta.runtime.core;

import java.io.File;
import java.io.IOException;
import network.crypta.node.MasterKeysFileSizeException;
import network.crypta.node.MasterKeysWrongPasswordException;
import network.crypta.node.Node;
import network.crypta.node.SecurityLevels;
import network.crypta.node.subsystem.NodeStorageSubsystem;
import network.crypta.runtime.spi.MasterPasswordMutationStatus;
import network.crypta.runtime.spi.SecurityLevelsSnapshot;
import network.crypta.runtime.spi.SecurityNetworkThreatLevel;
import network.crypta.runtime.spi.SecurityPhysicalThreatLevel;
import network.crypta.support.HTMLNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings("java:S100")
class LegacySecurityLevelsPortTest {

  @Mock(answer = org.mockito.Answers.RETURNS_DEEP_STUBS)
  private Node node;

  @Mock private SecurityLevels securityLevels;
  @Mock private NodeStorageSubsystem storage;

  @TempDir File tempDir;

  @Test
  void snapshot_whenCalled_mapsDetachedThreatLevelsAndPasswordFileMetadata() throws Exception {
    File masterKeysFile = new File(tempDir, "master.keys");
    assertTrue(masterKeysFile.createNewFile());
    when(node.services().securityLevels()).thenReturn(securityLevels);
    when(node.storage()).thenReturn(storage);
    when(node.hasDatabase()).thenReturn(true);
    when(storage.getMasterKeysFile()).thenReturn(masterKeysFile);
    when(securityLevels.getNetworkThreatLevel())
        .thenReturn(SecurityLevels.NETWORK_THREAT_LEVEL.MAXIMUM);
    when(securityLevels.getPhysicalThreatLevel())
        .thenReturn(SecurityLevels.PHYSICAL_THREAT_LEVEL.HIGH);

    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    SecurityLevelsSnapshot snapshot = port.snapshot();

    assertEquals(SecurityNetworkThreatLevel.MAXIMUM, snapshot.networkThreatLevel());
    assertEquals(SecurityPhysicalThreatLevel.HIGH, snapshot.physicalThreatLevel());
    assertTrue(snapshot.hasDatabase());
    assertTrue(snapshot.masterPasswordFileExists());
    assertEquals(masterKeysFile.getPath(), snapshot.masterPasswordFilePath());
  }

  @Test
  void networkThreatLevelConfirmWarningHtml_whenWarningExists_returnsRenderedHtml() {
    HTMLNode warning = new HTMLNode("div");
    warning.addChild("p", "Need confirmation");
    when(node.services().securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getConfirmWarning(
            SecurityLevels.NETWORK_THREAT_LEVEL.HIGH, "confirmNetworkThreatLevel"))
        .thenReturn(warning);

    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    String warningHtml =
        port.networkThreatLevelConfirmWarningHtml(
            SecurityNetworkThreatLevel.HIGH, "confirmNetworkThreatLevel");

    assertNotNull(warningHtml);
    assertTrue(warningHtml.contains("Need confirmation"));
  }

  @Test
  void setNetworkThreatLevel_whenCalled_delegatesWithMappedEnum() {
    when(node.services().securityLevels()).thenReturn(securityLevels);
    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    port.setNetworkThreatLevel(SecurityNetworkThreatLevel.LOW);

    verify(securityLevels).setThreatLevel(SecurityLevels.NETWORK_THREAT_LEVEL.LOW);
  }

  @Test
  void setPhysicalThreatLevel_whenCalled_delegatesWithMappedEnum() {
    when(node.services().securityLevels()).thenReturn(securityLevels);
    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    port.setPhysicalThreatLevel(SecurityPhysicalThreatLevel.MAXIMUM);

    verify(securityLevels).setThreatLevel(SecurityLevels.PHYSICAL_THREAT_LEVEL.MAXIMUM);
  }

  @Test
  void changeMasterPassword_whenSuccessful_returnsSuccess() throws Exception {
    when(node.storage()).thenReturn(storage);
    doNothing().when(storage).changeMasterPassword("old", "new", false);
    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    MasterPasswordMutationStatus status = port.changeMasterPassword("old", "new");

    assertEquals(MasterPasswordMutationStatus.SUCCESS, status);
  }

  @Test
  void changeMasterPassword_whenWrongPassword_returnsWrongPassword() throws Exception {
    when(node.storage()).thenReturn(storage);
    doThrow(new MasterKeysWrongPasswordException())
        .when(storage)
        .changeMasterPassword("old", "new", false);
    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    MasterPasswordMutationStatus status = port.changeMasterPassword("old", "new");

    assertEquals(MasterPasswordMutationStatus.WRONG_PASSWORD, status);
  }

  @Test
  void changeMasterPassword_whenAlreadySet_returnsAlreadySet() throws Exception {
    when(node.storage()).thenReturn(storage);
    doThrow(new Node.AlreadySetPasswordException())
        .when(storage)
        .changeMasterPassword("old", "new", false);
    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    MasterPasswordMutationStatus status = port.changeMasterPassword("old", "new");

    assertEquals(MasterPasswordMutationStatus.ALREADY_SET, status);
  }

  @Test
  void changeMasterPassword_whenCorruptedFile_returnsCorruptedFile() throws Exception {
    when(node.storage()).thenReturn(storage);
    doThrow(new MasterKeysFileSizeException(false))
        .when(storage)
        .changeMasterPassword("old", "new", false);
    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    MasterPasswordMutationStatus status = port.changeMasterPassword("old", "new");

    assertEquals(MasterPasswordMutationStatus.CORRUPTED_FILE, status);
  }

  @Test
  void changeMasterPassword_whenIoFails_propagatesIOException() throws Exception {
    when(node.storage()).thenReturn(storage);
    IOException failure = new IOException("boom");
    doThrow(failure).when(storage).changeMasterPassword("old", "new", false);
    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    IOException thrown =
        assertThrows(IOException.class, () -> port.changeMasterPassword("old", "new"));

    assertEquals(failure, thrown);
  }

  @Test
  void setMasterPassword_whenWrongPassword_returnsWrongPassword() throws Exception {
    when(node.storage()).thenReturn(storage);
    doThrow(new MasterKeysWrongPasswordException())
        .when(storage)
        .setMasterPassword("secret", false);
    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    MasterPasswordMutationStatus status = port.setMasterPassword("secret");

    assertEquals(MasterPasswordMutationStatus.WRONG_PASSWORD, status);
  }

  @Test
  void deleteMasterPasswordFile_whenCalled_delegatesToStorage() throws Exception {
    when(node.storage()).thenReturn(storage);
    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    port.deleteMasterPasswordFile();

    verify(storage).killMasterKeysFile();
  }

  @Test
  void networkThreatLevelConfirmWarningHtml_whenNoWarning_returnsNull() {
    when(node.services().securityLevels()).thenReturn(securityLevels);
    when(securityLevels.getConfirmWarning(
            SecurityLevels.NETWORK_THREAT_LEVEL.NORMAL, "confirmNetworkThreatLevel"))
        .thenReturn(null);
    LegacySecurityLevelsPort port = new LegacySecurityLevelsPort(node);

    String warningHtml =
        port.networkThreatLevelConfirmWarningHtml(
            SecurityNetworkThreatLevel.NORMAL, "confirmNetworkThreatLevel");

    assertNull(warningHtml);
  }
}
