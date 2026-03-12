package network.crypta.node;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Random;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.MasterSecret;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100") // test method naming style: method_whenCondition_expectOutcome
class MasterKeysTest {

  @TempDir File base;
  private int prevIterateTime;

  @BeforeEach
  void setUp() {
    // Keep password hashing loop instantaneous for deterministic, fast tests.
    // Remember the current value so we can restore it after each test run.
    prevIterateTime = MasterKeys.iterateTime;
    MasterKeys.setIterateTimeForTests(0);
  }

  @AfterEach
  void tearDown() {
    // Restore production/default behavior for subsequent tests in the same JVM.
    MasterKeys.setIterateTimeForTests(prevIterateTime);
  }

  @Test
  void read_whenNoPassword_persistsAndRestoresSameKeys()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    read_persistsAndRestoresSameKeys("");
  }

  @Test
  void read_whenWithPassword_persistsAndRestoresSameKeys()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    read_persistsAndRestoresSameKeys("password");
  }

  private void read_persistsAndRestoresSameKeys(String password)
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    File keysFile = new File(base, "test.master.keys");
    DummyRandomSource random = new DummyRandomSource(77391);

    MasterKeys original = MasterKeys.read(keysFile, random, password);
    byte[] clientCacheMasterKey = original.clientCacheMasterKey;
    DatabaseKey dkey = original.createDatabaseKey();
    MasterSecret tempfileMasterSecret = original.getPersistentMasterSecret();

    MasterKeys restored = MasterKeys.read(keysFile, random, password);
    assertArrayEquals(clientCacheMasterKey, restored.clientCacheMasterKey);
    assertEquals(dkey, restored.createDatabaseKey());
    assertEquals(tempfileMasterSecret, restored.getPersistentMasterSecret());
  }

  @Test
  void changePassword_whenEmptyToSomething_oldPasswordRejectedNewAccepted()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    changePassword_preservesKeysAndEnforcesNewPassword("", "password");
  }

  @Test
  void changePassword_whenEmptyToEmpty_oldPasswordStillAccepted()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    changePassword_preservesKeysAndEnforcesNewPassword("", "");
  }

  @Test
  void changePassword_whenSomethingToEmpty_oldPasswordRejectedAndKeysStable()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    changePassword_preservesKeysAndEnforcesNewPassword("password", "");
  }

  @Test
  void changePassword_whenSomethingToSomething_oldPasswordRejectedAndKeysStable()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    changePassword_preservesKeysAndEnforcesNewPassword("password", "new password");
  }

  private void changePassword_preservesKeysAndEnforcesNewPassword(
      String oldPassword, String newPassword)
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    File keysFile = new File(base, "test.master.keys");
    DummyRandomSource random = new DummyRandomSource(77391);

    MasterKeys original = MasterKeys.read(keysFile, random, oldPassword);
    byte[] clientCacheMasterKey = original.clientCacheMasterKey;
    DatabaseKey dkey = original.createDatabaseKey();
    MasterSecret tempfileMasterSecret = original.getPersistentMasterSecret();

    // Act: change password and reload
    original.changePassword(keysFile, newPassword, random);

    if (!oldPassword.equals(newPassword)) {
      assertThrows(
          MasterKeysWrongPasswordException.class,
          () -> MasterKeys.read(keysFile, random, oldPassword));
    }

    MasterKeys restored = MasterKeys.read(keysFile, random, newPassword);
    assertArrayEquals(clientCacheMasterKey, restored.clientCacheMasterKey);
    assertEquals(dkey, restored.createDatabaseKey());
    assertEquals(tempfileMasterSecret, restored.getPersistentMasterSecret());
  }

  @Test
  void clear_whenNull_doesNothing() {
    assertDoesNotThrow(() -> MasterKeys.clear(null));
  }

  @Test
  void clear_whenNonNull_zerosArray() {
    byte[] buf = new byte[] {1, 2, 3, (byte) 0xFF};
    MasterKeys.clear(buf);
    assertArrayEquals(new byte[] {0, 0, 0, 0}, buf);
  }

  @Test
  void killMasterKeys_whenExistingFile_deletesFile() throws IOException {
    File f = new File(base, "to-delete.master.keys");
    try (FileOutputStream os = new FileOutputStream(f)) {
      os.write(new byte[] {1, 2, 3, 4});
    }
    assertTrue(f.exists());
    MasterKeys.killMasterKeys(f);
    assertFalse(f.exists());
  }

  @Test
  void read_whenFileTooSmall_throwsFileSizeExceptionTooSmall() throws IOException {
    File f = new File(base, "too-small.master.keys");
    try (FileOutputStream os = new FileOutputStream(f)) {
      // Minimum acceptable is 32 + 32 + 8 + 32 = 104
      os.write(new byte[100]);
    }
    MasterKeysFileSizeException ex =
        assertThrows(MasterKeysFileSizeException.class, () -> MasterKeys.read(f, new Random(), ""));
    assertFalse(ex.isTooBig());
    assertEquals("small", ex.sizeToString());
  }

  @Test
  void read_whenFileTooBig_throwsFileSizeExceptionTooBig() throws IOException {
    File f = new File(base, "too-big.master.keys");
    try (FileOutputStream os = new FileOutputStream(f)) {
      os.write(new byte[1025]);
    }
    MasterKeysFileSizeException ex =
        assertThrows(MasterKeysFileSizeException.class, () -> MasterKeys.read(f, new Random(), ""));
    assertTrue(ex.isTooBig());
    assertEquals("big", ex.sizeToString());
  }

  @Test
  void read_whenOldFormatFileLengthButWrongPassword_throwsWrongPasswordException()
      throws IOException {
    // Old format path is triggered by len == 140; content is bogus so decryption fails → exception
    File f = new File(base, "old-format.master.keys");
    try (FileOutputStream os = new FileOutputStream(f)) {
      os.write(new byte[140]);
    }
    assertThrows(
        MasterKeysWrongPasswordException.class, () -> MasterKeys.read(f, new Random(), "p"));
  }

  @Test
  void createRandom_whenSeededRandom_producesDeterministicKeysAndSizes() {
    Random seeded = new Random(123456789L);
    MasterKeys mk = MasterKeys.createRandom(seeded);

    // Reconstruct expected bytes using the same sequence the implementation uses
    Random verify = new Random(123456789L);
    byte[] expectedClient = new byte[32];
    verify.nextBytes(expectedClient);
    byte[] expectedDb = new byte[32];
    verify.nextBytes(expectedDb);
    byte[] expectedTemp = new byte[64];
    verify.nextBytes(expectedTemp);

    assertArrayEquals(expectedClient, mk.clientCacheMasterKey);
    assertEquals(new DatabaseKey(expectedDb), mk.createDatabaseKey());
    assertEquals(new MasterSecret(expectedTemp), mk.getPersistentMasterSecret());
  }

  // Deprecated overload removed; modern createDatabaseKey() is covered by other tests

  @Test
  void getPersistentMasterSecret_whenCalledTwice_returnsEqualButNotSame() {
    MasterKeys mk = MasterKeys.createRandom(new Random(7L));
    MasterSecret a = mk.getPersistentMasterSecret();
    MasterSecret b = mk.getPersistentMasterSecret();
    assertNotNull(a);
    assertEquals(a, b);
    assertNotSame(a, b);
  }
}
