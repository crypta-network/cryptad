package network.crypta.node;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.io.IOException;
import network.crypta.crypt.DummyRandomSource;
import network.crypta.crypt.MasterSecret;
import network.crypta.support.io.FileUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class MasterKeysTest {

  private final File base = new File("tmp.master-keys-test");

  @BeforeEach
  public void setUp() {
    FileUtil.removeAll(base);
    base.mkdir();
    MasterKeys.ITERATE_TIME = 100; // Speed up test.
  }

  @AfterEach
  public void tearDown() {
    FileUtil.removeAll(base);
  }

  @Test
  public void testRestartNoPassword()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    testRestart("");
  }

  @Test
  public void testRestartWithPassword()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    testRestart("password");
  }

  private void testRestart(String password)
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
  public void testChangePasswordEmptyToSomething()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    testChangePassword("", "password");
  }

  @Test
  public void testChangePasswordEmptyToEmpty()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    testChangePassword("", "");
  }

  @Test
  public void testChangePasswordSomethingToEmpty()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    testChangePassword("password", "");
  }

  @Test
  public void testChangePasswordSomethingToSomething()
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    testChangePassword("password", "new password");
  }

  private void testChangePassword(String oldPassword, String newPassword)
      throws MasterKeysWrongPasswordException, MasterKeysFileSizeException, IOException {
    File keysFile = new File(base, "test.master.keys");
    DummyRandomSource random = new DummyRandomSource(77391);
    MasterKeys original = MasterKeys.read(keysFile, random, oldPassword);
    byte[] clientCacheMasterKey = original.clientCacheMasterKey;
    DatabaseKey dkey = original.createDatabaseKey();
    MasterSecret tempfileMasterSecret = original.getPersistentMasterSecret();
    // Change password.
    original.changePassword(keysFile, newPassword, random);
    // Now restore.
    if (!oldPassword.equals(newPassword)) {
      try {
        MasterKeys.read(keysFile, random, oldPassword);
        fail("Old password should not work!");
      } catch (MasterKeysWrongPasswordException e) {
        // Ok.
      }
    }
    MasterKeys restored = MasterKeys.read(keysFile, random, newPassword);
    assertArrayEquals(clientCacheMasterKey, restored.clientCacheMasterKey);
    assertEquals(dkey, restored.createDatabaseKey());
    assertEquals(tempfileMasterSecret, restored.getPersistentMasterSecret());
  }
}
