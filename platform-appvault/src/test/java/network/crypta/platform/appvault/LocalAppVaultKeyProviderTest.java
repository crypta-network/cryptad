package network.crypta.platform.appvault;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@SuppressWarnings("java:S100")
class LocalAppVaultKeyProviderTest {
  @TempDir private Path tempDir;

  @Test
  void currentKey_whenExistingKeyIsPermissive_expectOwnerOnlyPermissions() throws Exception {
    Path keyFile = tempDir.resolve("local-vault-key-v1.key");
    byte[] key = new byte[32];
    for (int index = 0; index < key.length; index++) {
      key[index] = (byte) index;
    }
    Files.writeString(keyFile, Base64.getEncoder().encodeToString(key) + "\n");
    assumeTrue(Files.getFileAttributeView(keyFile, PosixFileAttributeView.class) != null);
    Files.setPosixFilePermissions(
        keyFile,
        Set.of(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.GROUP_READ,
            PosixFilePermission.OTHERS_READ));

    AppVaultKeyProvider.VaultKey vaultKey =
        new LocalAppVaultKeyProvider(keyFile, new SecureRandom()).currentKey();

    assertArrayEquals(key, vaultKey.keyBytes());
    assertEquals(LocalAppVaultKeyProvider.KEY_ID, vaultKey.keyId());
    assertEquals(
        Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
        Files.getPosixFilePermissions(keyFile));
  }

  @Test
  void currentKey_whenExistingKeyIsMalformed_expectIoFailure() throws Exception {
    Path keyFile = tempDir.resolve("local-vault-key-v1.key");
    Files.writeString(keyFile, "not base64!!!\n");

    IOException exception =
        assertThrows(
            IOException.class,
            () -> new LocalAppVaultKeyProvider(keyFile, new SecureRandom()).currentKey());

    assertEquals("local vault key is not valid Base64", exception.getMessage());
  }
}
