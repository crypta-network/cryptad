package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("java:S100")
class AppCatalogFilePermissionsTest {
  @TempDir Path tempDir;

  @Test
  void restrictOwnerOnlyFile_whenNativeFilesystem_expectPrivateWritableFile() throws IOException {
    Path file = Files.createFile(tempDir.resolve("snapshot.zip"));

    AppCatalogFilePermissions.restrictOwnerOnlyFile(file);

    Files.writeString(file, "artifact");
    assertEquals("artifact", Files.readString(file));
    if (Files.getFileAttributeView(file, PosixFileAttributeView.class) != null) {
      assertEquals(
          Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
          Files.getPosixFilePermissions(file));
    } else {
      AclFileAttributeView view = Files.getFileAttributeView(file, AclFileAttributeView.class);
      assertOwnerOnlyAcl(view.getAcl(), view.getOwner());
    }
    Files.delete(file);
    assertFalse(Files.exists(file));
  }

  @Test
  void restrictOwnerOnlyFile_whenPosixUnavailable_expectOwnerOnlyAcl() throws IOException {
    Path file = tempDir.resolve("snapshot.zip");
    AclFileAttributeView view = mock(AclFileAttributeView.class);
    UserPrincipal owner = () -> "snapshot-owner";
    when(view.getOwner()).thenReturn(owner);
    try (var files = mockStatic(Files.class)) {
      files
          .when(() -> Files.setPosixFilePermissions(any(Path.class), anySet()))
          .thenThrow(new UnsupportedOperationException());
      files
          .when(
              () ->
                  Files.getFileAttributeView(
                      file, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS))
          .thenReturn(view);

      AppCatalogFilePermissions.restrictOwnerOnlyFile(file);

      ArgumentCaptor<List<AclEntry>> acl = ArgumentCaptor.captor();
      verify(view).setAcl(acl.capture());
      assertOwnerOnlyAcl(acl.getValue(), owner);
    }
  }

  @Test
  void restrictOwnerOnlyFile_whenPermissionViewsUnavailable_expectFailure() {
    Path file = tempDir.resolve("snapshot.zip");
    try (var files = mockStatic(Files.class)) {
      files
          .when(() -> Files.setPosixFilePermissions(any(Path.class), anySet()))
          .thenThrow(new UnsupportedOperationException());

      assertThrows(IOException.class, () -> AppCatalogFilePermissions.restrictOwnerOnlyFile(file));
    }
  }

  @Test
  void restrictOwnerOnlyFile_whenAclUpdateFails_expectFailurePropagated() throws IOException {
    Path file = tempDir.resolve("snapshot.zip");
    AclFileAttributeView view = mock(AclFileAttributeView.class);
    when(view.getOwner()).thenReturn(() -> "snapshot-owner");
    IOException failure = new IOException("ACL update rejected");
    doThrow(failure).when(view).setAcl(any());
    try (var files = mockStatic(Files.class)) {
      files
          .when(() -> Files.setPosixFilePermissions(any(Path.class), anySet()))
          .thenThrow(new UnsupportedOperationException());
      files
          .when(
              () ->
                  Files.getFileAttributeView(
                      file, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS))
          .thenReturn(view);

      assertSame(
          failure,
          assertThrows(
              IOException.class, () -> AppCatalogFilePermissions.restrictOwnerOnlyFile(file)));
    }
  }

  private static void assertOwnerOnlyAcl(List<AclEntry> acl, UserPrincipal owner) {
    assertEquals(1, acl.size());
    AclEntry entry = acl.getFirst();
    assertEquals(owner, entry.principal());
    assertEquals(AclEntryType.ALLOW, entry.type());
    assertTrue(entry.permissions().contains(AclEntryPermission.READ_DATA));
    assertTrue(entry.permissions().contains(AclEntryPermission.WRITE_DATA));
    assertTrue(entry.permissions().contains(AclEntryPermission.DELETE));
    assertFalse(entry.permissions().contains(AclEntryPermission.EXECUTE));
    assertTrue(entry.flags().isEmpty());
  }
}
