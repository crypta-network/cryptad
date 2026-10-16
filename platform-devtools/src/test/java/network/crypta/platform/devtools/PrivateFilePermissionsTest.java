package network.crypta.platform.devtools;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import static org.mockito.ArgumentMatchers.any;

class PrivateFilePermissionsTest {
  @TempDir Path temporary;

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  void restrictToOwner_replacesAclWithOnlyOwnerAccess(boolean directory) throws IOException {
    AclFileAttributeView view = mock(AclFileAttributeView.class);
    UserPrincipal owner = () -> "owner";
    when(view.getOwner()).thenReturn(owner);
    try (var files = mockStatic(Files.class)) {
      files
          .when(
              () ->
                  Files.getFileAttributeView(
                      temporary, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS))
          .thenReturn(view);

      PrivateFilePermissions.restrictToOwner(temporary, directory);

      ArgumentCaptor<List<AclEntry>> entries = ArgumentCaptor.captor();
      verify(view).setAcl(entries.capture());
      assertEquals(1, entries.getValue().size());
      AclEntry entry = entries.getValue().getFirst();
      assertEquals(owner, entry.principal());
      assertEquals(AclEntryType.ALLOW, entry.type());
      assertTrue(entry.permissions().contains(AclEntryPermission.READ_DATA));
      assertTrue(entry.permissions().contains(AclEntryPermission.WRITE_DATA));
      assertTrue(entry.permissions().contains(AclEntryPermission.DELETE));
      assertEquals(directory, entry.permissions().contains(AclEntryPermission.EXECUTE));
      assertEquals(
          directory ? Set.of(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT) : Set.of(),
          entry.flags());
    }
  }

  @Test
  void restrictToOwner_whenAclUnavailable_rejects() {
    try (var files = mockStatic(Files.class)) {
      files
          .when(
              () ->
                  Files.getFileAttributeView(
                      temporary, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS))
          .thenReturn(null);
      assertThrows(
          IOException.class, () -> PrivateFilePermissions.restrictToOwner(temporary, true));
    }
  }

  @Test
  void restrictToOwner_whenAclWriteFails_propagatesFailure() throws IOException {
    AclFileAttributeView view = mock(AclFileAttributeView.class);
    when(view.getOwner()).thenReturn(() -> "owner");
    IOException failure = new IOException("ACL rejected");
    doThrow(failure).when(view).setAcl(any());
    try (var files = mockStatic(Files.class)) {
      files
          .when(
              () ->
                  Files.getFileAttributeView(
                      temporary, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS))
          .thenReturn(view);
      assertSame(
          failure,
          assertThrows(
              IOException.class, () -> PrivateFilePermissions.restrictToOwner(temporary, false)));
    }
  }
}
