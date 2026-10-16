package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/** Applies owner-only access to private catalog files before any artifact bytes are written. */
final class AppCatalogFilePermissions {
  private AppCatalogFilePermissions() {}

  /**
   * Restricts a newly created file to its owner, using POSIX permissions or a replacement ACL.
   *
   * @param file empty private file whose permissions must be restricted
   * @throws IOException if permissions cannot be applied or neither permission model is available
   */
  static void restrictOwnerOnlyFile(Path file) throws IOException {
    try {
      Files.setPosixFilePermissions(
          file, Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE));
      return;
    } catch (UnsupportedOperationException _) {
      // Windows uses ACLs; java.io.File permission setters do not enforce owner-only access.
    }
    AclFileAttributeView view =
        Files.getFileAttributeView(file, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
    if (view == null) {
      throw new IOException("owner-only catalog file permissions are unavailable");
    }
    EnumSet<AclEntryPermission> permissions = EnumSet.allOf(AclEntryPermission.class);
    permissions.remove(AclEntryPermission.EXECUTE);
    permissions.remove(AclEntryPermission.DELETE_CHILD);
    AclEntry ownerAccess =
        AclEntry.newBuilder()
            .setType(AclEntryType.ALLOW)
            .setPrincipal(view.getOwner())
            .setPermissions(permissions)
            .build();
    view.setAcl(List.of(ownerAccess));
  }
}
