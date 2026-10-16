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
import java.util.EnumSet;
import java.util.List;

/** Owner-only ACL fallback for private developer keys and staging directories. */
final class PrivateFilePermissions {
  private PrivateFilePermissions() {}

  /**
   * Replaces inherited access before private content is written on a non-POSIX filesystem.
   *
   * @param path newly created file or directory
   * @param directory whether traversal and child inheritance are required
   * @throws IOException if owner-only access cannot be enforced
   */
  static void restrictToOwner(Path path, boolean directory) throws IOException {
    AclFileAttributeView view =
        Files.getFileAttributeView(path, AclFileAttributeView.class, LinkOption.NOFOLLOW_LINKS);
    if (view == null) {
      throw new IOException("owner-only permissions are unavailable");
    }
    EnumSet<AclEntryPermission> permissions = EnumSet.allOf(AclEntryPermission.class);
    AclEntry.Builder entry =
        AclEntry.newBuilder().setType(AclEntryType.ALLOW).setPrincipal(view.getOwner());
    if (directory) {
      entry.setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT);
    } else {
      permissions.remove(AclEntryPermission.EXECUTE);
      permissions.remove(AclEntryPermission.DELETE_CHILD);
    }
    view.setAcl(List.of(entry.setPermissions(permissions).build()));
  }
}
