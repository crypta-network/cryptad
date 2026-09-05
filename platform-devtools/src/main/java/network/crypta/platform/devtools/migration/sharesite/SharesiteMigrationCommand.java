package network.crypta.platform.devtools.migration.sharesite;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;

/**
 * Offline migration command tree. Private input paths are never included in output or exceptions.
 *
 * <p>Each command requires an operator assertion that the legacy writer was stopped for the
 * snapshot. A private owner-only workspace stores fixed output names with create-new semantics.
 * Export binds the exact private plan checksum and recomputes its contents against the current
 * snapshot; no node, browser, catalog, publication, or app-install operation is performed by this
 * command tree.
 *
 * <p>The ordered workflow is inspect, plan, then export. Planning and export require the exact
 * preceding private inspection, and export additionally checks the acknowledged private plan.
 * Changed input or existing output files require a fresh operation workspace rather than repair or
 * replacement. Command instances hold invocation-local parsed options and are not shared across
 * threads. Ordinary output contains only bounded completion or failure codes; private labels, text,
 * paths, and comparison hashes remain in operator-owned files.
 */
@Command(
    name = "migration",
    mixinStandardHelpOptions = true,
    subcommands = SharesiteMigrationCommand.Sharesite.class)
public final class SharesiteMigrationCommand {
  /**
   * Creates the offline migration command group for command-line registration.
   *
   * <p>Construction performs no file access and allocates no migration session. Picocli selects the
   * nested Sharesite action and populates its invocation-local options before execution. The group
   * itself does not accept a node endpoint or publication authority; all supported operations
   * inspect private files and produce private conversion artifacts only.
   */
  private SharesiteMigrationCommand() {
    // Picocli constructs this command group reflectively; all work belongs to its subcommands.
  }

  @Command(
      name = "sharesite",
      mixinStandardHelpOptions = true,
      subcommands = {Inspect.class, Plan.class, Export.class})
  static final class Sharesite {}

  abstract static class Input implements Callable<Integer> {
    @Spec CommandSpec spec;

    @Option(names = "--snapshot", required = true)
    Path snapshot;

    @Option(names = "--workspace", required = true)
    Path workspace;

    @Option(
        names = "--writer-stopped",
        required = true,
        description = "Assert the snapshot was created while the legacy writer was stopped.")
    boolean stopped;

    @Override
    public final Integer call() {
      try {
        if (!stopped) throw SharesiteSnapshot.failure("writer_stop_required");
        prepareWorkspace(workspace);
        executePrivate();
        spec.commandLine().getOut().println("sharesite_private_operation_complete");
        return 0;
      } catch (IOException | IllegalArgumentException | UnsupportedOperationException exception) {
        String reason = exception.getMessage();
        spec.commandLine()
            .getErr()
            .println(
                reason != null && reason.matches("sharesite_[a-z_]+")
                    ? reason
                    : "sharesite_operation_failed");
        return 1;
      }
    }

    abstract void executePrivate() throws IOException;
  }

  @Command(
      name = "inspect",
      mixinStandardHelpOptions = true,
      description =
          "Write PRIVATE inspection.json with supported page IDs and explicit exclusions.")
  static final class Inspect extends Input {
    @Override
    void executePrivate() throws IOException {
      byte[] inspection = SharesiteSnapshot.inspect(snapshot, SharesiteConversion::inspect);
      writePrivate(workspace, "inspection.json", inspection);
    }
  }

  abstract static class Selection extends Input {
    @Option(names = "--select", required = true, split = ",")
    List<Integer> selected;

    @Option(names = "--operation-id", required = true)
    UUID operationId;

    @Option(
        names = "--provenance",
        required = true,
        description =
            "PRIVATE description of the stopped-writer snapshot preparation; avoid secrets.")
    String provenance;

    @Option(
        names = "--ack-exclusions",
        required = true,
        description = "Acknowledge the inspected exclusions and exact selected IDs.")
    boolean acknowledged;

    byte[] conversion() throws IOException {
      if (!acknowledged) throw SharesiteSnapshot.failure("selection_ack_required");
      Path inspection = workspace.toAbsolutePath().normalize().resolve("inspection.json");
      requirePrivateFile(inspection);
      byte[] preview = SharesiteSnapshot.read(inspection, SharesiteConversion.MAX_PACKAGE_BYTES);
      return SharesiteSnapshot.inspect(
          snapshot,
          source -> {
            if (!MessageDigest.isEqual(preview, SharesiteConversion.inspect(source))) {
              throw new IllegalArgumentException("sharesite_stale_inspection");
            }
            return SharesiteConversion.convert(source, selected, operationId, provenance);
          });
    }
  }

  @Command(
      name = "plan",
      mixinStandardHelpOptions = true,
      description =
          "Write PRIVATE plan.json containing exact selected draft data for local review.")
  static final class Plan extends Selection {
    @Override
    void executePrivate() throws IOException {
      writePrivate(workspace, "plan.json", conversion());
    }
  }

  @Command(
      name = "export",
      mixinStandardHelpOptions = true,
      description =
          "Verify exact private consent and write PRIVATE migration.json for Site Publisher.")
  static final class Export extends Selection {
    @Option(
        names = "--ack-plan-sha256",
        required = true,
        description =
            "Locally reviewed SHA-256 of PRIVATE plan.json; never attach this identity to public"
                + " evidence.")
    String acknowledgedDigest;

    @Override
    void executePrivate() throws IOException {
      Path plan = workspace.toAbsolutePath().normalize().resolve("plan.json");
      requirePrivateFile(plan);
      byte[] planned = SharesiteSnapshot.read(plan, SharesiteConversion.MAX_PACKAGE_BYTES);
      if (!SharesiteSnapshot.sha256(planned).equals(acknowledgedDigest))
        throw SharesiteSnapshot.failure("plan_consent_mismatch");
      byte[] current = conversion();
      if (!MessageDigest.isEqual(planned, current))
        throw SharesiteSnapshot.failure("stale_private_plan");
      writePrivate(workspace, "migration.json", current);
    }
  }

  private static void prepareWorkspace(Path directory) throws IOException {
    Path normalized = directory.toAbsolutePath().normalize();
    SharesiteSnapshot.requireSafePath(normalized);
    if (!Files.exists(normalized, LinkOption.NOFOLLOW_LINKS)) {
      Files.createDirectory(
          normalized,
          PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
    }
    if (!Files.isDirectory(normalized, LinkOption.NOFOLLOW_LINKS))
      throw SharesiteSnapshot.failure("unsafe_workspace");
    requireOwnerOnly(normalized);
  }

  private static void requirePrivateFile(Path file) throws IOException {
    SharesiteSnapshot.requireSafePath(file);
    if (!Files.isRegularFile(file, LinkOption.NOFOLLOW_LINKS))
      throw SharesiteSnapshot.failure("unsafe_private_file");
    requireOwnerOnly(file);
  }

  private static void requireOwnerOnly(Path path) throws IOException {
    Set<PosixFilePermission> permissions =
        Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
    if (permissions.stream()
        .anyMatch(
            permission ->
                permission.name().startsWith("GROUP_")
                    || permission.name().startsWith("OTHERS_"))) {
      throw SharesiteSnapshot.failure("private_permissions_required");
    }
  }

  private static void writePrivate(Path directory, String name, byte[] bytes) throws IOException {
    prepareWorkspace(directory);
    Path output = directory.toAbsolutePath().normalize().resolve(name);
    SharesiteSnapshot.requireSafePath(output);
    try (var channel =
        java.nio.channels.FileChannel.open(
            output,
            Set.of(
                StandardOpenOption.WRITE, StandardOpenOption.CREATE_NEW, LinkOption.NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")))) {
      var buffer = java.nio.ByteBuffer.wrap(bytes);
      while (buffer.hasRemaining()) {
        if (channel.write(buffer) <= 0) {
          throw SharesiteSnapshot.failure("private_write_stalled");
        }
      }
      channel.force(true);
    }
  }
}
