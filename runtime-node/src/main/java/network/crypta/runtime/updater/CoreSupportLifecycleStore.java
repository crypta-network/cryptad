package network.crypta.runtime.updater;

import com.sun.jna.platform.win32.Kernel32;
import com.sun.jna.platform.win32.WinBase;
import com.sun.jna.platform.win32.WinDef.DWORD;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import network.crypta.fs.AppEnv;

/**
 * Exact-byte local persistence for the last-known-good support-lifecycle descriptor.
 *
 * <p>The file contains only the authenticated public descriptor. Reads reject symbolic links,
 * non-regular files, and oversized content. Writes use a newly created sibling file and an atomic
 * replacement when the filesystem supports it, so a crash cannot silently turn partial bytes into
 * accepted lifecycle state. A fixed-content sibling marker and optional independent fallback marker
 * durably prevent state authenticated by a compromised update key from loading or being replaced.
 * No path or descriptor body is returned to logs or operator surfaces.
 */
final class CoreSupportLifecycleStore {
  /** Exact marker body identifying the versioned update-key trust-invalidation record. */
  private static final byte[] INVALIDATION_MARKER =
      "stable-1.0-support-lifecycle-update-key-trust-invalidated-v1\n"
          .getBytes(StandardCharsets.US_ASCII);

  /** Canonical node-local path for the exact last-known-good descriptor bytes. */
  private final Path descriptorFile;

  /** Primary trust-invalidation marker stored beside the descriptor. */
  private final Path invalidationFile;

  /**
   * Independently located fallback marker, or the primary marker when no fallback is configured.
   */
  private final Path fallbackInvalidationFile;

  /** Platform-specific durable file publication operations. */
  private final PersistenceSync persistenceSync;

  /**
   * Creates a store for one node-local descriptor file.
   *
   * @param descriptorFile target file inside the node's private updater state directory
   */
  CoreSupportLifecycleStore(Path descriptorFile) {
    this(descriptorFile, null);
  }

  /**
   * Creates a store with an independent fallback marker for update-key compromise.
   *
   * <p>The fallback is intentionally outside the descriptor directory in the runtime integration,
   * so a localized failure in that directory cannot erase the only durable compromise latch.
   *
   * @param descriptorFile target file inside the node's private updater state directory
   * @param fallbackInvalidationFile independent fixed-content compromise marker, or {@code null} to
   *     use only the descriptor sibling
   */
  CoreSupportLifecycleStore(Path descriptorFile, Path fallbackInvalidationFile) {
    this(descriptorFile, fallbackInvalidationFile, platformPersistenceSync());
  }

  /**
   * Creates a store with explicit persistence operations, primarily for deterministic tests.
   *
   * @param descriptorFile target file inside the node's private updater state directory
   * @param fallbackInvalidationFile independent fixed-content compromise marker, or {@code null}
   * @param persistenceSync platform-specific durable publication implementation
   */
  CoreSupportLifecycleStore(
      Path descriptorFile, Path fallbackInvalidationFile, PersistenceSync persistenceSync) {
    this.descriptorFile = descriptorFile.toAbsolutePath().normalize();
    this.invalidationFile =
        this.descriptorFile.resolveSibling(
            this.descriptorFile.getFileName() + ".trust-invalidated");
    this.fallbackInvalidationFile =
        fallbackInvalidationFile == null
            ? this.invalidationFile
            : fallbackInvalidationFile.toAbsolutePath().normalize();
    this.persistenceSync = Objects.requireNonNull(persistenceSync, "persistenceSync");
  }

  /**
   * Loads exact descriptor bytes when a safe last-known-good file exists.
   *
   * @return exact stored bytes, or {@code null} when no prior descriptor exists
   * @throws IOException if the path is unsafe, unreadable, or outside runtime size bounds
   */
  StoredDescriptor load() throws IOException {
    rejectSymbolicPath(descriptorFile.getParent());
    if (isTrustInvalidated()) {
      return null;
    }
    if (!Files.exists(descriptorFile, LinkOption.NOFOLLOW_LINKS)) {
      return null;
    }
    if (Files.isSymbolicLink(descriptorFile)
        || !Files.isRegularFile(descriptorFile, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("lifecycle store path is not a regular file");
    }
    long size = Files.size(descriptorFile);
    if (size <= 0 || size > CoreSupportLifecycleParser.MAX_DESCRIPTOR_BYTES) {
      throw new IOException("lifecycle store file is outside runtime size bounds");
    }
    byte[] bytes = Files.readAllBytes(descriptorFile);
    Instant verifiedAt =
        Files.getLastModifiedTime(descriptorFile, LinkOption.NOFOLLOW_LINKS).toInstant();
    return new StoredDescriptor(bytes, verifiedAt);
  }

  /**
   * Replaces the last-known-good file with one already validated exact byte sequence.
   *
   * @param bytes exact authenticated descriptor bytes to persist
   * @param verifiedAt local time at which validation of these exact bytes succeeded
   * @throws IOException if the parent or target is unsafe or replacement cannot complete
   */
  void save(byte[] bytes, Instant verifiedAt) throws IOException {
    if (bytes == null
        || bytes.length == 0
        || bytes.length > CoreSupportLifecycleParser.MAX_DESCRIPTOR_BYTES) {
      throw new IOException("lifecycle descriptor is outside runtime size bounds");
    }
    if (verifiedAt == null) {
      throw new IOException("lifecycle verification time is unavailable");
    }
    Path parent = descriptorFile.getParent();
    if (parent == null) {
      throw new IOException("lifecycle store has no parent directory");
    }
    rejectSymbolicPath(parent);
    Files.createDirectories(parent);
    rejectSymbolicPath(parent);
    if (isTrustInvalidated()) {
      throw new IOException("lifecycle store trust has been invalidated");
    }
    if (Files.exists(descriptorFile, LinkOption.NOFOLLOW_LINKS)
        && Files.isSymbolicLink(descriptorFile)) {
      throw new IOException("lifecycle store target is a symbolic link");
    }

    Path temporary = Files.createTempFile(parent, ".support-lifecycle-", ".tmp");
    try {
      Files.write(temporary, bytes, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
      Files.setLastModifiedTime(temporary, FileTime.from(verifiedAt));
      persistenceSync.forceFile(temporary);
      persistenceSync.publish(temporary, descriptorFile, true);
    } finally {
      Files.deleteIfExists(temporary);
    }
  }

  /**
   * Durably invalidates persisted state after the configured update key is compromised.
   *
   * <p>Atomic fixed-content markers are attempted before descriptor cleanup. At least one exact
   * marker must be durable for this operation to report success. Loading and saving fail closed on
   * either marker, so even a descriptor that cannot be removed is not trusted after a restart.
   * Symbolic or malformed markers are rejected rather than followed or ignored.
   *
   * @throws IOException if durable invalidation cannot be recorded safely
   */
  void invalidateTrust() throws IOException {
    IOException firstFailure = null;
    boolean durablyInvalidated = false;
    try {
      ensureInvalidationMarker(invalidationFile);
      durablyInvalidated = true;
    } catch (IOException e) {
      firstFailure = e;
    }
    if (!fallbackInvalidationFile.equals(invalidationFile)) {
      try {
        ensureInvalidationMarker(fallbackInvalidationFile);
        durablyInvalidated = true;
      } catch (IOException e) {
        if (firstFailure == null) {
          firstFailure = e;
        } else {
          firstFailure.addSuppressed(e);
        }
      }
    }
    if (!durablyInvalidated) {
      throw new IOException(
          "unable to record an exact lifecycle trust invalidation marker", firstFailure);
    }
    try {
      clearDescriptor();
    } catch (IOException _) {
      // The durable marker already prevents this descriptor from being loaded or replaced.
    }
  }

  /**
   * Returns whether durable update-key trust invalidation evidence exists.
   *
   * <p>An existing marker that is malformed, symbolic, or unreadable is still invalidation
   * evidence. Treating it as absent would let a damaged or attacker-substituted marker reopen the
   * package updater after restart.
   *
   * @return {@code true} when either configured marker records or conservatively indicates
   *     update-key trust invalidation
   */
  boolean isTrustInvalidated() {
    return trustInvalidationStatus() != TrustInvalidationStatus.ABSENT;
  }

  /**
   * Inspects one marker without inventing compromise evidence from a missing file.
   *
   * <p>The leaf is checked for existence before ancestor safety so an accepted, symlinked node
   * directory with no marker remains {@link TrustInvalidationStatus#ABSENT}. Once a marker exists,
   * unsafe ancestors, an unsafe leaf, malformed content, or read failure remain fail-closed as
   * {@link TrustInvalidationStatus#INVALID}.
   *
   * @return combined trust-invalidation status for the primary and fallback markers
   */
  TrustInvalidationStatus trustInvalidationStatus() {
    TrustInvalidationStatus primary = trustInvalidationStatus(invalidationFile);
    if (fallbackInvalidationFile.equals(invalidationFile)) {
      return primary;
    }
    TrustInvalidationStatus fallback = trustInvalidationStatus(fallbackInvalidationFile);
    if (primary == TrustInvalidationStatus.INVALID || fallback == TrustInvalidationStatus.INVALID) {
      return TrustInvalidationStatus.INVALID;
    }
    if (primary == TrustInvalidationStatus.VALID || fallback == TrustInvalidationStatus.VALID) {
      return TrustInvalidationStatus.VALID;
    }
    return TrustInvalidationStatus.ABSENT;
  }

  /**
   * Inspects one fixed-content marker without following its leaf or ancestor symbolic links.
   *
   * @param marker marker path to inspect
   * @return {@link TrustInvalidationStatus#ABSENT} only when the marker leaf does not exist;
   *     otherwise a valid or fail-closed invalid result
   */
  private static TrustInvalidationStatus trustInvalidationStatus(Path marker) {
    BasicFileAttributes attributes;
    try {
      attributes =
          Files.readAttributes(marker, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
    } catch (NoSuchFileException _) {
      return TrustInvalidationStatus.ABSENT;
    } catch (IOException | SecurityException _) {
      return TrustInvalidationStatus.INVALID;
    }
    try {
      rejectSymbolicPath(marker.getParent());
    } catch (IOException | SecurityException _) {
      return TrustInvalidationStatus.INVALID;
    }
    if (attributes.isSymbolicLink()
        || !attributes.isRegularFile()
        || attributes.size() != INVALIDATION_MARKER.length) {
      return TrustInvalidationStatus.INVALID;
    }
    try {
      byte[] markerBytes = Files.readAllBytes(marker);
      return Arrays.equals(markerBytes, INVALIDATION_MARKER)
          ? TrustInvalidationStatus.VALID
          : TrustInvalidationStatus.INVALID;
    } catch (IOException | SecurityException _) {
      return TrustInvalidationStatus.INVALID;
    }
  }

  /**
   * Creates or verifies one durable fixed-content trust-invalidation marker.
   *
   * @param marker destination marker path
   * @throws IOException if an existing marker conflicts or durable publication cannot be verified
   */
  private void ensureInvalidationMarker(Path marker) throws IOException {
    TrustInvalidationStatus existing = trustInvalidationStatus(marker);
    if (existing == TrustInvalidationStatus.INVALID) {
      throw new IOException("lifecycle trust invalidation marker conflicts with existing state");
    }
    Path parent = marker.getParent();
    if (parent == null) {
      throw new IOException("lifecycle trust invalidation marker has no parent directory");
    }
    rejectSymbolicPath(parent);
    Files.createDirectories(parent);
    rejectSymbolicPath(parent);
    Path temporary = Files.createTempFile(parent, ".support-lifecycle-invalidation-", ".tmp");
    try {
      Files.write(
          temporary,
          INVALIDATION_MARKER,
          StandardOpenOption.WRITE,
          StandardOpenOption.TRUNCATE_EXISTING);
      persistenceSync.forceFile(temporary);
      persistenceSync.publish(temporary, marker, existing == TrustInvalidationStatus.VALID);
    } finally {
      Files.deleteIfExists(temporary);
    }
    if (trustInvalidationStatus(marker) != TrustInvalidationStatus.VALID) {
      throw new IOException("lifecycle trust invalidation marker verification failed");
    }
  }

  /**
   * Removes the persisted descriptor after trust invalidation when its leaf remains safe.
   *
   * @throws IOException if the descriptor leaf is unsafe or cannot be removed
   */
  private void clearDescriptor() throws IOException {
    if (!Files.exists(descriptorFile, LinkOption.NOFOLLOW_LINKS)) {
      return;
    }
    if (Files.isSymbolicLink(descriptorFile)
        || !Files.isRegularFile(descriptorFile, LinkOption.NOFOLLOW_LINKS)) {
      throw new IOException("lifecycle store path is not a regular file");
    }
    Files.delete(descriptorFile);
  }

  /**
   * Rejects a persistence directory when an existing path component is a symbolic link.
   *
   * @param path directory path to validate without following existing symbolic links
   * @throws IOException if the path has no parent context or is not a safe directory path
   */
  private static void rejectSymbolicPath(Path path) throws IOException {
    if (path == null) {
      throw new IOException("lifecycle store has no parent directory");
    }
    Path absolute = path.toAbsolutePath().normalize();
    Path current = absolute.getRoot();
    for (Path component : absolute) {
      current = current == null ? component : current.resolve(component);
      if (Files.exists(current, LinkOption.NOFOLLOW_LINKS) && Files.isSymbolicLink(current)) {
        throw new IOException("lifecycle store path contains a symbolic link");
      }
    }
    if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)
        && (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path))) {
      throw new IOException("lifecycle store parent is not a safe directory");
    }
  }

  /** Platform-specific operations that make an exact file replacement crash-durable. */
  interface PersistenceSync {
    /**
     * Forces one completed temporary file to stable storage before publication.
     *
     * @param file temporary file containing complete exact bytes
     * @throws IOException if stable-storage synchronization fails
     */
    void forceFile(Path file) throws IOException;

    /**
     * Publishes one forced temporary file and durably records its directory entry.
     *
     * @param temporary forced sibling temporary file
     * @param target final descriptor or marker path
     * @param replaceExisting whether an existing target may be replaced
     * @throws IOException if publication or directory synchronization fails
     */
    void publish(Path temporary, Path target, boolean replaceExisting) throws IOException;
  }

  /** Narrow wrapper around the Windows write-through file-move primitive. */
  interface WindowsMove {
    /**
     * Moves one file with the supplied operating-system flags.
     *
     * @param source source path
     * @param target destination path
     * @param flags Windows move flags
     * @return whether the operating-system move succeeded
     */
    boolean move(String source, String target, int flags);

    /**
     * Returns the error code from the most recent failed move.
     *
     * @return Windows operating-system error code
     */
    int lastError();
  }

  /**
   * Selects the durable publication implementation for a known platform.
   *
   * @param windows whether Windows write-through move behavior is required
   * @param windowsMove Windows move adapter, required only when {@code windows} is true
   * @return platform-appropriate persistence synchronization implementation
   */
  static PersistenceSync persistenceSyncFor(boolean windows, WindowsMove windowsMove) {
    return windows
        ? new WindowsPersistenceSync(Objects.requireNonNull(windowsMove, "windowsMove"))
        : new FileChannelPersistenceSync();
  }

  /**
   * Selects durable publication behavior for the detected runtime platform.
   *
   * @return platform-appropriate persistence synchronization implementation
   */
  private static PersistenceSync platformPersistenceSync() {
    if (new AppEnv().isWindows()) {
      return persistenceSyncFor(true, new Kernel32WindowsMove());
    }
    return persistenceSyncFor(false, null);
  }

  /** Shared stable-file synchronization used before both Unix and Windows publication. */
  private abstract static class FilePersistenceSync implements PersistenceSync {
    /** Creates a stable-file synchronization implementation. */
    FilePersistenceSync() {}

    @Override
    public void forceFile(Path file) throws IOException {
      try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE)) {
        channel.force(true);
      }
    }
  }

  /** Filesystem publication using atomic moves and parent-directory synchronization. */
  private static final class FileChannelPersistenceSync extends FilePersistenceSync {
    /** Creates the filesystem-backed persistence implementation. */
    FileChannelPersistenceSync() {}

    @Override
    public void publish(Path temporary, Path target, boolean replaceExisting) throws IOException {
      try {
        if (replaceExisting) {
          Files.move(
              temporary,
              target,
              StandardCopyOption.ATOMIC_MOVE,
              StandardCopyOption.REPLACE_EXISTING);
        } else {
          Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE);
        }
      } catch (AtomicMoveNotSupportedException _) {
        if (replaceExisting) {
          Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
        } else {
          Files.move(temporary, target);
        }
      }
      Path directory = target.getParent();
      if (directory == null) {
        throw new IOException("lifecycle store target has no parent directory");
      }
      try (FileChannel channel = FileChannel.open(directory, StandardOpenOption.READ)) {
        channel.force(true);
      }
    }
  }

  /** Windows publication using the native write-through move operation. */
  private static final class WindowsPersistenceSync extends FilePersistenceSync {
    /** Native move adapter used to keep the implementation deterministic in tests. */
    private final WindowsMove windowsMove;

    /**
     * Creates a Windows persistence implementation.
     *
     * @param windowsMove native write-through move adapter
     */
    WindowsPersistenceSync(WindowsMove windowsMove) {
      this.windowsMove = windowsMove;
    }

    @Override
    public void publish(Path temporary, Path target, boolean replaceExisting) throws IOException {
      int flags = WinBase.MOVEFILE_WRITE_THROUGH;
      if (replaceExisting) {
        flags |= WinBase.MOVEFILE_REPLACE_EXISTING;
      }
      if (!windowsMove.move(temporary.toString(), target.toString(), flags)) {
        throw new IOException(
            "Windows lifecycle state publication failed with operating-system error "
                + windowsMove.lastError());
      }
    }
  }

  /** Production Windows move adapter backed by the platform Kernel32 API. */
  private static final class Kernel32WindowsMove implements WindowsMove {
    /** Creates the production native move adapter. */
    Kernel32WindowsMove() {}

    @Override
    public boolean move(String source, String target, int flags) {
      return Kernel32.INSTANCE.MoveFileEx(source, target, new DWORD(flags));
    }

    @Override
    public int lastError() {
      return Kernel32.INSTANCE.GetLastError();
    }
  }

  /** Closed result of inspecting the durable compromise marker. */
  enum TrustInvalidationStatus {
    /** Neither configured marker leaf exists. */
    ABSENT,

    /** At least one marker contains the exact authenticated invalidation record. */
    VALID,

    /** An existing marker or its path cannot be safely authenticated. */
    INVALID
  }

  /** Exact persisted descriptor bytes and their durable local verification timestamp. */
  @SuppressWarnings({"java:S6206", "ClassCanBeRecord"})
  // A record component would expose mutable array representation.
  static final class StoredDescriptor {
    /** Private exact-byte copy of the authenticated descriptor. */
    private final byte[] bytes;

    /** Durable last-modified timestamp set when these exact bytes were accepted. */
    private final Instant verifiedAt;

    /**
     * Creates an immutable stored-descriptor value.
     *
     * @param bytes exact authenticated descriptor bytes
     * @param verifiedAt local time at which the bytes were verified
     */
    StoredDescriptor(byte[] bytes, Instant verifiedAt) {
      this.bytes = bytes.clone();
      this.verifiedAt = verifiedAt;
    }

    /**
     * Returns a defensive copy of the exact descriptor bytes.
     *
     * @return independent descriptor byte array
     */
    byte[] bytes() {
      return bytes.clone();
    }

    /**
     * Returns the durable local verification time.
     *
     * @return verification timestamp stored as the file modification time
     */
    Instant verifiedAt() {
      return verifiedAt;
    }
  }
}
