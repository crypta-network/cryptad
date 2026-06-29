package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * File-backed public-beta app submission intake queue.
 *
 * <p>The store layout is deterministic:
 *
 * <pre>
 * queue/
 *   records/&lt;submission-id&gt;.json
 *   submissions/&lt;submission-id&gt;.zip
 * </pre>
 *
 * <p>Only the copied submission ZIP contains raw package bytes. Queue records remain safe metadata
 * JSON. The record JSON never stores absolute local paths; the store derives queue-owned paths from
 * the configured queue directory and normalized submission id.
 *
 * @param queueDir local host-owned queue directory
 */
public record FileAppSubmissionIntakeStore(Path queueDir) implements AppSubmissionIntakeStore {
  private static final String RECORDS_DIR = "records";
  private static final String SUBMISSIONS_DIR = "submissions";

  public FileAppSubmissionIntakeStore {
    queueDir = Objects.requireNonNull(queueDir, "queueDir").toAbsolutePath().normalize();
  }

  @Override
  public synchronized AppSubmissionIntakeRecord importSubmission(
      Path submissionZip, Instant importedAt) throws IOException {
    Path submissionsDir = queueDir.resolve(SUBMISSIONS_DIR);
    Files.createDirectories(submissionsDir);
    Path temporaryPackage = Files.createTempFile(submissionsDir, "incoming-", ".zip.tmp");
    boolean moved = false;
    try {
      Files.copy(
          submissionZip.toAbsolutePath().normalize(),
          temporaryPackage,
          StandardCopyOption.REPLACE_EXISTING);
      AppSubmissionPackage submission = AppSubmissionPackageVerifier.verify(temporaryPackage);
      AppSubmissionIntakeRecord intakeRecord =
          AppSubmissionIntakeRecord.fromSubmission(submission, importedAt);
      Path recordPath = recordPath(intakeRecord.submissionId());
      Path packagePath = submissionPackagePath(intakeRecord.submissionId());
      if (Files.exists(recordPath, LinkOption.NOFOLLOW_LINKS)
          || Files.exists(packagePath, LinkOption.NOFOLLOW_LINKS)) {
        throw new FileAlreadyExistsException(
            "submission already exists: " + intakeRecord.submissionId());
      }
      Files.createDirectories(recordPath.getParent());
      moveAtomically(temporaryPackage, packagePath);
      moved = true;
      try {
        writeRecord(recordPath, intakeRecord);
      } catch (IOException | RuntimeException exception) {
        Files.deleteIfExists(packagePath);
        throw exception;
      }
      return intakeRecord;
    } finally {
      if (!moved) {
        Files.deleteIfExists(temporaryPackage);
      }
    }
  }

  @Override
  public synchronized Optional<AppSubmissionIntakeRecord> load(String submissionId)
      throws IOException {
    Path recordPath = recordPath(submissionId);
    if (!Files.isRegularFile(recordPath, LinkOption.NOFOLLOW_LINKS)) {
      return Optional.empty();
    }
    return Optional.of(
        AppSubmissionIntakeRecord.parse(
            Files.readString(recordPath, java.nio.charset.StandardCharsets.UTF_8)));
  }

  @Override
  public synchronized void save(AppSubmissionIntakeRecord intakeRecord) throws IOException {
    Path recordPath = recordPath(intakeRecord.submissionId());
    if (!Files.isRegularFile(
        submissionPackagePath(intakeRecord.submissionId()), LinkOption.NOFOLLOW_LINKS)) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, "submission package is missing from queue");
    }
    Files.createDirectories(recordPath.getParent());
    writeRecord(recordPath, intakeRecord);
  }

  @Override
  public synchronized List<AppSubmissionIntakeSummary> listSummaries() throws IOException {
    Path recordsDir = queueDir.resolve(RECORDS_DIR);
    if (!Files.isDirectory(recordsDir, LinkOption.NOFOLLOW_LINKS)) {
      return List.of();
    }
    try (var stream = Files.list(recordsDir)) {
      return stream
          .filter(path -> path.getFileName().toString().endsWith(".json"))
          .sorted(Comparator.comparing(path -> path.getFileName().toString()))
          .map(FileAppSubmissionIntakeStore::parseRecordUnchecked)
          .map(AppSubmissionIntakeRecord::toSummary)
          .toList();
    }
  }

  @Override
  public Path submissionPackagePath(String submissionId) {
    return queueDir
        .resolve(SUBMISSIONS_DIR)
        .resolve(safeSubmissionIdComponent(submissionId) + ".zip");
  }

  private Path recordPath(String submissionId) {
    return queueDir.resolve(RECORDS_DIR).resolve(safeSubmissionIdComponent(submissionId) + ".json");
  }

  private static AppSubmissionIntakeRecord parseRecordUnchecked(Path path) {
    try {
      return AppSubmissionIntakeRecord.parse(
          Files.readString(path, java.nio.charset.StandardCharsets.UTF_8));
    } catch (IOException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY, "failed to read intake record", exception);
    }
  }

  private static void writeRecord(Path recordPath, AppSubmissionIntakeRecord intakeRecord)
      throws IOException {
    Path temporary = recordPath.resolveSibling(recordPath.getFileName() + ".tmp");
    Files.writeString(
        temporary,
        intakeRecord.toJson(),
        java.nio.charset.StandardCharsets.UTF_8,
        StandardOpenOption.CREATE,
        StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE);
    try {
      Files.move(
          temporary,
          recordPath,
          StandardCopyOption.REPLACE_EXISTING,
          StandardCopyOption.ATOMIC_MOVE);
    } catch (IOException _) {
      Files.move(temporary, recordPath, StandardCopyOption.REPLACE_EXISTING);
    }
  }

  private static void moveAtomically(Path source, Path target) throws IOException {
    try {
      Files.move(source, target, StandardCopyOption.ATOMIC_MOVE);
    } catch (AtomicMoveNotSupportedException _) {
      Files.move(source, target);
    }
  }

  /**
   * Returns a queue filename component derived from a submission id.
   *
   * <p>Submission ids are also used by CLI defaults for per-submission artifact directories, so dot
   * path segments are rejected even though record and package files append an extension.
   *
   * @param submissionId metadata submission id supplied by the package or operator
   * @return path-component-safe submission id
   */
  public static String safeSubmissionIdComponent(String submissionId) {
    String value =
        AppCatalogSidecars.requireBoundedSingleLine(
            submissionId, "submissionId", AppCatalogSidecars.INVALID_CATALOG_ENTRY, 96);
    if (!value.matches("[A-Za-z0-9._-]+")) {
      throw AppCatalogSidecars.invalidEntry("submissionId contains unsafe path characters");
    }
    if (".".equals(value) || "..".equals(value)) {
      throw AppCatalogSidecars.invalidEntry("submissionId must not be a dot path segment");
    }
    return value;
  }
}
