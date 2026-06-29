package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Durable local queue for public-beta third-party submission intake records.
 *
 * <p>Implementations own storage of queue metadata and copied submission packages. Public read
 * methods return redacted metadata models only; callers that need raw submission ZIP bytes must
 * explicitly resolve the copied submission package path for local reviewer tooling.
 */
public interface AppSubmissionIntakeStore {
  /**
   * Imports a verified submission ZIP into the queue.
   *
   * @param submissionZip source submission package
   * @param importedAt import timestamp
   * @return created intake record
   */
  AppSubmissionIntakeRecord importSubmission(Path submissionZip, Instant importedAt)
      throws IOException;

  /**
   * Loads one record by submission id.
   *
   * @param submissionId submission id
   * @return matching record when present
   */
  Optional<AppSubmissionIntakeRecord> load(String submissionId) throws IOException;

  /**
   * Persists an updated record.
   *
   * @param intakeRecord record to save
   */
  void save(AppSubmissionIntakeRecord intakeRecord) throws IOException;

  /**
   * Lists all queue summaries sorted by submission id.
   *
   * @return operator-safe summaries
   */
  List<AppSubmissionIntakeSummary> listSummaries() throws IOException;

  /**
   * Resolves the queue-owned copy of a submission package for local reviewer tooling.
   *
   * @param submissionId submission id
   * @return queue-owned submission package path
   */
  Path submissionPackagePath(String submissionId);
}
