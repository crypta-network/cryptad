package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * File-backed JSONL store for the local review transparency log.
 *
 * <p>The store persists one redacted {@link AppReviewTransparencyRecord} per line. Each append
 * reads the current file, de-duplicates receipt-observation records by stable record id, assigns
 * the next sequence number, links the previous hash, computes the new record hash, and appends a
 * canonical JSON object. Verification reparses the file and recomputes the same canonical chain.
 *
 * <p>The configured path is host-owned state. API, Web Shell, CLI, and release-certification
 * surfaces expose record counts, hashes, and redacted errors instead of filesystem paths or raw
 * JSONL lines. The store methods are synchronized because callers may share one store instance
 * across request handlers.
 *
 * @param logFile host-owned JSONL log file path
 */
public record FileAppReviewTransparencyStore(Path logFile) implements AppReviewTransparencyStore {
  /**
   * Default log file name below the review transparency directory.
   *
   * <p>Runtime composition may place this file under the catalog store root or another host-owned
   * state directory. The name is stable for CLI verification and release-certification fixtures.
   */
  public static final String LOG_FILE_NAME = "review-transparency-log.jsonl";

  public FileAppReviewTransparencyStore {
    logFile = Objects.requireNonNull(logFile, "logFile").toAbsolutePath().normalize();
  }

  /**
   * {@inheritDoc}
   *
   * <p>The file-backed implementation appends a single JSON object plus the platform line
   * separator. Missing parent directories are created lazily on the first write. If a matching
   * receipt observation already exists, the existing record is returned and the file is left
   * unchanged.
   */
  @Override
  public synchronized AppReviewTransparencyRecord append(AppReviewTransparencyRecord recordDraft)
      throws IOException {
    List<AppReviewTransparencyRecord> records = readAll();
    for (AppReviewTransparencyRecord existing : records) {
      if (Objects.equals(existing.recordId(), recordDraft.recordId())
          && existing.kind() == AppReviewTransparencyEventKind.REVIEW_RECEIPT_OBSERVED) {
        return existing;
      }
    }
    String previousHash = records.isEmpty() ? "" : records.getLast().recordHash();
    AppReviewTransparencyRecord appended =
        recordDraft.withChain(records.size() + 1L, previousHash, Instant.now());
    Files.createDirectories(logFile.getParent());
    Files.writeString(
        logFile,
        appended.toJsonLine() + System.lineSeparator(),
        StandardOpenOption.CREATE,
        StandardOpenOption.APPEND);
    return appended;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Records are read from the JSONL file in stored order, filtered after the cursor, and
   * returned in ascending sequence order. A missing file is treated as an empty log.
   */
  @Override
  public synchronized AppReviewTransparencyPage page(AppReviewTransparencyQuery query)
      throws IOException {
    AppReviewTransparencyQuery checkedQuery =
        query == null ? AppReviewTransparencyQuery.defaultQuery() : query;
    long cursor = checkedQuery.cursorSequence();
    List<AppReviewTransparencyRecord> page = new ArrayList<>();
    String nextCursor = null;
    for (AppReviewTransparencyRecord transparencyRecord : readAll()) {
      if (transparencyRecord.sequence() > cursor && checkedQuery.includes(transparencyRecord)) {
        if (page.size() >= checkedQuery.limit()) {
          nextCursor = Long.toString(page.getLast().sequence());
          break;
        }
        page.add(transparencyRecord);
      }
    }
    return new AppReviewTransparencyPage(page, nextCursor);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Malformed persisted records return a redacted failed result rather than leaking the bad line
   * or the local file path. IO failures are still surfaced to direct callers.
   */
  @Override
  public synchronized AppReviewTransparencyVerificationResult verify() throws IOException {
    try {
      return verifyRecords(readAll());
    } catch (AppCatalogException _) {
      return AppReviewTransparencyVerificationResult.failed(
          0L, null, "invalid review transparency record");
    }
  }

  /**
   * {@inheritDoc}
   *
   * <p>The count reflects non-blank persisted JSONL records that parse successfully. A missing file
   * counts as zero records.
   */
  @Override
  public synchronized long recordCount() throws IOException {
    return readAll().size();
  }

  /**
   * {@inheritDoc}
   *
   * <p>The latest hash is read from the final parsed record. A missing or empty file has no chain
   * head and returns {@code null}.
   */
  @Override
  public synchronized String latestRecordHash() throws IOException {
    List<AppReviewTransparencyRecord> records = readAll();
    return records.isEmpty() ? null : records.getLast().recordHash();
  }

  /**
   * Verifies a standalone log file.
   *
   * <p>This helper is used by developer tooling and release-certification checks when they receive
   * an explicit JSONL path. The returned result follows the same redaction rules as instance
   * verification and does not expose the supplied path.
   *
   * @param logFile host-owned JSONL log file to verify
   * @return redacted verification result for the standalone file
   * @throws IOException if the log file cannot be read by the current process
   */
  public static AppReviewTransparencyVerificationResult verifyFile(Path logFile)
      throws IOException {
    return new FileAppReviewTransparencyStore(logFile).verify();
  }

  static AppReviewTransparencyVerificationResult verifyRecords(
      List<AppReviewTransparencyRecord> records) {
    String previousHash = "";
    long expectedSequence = 1L;
    for (AppReviewTransparencyRecord transparencyRecord : records) {
      if (transparencyRecord.sequence() != expectedSequence) {
        return AppReviewTransparencyVerificationResult.failed(
            records.size(), previousHash, "record sequence gap at " + expectedSequence);
      }
      if (!previousHash.equals(transparencyRecord.previousRecordHash())) {
        return AppReviewTransparencyVerificationResult.failed(
            records.size(),
            previousHash,
            "previous hash mismatch at " + transparencyRecord.sequence());
      }
      String recomputedHash = transparencyRecord.computeRecordHash();
      if (!recomputedHash.equals(transparencyRecord.recordHash())) {
        return AppReviewTransparencyVerificationResult.failed(
            records.size(),
            previousHash,
            "record hash mismatch at " + transparencyRecord.sequence());
      }
      previousHash = transparencyRecord.recordHash();
      expectedSequence++;
    }
    return AppReviewTransparencyVerificationResult.verified(records.size(), previousHash);
  }

  private List<AppReviewTransparencyRecord> readAll() throws IOException {
    if (!Files.isRegularFile(logFile)) {
      return List.of();
    }
    List<AppReviewTransparencyRecord> records = new ArrayList<>();
    for (String line : Files.readAllLines(logFile)) {
      if (!line.isBlank()) {
        records.add(parseRecordLine(line));
      }
    }
    return List.copyOf(records);
  }

  private static AppReviewTransparencyRecord parseRecordLine(String line) {
    try {
      return AppReviewTransparencyRecord.parseJsonLine(line);
    } catch (AppCatalogException exception) {
      throw exception;
    } catch (RuntimeException exception) {
      throw new AppCatalogException(
          AppCatalogSidecars.INVALID_CATALOG_ENTRY,
          "invalid review transparency record",
          exception);
    }
  }
}
