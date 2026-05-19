package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * In-memory transparency store used by tests and no-filesystem embeddings.
 *
 * <p>The store mirrors the file-backed sequencing, receipt-observation de-duplication, previous
 * hash linking, and verification logic without touching the filesystem. It is useful for unit
 * tests, API handler fixtures, and controlled embeddings that need governance behavior but do not
 * want durable local state.
 *
 * <p>Records live only for the lifetime of this object. A successful verification result from this
 * store proves that the in-memory chain is internally consistent, not that release-candidate
 * evidence was persisted. Methods are synchronized so a shared test fixture behaves predictably
 * when accessed from multiple request paths.
 */
public final class InMemoryAppReviewTransparencyStore implements AppReviewTransparencyStore {
  private final List<AppReviewTransparencyRecord> records = new ArrayList<>();

  /**
   * Creates an empty in-memory transparency store.
   *
   * <p>The store starts with no records and assigns sequence {@code 1} to the first appended draft.
   * It keeps all state in this object and does not create local files or directories.
   */
  public InMemoryAppReviewTransparencyStore() {
    // State is initialized by the field declaration; the public constructor exists for doclint.
  }

  /**
   * {@inheritDoc}
   *
   * <p>The in-memory implementation assigns the next sequence and hash-chain fields immediately.
   * Duplicate receipt observation records return the existing record and leave the list unchanged.
   */
  @Override
  public synchronized AppReviewTransparencyRecord append(AppReviewTransparencyRecord recordDraft)
      throws IOException {
    for (AppReviewTransparencyRecord existing : records) {
      if (Objects.equals(existing.recordId(), recordDraft.recordId())
          && existing.kind() == AppReviewTransparencyEventKind.REVIEW_RECEIPT_OBSERVED) {
        return existing;
      }
    }
    String previousHash = records.isEmpty() ? "" : records.getLast().recordHash();
    AppReviewTransparencyRecord appended =
        recordDraft.withChain(records.size() + 1L, previousHash, Instant.now());
    records.add(appended);
    return appended;
  }

  /**
   * {@inheritDoc}
   *
   * <p>Filtering and cursor handling match {@link FileAppReviewTransparencyStore}. The returned
   * page contains immutable snapshots of the currently stored records.
   */
  @Override
  public synchronized AppReviewTransparencyPage page(AppReviewTransparencyQuery query) {
    AppReviewTransparencyQuery checkedQuery =
        query == null ? AppReviewTransparencyQuery.defaultQuery() : query;
    long cursor = checkedQuery.cursorSequence();
    List<AppReviewTransparencyRecord> page = new ArrayList<>();
    String nextCursor = null;
    for (AppReviewTransparencyRecord transparencyRecord : records) {
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
   * <p>Verification delegates to the shared record-chain verifier so in-memory tests exercise the
   * same canonical hash behavior as persisted JSONL logs.
   */
  @Override
  public synchronized AppReviewTransparencyVerificationResult verify() {
    return FileAppReviewTransparencyStore.verifyRecords(records);
  }

  /**
   * {@inheritDoc}
   *
   * <p>The count reflects records currently held by this store instance.
   */
  @Override
  public synchronized long recordCount() {
    return records.size();
  }

  /**
   * {@inheritDoc}
   *
   * <p>The latest hash is the hash of the final in-memory record, or {@code null} when no records
   * have been appended.
   */
  @Override
  public synchronized String latestRecordHash() {
    return records.isEmpty() ? null : records.getLast().recordHash();
  }
}
