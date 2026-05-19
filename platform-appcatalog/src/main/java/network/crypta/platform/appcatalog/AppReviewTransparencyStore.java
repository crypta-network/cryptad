package network.crypta.platform.appcatalog;

import java.io.IOException;

/**
 * Persistence boundary for local review transparency records.
 *
 * <p>Stores are responsible for assigning append metadata and preserving the local hash chain.
 * Callers normally use {@link AppReviewTransparencyLog}, which wraps this interface with
 * best-effort behavior for install and update paths. Direct store callers, including tests and CLI
 * verification code, receive {@link IOException} when storage cannot be read or written.
 *
 * <p>Implementations must keep records redacted. They should never persist private reviewer keys,
 * raw public key bytes, local browser sessions, process tokens, scratch paths, request bodies, or
 * receipt signatures. The file-backed implementation writes JSONL records; the in-memory
 * implementation mirrors the same sequencing and verification rules for deterministic tests.
 */
public interface AppReviewTransparencyStore {
  /**
   * Appends one record draft and assigns sequence/hash-chain metadata.
   *
   * <p>The supplied record is expected to have draft values for sequence, timestamps, and hash
   * fields. The store reads the current chain head, assigns the next sequence, sets the previous
   * hash, computes the record hash, persists the result, and returns the chained record. Receipt
   * observation records may be de-duplicated by stable record id.
   *
   * @param recordDraft unchained redacted record draft to append
   * @return chained record that was persisted or matched by de-duplication
   * @throws IOException if the backing store cannot be read or written
   */
  AppReviewTransparencyRecord append(AppReviewTransparencyRecord recordDraft) throws IOException;

  /**
   * Reads one bounded page.
   *
   * <p>Stores should apply cursor, limit, and filter constraints after reading records in sequence
   * order. Implementations may treat a {@code null} query as {@link
   * AppReviewTransparencyQuery#defaultQuery()} to match facade behavior.
   *
   * @param query bounded query with cursor and optional filters
   * @return matching redacted page in ascending sequence order
   * @throws IOException if records cannot be read from the backing store
   */
  AppReviewTransparencyPage page(AppReviewTransparencyQuery query) throws IOException;

  /**
   * Recomputes the local hash chain.
   *
   * <p>Verification checks sequence continuity, previous-hash linkage, and each record hash over
   * the canonical fields understood by the current schema. A failed result should be redacted and
   * must not include local paths or raw record bodies.
   *
   * @return verification result with record count and latest verified hash
   * @throws IOException if records cannot be read from the backing store
   */
  AppReviewTransparencyVerificationResult verify() throws IOException;

  /**
   * Returns the number of stored records.
   *
   * <p>The count is a summary helper for governance status and should reflect the number of
   * non-blank persisted records that parse successfully.
   *
   * @return number of stored transparency records
   * @throws IOException if records cannot be read from the backing store
   */
  long recordCount() throws IOException;

  /**
   * Returns the latest record hash, or {@code null} when empty.
   *
   * <p>The latest hash is the current local chain head. It is display-safe but not a global
   * checkpoint, and callers must still verify the chain before treating it as integrity evidence.
   *
   * @return latest local record hash, or {@code null} for an empty store
   * @throws IOException if records cannot be read from the backing store
   */
  String latestRecordHash() throws IOException;
}
