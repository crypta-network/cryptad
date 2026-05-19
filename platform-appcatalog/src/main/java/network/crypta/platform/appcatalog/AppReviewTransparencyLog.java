package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Local host-owned review transparency log facade.
 *
 * <p>This is not a global public log and does not change catalog, bundle, receipt, or update-gate
 * verification. It records redacted local governance events in a hash chain so operators can see
 * how local review trust decisions changed over time.
 *
 * <p>The facade is the safety boundary used by catalog install, update, API, and certification
 * code. Append methods are intentionally best-effort: malformed or unavailable log storage is
 * contained inside this class so audit logging cannot turn a valid install or update into a
 * failure. Read methods return redacted empty or failed summaries when storage cannot be read.
 * Callers that need a hard release gate should verify the returned {@link
 * AppReviewTransparencyVerificationResult} rather than relying on exceptions.
 *
 * <p>Instances are immutable wrappers around a store implementation. File-backed instances persist
 * JSONL records, in-memory instances are deterministic test fixtures, and the disabled singleton is
 * a no-op for deployments that have not configured host-owned governance state.
 */
public final class AppReviewTransparencyLog {
  private static final AppReviewTransparencyLog DISABLED =
      new AppReviewTransparencyLog(new NoOpStore(), false);

  private final AppReviewTransparencyStore store;
  private final boolean configured;

  /**
   * Redacted app and artifact identity for review-trust map events.
   *
   * <p>Update and API paths often have review governance data as a JSON-compatible {@code
   * reviewTrust} map rather than a full catalog entry. This subject carries the catalog-facing
   * fields that identify the candidate being evaluated without bundling local paths, process state,
   * app browser sessions, or other host-only details into the transparency record.
   *
   * @param appId app id for the candidate being evaluated
   * @param appVersion candidate app version displayed to operators
   * @param catalogId catalog id that supplied the candidate, when known
   * @param artifactSha256 lowercase SHA-256 digest of the candidate artifact
   * @param artifactSizeBytes candidate artifact size in bytes
   */
  public record ReviewTrustMapSubject(
      String appId,
      String appVersion,
      String catalogId,
      String artifactSha256,
      long artifactSizeBytes) {}

  private AppReviewTransparencyLog(AppReviewTransparencyStore store, boolean configured) {
    this.store = Objects.requireNonNull(store, "store");
    this.configured = configured;
  }

  /**
   * Returns a disabled no-op log.
   *
   * <p>The disabled instance reports no records and accepts append calls without side effects. It
   * is useful when runtime composition has not configured a host-owned log location, and it lets
   * callers keep one code path without treating audit logging as mandatory.
   *
   * @return shared disabled log that never persists records
   */
  public static AppReviewTransparencyLog disabled() {
    return DISABLED;
  }

  /**
   * Returns an in-memory log.
   *
   * <p>The store assigns the same sequence and hash-chain metadata as the file-backed store but
   * does not write to disk. Tests and embedded callers use it to exercise governance surfaces
   * without creating local state or exposing filesystem paths.
   *
   * @return configured in-memory transparency log
   */
  public static AppReviewTransparencyLog inMemory() {
    return new AppReviewTransparencyLog(new InMemoryAppReviewTransparencyStore(), true);
  }

  /**
   * Returns a file-backed JSONL log.
   *
   * <p>The file path is host-owned local state and must not be exposed through API, CLI, Web Shell,
   * or certification output. The underlying store creates parent directories lazily when the first
   * record is appended.
   *
   * @param logFile local JSONL file used for redacted transparency records
   * @return configured file-backed transparency log
   */
  public static AppReviewTransparencyLog fileBacked(Path logFile) {
    return new AppReviewTransparencyLog(new FileAppReviewTransparencyStore(logFile), true);
  }

  /**
   * Returns whether the log is configured for append and read operations.
   *
   * <p>A configured log may still be temporarily unreadable or contain malformed records. Use
   * {@link #verify()} when the caller needs to distinguish an available, intact hash chain from a
   * best-effort failure summary.
   *
   * @return {@code true} when a real store is attached to this facade
   */
  public boolean configured() {
    return configured;
  }

  /**
   * Appends a record draft, failing only inside this method.
   *
   * <p>The store assigns sequence, creation time, previous hash, and record hash. IO failures,
   * parser failures while reading existing records, and other runtime failures are swallowed so
   * review logging never changes install, update, or verification behavior. Callers should treat
   * this as audit the best effort rather than durable confirmation.
   *
   * @param recordDraft unchained redacted record draft to persist when storage is available
   */
  public void appendBestEffort(AppReviewTransparencyRecord recordDraft) {
    if (!configured) {
      return;
    }
    try {
      store.append(recordDraft);
    } catch (IOException | RuntimeException _) {
      // Review logging must not change install/update security semantics.
    }
  }

  /**
   * Records a redacted catalog-app review decision and receipt observation, when present.
   *
   * <p>If the catalog entry contains an independent receipt, a de-duplicated {@code
   * review_receipt_observed} record is written using fields from the receipt payload. The requested
   * event kind is then appended with the local trust decision and any additional warning strings.
   * Both records are redacted and best-effort; a corrupt log cannot block the gate that produced
   * the decision.
   *
   * @param kind event kind that describes the local evaluation or gate path
   * @param catalogId catalog id associated with the candidate entry
   * @param entry catalog entry whose receipt and artifact metadata were evaluated
   * @param decision local trust decision produced by the receipt verifier
   * @param warnings extra bounded event warnings supplied by the caller
   */
  public void recordCatalogDecision(
      AppReviewTransparencyEventKind kind,
      String catalogId,
      AppCatalogEntry entry,
      AppReviewTrustDecision decision,
      List<String> warnings) {
    if (!configured) {
      return;
    }
    try {
      entry.reviewReceipt().ifPresent(receipt -> recordReceiptObserved(catalogId, receipt));
      List<String> combinedWarnings = new ArrayList<>(decision.warnings());
      if (warnings != null) {
        combinedWarnings.addAll(warnings);
      }
      appendBestEffort(
          AppReviewTransparencyRecord.fromCatalogDecision(
              kind, catalogId, entry, decision, combinedWarnings));
    } catch (RuntimeException _) {
      // Logging must not change review-gate behavior.
    }
  }

  /**
   * Records a redacted app-update review gate decision from a reviewTrust map.
   *
   * <p>Update scheduler and API code sometimes carry review trust as JSON-compatible maps rather
   * than full catalog entries. This method preserves the same redaction and hash-chain behavior for
   * those paths. Missing optional trust fields remain absent in the resulting record; malformed
   * values are contained by the best-effort wrapper.
   *
   * @param kind event kind that describes the update or policy gate being recorded
   * @param subject redacted app and artifact identity for the candidate
   * @param reviewTrust JSON-compatible reviewTrust map from API or scheduler code
   * @param warnings bounded warnings that explain gate context or acknowledgements
   */
  public void recordReviewTrustMap(
      AppReviewTransparencyEventKind kind,
      ReviewTrustMapSubject subject,
      Map<String, Object> reviewTrust,
      List<String> warnings) {
    try {
      ReviewTrustMapSubject checkedSubject = Objects.requireNonNull(subject, "subject");
      appendBestEffort(
          AppReviewTransparencyRecord.fromReviewTrustMap(
              kind,
              checkedSubject.appId(),
              checkedSubject.appVersion(),
              checkedSubject.catalogId(),
              checkedSubject.artifactSha256(),
              checkedSubject.artifactSizeBytes(),
              reviewTrust,
              warnings == null ? List.of() : warnings));
    } catch (RuntimeException _) {
      // Logging must not change update lifecycle behavior.
    }
  }

  /**
   * Returns one bounded page, or an empty page if unavailable.
   *
   * <p>The query defaults to {@link AppReviewTransparencyQuery#defaultQuery()} when {@code null}.
   * Any IO or parser failure is converted to an empty page to keep operator API reads redacted and
   * non-disruptive. Callers that need tamper evidence should call {@link #verify()} separately.
   *
   * @param query optional bounded query with cursor and filter constraints
   * @return matching redacted page, or an empty page when the log cannot be read
   */
  public AppReviewTransparencyPage page(AppReviewTransparencyQuery query) {
    if (!configured) {
      return new AppReviewTransparencyPage(List.of(), null);
    }
    try {
      return store.page(query == null ? AppReviewTransparencyQuery.defaultQuery() : query);
    } catch (IOException | RuntimeException _) {
      return new AppReviewTransparencyPage(List.of(), null);
    }
  }

  /**
   * Verifies the hash chain and returns a redacted result.
   *
   * <p>The verification result never includes the local store path or raw record contents. Disabled
   * logs verify as an empty chain because there is no configured local evidence to inspect. A
   * configured but unreadable or malformed log returns a failed result with a stable, display-safe
   * error string.
   *
   * @return verification status, record count, latest hash, and redacted error text
   */
  public AppReviewTransparencyVerificationResult verify() {
    if (!configured) {
      return AppReviewTransparencyVerificationResult.verified(0L, null);
    }
    try {
      return store.verify();
    } catch (IOException | RuntimeException _) {
      return AppReviewTransparencyVerificationResult.failed(
          0L, null, "review transparency log unavailable");
    }
  }

  /**
   * Returns the record count, or zero when unavailable.
   *
   * <p>This is a summary helper for governance status responses. It intentionally hides read
   * failures because verification is the explicit API for diagnosing log integrity.
   *
   * @return number of persisted records, or {@code 0} for disabled or unreadable logs
   */
  public long recordCount() {
    if (!configured) {
      return 0L;
    }
    try {
      return store.recordCount();
    } catch (IOException | RuntimeException _) {
      return 0L;
    }
  }

  /**
   * Returns the latest record hash, or {@code null} when empty or unavailable.
   *
   * <p>The latest hash is display-safe evidence for the current local chain head. It is not a
   * global checkpoint and should not be interpreted as public consensus about review state.
   *
   * @return lowercase SHA-256 chain head, or {@code null} when no head is available
   */
  public String latestRecordHash() {
    if (!configured) {
      return null;
    }
    try {
      return store.latestRecordHash();
    } catch (IOException | RuntimeException _) {
      return null;
    }
  }

  private void recordReceiptObserved(String catalogId, AppReviewReceipt receipt) {
    try {
      AppReviewReceiptPayload payload = receipt.payload();
      appendBestEffort(
          new AppReviewTransparencyRecord(
              AppReviewTransparencyRecord.SCHEMA_VERSION,
              0L,
              "receipt:" + receiptFingerprint(receipt),
              null,
              AppReviewTransparencyEventKind.REVIEW_RECEIPT_OBSERVED,
              "app",
              payload.appId(),
              payload.appVersion(),
              catalogId,
              payload.artifactSha256(),
              payload.artifactSizeBytes(),
              payload.reviewerKeyId(),
              null,
              payload.policyId(),
              payload.policyVersion(),
              payload.status().catalogValue(),
              null,
              null,
              null,
              null,
              null,
              null,
              null,
              payload.evidenceSha256().orElse(null),
              payload.evidenceUri().map(Object::toString).orElse(null),
              null,
              null,
              List.of()));
    } catch (RuntimeException _) {
      // Logging must not change catalog behavior.
    }
  }

  private static String receiptFingerprint(AppReviewReceipt receipt) {
    MessageDigest digest = AppCatalogSidecars.newArtifactSha256Digest();
    digest.update(receipt.payload().canonicalPayloadBytes());
    digest.update(receipt.signature().signatureBytes());
    return AppCatalogSidecars.lowercaseHex(digest.digest());
  }

  private static final class NoOpStore implements AppReviewTransparencyStore {
    @Override
    public AppReviewTransparencyRecord append(AppReviewTransparencyRecord recordDraft) {
      return recordDraft;
    }

    @Override
    public AppReviewTransparencyPage page(AppReviewTransparencyQuery query) {
      return new AppReviewTransparencyPage(List.of(), null);
    }

    @Override
    public AppReviewTransparencyVerificationResult verify() {
      return AppReviewTransparencyVerificationResult.verified(0L, null);
    }

    @Override
    public long recordCount() {
      return 0L;
    }

    @Override
    public String latestRecordHash() {
      return null;
    }
  }
}
