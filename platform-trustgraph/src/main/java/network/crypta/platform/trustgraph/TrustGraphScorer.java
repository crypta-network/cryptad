package network.crypta.platform.trustgraph;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Deterministic direct-anchor Trust Graph local RC scorer.
 *
 * <p>The scorer is deliberately small. It does not crawl the network, follow transitive trust
 * chains, subscribe to feeds, or apply content-blocking decisions. For one subject/context query it
 * scans retained local statements, records bounded evidence, and computes a confidence-weighted
 * average from statements that pass every contribution gate.
 *
 * <p>A statement contributes only when its issuer fingerprint is a local anchor. Its signature must
 * verify against issuer public key material, and it must not be expired at the scorer clock.
 * Confidence must be greater than zero, and the local lifecycle status must be active. Deprecated
 * and revoked local lifecycle records remain visible as explanation evidence but cannot affect
 * scores.
 */
public final class TrustGraphScorer {
  /** Maximum evidence rows returned for one score explanation. */
  public static final int MAX_EVIDENCE_ROWS = 25;

  private final TrustGraphStore store;
  private final Clock clock;

  /**
   * Creates a scorer over one local trust graph store.
   *
   * @param store local store supplying retained statements and anchor lookups
   * @param clock clock used to decide whether retained statements are expired
   */
  public TrustGraphScorer(TrustGraphStore store, Clock clock) {
    this.store = java.util.Objects.requireNonNull(store, "store");
    this.clock = java.util.Objects.requireNonNull(clock, "clock");
  }

  /**
   * Scores one subject/context query using only direct local trust anchors.
   *
   * @param query subject and context to match exactly against retained statement payloads
   * @return deterministic score summary with bounded evidence rows
   */
  public TrustGraphScore score(TrustGraphQuery query) {
    Instant now = clock.instant();
    ArrayList<TrustGraphEvidence> evidence = new ArrayList<>();
    long weightedScoreSum = 0;
    long confidenceSum = 0;
    int contributing = 0;
    int evidenceCount = 0;
    boolean hasPositive = false;
    boolean hasNegative = false;
    for (TrustGraphStore.StoredTrustStatement statement : store.statements()) {
      TrustStatementPayload payload = statement.document().payload();
      if (!query.matches(payload)) {
        continue;
      }
      boolean expired = payload.expiredAt(now);
      boolean anchored = store.isAnchor(payload.issuer().publicKeyFingerprint());
      TrustStatementLifecycleStatus lifecycleStatus =
          store.lifecycle(statement.documentFingerprint()).status();
      List<String> nonContributingReasons =
          nonContributingReasons(statement, anchored, expired, lifecycleStatus);
      boolean contributes = nonContributingReasons.isEmpty();
      evidenceCount++;
      if (contributes) {
        weightedScoreSum += (long) payload.score() * payload.confidence();
        confidenceSum += payload.confidence();
        contributing++;
        hasPositive |= payload.score() > 0;
        hasNegative |= payload.score() < 0;
      }
      if (evidence.size() < MAX_EVIDENCE_ROWS) {
        evidence.add(
            new TrustGraphEvidence(
                payload.issuer().publicKeyFingerprint(),
                payload.score(),
                payload.confidence(),
                payload.issuedAt(),
                payload.expiresAt(),
                statement.signatureVerified(),
                anchored,
                contributes,
                expired,
                lifecycleStatus,
                nonContributingReasons,
                statement.source()));
      }
    }
    int score = confidenceSum == 0 ? 0 : Math.round((float) weightedScoreSum / confidenceSum);
    int confidence = contributing == 0 ? 0 : Math.round((float) confidenceSum / contributing);
    String status = status(contributing, score, hasPositive, hasNegative);
    return new TrustGraphScore(
        new TrustSubject(query.subjectKind(), query.subjectUri(), null),
        query.context(),
        status,
        score,
        confidence,
        evidenceCount,
        contributing,
        evidenceCount > evidence.size(),
        MAX_EVIDENCE_ROWS,
        List.copyOf(evidence));
  }

  private static List<String> nonContributingReasons(
      TrustGraphStore.StoredTrustStatement statement,
      boolean anchored,
      boolean expired,
      TrustStatementLifecycleStatus lifecycleStatus) {
    ArrayList<String> reasons = new ArrayList<>();
    TrustStatementPayload payload = statement.document().payload();
    if (!anchored) {
      reasons.add("unanchored");
    }
    if (!statement.signatureVerified()) {
      reasons.add("unverified");
    }
    if (expired) {
      reasons.add("expired");
    }
    if (payload.confidence() == 0) {
      reasons.add("zero-confidence");
    }
    if (lifecycleStatus == TrustStatementLifecycleStatus.REVOKED) {
      reasons.add("revoked");
    } else if (lifecycleStatus == TrustStatementLifecycleStatus.DEPRECATED) {
      reasons.add("deprecated");
    }
    return List.copyOf(reasons);
  }

  private static String status(
      int contributing, int score, boolean hasPositive, boolean hasNegative) {
    if (contributing == 0) {
      return "unknown";
    }
    if (hasPositive && hasNegative) {
      return "mixed";
    }
    if (score > 0) {
      return "trusted";
    }
    if (score < 0) {
      return "distrusted";
    }
    return "mixed";
  }
}
