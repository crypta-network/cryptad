package network.crypta.platform.trustgraph;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Deterministic direct-anchor Trust Graph Preview scorer.
 *
 * <p>The scorer is deliberately small. It does not crawl the network, follow transitive trust
 * chains, subscribe to feeds, or apply content-blocking decisions. For one subject/context query it
 * scans retained local statements, records bounded evidence, and computes a confidence-weighted
 * average from statements that pass every contribution gate.
 *
 * <p>A statement contributes only when its issuer fingerprint is a local anchor, its signature
 * verified against issuer public key material, it is not expired at the scorer clock, and its
 * confidence is greater than zero. All other matching statements can still appear as evidence.
 */
public final class TrustGraphScorer {
  private static final int MAX_EVIDENCE_ROWS = 25;

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
      boolean contributes =
          anchored && statement.signatureVerified() && !expired && payload.confidence() > 0;
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
                contributes,
                expired,
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
        List.copyOf(evidence));
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
