package network.crypta.platform.appcatalog;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Verifies app review receipts against a separate trusted-reviewer registry.
 *
 * <p>Verification is independent of signed catalog and signed bundle verification. The verifier
 * checks that the receipt binds to the catalog entry, that it has not expired, that the reviewer
 * key is configured for the named policy, and that Ed25519 verifies over the payload's canonical
 * bytes.
 *
 * <p>The verifier returns a display-safe {@link AppReviewTrustDecision} instead of throwing for
 * normal trust failures. Missing receipts, unknown reviewers, expired receipts, binding mismatches,
 * and invalid signatures all become stable statuses and redacted warnings. That behavior lets API,
 * Web Shell, CLI, and release-certification callers report the same failure mode without exposing
 * reviewer public key bytes, private key material, local paths, or staging directories.
 *
 * <p>Trust is local. A catalog may carry publisher advisory review metadata and an embedded
 * receipt, but this class decides whether the receipt is meaningful on the current node by using
 * the supplied {@link TrustedReviewerKeys}, {@link AppReviewPolicy}, and clock value.
 */
public final class AppReviewReceiptVerifier {
  private AppReviewReceiptVerifier() {}

  /**
   * Evaluates review trust for one catalog entry.
   *
   * <p>This is the normal catalog path. The method reads advisory publisher review metadata and the
   * optional embedded receipt from the entry, then evaluates both against local reviewer trust. The
   * catalog signature is assumed to have been checked before the entry reached this method.
   *
   * @param entry catalog entry that may carry an embedded review receipt
   * @param trustedReviewerKeys local reviewer trust registry used for key lookup
   * @param policy local review policy used to derive blocking flags
   * @param now time used for strict receipt expiry checks
   * @return display-safe review trust decision for API and UI responses
   */
  public static AppReviewTrustDecision evaluate(
      AppCatalogEntry entry,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy policy,
      Instant now) {
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(now, "now");
    return evaluate(ReviewEvaluationTarget.catalogEntry(entry), trustedReviewerKeys, policy, now);
  }

  /**
   * Evaluates a standalone review receipt against one catalog entry.
   *
   * <p>This overload is used by offline developer tooling before a receipt has been embedded into a
   * signed catalog. It performs the same binding, expiry, reviewer-key, and signature checks as
   * catalog-entry evaluation.
   *
   * <p>The receipt still must bind to the entry app id, version, artifact digest, and artifact
   * size. A valid signature over the wrong artifact produces a mismatch status rather than trusted
   * positive review.
   *
   * @param entry catalog entry metadata that the receipt must bind to
   * @param receipt standalone receipt to evaluate against the entry metadata
   * @param trustedReviewerKeys local reviewer trust registry used for key lookup
   * @param policy local review policy used to derive blocking flags
   * @param now time used for strict receipt expiry checks
   * @return display-safe review trust decision for CLI or API callers
   */
  public static AppReviewTrustDecision evaluate(
      AppCatalogEntry entry,
      AppReviewReceipt receipt,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy policy,
      Instant now) {
    Objects.requireNonNull(entry, "entry");
    Objects.requireNonNull(receipt, "receipt");
    Objects.requireNonNull(now, "now");
    return evaluate(
        ReviewEvaluationTarget.standaloneReceipt(entry, receipt), trustedReviewerKeys, policy, now);
  }

  /**
   * Evaluates trust for a missing receipt.
   *
   * <p>This helper keeps old catalogs compatible. A publisher advisory review claim without a
   * receipt is reported as {@link AppReviewTrustStatus#PUBLISHER_CLAIM_ONLY}; an entry with no
   * publisher review fields is reported as missing or not configured depending on local reviewer
   * key availability.
   *
   * @param review advisory publisher review metadata from the signed catalog
   * @param trustedReviewerKeys local reviewer trust registry used to distinguish missing from
   *     unconfigured receipt states
   * @param policy local review policy used to derive acknowledgement and blocking flags
   * @return display-safe decision for entries that carry no independent receipt
   */
  public static AppReviewTrustDecision evaluateMissingReceipt(
      AppCatalogReviewMetadata review,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy policy) {
    return evaluate(
        ReviewEvaluationTarget.missingReceipt(review), trustedReviewerKeys, policy, Instant.EPOCH);
  }

  private static AppReviewTrustDecision evaluate(
      ReviewEvaluationTarget target,
      TrustedReviewerKeys trustedReviewerKeys,
      AppReviewPolicy policy,
      Instant now) {
    Objects.requireNonNull(target, "target");
    TrustedReviewerKeys keys =
        Objects.requireNonNullElse(trustedReviewerKeys, TrustedReviewerKeys.empty());
    AppReviewPolicy checkedPolicy = Objects.requireNonNullElse(policy, AppReviewPolicy.DEFAULT);
    if (!target.hasReceipt()) {
      return missingReceiptDecision(target.review(), keys, checkedPolicy);
    }
    AppReviewReceipt receipt = target.receipt();
    AppReviewReceiptRevocation revocation = keys.findReceiptRevocation(receipt).orElse(null);
    if (revocation != null) {
      return revokedReceiptDecision(receipt, checkedPolicy, revocation);
    }
    AppReviewTrustDecision mismatchDecision = bindingMismatchDecision(target, checkedPolicy);
    if (mismatchDecision != null) {
      return mismatchDecision;
    }
    AppReviewTrustDecision expiryDecision = expiryDecision(receipt, checkedPolicy, now);
    if (expiryDecision != null) {
      return expiryDecision;
    }
    if (keys.isEmpty()) {
      return decision(
          AppReviewTrustStatus.NOT_CONFIGURED,
          receipt,
          null,
          checkedPolicy,
          List.of("No trusted reviewer keys are configured."));
    }
    TrustedReviewerKey reviewerKey = keys.find(receipt.payload().reviewerKeyId()).orElse(null);
    if (reviewerKey == null) {
      return decision(
          AppReviewTrustStatus.UNKNOWN_REVIEWER,
          receipt,
          null,
          checkedPolicy,
          List.of("Review receipt reviewer key is not trusted by this node."));
    }
    if (reviewerPolicyMismatch(reviewerKey, receipt)) {
      return decision(
          AppReviewTrustStatus.REVIEW_POLICY_MISMATCH,
          receipt,
          reviewerKey,
          checkedPolicy,
          List.of("Review receipt policy id or version is not accepted for this reviewer key."));
    }
    AppReviewTrustStatus lifecycleFailure =
        reviewerKey.lifecycle().trustFailureAt(receipt.payload().reviewedAt()).orElse(null);
    if (lifecycleFailure != null) {
      return decision(
          lifecycleFailure,
          receipt,
          reviewerKey,
          checkedPolicy,
          lifecycleWarnings(lifecycleFailure));
    }
    if (!receipt.signature().algorithm().equals(reviewerKey.algorithm())) {
      return decision(
          AppReviewTrustStatus.INVALID_SIGNATURE,
          receipt,
          reviewerKey,
          checkedPolicy,
          List.of("Review receipt signature algorithm does not match the trusted reviewer key."));
    }
    if (!verifySignature(receipt, reviewerKey)) {
      return decision(
          AppReviewTrustStatus.INVALID_SIGNATURE,
          receipt,
          reviewerKey,
          checkedPolicy,
          List.of("Review receipt signature does not match the canonical payload."));
    }
    List<String> warnings = publisherMismatchWarnings(target.review(), receipt);
    AppReviewTrustStatus status =
        switch (receipt.payload().status()) {
          case REVIEWED -> AppReviewTrustStatus.TRUSTED_REVIEWED;
          case CAUTION -> AppReviewTrustStatus.TRUSTED_CAUTION;
          case REJECTED -> AppReviewTrustStatus.TRUSTED_REJECTED;
        };
    return decision(status, receipt, reviewerKey, checkedPolicy, warnings);
  }

  private static AppReviewTrustDecision revokedReceiptDecision(
      AppReviewReceipt receipt, AppReviewPolicy policy, AppReviewReceiptRevocation revocation) {
    return decision(
        AppReviewTrustStatus.REVOKED_RECEIPT,
        receipt,
        null,
        policy,
        List.of("Review receipt fingerprint is revoked by local policy: " + revocation.reason()));
  }

  private static AppReviewTrustDecision missingReceiptDecision(
      AppCatalogReviewMetadata review, TrustedReviewerKeys keys, AppReviewPolicy policy) {
    return decision(
        missingReceiptStatus(review, keys), null, null, policy, missingReceiptWarnings(review));
  }

  private static AppReviewTrustStatus missingReceiptStatus(
      AppCatalogReviewMetadata review, TrustedReviewerKeys keys) {
    if (review.hasCatalogFields()) {
      return AppReviewTrustStatus.PUBLISHER_CLAIM_ONLY;
    }
    if (keys.isEmpty()) {
      return AppReviewTrustStatus.NOT_CONFIGURED;
    }
    return AppReviewTrustStatus.MISSING_RECEIPT;
  }

  private static List<String> missingReceiptWarnings(AppCatalogReviewMetadata review) {
    if (review.hasCatalogFields()) {
      return List.of("Catalog publisher review metadata is advisory; no trusted receipt verified.");
    }
    return List.of("No trusted review receipt is attached to this catalog entry.");
  }

  private static AppReviewTrustDecision bindingMismatchDecision(
      ReviewEvaluationTarget target, AppReviewPolicy policy) {
    AppReviewTrustStatus mismatch = target.mismatchStatus();
    if (mismatch == null) {
      return null;
    }
    return decision(
        mismatch,
        target.receipt(),
        null,
        policy,
        List.of("Review receipt does not match the catalog entry."));
  }

  private static AppReviewTrustDecision expiryDecision(
      AppReviewReceipt receipt, AppReviewPolicy policy, Instant now) {
    Instant expiresAt = receipt.payload().expiresAt().orElse(null);
    if (expiresAt == null || expiresAt.isAfter(now)) {
      return null;
    }
    return decision(
        AppReviewTrustStatus.EXPIRED,
        receipt,
        null,
        policy,
        List.of("Review receipt has expired."));
  }

  private static boolean reviewerPolicyMismatch(
      TrustedReviewerKey reviewerKey, AppReviewReceipt receipt) {
    return !reviewerKey
        .policyConstraint()
        .matches(receipt.payload().policyId(), receipt.payload().policyVersion());
  }

  private static List<String> lifecycleWarnings(AppReviewTrustStatus status) {
    return switch (status) {
      case REVOKED_REVIEWER -> List.of("Review receipt reviewer key is revoked by local policy.");
      case RETIRED_REVIEWER ->
          List.of("Review receipt reviewer key is retired for this review timestamp.");
      case REVIEWER_NOT_YET_VALID ->
          List.of("Review receipt predates the reviewer key validity window.");
      case REVIEWER_EXPIRED ->
          List.of("Review receipt was produced after the reviewer key validity window.");
      default -> List.of("Review receipt reviewer key lifecycle policy rejected the receipt.");
    };
  }

  private static boolean verifySignature(AppReviewReceipt receipt, TrustedReviewerKey reviewerKey) {
    try {
      Signature verifier = Signature.getInstance(receipt.signature().algorithm());
      verifier.initVerify(reviewerKey.publicKey());
      verifier.update(receipt.payload().canonicalPayloadBytes());
      return verifier.verify(receipt.signature().signatureBytes());
    } catch (GeneralSecurityException _) {
      return false;
    }
  }

  private static List<String> publisherMismatchWarnings(
      AppCatalogReviewMetadata review, AppReviewReceipt receipt) {
    List<String> warnings = new ArrayList<>();
    if (review.hasCatalogFields()
        && !receipt.payload().status().catalogValue().equals(review.status().catalogValue())) {
      warnings.add("Catalog publisher advisory review differs from the trusted receipt.");
    }
    if (receipt.payload().status() == AppReviewReceiptStatus.CAUTION) {
      warnings.add("Trusted reviewer marked this app with caution.");
    }
    if (receipt.payload().status() == AppReviewReceiptStatus.REJECTED) {
      warnings.add("Trusted reviewer rejected this app version.");
    }
    return List.copyOf(warnings);
  }

  private static AppReviewTrustDecision decision(
      AppReviewTrustStatus status,
      AppReviewReceipt receipt,
      TrustedReviewerKey reviewerKey,
      AppReviewPolicy policy,
      List<String> warnings) {
    boolean trusted =
        status == AppReviewTrustStatus.TRUSTED_REVIEWED
            || status == AppReviewTrustStatus.TRUSTED_CAUTION
            || status == AppReviewTrustStatus.TRUSTED_REJECTED;
    boolean positive = status == AppReviewTrustStatus.TRUSTED_REVIEWED;
    AppReviewReceiptPayload payload = receipt == null ? null : receipt.payload();
    return new AppReviewTrustDecision(
        status,
        trusted,
        positive,
        policy.requiresAcknowledgement(status),
        policy.blocksManualInstallOrUpdate(status),
        policy.blocksManualInstallOrUpdate(status),
        policy.blocksPolicyApply(status),
        payload == null ? null : payload.reviewerKeyId(),
        reviewerKey == null ? null : reviewerKey.displayName().orElse(null),
        reviewerKey == null ? null : reviewerKey.status().jsonValue(),
        payload == null ? null : payload.policyId(),
        payload == null ? null : payload.policyVersion(),
        policyVersionStatus(status, reviewerKey),
        payload == null ? null : payload.reviewedAt(),
        payload == null ? null : payload.expiresAt().orElse(null),
        payload == null ? null : payload.evidenceSha256().orElse(null),
        payload == null ? null : payload.evidenceUri().orElse(null),
        List.copyOf(warnings),
        policy.mode());
  }

  private static String policyVersionStatus(
      AppReviewTrustStatus status, TrustedReviewerKey reviewerKey) {
    if (reviewerKey == null) {
      return null;
    }
    if (status == AppReviewTrustStatus.REVIEW_POLICY_MISMATCH
        || status == AppReviewTrustStatus.REVOKED_REVIEWER) {
      return "rejected";
    }
    if (status == AppReviewTrustStatus.RETIRED_REVIEWER
        || reviewerKey.status() == TrustedReviewerKeyStatus.RETIRED) {
      return "retired";
    }
    if (reviewerKey.status() == TrustedReviewerKeyStatus.ACTIVE) {
      return "active";
    }
    return reviewerKey.status().jsonValue();
  }

  private record ReviewEvaluationTarget(
      AppCatalogReviewMetadata review, AppReviewReceipt receipt, CatalogArtifactBinding binding) {
    private ReviewEvaluationTarget {
      Objects.requireNonNull(review, "review");
    }

    static ReviewEvaluationTarget catalogEntry(AppCatalogEntry entry) {
      return new ReviewEvaluationTarget(
          entry.review(), entry.reviewReceipt().orElse(null), CatalogArtifactBinding.from(entry));
    }

    static ReviewEvaluationTarget standaloneReceipt(
        AppCatalogEntry entry, AppReviewReceipt receipt) {
      return new ReviewEvaluationTarget(
          entry.review(), receipt, CatalogArtifactBinding.from(entry));
    }

    static ReviewEvaluationTarget missingReceipt(AppCatalogReviewMetadata review) {
      return new ReviewEvaluationTarget(review, null, null);
    }

    boolean hasReceipt() {
      return receipt != null;
    }

    AppReviewTrustStatus mismatchStatus() {
      if (receipt == null || binding == null) {
        return null;
      }
      return receipt.mismatchStatus(
          binding.appId(),
          binding.version(),
          binding.artifactSha256(),
          binding.artifactSizeBytes());
    }
  }

  private record CatalogArtifactBinding(
      String appId, String version, String artifactSha256, long artifactSizeBytes) {
    static CatalogArtifactBinding from(AppCatalogEntry entry) {
      return new CatalogArtifactBinding(
          entry.appId(), entry.version(), entry.bundleSha256(), entry.bundleSizeBytes());
    }
  }
}
