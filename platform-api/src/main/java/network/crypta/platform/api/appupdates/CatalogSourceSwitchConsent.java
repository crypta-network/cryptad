package network.crypta.platform.api.appupdates;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Objects;
import network.crypta.platform.appcatalog.AppCatalog;
import network.crypta.platform.appcatalog.AppCatalogInstallPlan;
import network.crypta.platform.appcatalog.AppCatalogOriginContext;
import network.crypta.platform.appcatalog.AppReviewReceipt;
import network.crypta.platform.apphost.InstalledAppOrigin;

/**
 * Builds exact, path-free operator consent subjects for catalog or publisher source switching.
 *
 * <p>The direct catalog-update preview and the installed-app lifecycle use this utility so both
 * paths commit to the same authenticated fields. A decision binds the current host-owned origin,
 * the catalog revision and local trust binding captured in the retained installation plan, the
 * target bundle, the publisher authorization, and the review receipt. It does not read catalog
 * sources, fetch remote content, persist consent, or mutate app state.
 *
 * <p>The class is stateless and thread-safe. Callers must still reverify the retained installation
 * plan immediately before mutation. If any bound catalog, publisher, bundle, review, or
 * local-policy subject changes, a newly evaluated digest differs and stale operator consent fails
 * closed.
 */
public final class CatalogSourceSwitchConsent {
  /** Prevents construction of this stateless consent-subject utility. */
  private CatalogSourceSwitchConsent() {}

  /**
   * Normalizes an operator-selected catalog id before exact source-switch matching.
   *
   * <p>This method keeps the lifecycle service independent of the catalog wire model while using
   * the same path-safe, lower-case identity grammar as verified catalog plans. Invalid values
   * retain the catalog module's stable rejection semantics for the caller to map to an API error.
   *
   * @param catalogId operator-supplied target catalog identifier
   * @return normalized path-safe catalog identifier used by retained plans
   * @throws network.crypta.platform.appcatalog.AppCatalogException if the identifier is invalid
   */
  static String normalizeTargetCatalogId(String catalogId) {
    return AppCatalog.normalizeCatalogId(catalogId);
  }

  /**
   * Returns the verified review-receipt fingerprint bound to a retained catalog plan.
   *
   * <p>Catalog entries without a review receipt use the existing empty marker. The projection is
   * shared by installed-origin creation and source-switch consent so both paths commit to the same
   * authenticated receipt identity without exposing the receipt body.
   *
   * @param plan retained catalog plan containing the verified entry and optional receipt
   * @return lowercase receipt fingerprint, or an empty string when the entry has no receipt
   */
  static String reviewReceiptFingerprint(AppCatalogInstallPlan plan) {
    Objects.requireNonNull(plan, "plan");
    return plan.entry().reviewReceipt().map(AppReviewReceipt::fingerprintSha256).orElse("");
  }

  /**
   * Evaluates whether a retained plan changes the installed catalog or publisher identity.
   *
   * <p>The returned digest is deterministic for the exact current origin and authenticated plan.
   * Timestamps and local paths are excluded, so a preview can be compared with a later staging
   * request without exposing host filesystem state. The plan must contain an origin context
   * captured by {@code AppCatalogManager}; compatibility plans without that context are rejected.
   *
   * @param plan retained verified plan containing the exact target catalog authority
   * @param current host-owned provenance for the currently installed app revision
   * @return immutable decision containing switch flags and the exact consent digest
   * @throws IllegalArgumentException if the plan has no authenticated catalog-origin context
   */
  public static Decision evaluate(AppCatalogInstallPlan plan, InstalledAppOrigin current) {
    Objects.requireNonNull(plan, "plan");
    Objects.requireNonNull(current, "current");
    AppCatalogOriginContext target =
        plan.originContext()
            .orElseThrow(
                () -> new IllegalArgumentException("catalog plan has no authenticated origin"));
    if (!target.federationScoped()) {
      throw new IllegalArgumentException("catalog plan origin is not federation scoped");
    }
    boolean catalogSwitch = !current.catalogId().equals(plan.catalogId());
    String targetPublisherKeyId = plan.bundleVerification().publisherKeyId();
    String targetPublisherFingerprint = plan.bundleVerification().publisherKeyFingerprintSha256();
    boolean publisherSwitch =
        !current.publisherKeyId().equals(targetPublisherKeyId)
            || !current.publisherKeyFingerprintSha256().equals(targetPublisherFingerprint);
    String targetPublisherPolicyDigest =
        plan.bundleVerification().authorizationPolicyDigestSha256();
    String digest =
        sha256(
            String.join(
                    "\n",
                    "source-switch-v1",
                    current.selfDigestSha256(),
                    target.catalogId(),
                    target.catalogSignerKeyId(),
                    target.catalogSignerFingerprintSha256(),
                    target.catalogRevisionDigestSha256(),
                    target.trustBindingId(),
                    target.trustBindingDigestSha256(),
                    plan.entry().appId(),
                    plan.entry().version(),
                    plan.entry().bundleSha256(),
                    targetPublisherKeyId,
                    targetPublisherFingerprint,
                    targetPublisherPolicyDigest,
                    plan.entry()
                        .reviewReceipt()
                        .map(AppReviewReceipt::fingerprintSha256)
                        .orElse(""))
                + "\n");
    return new Decision(
        current, target, targetPublisherPolicyDigest, catalogSwitch, publisherSwitch, digest);
  }

  /**
   * Hashes one canonical source-switch consent subject as UTF-8.
   *
   * @param value canonical newline-delimited consent subject
   * @return lowercase hexadecimal SHA-256 digest
   */
  private static String sha256(String value) {
    try {
      return HexFormat.of()
          .formatHex(
              MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException exception) {
      throw new IllegalStateException("SHA-256 is unavailable", exception);
    }
  }

  /**
   * Exact source-switch decision safe for local operator summaries.
   *
   * <p>The record contains public identities and digests only. It does not contain source URIs,
   * catalog bodies, private keys, tokens, app data, or local paths. Consumers may display the
   * switch flags and consent digest, but the record itself grants no trust or mutation authority.
   *
   * @param currentOrigin exact host-owned origin being replaced
   * @param target authenticated catalog authority captured with the target plan
   * @param targetPublisherPolicyDigest exact local publisher-authorization policy digest
   * @param catalogSwitch whether the target catalog differs from the pinned origin
   * @param publisherSwitch whether the target publisher fingerprint differs from the pinned origin
   * @param consentDigestSha256 deterministic SHA-256 digest of every bound consent subject
   */
  public record Decision(
      InstalledAppOrigin currentOrigin,
      AppCatalogOriginContext target,
      String targetPublisherPolicyDigest,
      boolean catalogSwitch,
      boolean publisherSwitch,
      String consentDigestSha256) {
    /** Validates that every decision identity and digest field is present. */
    public Decision {
      Objects.requireNonNull(currentOrigin, "currentOrigin");
      Objects.requireNonNull(target, "target");
      Objects.requireNonNull(targetPublisherPolicyDigest, "targetPublisherPolicyDigest");
      Objects.requireNonNull(consentDigestSha256, "consentDigestSha256");
    }

    /**
     * Returns whether either pinned catalog or publisher identity changes.
     *
     * @return {@code true} when mutation requires exact operator source-switch consent
     */
    public boolean requiresExplicitConsent() {
      return catalogSwitch || publisherSwitch;
    }
  }
}
