package network.crypta.runtime.updater;

import java.time.Instant;
import java.util.List;
import network.crypta.runtime.spi.CoreSupportLifecycleStatus;

/**
 * Authenticated public release identity and current support state for one Stable 1.0 build.
 *
 * <p>Instances come only from a validated support-lifecycle descriptor. Release identity fields
 * remain immutable across later descriptor editions, while lifecycle status and its associated
 * public guidance may advance according to the closed transition order. The record contains no
 * update insert URI, credential, local path, raw advisory body, or user-derived data.
 *
 * @param releaseId authenticated Stable 1.0 release identifier
 * @param buildVersion strictly positive Cryptad integer build number
 * @param tag exact integer-build tag in {@code v<build>} form
 * @param sourceCommit public lowercase source commit identifier
 * @param productDigest lowercase SHA-256 of the published product identity
 * @param publicationReceiptDigest lowercase SHA-256 of the authenticated publication receipt
 * @param baselineDigest lowercase SHA-256 of the immutable release baseline
 * @param publishedAt canonical UTC publication timestamp
 * @param lifecycleStatus closed current build lifecycle state
 * @param statusEffectiveAt canonical UTC timestamp at which the state became effective
 * @param fullSupportUntil full-maintenance deadline, when one is defined
 * @param securityFixesUntil security-fix deadline, when one is defined
 * @param deprecationEffectiveAt deprecation-notice effective timestamp, when defined
 * @param endOfSupportAt end-of-support effective timestamp, when defined
 * @param securityRevocationEffectiveAt explicit build-revocation effective timestamp
 * @param replacementBuild authenticated safe replacement build, when required
 * @param recoveryGuidance bounded authenticated public recovery guidance when no safe replacement
 *     build exists
 * @param advisoryIds sorted public advisory or incident identifiers
 * @param reasonCodes sorted public lifecycle reason codes
 */
public record CoreSupportLifecycleEntry(
    String releaseId,
    int buildVersion,
    String tag,
    String sourceCommit,
    String productDigest,
    String publicationReceiptDigest,
    String baselineDigest,
    Instant publishedAt,
    CoreSupportLifecycleStatus lifecycleStatus,
    Instant statusEffectiveAt,
    Instant fullSupportUntil,
    Instant securityFixesUntil,
    Instant deprecationEffectiveAt,
    Instant endOfSupportAt,
    Instant securityRevocationEffectiveAt,
    Integer replacementBuild,
    String recoveryGuidance,
    List<String> advisoryIds,
    List<String> reasonCodes) {

  /** Defensively copies public identifier lists retained by this immutable record. */
  public CoreSupportLifecycleEntry {
    advisoryIds = List.copyOf(advisoryIds);
    reasonCodes = List.copyOf(reasonCodes);
  }
}
