package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppReviewReceiptTest {
  private static final String APP_ID = "sample-app";
  private static final String APP_VERSION = "1.2.3";
  private static final String ARTIFACT_SHA256 = "a".repeat(64);
  private static final long ARTIFACT_SIZE = 1234L;
  private static final String REVIEWER_KEY_ID = "crypta-first-party-review";
  private static final String POLICY_ID = "crypta-app-review-v1";
  private static final String POLICY_VERSION = "1";
  private static final String RECEIPT_REVOCATION_ID = "receipt-1";
  private static final Instant REVIEWED_AT = Instant.parse("2026-05-01T00:00:00Z");
  private static final Instant FUTURE = Instant.parse("2026-06-01T00:00:00Z");

  @TempDir private Path tempDir;

  @Test
  void canonicalPayloadText_whenCalledRepeatedly_expectDeterministicSignatureFreeProperties() {
    AppReviewReceiptPayload payload = payload(AppReviewReceiptStatus.REVIEWED);

    String expected =
        lines(
            "review.receipt.version=1",
            "review.receipt.app.id=sample-app",
            "review.receipt.app.version=1.2.3",
            "review.receipt.artifact.sha256=" + ARTIFACT_SHA256,
            "review.receipt.artifact.size=1234",
            "review.receipt.policy.id=crypta-app-review-v1",
            "review.receipt.policy.version=1",
            "review.receipt.status=reviewed",
            "review.receipt.reviewer.key.id=crypta-first-party-review",
            "review.receipt.reviewed.at=2026-05-01T00:00:00Z");

    assertEquals(expected, payload.canonicalPayloadText());
    assertEquals(expected, new String(payload.canonicalPayloadBytes(), StandardCharsets.UTF_8));
    assertEquals(payload.canonicalPayloadText(), payload.canonicalPayloadText());
    assertFalse(payload.canonicalPayloadText().contains("signature.value"));
  }

  @Test
  void evaluate_whenReceiptIsSignedByTrustedReviewer_expectTrustedReviewed() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeys(keyPair),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.TRUSTED_REVIEWED, decision.status());
    assertTrue(decision.trusted());
    assertTrue(decision.positive());
    assertEquals(REVIEWER_KEY_ID, decision.reviewerKeyId());
  }

  @Test
  void fingerprintSha256_whenReceiptRoundTrips_expectStableFingerprint() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppReviewReceipt parsed = AppReviewReceiptIO.parse(AppReviewReceiptIO.serialize(receipt));

    assertEquals(receipt.fingerprintSha256(), parsed.fingerprintSha256());
    assertEquals(receipt.payloadSha256(), parsed.payloadSha256());
    assertTrue(receipt.fingerprintSha256().matches("[0-9a-f]{64}"));
    assertTrue(receipt.payloadSha256().matches("[0-9a-f]{64}"));
  }

  @Test
  void serialize_whenDecisionReasonDigestIsPresent_expectSignedRoundTrip() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    String preReviewDigest = "b".repeat(64);
    String reasonDigest = "c".repeat(64);
    AppReviewReceiptPayload payload =
        new AppReviewReceiptPayload(
            AppReviewReceiptPayload.RECEIPT_VERSION_WITH_DECISION_REASON,
            APP_ID,
            APP_VERSION,
            ARTIFACT_SHA256,
            ARTIFACT_SIZE,
            Optional.empty(),
            POLICY_ID,
            POLICY_VERSION,
            AppReviewReceiptStatus.REVIEWED,
            REVIEWER_KEY_ID,
            REVIEWED_AT,
            Optional.empty(),
            Optional.of(preReviewDigest),
            Optional.of(reasonDigest),
            Optional.empty(),
            Optional.empty());
    AppReviewReceipt receipt = AppReviewReceiptSigner.sign(payload, keyPair.getPrivate());

    AppReviewReceipt parsed = AppReviewReceiptIO.parse(AppReviewReceiptIO.serialize(receipt));

    assertEquals(reasonDigest, parsed.payload().decisionReasonSha256().orElseThrow());
    assertEquals(preReviewDigest, parsed.payload().evidenceSha256().orElseThrow());
    assertTrue(parsed.payload().canonicalPayloadText().contains("review.receipt.version=2\n"));
    assertTrue(
        parsed
            .payload()
            .canonicalPayloadText()
            .contains("review.receipt.decision.reason.sha256=" + reasonDigest + "\n"));
    assertEquals(
        AppReviewTrustStatus.TRUSTED_REVIEWED,
        AppReviewReceiptVerifier.evaluate(
                entry(parsed, AppCatalogReviewMetadata.EMPTY),
                trustedKeys(keyPair),
                AppReviewPolicy.DEFAULT,
                REVIEWED_AT)
            .status());
  }

  @Test
  void payload_whenVersionOneCarriesDecisionReasonDigest_expectInvalidCatalogEntry() {
    Optional<String> noBundleKeyId = Optional.empty();
    Optional<Instant> noExpiration = Optional.empty();
    Optional<String> noEvidenceDigest = Optional.empty();
    Optional<String> decisionReasonDigest = Optional.of("c".repeat(64));
    Optional<URI> noEvidenceUri = Optional.empty();
    Optional<String> noNote = Optional.empty();

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                new AppReviewReceiptPayload(
                    AppReviewReceiptPayload.RECEIPT_VERSION,
                    APP_ID,
                    APP_VERSION,
                    ARTIFACT_SHA256,
                    ARTIFACT_SIZE,
                    noBundleKeyId,
                    POLICY_ID,
                    POLICY_VERSION,
                    AppReviewReceiptStatus.REVIEWED,
                    REVIEWER_KEY_ID,
                    REVIEWED_AT,
                    noExpiration,
                    noEvidenceDigest,
                    decisionReasonDigest,
                    noEvidenceUri,
                    noNote));

    assertTrue(exception.getMessage().contains("requires review.receipt.version 2"));
  }

  @Test
  void evaluate_whenSignedPayloadIsTampered_expectInvalidSignature() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt signed =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppReviewReceipt tampered =
        new AppReviewReceipt(payload(AppReviewReceiptStatus.REJECTED), signed.signature());

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(tampered, AppCatalogReviewMetadata.EMPTY),
            trustedKeys(keyPair),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.INVALID_SIGNATURE, decision.status());
    assertFalse(decision.trusted());
  }

  @Test
  void evaluate_whenReviewerKeyIsUnknown_expectUnknownReviewer() throws Exception {
    KeyPair signingKey = reviewerKeyPair();
    KeyPair trustedKey = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(
            payload(AppReviewReceiptStatus.REVIEWED), signingKey.getPrivate());

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeys("other-reviewer", trustedKey),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.UNKNOWN_REVIEWER, decision.status());
    assertFalse(decision.trusted());
  }

  @Test
  void evaluate_whenReviewerKeyIsRevoked_expectRevokedReviewer() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    TrustedReviewerKeyLifecycle lifecycle =
        TrustedReviewerKeyLifecycle.of(
            TrustedReviewerKeyStatus.REVOKED,
            null,
            null,
            Instant.parse("2026-05-02T00:00:00Z"),
            "Key compromise.",
            null,
            null);

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeys(REVIEWER_KEY_ID, keyPair, POLICY_VERSION, lifecycle),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.REVOKED_REVIEWER, decision.status());
    assertFalse(decision.trusted());
    assertEquals("revoked", decision.reviewerKeyStatus());
  }

  @Test
  void evaluate_whenRetiredReviewerCoversReviewedAt_expectTrustedHistoricalReview()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    TrustedReviewerKeyLifecycle lifecycle =
        TrustedReviewerKeyLifecycle.of(
            TrustedReviewerKeyStatus.RETIRED,
            Instant.parse("2026-04-01T00:00:00Z"),
            Instant.parse("2026-06-01T00:00:00Z"),
            null,
            null,
            null,
            null);

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeys(REVIEWER_KEY_ID, keyPair, POLICY_VERSION, lifecycle),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.TRUSTED_REVIEWED, decision.status());
    assertTrue(decision.trusted());
    assertEquals("retired", decision.reviewerKeyStatus());
    assertEquals("retired", decision.policyVersionStatus());
  }

  @Test
  void evaluate_whenRetiredReviewerNoLongerCoversReviewedAt_expectRetiredReviewer()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    TrustedReviewerKeyLifecycle lifecycle =
        TrustedReviewerKeyLifecycle.of(
            TrustedReviewerKeyStatus.RETIRED,
            Instant.parse("2026-04-01T00:00:00Z"),
            REVIEWED_AT,
            null,
            null,
            null,
            null);

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeys(REVIEWER_KEY_ID, keyPair, POLICY_VERSION, lifecycle),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.RETIRED_REVIEWER, decision.status());
    assertFalse(decision.trusted());
  }

  @Test
  void evaluate_whenRetiredReviewerHasNoValidityEnd_expectRetiredReviewer() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    TrustedReviewerKeyLifecycle lifecycle =
        TrustedReviewerKeyLifecycle.of(
            TrustedReviewerKeyStatus.RETIRED,
            Instant.parse("2026-04-01T00:00:00Z"),
            null,
            null,
            null,
            null,
            null);

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeys(REVIEWER_KEY_ID, keyPair, POLICY_VERSION, lifecycle),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.RETIRED_REVIEWER, decision.status());
    assertFalse(decision.trusted());
  }

  @Test
  void evaluate_whenPolicyVersionDoesNotMatchReviewerConstraint_expectPolicyMismatch()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeys(REVIEWER_KEY_ID, keyPair, "2", TrustedReviewerKeyLifecycle.ACTIVE),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.REVIEW_POLICY_MISMATCH, decision.status());
    assertFalse(decision.trusted());
    assertEquals("rejected", decision.policyVersionStatus());
  }

  @Test
  void evaluate_whenReceiptIsExpired_expectExpired() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt = AppReviewReceiptSigner.sign(expiredPayload(), keyPair.getPrivate());

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeys(keyPair),
            AppReviewPolicy.DEFAULT,
            FUTURE);

    assertEquals(AppReviewTrustStatus.EXPIRED, decision.status());
    assertFalse(decision.trusted());
  }

  @Test
  void evaluate_whenTrustedReceiptIsRejected_expectTrustedButNotPositive() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REJECTED), keyPair.getPrivate());
    AppCatalogReviewMetadata matchingPublisherReview =
        new AppCatalogReviewMetadata(AppCatalogReviewStatus.REJECTED, "Publisher says rejected.");

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, matchingPublisherReview),
            trustedKeys(keyPair),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.TRUSTED_REJECTED, decision.status());
    assertTrue(decision.trusted());
    assertFalse(decision.positive());
    assertTrue(decision.warnings().getFirst().contains("rejected"));
  }

  @Test
  void evaluate_whenPublisherClaimsReviewedWithoutReceipt_expectPublisherClaimOnly() {
    AppCatalogReviewMetadata advisoryReview =
        new AppCatalogReviewMetadata(AppCatalogReviewStatus.REVIEWED, "Publisher says reviewed.");

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entryWithoutReceipt(advisoryReview),
            TrustedReviewerKeys.empty(),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.PUBLISHER_CLAIM_ONLY, decision.status());
    assertFalse(decision.trusted());
    assertTrue(decision.warnings().getFirst().contains("advisory"));
  }

  @Test
  void evaluateMissingReceipt_whenPolicyModesDiffer_expectExplicitGateFlags() throws Exception {
    KeyPair keyPair = reviewerKeyPair();

    AppReviewTrustDecision advisory =
        AppReviewReceiptVerifier.evaluateMissingReceipt(
            AppCatalogReviewMetadata.EMPTY, trustedKeys(keyPair), AppReviewPolicy.DEFAULT);
    AppReviewTrustDecision warn =
        AppReviewReceiptVerifier.evaluateMissingReceipt(
            AppCatalogReviewMetadata.EMPTY,
            trustedKeys(keyPair),
            new AppReviewPolicy(AppReviewPolicyMode.WARN_UNTRUSTED));
    AppReviewTrustDecision requireTrusted =
        AppReviewReceiptVerifier.evaluateMissingReceipt(
            AppCatalogReviewMetadata.EMPTY,
            trustedKeys(keyPair),
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW));
    AppReviewTrustDecision applyWhenStopped =
        AppReviewReceiptVerifier.evaluateMissingReceipt(
            AppCatalogReviewMetadata.EMPTY,
            trustedKeys(keyPair),
            new AppReviewPolicy(AppReviewPolicyMode.REQUIRE_TRUSTED_REVIEW_FOR_APPLY_WHEN_STOPPED));

    assertEquals(AppReviewTrustStatus.MISSING_RECEIPT, advisory.status());
    assertFalse(advisory.requiresAcknowledgement());
    assertFalse(advisory.blocksInstall());
    assertFalse(advisory.blocksUpdate());
    assertFalse(advisory.blocksPolicyApply());
    assertTrue(warn.requiresAcknowledgement());
    assertFalse(warn.blocksUpdate());
    assertFalse(warn.blocksPolicyApply());
    assertFalse(requireTrusted.requiresAcknowledgement());
    assertTrue(requireTrusted.blocksInstall());
    assertTrue(requireTrusted.blocksUpdate());
    assertTrue(requireTrusted.blocksPolicyApply());
    assertTrue(applyWhenStopped.requiresAcknowledgement());
    assertFalse(applyWhenStopped.blocksUpdate());
    assertTrue(applyWhenStopped.blocksPolicyApply());
  }

  @Test
  void evaluate_whenReceiptDoesNotBindToEntry_expectMismatchStatuses() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt wrongAppReceipt =
        AppReviewReceiptSigner.sign(
            payloadWithBinding("other-app", ARTIFACT_SHA256), keyPair.getPrivate());
    AppReviewReceipt wrongArtifactReceipt =
        AppReviewReceiptSigner.sign(
            payloadWithBinding(APP_ID, "b".repeat(64)), keyPair.getPrivate());

    AppReviewTrustDecision appDecision =
        AppReviewReceiptVerifier.evaluate(
            entry(wrongAppReceipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeys(keyPair),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);
    AppReviewTrustDecision artifactDecision =
        AppReviewReceiptVerifier.evaluate(
            entry(wrongArtifactReceipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeys(keyPair),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.APP_MISMATCH, appDecision.status());
    assertEquals(AppReviewTrustStatus.ARTIFACT_MISMATCH, artifactDecision.status());
  }

  @Test
  void receiptIo_whenSerializedAndParsed_expectRoundTrip() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.CAUTION), keyPair.getPrivate());

    AppReviewReceipt parsed = AppReviewReceiptIO.parse(AppReviewReceiptIO.serialize(receipt));

    assertEquals(receipt, parsed);
    assertEquals(AppReviewReceiptStatus.CAUTION, parsed.payload().status());
  }

  @Test
  void entryDescriptor_whenInlineReceiptIsPresent_expectReceiptParsed() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    Path descriptor =
        Files.writeString(
            tempDir.resolve("entry.properties"),
            lines(
                    "artifact.path=" + tempDir.resolve("sample-app.zip").toAbsolutePath(),
                    "bundle.uri=https://example.invalid/apps/sample-app.zip",
                    "summary=Sample catalog entry")
                + AppReviewReceiptIO.serializeText(receipt),
            StandardCharsets.UTF_8);

    AppCatalogEntryDescriptor parsed = AppCatalogEntryDescriptor.parse(descriptor);

    assertTrue(parsed.reviewReceipt().isPresent());
    assertEquals(receipt, parsed.reviewReceipt().orElseThrow());
  }

  @Test
  void catalogParserWriter_whenEntryCarriesReceipt_expectDeterministicRoundTrip() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppCatalog catalog =
        new AppCatalog(
            AppCatalog.VERSION_STORE_METADATA,
            "core",
            "Crypta Core Apps",
            REVIEWED_AT,
            List.of(entry(receipt, AppCatalogReviewMetadata.EMPTY)));

    String serialized = new String(AppCatalogWriter.serialize(catalog), StandardCharsets.UTF_8);
    AppCatalog parsed = AppCatalogParser.parse(serialized.getBytes(StandardCharsets.UTF_8));

    assertTrue(serialized.contains("app.sample-app.review.receipt.status=reviewed\n"));
    assertTrue(serialized.contains("app.sample-app.review.receipt.signature.value.base64="));
    assertTrue(parsed.entries().getFirst().reviewReceipt().isPresent());
    assertEquals(
        serialized, new String(AppCatalogWriter.serialize(parsed), StandardCharsets.UTF_8));
  }

  @Test
  void parse_whenReceiptNoteIsMultiLine_expectInvalidCatalogEntry() {
    String receiptText =
        lines(
            "review.receipt.version=1",
            "review.receipt.app.id=sample-app",
            "review.receipt.app.version=1.2.3",
            "review.receipt.artifact.sha256=" + ARTIFACT_SHA256,
            "review.receipt.artifact.size=1234",
            "review.receipt.policy.id=crypta-app-review-v1",
            "review.receipt.policy.version=1",
            "review.receipt.status=reviewed",
            "review.receipt.reviewer.key.id=crypta-first-party-review",
            "review.receipt.reviewed.at=2026-05-01T00:00:00Z",
            "review.receipt.note=first line",
            "second line",
            "review.receipt.signature.algorithm=Ed25519",
            "review.receipt.signature.value.base64="
                + Base64.getEncoder().encodeToString(new byte[64]));
    byte[] receiptBytes = receiptText.getBytes(StandardCharsets.UTF_8);

    assertThrows(AppCatalogException.class, () -> AppReviewReceiptIO.parse(receiptBytes));
  }

  @Test
  void trustedReviewerKeysLoad_whenPropertiesFileIsValid_expectFindsReviewer() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    Path trustedReviewers = tempDir.resolve("trusted-reviewers.properties");
    Files.writeString(trustedReviewers, trustedReviewerProperties(keyPair), StandardCharsets.UTF_8);

    TrustedReviewerKeys keys = TrustedReviewerKeys.load(trustedReviewers);

    TrustedReviewerKey key = keys.find(REVIEWER_KEY_ID).orElseThrow();
    assertFalse(keys.isEmpty());
    assertEquals(REVIEWER_KEY_ID, key.keyId());
    assertEquals(TrustedReviewerKey.SIGNATURE_ALGORITHM, key.algorithm());
    assertEquals(Optional.of("Crypta First-Party Review"), key.displayName());
    assertEquals(Optional.of(POLICY_ID), key.policyId());
    assertEquals(TrustedReviewerKeyStatus.ACTIVE, key.status());
  }

  @Test
  void trustedReviewerKeysLoad_whenV2LifecycleConfigured_expectParsesStatuses() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    Path trustedReviewers = tempDir.resolve("trusted-reviewers-v2.properties");
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=2",
            reviewerProperties("reviewer.1", keyPair, "active-reviewer"),
            "reviewer.1.policy.version=1",
            "reviewer.1.status=active",
            "reviewer.1.valid.from=2026-04-01T00:00:00Z",
            "reviewer.1.valid.until=2026-07-01T00:00:00Z",
            "reviewer.1.rotates.from=retired-reviewer",
            reviewerProperties("reviewer.2", keyPair, "retired-reviewer"),
            "reviewer.2.policy.version=1",
            "reviewer.2.status=retired",
            "reviewer.2.valid.from=2026-01-01T00:00:00Z",
            "reviewer.2.valid.until=2026-04-01T00:00:00Z",
            "reviewer.2.rotates.to=active-reviewer",
            reviewerProperties("reviewer.3", keyPair, "revoked-reviewer"),
            "reviewer.3.policy.version=1",
            "reviewer.3.status=revoked",
            "reviewer.3.revoked.at=2026-05-01T00:00:00Z",
            "reviewer.3.revocation.reason=Key compromise."),
        StandardCharsets.UTF_8);

    TrustedReviewerKeys keys = TrustedReviewerKeys.load(trustedReviewers);

    assertEquals(2, keys.registryVersion());
    assertEquals(
        TrustedReviewerKeyStatus.ACTIVE, keys.find("active-reviewer").orElseThrow().status());
    assertEquals(
        TrustedReviewerKeyStatus.RETIRED, keys.find("retired-reviewer").orElseThrow().status());
    assertEquals(
        TrustedReviewerKeyStatus.REVOKED, keys.find("revoked-reviewer").orElseThrow().status());
    assertFalse(
        keys.summaries().getFirst().toJsonValue().containsKey("publicKey"),
        "raw public key bytes must not appear in trusted reviewer summaries");
  }

  @Test
  void trustedReviewerKeysLoad_whenV3ReceiptRevocationConfigured_expectParsesRevocation()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    Path trustedReviewers = tempDir.resolve("trusted-reviewers-v3.properties");
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=3",
            reviewerProperties("reviewer.1", keyPair),
            "reviewer.1.policy.version=1",
            "reviewer.1.status=active",
            receiptRevocationProperties(receipt)),
        StandardCharsets.UTF_8);

    TrustedReviewerKeys keys = TrustedReviewerKeys.load(trustedReviewers);

    assertEquals(3, keys.registryVersion());
    assertEquals(1, keys.receiptRevocations().size());
    assertEquals(1, keys.summary().receiptRevocationCount());
    assertTrue(keys.findReceiptRevocation(receipt).isPresent());
  }

  @Test
  void evaluate_whenReceiptFingerprintIsRevoked_expectRevokedReceiptNotTrusted() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    Path trustedReviewers = tempDir.resolve("trusted-reviewers-revoked-receipt.properties");
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=3",
            reviewerProperties("reviewer.1", keyPair),
            "reviewer.1.policy.version=1",
            "reviewer.1.status=active",
            receiptRevocationProperties(receipt)),
        StandardCharsets.UTF_8);

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            TrustedReviewerKeys.load(trustedReviewers),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.REVOKED_RECEIPT, decision.status());
    assertFalse(decision.trusted());
    assertFalse(decision.positive());
    assertTrue(decision.blocksInstall());
    assertTrue(decision.blocksUpdate());
  }

  @Test
  void evaluate_whenRevokedReceiptIsAlsoExpired_expectRevocationWins() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt = AppReviewReceiptSigner.sign(expiredPayload(), keyPair.getPrivate());

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeysWithRevokedReceipt(keyPair, receipt),
            AppReviewPolicy.DEFAULT,
            FUTURE);

    assertEquals(AppReviewTrustStatus.REVOKED_RECEIPT, decision.status());
    assertFalse(decision.trusted());
    assertTrue(decision.blocksInstall());
    assertTrue(decision.blocksUpdate());
  }

  @Test
  void evaluate_whenRevokedReceiptIsAlsoMismatched_expectRevocationWins() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(
            payloadWithBinding("other-app", ARTIFACT_SHA256), keyPair.getPrivate());

    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry(receipt, AppCatalogReviewMetadata.EMPTY),
            trustedKeysWithRevokedReceipt(keyPair, receipt),
            AppReviewPolicy.DEFAULT,
            REVIEWED_AT);

    assertEquals(AppReviewTrustStatus.REVOKED_RECEIPT, decision.status());
    assertFalse(decision.trusted());
    assertTrue(decision.blocksInstall());
    assertTrue(decision.blocksUpdate());
  }

  @Test
  void trustedReviewerKeysLoad_whenV2RegistryContainsReceiptRevocation_expectInvalidCatalogEntry()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    Path trustedReviewers = tempDir.resolve("trusted-reviewers-v2-revocation.properties");
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=2",
            reviewerProperties("reviewer.1", keyPair),
            "reviewer.1.policy.version=1",
            "reviewer.1.status=active",
            receiptRevocationProperties(receipt)),
        StandardCharsets.UTF_8);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> TrustedReviewerKeys.load(trustedReviewers));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
    assertTrue(exception.getMessage().contains("unsupported trusted reviewer keys property"));
  }

  @Test
  void trustedReviewerKeysLoad_whenPolicyVersionOmitsPolicyId_expectInvalidCatalogEntry()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    Path trustedReviewers = tempDir.resolve("trusted-reviewers-version-only.properties");
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=2",
            "reviewer.1.id=version-only-reviewer",
            "reviewer.1.algorithm=Ed25519",
            "reviewer.1.public.key.base64="
                + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
            "reviewer.1.policy.version=1",
            "reviewer.1.status=active"),
        StandardCharsets.UTF_8);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> TrustedReviewerKeys.load(trustedReviewers));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
    assertTrue(exception.getMessage().contains("policy.version requires policy.id"));
  }

  @Test
  void transparencyLog_whenReceiptObservedTwice_expectReceiptObservationDeduplicated()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppCatalogEntry entry = entry(receipt, AppCatalogReviewMetadata.EMPTY);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, trustedKeys(keyPair), AppReviewPolicy.DEFAULT, REVIEWED_AT);
    AppReviewTransparencyLog log = AppReviewTransparencyLog.inMemory();

    log.recordCatalogDecision(
        AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL, "core", entry, decision, List.of());
    log.recordCatalogDecision(
        AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL, "core", entry, decision, List.of());

    AppReviewTransparencyPage observed =
        log.page(
            new AppReviewTransparencyQuery(
                10,
                null,
                null,
                null,
                null,
                AppReviewTransparencyEventKind.REVIEW_RECEIPT_OBSERVED));
    assertEquals(1, observed.records().size());
    assertTrue(log.verify().verified());
  }

  @Test
  void transparencyLog_whenMismatchedReceiptObserved_expectReceiptPayloadBinding()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    String receiptAppId = "other-app";
    String receiptVersion = "9.9.9";
    String receiptSha256 = "b".repeat(64);
    long receiptSize = 4321L;
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(
            payloadWithBinding(receiptAppId, receiptVersion, receiptSha256, receiptSize),
            keyPair.getPrivate());
    AppCatalogEntry entry = entry(receipt, AppCatalogReviewMetadata.EMPTY);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, trustedKeys(keyPair), AppReviewPolicy.DEFAULT, REVIEWED_AT);
    AppReviewTransparencyLog log = AppReviewTransparencyLog.inMemory();

    log.recordCatalogDecision(
        AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL, "core", entry, decision, List.of());

    AppReviewTransparencyPage observed =
        log.page(
            new AppReviewTransparencyQuery(
                10,
                null,
                null,
                null,
                null,
                AppReviewTransparencyEventKind.REVIEW_RECEIPT_OBSERVED));
    assertEquals(AppReviewTrustStatus.APP_MISMATCH, decision.status());
    assertEquals(1, observed.records().size());
    AppReviewTransparencyRecord observedRecord = observed.records().getFirst();
    assertEquals(receiptAppId, observedRecord.appId());
    assertEquals(receiptVersion, observedRecord.appVersion());
    assertEquals(receiptSha256, observedRecord.artifactSha256());
    assertEquals(receiptSize, observedRecord.artifactSizeBytes());
  }

  @Test
  void
      transparencyRecordFromCatalogDecision_whenReceiptAndPublisherStatusesDiffer_expectReceiptStatus()
          throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REJECTED), keyPair.getPrivate());
    AppCatalogReviewMetadata publisherReview =
        new AppCatalogReviewMetadata(AppCatalogReviewStatus.REVIEWED, "Publisher says reviewed.");
    AppCatalogEntry entry = entry(receipt, publisherReview);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, trustedKeys(keyPair), AppReviewPolicy.DEFAULT, REVIEWED_AT);

    AppReviewTransparencyRecord transparencyRecord =
        AppReviewTransparencyRecord.fromCatalogDecision(
            AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
            "core",
            entry,
            decision,
            List.of());

    assertEquals(AppReviewTrustStatus.TRUSTED_REJECTED, decision.status());
    assertEquals("rejected", transparencyRecord.receiptStatus());
  }

  @Test
  void transparencyRecordFromCatalogDecision_whenOnlyPublisherReviewExists_expectNoReceiptStatus() {
    AppCatalogReviewMetadata publisherReview =
        new AppCatalogReviewMetadata(AppCatalogReviewStatus.REVIEWED, "Publisher says reviewed.");
    AppCatalogEntry entry = entryWithoutReceipt(publisherReview);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, TrustedReviewerKeys.empty(), AppReviewPolicy.DEFAULT, REVIEWED_AT);

    AppReviewTransparencyRecord transparencyRecord =
        AppReviewTransparencyRecord.fromCatalogDecision(
            AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
            "core",
            entry,
            decision,
            List.of());

    assertEquals(AppReviewTrustStatus.PUBLISHER_CLAIM_ONLY, decision.status());
    assertNull(transparencyRecord.receiptStatus());
  }

  @Test
  void transparencyStoreVerify_whenRecordIsTampered_expectVerificationFailure() throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppCatalogEntry entry = entry(receipt, AppCatalogReviewMetadata.EMPTY);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, trustedKeys(keyPair), AppReviewPolicy.DEFAULT, REVIEWED_AT);
    Path logFile = tempDir.resolve("review-transparency-log.jsonl");
    FileAppReviewTransparencyStore store = new FileAppReviewTransparencyStore(logFile);
    store.append(
        AppReviewTransparencyRecord.fromCatalogDecision(
            AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
            "core",
            entry,
            decision,
            List.of()));
    String tampered = Files.readString(logFile).replace("trusted_reviewed", "trusted_rejected");
    Files.writeString(logFile, tampered, StandardCharsets.UTF_8);

    AppReviewTransparencyVerificationResult result = store.verify();

    assertFalse(result.verified());
    assertTrue(result.error().contains("hash mismatch"));
  }

  @Test
  void transparencyStoreVerify_whenRecordHasUnknownField_expectVerificationFailure()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppCatalogEntry entry = entry(receipt, AppCatalogReviewMetadata.EMPTY);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, trustedKeys(keyPair), AppReviewPolicy.DEFAULT, REVIEWED_AT);
    Path logFile = tempDir.resolve("review-transparency-log.jsonl");
    FileAppReviewTransparencyStore store = new FileAppReviewTransparencyStore(logFile);
    store.append(
        AppReviewTransparencyRecord.fromCatalogDecision(
            AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
            "core",
            entry,
            decision,
            List.of()));
    String original = Files.readString(logFile, StandardCharsets.UTF_8).stripTrailing();
    String tampered =
        original.substring(0, original.length() - 1)
            + ",\"unexpected\":\"value\"}"
            + System.lineSeparator();
    Files.writeString(logFile, tampered, StandardCharsets.UTF_8);

    AppReviewTransparencyVerificationResult result = store.verify();

    assertFalse(result.verified());
    assertTrue(result.error().contains("invalid review transparency record"));
  }

  @Test
  void transparencyStoreVerify_whenRecordHasTrailingData_expectVerificationFailure()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppCatalogEntry entry = entry(receipt, AppCatalogReviewMetadata.EMPTY);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, trustedKeys(keyPair), AppReviewPolicy.DEFAULT, REVIEWED_AT);
    Path logFile = tempDir.resolve("review-transparency-log.jsonl");
    FileAppReviewTransparencyStore store = new FileAppReviewTransparencyStore(logFile);
    store.append(
        AppReviewTransparencyRecord.fromCatalogDecision(
            AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
            "core",
            entry,
            decision,
            List.of()));
    String tampered =
        Files.readString(logFile, StandardCharsets.UTF_8).stripTrailing()
            + " trailing"
            + System.lineSeparator();
    Files.writeString(logFile, tampered, StandardCharsets.UTF_8);

    AppReviewTransparencyVerificationResult result = store.verify();

    assertFalse(result.verified());
    assertTrue(result.error().contains("invalid review transparency record"));
  }

  @Test
  void transparencyStoreVerify_whenWarningListShapeIsTampered_expectVerificationFailure()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppCatalogEntry entry = entry(receipt, AppCatalogReviewMetadata.EMPTY);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, trustedKeys(keyPair), AppReviewPolicy.DEFAULT, REVIEWED_AT);
    Path logFile = tempDir.resolve("review-transparency-log.jsonl");
    FileAppReviewTransparencyStore store = new FileAppReviewTransparencyStore(logFile);
    store.append(
        AppReviewTransparencyRecord.fromCatalogDecision(
            AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
            "core",
            entry,
            decision,
            List.of("a", "b")));
    String original = Files.readString(logFile, StandardCharsets.UTF_8);
    String tampered = original.replace("\"warnings\":[\"a\",\"b\"]", "\"warnings\":[\"a|b\"]");
    assertNotEquals(original, tampered);
    Files.writeString(logFile, tampered, StandardCharsets.UTF_8);

    AppReviewTransparencyVerificationResult result = store.verify();

    assertFalse(result.verified());
    assertTrue(result.error().contains("hash mismatch"));
  }

  @Test
  void transparencyStoreVerify_whenBooleanFieldHasStringValue_expectVerificationFailure()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppCatalogEntry entry = entry(receipt, AppCatalogReviewMetadata.EMPTY);
    Path logFile = tempDir.resolve("review-transparency-log.jsonl");
    FileAppReviewTransparencyStore store =
        storeWithReceiptObservationForBooleanTamper(logFile, entry);
    String original = Files.readString(logFile, StandardCharsets.UTF_8);
    String tampered = original.replace("\"trusted\":null", "\"trusted\":\"true\"");
    assertNotEquals(original, tampered);
    Files.writeString(logFile, tampered, StandardCharsets.UTF_8);

    AppReviewTransparencyVerificationResult result = store.verify();

    assertFalse(result.verified());
    assertTrue(result.error().contains("invalid review transparency record"));
  }

  @Test
  void transparencyStoreVerify_whenSchemaVersionIsOutOfRange_expectVerificationFailure()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppCatalogEntry entry = entry(receipt, AppCatalogReviewMetadata.EMPTY);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, trustedKeys(keyPair), AppReviewPolicy.DEFAULT, REVIEWED_AT);
    Path logFile = tempDir.resolve("review-transparency-log.jsonl");
    FileAppReviewTransparencyStore store = new FileAppReviewTransparencyStore(logFile);
    store.append(
        AppReviewTransparencyRecord.fromCatalogDecision(
            AppReviewTransparencyEventKind.REVIEW_TRUST_EVALUATED,
            "core",
            entry,
            decision,
            List.of()));
    String original = Files.readString(logFile, StandardCharsets.UTF_8);
    String tampered = original.replace("\"schemaVersion\":1", "\"schemaVersion\":4294967297");
    assertNotEquals(original, tampered);
    Files.writeString(logFile, tampered, StandardCharsets.UTF_8);

    AppReviewTransparencyVerificationResult result = store.verify();

    assertFalse(result.verified());
    assertTrue(result.error().contains("invalid review transparency record"));
  }

  @Test
  void transparencyLogRecordCatalogDecision_whenExistingLogIsMalformed_expectBestEffort()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppCatalogEntry entry = entry(receipt, AppCatalogReviewMetadata.EMPTY);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, trustedKeys(keyPair), AppReviewPolicy.DEFAULT, REVIEWED_AT);
    Path logFile = tempDir.resolve("review-transparency-log.jsonl");
    Files.writeString(logFile, "{}" + System.lineSeparator(), StandardCharsets.UTF_8);
    AppReviewTransparencyLog log = AppReviewTransparencyLog.fileBacked(logFile);

    assertDoesNotThrow(
        () ->
            log.recordCatalogDecision(
                AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL,
                "core",
                entry,
                decision,
                List.of()));
  }

  @Test
  void transparencyLogRecordCatalogDecision_whenExistingReceiptRecordHasNullId_expectBestEffort()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(payload(AppReviewReceiptStatus.REVIEWED), keyPair.getPrivate());
    AppCatalogEntry entry = entry(receipt, AppCatalogReviewMetadata.EMPTY);
    AppReviewTrustDecision decision =
        AppReviewReceiptVerifier.evaluate(
            entry, trustedKeys(keyPair), AppReviewPolicy.DEFAULT, REVIEWED_AT);
    Path logFile = tempDir.resolve("review-transparency-log.jsonl");
    AppReviewTransparencyRecord existing =
        new AppReviewTransparencyRecord(
            AppReviewTransparencyRecord.SCHEMA_VERSION,
            1L,
            null,
            REVIEWED_AT,
            AppReviewTransparencyEventKind.REVIEW_RECEIPT_OBSERVED,
            "app",
            APP_ID,
            APP_VERSION,
            "core",
            ARTIFACT_SHA256,
            ARTIFACT_SIZE,
            REVIEWER_KEY_ID,
            null,
            POLICY_ID,
            POLICY_VERSION,
            "reviewed",
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            "",
            "0".repeat(64),
            List.of());
    Files.writeString(
        logFile, existing.toJsonLine() + System.lineSeparator(), StandardCharsets.UTF_8);
    AppReviewTransparencyLog log = AppReviewTransparencyLog.fileBacked(logFile);

    assertDoesNotThrow(
        () ->
            log.recordCatalogDecision(
                AppReviewTransparencyEventKind.REVIEW_GATE_INSTALL,
                "core",
                entry,
                decision,
                List.of()));
  }

  @Test
  void trustedReviewerKeysLoad_whenKeyIdsAreDuplicated_expectInvalidCatalogEntry()
      throws Exception {
    KeyPair keyPair = reviewerKeyPair();
    Path trustedReviewers = tempDir.resolve("trusted-reviewers-duplicates.properties");
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=1",
            reviewerProperties("reviewer.1", keyPair),
            reviewerProperties("reviewer.2", keyPair)),
        StandardCharsets.UTF_8);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> TrustedReviewerKeys.load(trustedReviewers));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
    assertTrue(exception.getMessage().contains("duplicate trusted reviewer key id"));
  }

  private static AppReviewReceiptPayload payload(AppReviewReceiptStatus status) {
    return new AppReviewReceiptPayload(
        AppReviewReceiptPayload.RECEIPT_VERSION,
        APP_ID,
        APP_VERSION,
        ARTIFACT_SHA256,
        ARTIFACT_SIZE,
        Optional.empty(),
        POLICY_ID,
        POLICY_VERSION,
        status,
        REVIEWER_KEY_ID,
        REVIEWED_AT,
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty());
  }

  private static AppReviewReceiptPayload expiredPayload() {
    return new AppReviewReceiptPayload(
        AppReviewReceiptPayload.RECEIPT_VERSION,
        APP_ID,
        APP_VERSION,
        ARTIFACT_SHA256,
        ARTIFACT_SIZE,
        Optional.empty(),
        POLICY_ID,
        POLICY_VERSION,
        AppReviewReceiptStatus.REVIEWED,
        REVIEWER_KEY_ID,
        REVIEWED_AT,
        Optional.of(REVIEWED_AT),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty());
  }

  private static AppReviewReceiptPayload payloadWithBinding(String appId, String sha256) {
    return payloadWithBinding(appId, APP_VERSION, sha256, ARTIFACT_SIZE);
  }

  private static AppReviewReceiptPayload payloadWithBinding(
      String appId, String appVersion, String sha256, long artifactSize) {
    return new AppReviewReceiptPayload(
        AppReviewReceiptPayload.RECEIPT_VERSION,
        appId,
        appVersion,
        sha256,
        artifactSize,
        Optional.empty(),
        POLICY_ID,
        POLICY_VERSION,
        AppReviewReceiptStatus.REVIEWED,
        REVIEWER_KEY_ID,
        REVIEWED_AT,
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty());
  }

  private static AppCatalogEntry entry(AppReviewReceipt receipt, AppCatalogReviewMetadata review) {
    return entryWithReceipt(receipt, review);
  }

  private static AppCatalogEntry entryWithoutReceipt(AppCatalogReviewMetadata review) {
    return entryWithReceipt(null, review);
  }

  private static AppCatalogEntry entryWithReceipt(
      AppReviewReceipt receipt, AppCatalogReviewMetadata review) {
    return new AppCatalogEntry(
        APP_ID,
        "Sample App",
        APP_VERSION,
        "Sample app.",
        null,
        null,
        null,
        List.of(),
        AppCatalogCompatibilityMetadata.EMPTY,
        review,
        receipt,
        AppCatalogChangelog.EMPTY,
        List.of(),
        URI.create("https://example.invalid/sample-app.zip"),
        ARTIFACT_SHA256,
        ARTIFACT_SIZE,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of("queue.read"),
        Map.of());
  }

  private static TrustedReviewerKeys trustedKeys(KeyPair keyPair) {
    return trustedKeys(REVIEWER_KEY_ID, keyPair);
  }

  private static TrustedReviewerKeys trustedKeys(String keyId, KeyPair keyPair) {
    return trustedKeys(keyId, keyPair, null, TrustedReviewerKeyLifecycle.ACTIVE);
  }

  private static TrustedReviewerKeys trustedKeys(
      String keyId, KeyPair keyPair, String policyVersion, TrustedReviewerKeyLifecycle lifecycle) {
    return TrustedReviewerKeys.of(
        TrustedReviewerKey.ed25519(
            keyId,
            keyPair.getPublic().getEncoded(),
            "Crypta First-Party Review",
            POLICY_ID,
            policyVersion,
            lifecycle));
  }

  private TrustedReviewerKeys trustedKeysWithRevokedReceipt(
      KeyPair keyPair, AppReviewReceipt receipt) throws IOException {
    Path trustedReviewers =
        tempDir.resolve("trusted-reviewers-revoked-" + receipt.fingerprintSha256() + ".properties");
    Files.writeString(
        trustedReviewers,
        lines(
            "trusted.reviewers.version=3",
            reviewerProperties("reviewer.1", keyPair),
            "reviewer.1.policy.version=1",
            "reviewer.1.status=active",
            receiptRevocationProperties(receipt)),
        StandardCharsets.UTF_8);
    return TrustedReviewerKeys.load(trustedReviewers);
  }

  private static FileAppReviewTransparencyStore storeWithReceiptObservationForBooleanTamper(
      Path logFile, AppCatalogEntry entry) throws IOException {
    FileAppReviewTransparencyStore store = new FileAppReviewTransparencyStore(logFile);
    store.append(
        new AppReviewTransparencyRecord(
            AppReviewTransparencyRecord.SCHEMA_VERSION,
            0L,
            "receipt:test-boolean-type",
            null,
            AppReviewTransparencyEventKind.REVIEW_RECEIPT_OBSERVED,
            "app",
            entry.appId(),
            entry.version(),
            "core",
            entry.bundleSha256(),
            entry.bundleSizeBytes(),
            REVIEWER_KEY_ID,
            null,
            POLICY_ID,
            POLICY_VERSION,
            "reviewed",
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            null,
            List.of()));
    return store;
  }

  private static KeyPair reviewerKeyPair() throws Exception {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  private static String trustedReviewerProperties(KeyPair keyPair) {
    return lines("trusted.reviewers.version=1", reviewerProperties("reviewer.1", keyPair));
  }

  private static String reviewerProperties(String prefix, KeyPair keyPair) {
    return reviewerProperties(prefix, keyPair, REVIEWER_KEY_ID);
  }

  private static String reviewerProperties(String prefix, KeyPair keyPair, String keyId) {
    return lines(
        prefix + ".id=" + keyId,
        prefix + ".algorithm=Ed25519",
        prefix
            + ".public.key.base64="
            + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
        prefix + ".display.name=Crypta First-Party Review",
        prefix + ".policy.id=" + POLICY_ID);
  }

  private static String receiptRevocationProperties(AppReviewReceipt receipt) {
    AppReviewReceiptPayload payload = receipt.payload();
    String propertyPrefix = "review.revocation." + RECEIPT_REVOCATION_ID + ".";
    return lines(
        "review.revocations=" + RECEIPT_REVOCATION_ID,
        propertyPrefix + "receiptFingerprintSha256=" + receipt.fingerprintSha256(),
        propertyPrefix + "appId=" + payload.appId(),
        propertyPrefix + "appVersion=" + payload.appVersion(),
        propertyPrefix + "bundleSha256=" + payload.artifactSha256(),
        propertyPrefix + "reviewerKeyId=" + payload.reviewerKeyId(),
        propertyPrefix + "revokedAt=2026-06-11T00:00:00Z",
        propertyPrefix + "reason=Receipt revoked after advisory CRYPTA-2026-0001.");
  }

  private static String lines(String... values) {
    return String.join("\n", values) + "\n";
  }
}
