package network.crypta.platform.appcatalog;

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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
        new AppCatalogReviewMetadata(
            AppCatalogReviewStatus.REJECTED, Optional.of("Publisher says rejected."));

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
        new AppCatalogReviewMetadata(
            AppCatalogReviewStatus.REVIEWED, Optional.of("Publisher says reviewed."));

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
        Optional.empty());
  }

  private static AppReviewReceiptPayload payloadWithBinding(String appId, String sha256) {
    return new AppReviewReceiptPayload(
        AppReviewReceiptPayload.RECEIPT_VERSION,
        appId,
        APP_VERSION,
        sha256,
        ARTIFACT_SIZE,
        Optional.empty(),
        POLICY_ID,
        POLICY_VERSION,
        AppReviewReceiptStatus.REVIEWED,
        REVIEWER_KEY_ID,
        REVIEWED_AT,
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
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        List.of(),
        AppCatalogCompatibilityMetadata.EMPTY,
        review,
        Optional.ofNullable(receipt),
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
    return TrustedReviewerKeys.of(
        TrustedReviewerKey.ed25519(
            keyId, keyPair.getPublic().getEncoded(), "Crypta First-Party Review", POLICY_ID));
  }

  private static KeyPair reviewerKeyPair() throws Exception {
    return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
  }

  private static String trustedReviewerProperties(KeyPair keyPair) {
    return lines("trusted.reviewers.version=1", reviewerProperties("reviewer.1", keyPair));
  }

  private static String reviewerProperties(String prefix, KeyPair keyPair) {
    return lines(
        prefix + ".id=" + REVIEWER_KEY_ID,
        prefix + ".algorithm=Ed25519",
        prefix
            + ".public.key.base64="
            + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
        prefix + ".display.name=Crypta First-Party Review",
        prefix + ".policy.id=" + POLICY_ID);
  }

  private static String lines(String... values) {
    return String.join("\n", values) + "\n";
  }
}
