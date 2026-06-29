package network.crypta.platform.appcatalog;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AppSubmissionIntakeRecordTest {
  private static final Instant NOW = Instant.parse("2026-06-01T12:00:00Z");
  private static final String SHA256 = "0".repeat(64);
  private static final String SHA256_ALT = "1".repeat(64);
  private static final String REVIEWER_KEY_ID = "reviewer-prod-1";

  @Test
  void parse_whenRecordSerialized_expectRoundTripAndSafeSummary() {
    AppSubmissionIntakeRecord intakeRecord = submittedRecord().assignReviewer(assignment(), NOW);

    AppSubmissionIntakeRecord restored = AppSubmissionIntakeRecord.parse(intakeRecord.toJson());

    assertEquals(intakeRecord, restored);
    assertEquals("sub-hello", restored.toSummary().submissionId());
    assertEquals(REVIEWER_KEY_ID, restored.toSummary().reviewerKeyId());
    assertTrue(restored.toJson().contains("\"auditEvents\""));
  }

  @Test
  void assignReviewer_whenAlreadyAssigned_expectReassignmentAudited() {
    AppSubmissionIntakeRecord assigned = submittedRecord().assignReviewer(assignment(), NOW);

    AppSubmissionIntakeRecord reassigned =
        assigned.assignReviewer(
            new AppSubmissionReviewerAssignment(
                "reviewer-prod-2",
                "Reviewer Two",
                NOW.plusSeconds(60),
                SHA256_ALT,
                Optional.of(REVIEWER_KEY_ID)),
            NOW.plusSeconds(60));

    assertEquals("reviewer-prod-2", reassigned.reviewerAssignment().orElseThrow().reviewerKeyId());
    assertTrue(reassigned.warnings().contains("reviewerAssigned=true"));
    assertTrue(
        reassigned.auditEvents().stream()
            .anyMatch(event -> event.warnings().contains("reassigned=true")));
  }

  @Test
  void recordPreReview_whenRedactionFails_expectSummaryCarriesFailure() {
    AppSubmissionIntakeRecord reviewed =
        submittedRecord()
            .assignReviewer(assignment(), NOW)
            .recordPreReview(
                SHA256,
                AppSubmissionPreReviewStatus.FAIL,
                NOW.plusSeconds(1),
                "fail",
                List.of("redaction=redaction.private-key"));

    assertEquals(AppSubmissionIntakeStatus.PRE_REVIEW_FAILED, reviewed.status());
    assertEquals("fail", reviewed.toSummary().redactionStatus());
    assertTrue(reviewed.warnings().contains("redaction=redaction.private-key"));
  }

  @Test
  void preReviewRunning_whenAlreadyRunning_expectRetryAllowed() {
    AppSubmissionIntakeRecord running =
        submittedRecord().preReviewRunning(NOW.plusSeconds(1)).preReviewRunning(NOW.plusSeconds(2));

    AppSubmissionIntakeRecord passed =
        running.recordPreReview(SHA256, AppSubmissionPreReviewStatus.PASS, NOW.plusSeconds(3));

    assertEquals(AppSubmissionIntakeStatus.PRE_REVIEW_RUNNING, running.status());
    assertEquals(AppSubmissionIntakeStatus.PRE_REVIEW_PASSED, passed.status());
  }

  @Test
  void assignReviewer_whenPreReviewAlreadyPassed_expectPreReviewStatePreserved() {
    AppSubmissionIntakeRecord preReviewed =
        submittedRecord()
            .preReviewRunning(NOW.plusSeconds(1))
            .recordPreReview(SHA256, AppSubmissionPreReviewStatus.PASS, NOW.plusSeconds(2));

    AppSubmissionIntakeRecord assigned =
        preReviewed.assignReviewer(assignment(), NOW.plusSeconds(3));
    AppSubmissionIntakeRecord reviewed =
        assigned.recordDecision(decision(AppSubmissionReviewDecision.REVIEWED), NOW.plusSeconds(4));

    assertEquals(AppSubmissionIntakeStatus.PRE_REVIEW_PASSED, assigned.status());
    assertEquals(REVIEWER_KEY_ID, assigned.reviewerAssignment().orElseThrow().reviewerKeyId());
    assertEquals(AppSubmissionIntakeStatus.REVIEWED, reviewed.status());
  }

  @Test
  void recordDecision_whenNoPreReviewPassed_expectReviewedDecisionRejected() {
    AppSubmissionReviewDecisionRecord decision = decision(AppSubmissionReviewDecision.REVIEWED);
    AppSubmissionIntakeRecord assigned = submittedRecord().assignReviewer(assignment(), NOW);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> assigned.recordDecision(decision, NOW));

    assertTrue(exception.getMessage().contains("invalid intake status transition"));
  }

  @Test
  void recordCatalogCandidate_whenRejected_expectCandidateBlocked() {
    AppSubmissionIntakeRecord rejected =
        preReviewed().recordDecision(rejectedDecision(), NOW.plusSeconds(2));
    AppSubmissionCatalogCandidateRecord candidate = candidate();
    Instant candidateAt = NOW.plusSeconds(3);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> rejected.recordCatalogCandidate(candidate, candidateAt));

    assertTrue(exception.getMessage().contains("only reviewed or caution"));
  }

  @Test
  void recordCatalogCandidate_whenCautionWithoutAllowance_expectBlocked() {
    AppSubmissionIntakeRecord caution =
        preReviewed()
            .recordDecision(decision(AppSubmissionReviewDecision.CAUTION), NOW.plusSeconds(2));
    AppSubmissionCatalogCandidateRecord candidate = candidate();
    Instant candidateAt = NOW.plusSeconds(3);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> caution.recordCatalogCandidate(candidate, candidateAt));

    assertTrue(exception.getMessage().contains("caution candidates require explicit allowance"));
  }

  @Test
  void recordCatalogCandidate_whenReceiptDoesNotMatchDecision_expectBlocked() {
    AppSubmissionIntakeRecord reviewed =
        preReviewed()
            .recordDecision(decision(AppSubmissionReviewDecision.REVIEWED), NOW.plusSeconds(2));
    AppSubmissionCatalogCandidateRecord candidate = candidateWithMismatchedReceipt();
    Instant candidateAt = NOW.plusSeconds(3);

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () -> reviewed.recordCatalogCandidate(candidate, candidateAt));

    assertTrue(exception.getMessage().contains("does not match reviewer decision receipt"));
  }

  @Test
  void recordCatalogCandidate_whenReviewed_expectInstallSmokeStatus() {
    AppSubmissionIntakeRecord reviewed =
        preReviewed()
            .recordDecision(decision(AppSubmissionReviewDecision.REVIEWED), NOW.plusSeconds(2));

    AppSubmissionIntakeRecord staged =
        reviewed
            .recordCatalogCandidate(candidate(), NOW.plusSeconds(3))
            .recordInstallSmokePassed(SHA256_ALT, NOW.plusSeconds(4));

    assertEquals(AppSubmissionIntakeStatus.BETA_INSTALL_SMOKE_PASSED, staged.status());
    assertEquals("pass", staged.toSummary().installSmokeStatus());
    assertEquals(SHA256_ALT, staged.transparencyLogDigest().orElseThrow());
  }

  @Test
  void parse_whenResubmissionRecord_expectPriorSubmissionLinked() {
    AppSubmissionIntakeRecord intakeRecord = resubmissionRecord();

    AppSubmissionIntakeRecord restored = AppSubmissionIntakeRecord.parse(intakeRecord.toJson());

    assertEquals("sub-prior", restored.resubmissionOf().orElseThrow());
    assertTrue(restored.toJson().contains("\"resubmissionOf\":\"sub-prior\""));
  }

  private static AppSubmissionIntakeRecord preReviewed() {
    return submittedRecord()
        .assignReviewer(assignment(), NOW)
        .recordPreReview(SHA256, AppSubmissionPreReviewStatus.PASS, NOW.plusSeconds(1));
  }

  private static AppSubmissionIntakeRecord submittedRecord() {
    return submittedRecord("new_app", null);
  }

  private static AppSubmissionIntakeRecord resubmissionRecord() {
    return submittedRecord("resubmission", "sub-prior");
  }

  private static AppSubmissionIntakeRecord submittedRecord(
      String submissionType, String priorSubmissionId) {
    return new AppSubmissionIntakeRecord(
        AppSubmissionIntakeRecord.SCHEMA_VERSION,
        AppSubmissionIntakeStatus.SUBMITTED,
        "sub-hello",
        SHA256,
        submissionType,
        Optional.ofNullable(priorSubmissionId),
        "hello-stable",
        "1.0.0",
        SHA256,
        SHA256,
        "stable",
        List.of("queue.read"),
        "Example Maintainer",
        "https://example.invalid/contact",
        "https://example.invalid/source",
        Optional.of("main"),
        NOW,
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        Optional.empty(),
        false,
        "pass",
        List.of(),
        List.of());
  }

  private static AppSubmissionReviewerAssignment assignment() {
    return new AppSubmissionReviewerAssignment(
        REVIEWER_KEY_ID, "Reviewer One", NOW, SHA256, Optional.empty());
  }

  private static AppSubmissionReviewDecisionRecord decision(AppSubmissionReviewDecision decision) {
    return new AppSubmissionReviewDecisionRecord(
        decision,
        NOW.plusSeconds(2),
        REVIEWER_KEY_ID,
        "crypta-app-review-v1/1",
        SHA256,
        SHA256,
        Optional.of(SHA256_ALT),
        Optional.empty(),
        Optional.empty(),
        false);
  }

  private static AppSubmissionReviewDecisionRecord rejectedDecision() {
    return new AppSubmissionReviewDecisionRecord(
        AppSubmissionReviewDecision.REJECTED,
        NOW.plusSeconds(2),
        REVIEWER_KEY_ID,
        "crypta-app-review-v1/1",
        SHA256,
        SHA256,
        Optional.empty(),
        Optional.of(SHA256_ALT),
        Optional.empty(),
        false);
  }

  private static AppSubmissionCatalogCandidateRecord candidate() {
    return candidateWithReceiptDigest(SHA256_ALT);
  }

  private static AppSubmissionCatalogCandidateRecord candidateWithMismatchedReceipt() {
    return candidateWithReceiptDigest(SHA256);
  }

  private static AppSubmissionCatalogCandidateRecord candidateWithReceiptDigest(
      String receiptDigest) {
    return new AppSubmissionCatalogCandidateRecord(
        SHA256,
        "beta",
        "beta-candidate:sub-hello/catalog-candidate.properties",
        receiptDigest,
        NOW.plusSeconds(3),
        false,
        "pending");
  }
}
