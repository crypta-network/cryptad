package network.crypta.platform.appcatalog;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppSubmissionPreReviewReportTest {
  private static final String APP_ID = "sample-app";
  private static final String APP_VERSION = "1.0.0";
  private static final String SUBMISSION_ID = "submission-1";
  private static final String WARNING_FINDING_ID = "review.warning";

  @Test
  void create_whenFindingsContainOnlyInfo_expectPassAndPromotionReady() {
    AppSubmissionPreReviewReport report =
        AppSubmissionPreReviewReport.create(
            SUBMISSION_ID,
            "Sample-App",
            APP_VERSION,
            List.of(finding("review.info", AppSubmissionFindingSeverity.INFO)),
            artifacts());

    assertEquals(AppSubmissionPreReviewStatus.PASS, report.status());
    assertTrue(report.promotionReady());
    assertEquals(APP_ID, report.appId());
  }

  @Test
  void create_whenFindingsContainWarning_expectWarnAndPromotionReady() {
    AppSubmissionPreReviewReport report =
        AppSubmissionPreReviewReport.create(
            SUBMISSION_ID,
            APP_ID,
            APP_VERSION,
            List.of(
                finding("review.info", AppSubmissionFindingSeverity.INFO),
                finding(WARNING_FINDING_ID, AppSubmissionFindingSeverity.WARNING)),
            artifacts());

    assertEquals(AppSubmissionPreReviewStatus.WARN, report.status());
    assertTrue(report.promotionReady());
  }

  @Test
  void create_whenFindingsContainBlocker_expectFailAndNotPromotionReady() {
    AppSubmissionPreReviewReport report =
        AppSubmissionPreReviewReport.create(
            SUBMISSION_ID,
            APP_ID,
            APP_VERSION,
            List.of(
                finding(WARNING_FINDING_ID, AppSubmissionFindingSeverity.WARNING),
                finding("review.blocker", AppSubmissionFindingSeverity.BLOCKER)),
            artifacts());

    assertEquals(AppSubmissionPreReviewStatus.FAIL, report.status());
    assertFalse(report.promotionReady());
  }

  @Test
  void parse_whenReportWasSerialized_expectRoundTrip() {
    LinkedHashMap<String, Object> details = new LinkedHashMap<>();
    details.put("zeta", "last");
    details.put("alpha", "first");
    AppSubmissionPreReviewReport report =
        AppSubmissionPreReviewReport.create(
            SUBMISSION_ID,
            APP_ID,
            APP_VERSION,
            List.of(
                new AppSubmissionFinding(
                    WARNING_FINDING_ID,
                    AppSubmissionFindingSeverity.WARNING,
                    "Reviewer attention needed.",
                    details)),
            artifacts());

    AppSubmissionPreReviewReport parsed = AppSubmissionPreReviewReport.parse(report.toJson());

    assertEquals(report, parsed);
    assertEquals("[alpha, zeta]", parsed.findings().getFirst().details().keySet().toString());
  }

  @Test
  void create_whenArtifactDigestIsNotLowercaseSha256_expectInvalidCatalogEntry() {
    List<AppSubmissionFinding> findings = List.of();
    Map<String, String> reportArtifacts = Map.of("submissionDigest", "A".repeat(64));

    AppCatalogException exception =
        assertThrows(
            AppCatalogException.class,
            () ->
                AppSubmissionPreReviewReport.create(
                    SUBMISSION_ID, APP_ID, APP_VERSION, findings, reportArtifacts));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
    assertTrue(exception.getMessage().contains("artifacts.submissionDigest"));
  }

  @Test
  void parse_whenStatusPassButWarningFindingExists_expectInvalidCatalogEntry() {
    String report =
        """
        {
          "schemaVersion": 1,
          "submissionId": "%s",
          "appId": "%s",
          "appVersion": "%s",
          "status": "pass",
           "promotionReady": true,
           "findings": [
             {
               "id": "permission.rationale.review",
               "severity": "warning",
               "summary": "Permission rationale needs reviewer attention.",
               "details": {}
             }
           ],
           "artifacts": {}
         }
        """
            .formatted(SUBMISSION_ID, APP_ID, APP_VERSION);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppSubmissionPreReviewReport.parse(report));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
    assertTrue(exception.getMessage().contains("pre-review status must match findings"));
  }

  @Test
  void parse_whenStatusFailButNoBlockerFindingExists_expectInvalidCatalogEntry() {
    String report =
        """
        {
          "schemaVersion": 1,
          "submissionId": "%s",
          "appId": "%s",
          "appVersion": "%s",
          "status": "fail",
          "promotionReady": true,
          "findings": [],
          "artifacts": {}
        }
        """
            .formatted(SUBMISSION_ID, APP_ID, APP_VERSION);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppSubmissionPreReviewReport.parse(report));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
    assertTrue(exception.getMessage().contains("pre-review status must match findings"));
  }

  private static AppSubmissionFinding finding(String id, AppSubmissionFindingSeverity severity) {
    return new AppSubmissionFinding(id, severity, "Summary.", Map.of());
  }

  private static Map<String, String> artifacts() {
    LinkedHashMap<String, String> artifacts = new LinkedHashMap<>();
    artifacts.put("submissionDigest", "a".repeat(64));
    artifacts.put("manifestDigest", "b".repeat(64));
    artifacts.put("bundleBytes", "1234");
    return artifacts;
  }
}
