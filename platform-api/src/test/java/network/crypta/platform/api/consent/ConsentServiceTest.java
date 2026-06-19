package network.crypta.platform.api.consent;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import network.crypta.platform.api.PlatformApiException;
import network.crypta.platform.api.PlatformApiPrincipal;
import network.crypta.platform.api.PlatformApiRequest;
import network.crypta.platform.api.PlatformApiResponse;
import network.crypta.platform.api.appcatalogs.AppCatalogsApiHandler;
import network.crypta.platform.api.appservices.AppServiceCoordinator;
import network.crypta.platform.api.appupdates.AppUpdateService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@SuppressWarnings({"java:S100", "unchecked"})
class ConsentServiceTest {
  private static final String APP_ID = "example.app";
  private static final String CATALOG_ID = "first-party";
  private static final String DIGEST =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  private static final String DIGEST_PREFIX = "sha256:";
  private static final String ERROR_STALE_CONSENT_SNAPSHOT = "stale_consent_snapshot";
  private static final String KEY_ADDED = "added";
  private static final String KEY_API_COMPATIBILITY = "apiCompatibility";
  private static final String KEY_APP_ID = "appId";
  private static final String KEY_BLOCKING_REASONS = "blockingReasons";
  private static final String KEY_BLOCKS_INSTALL = "blocksInstall";
  private static final String KEY_BLOCKS_UPDATE = "blocksUpdate";
  private static final String KEY_BUNDLE = "bundle";
  private static final String KEY_CHANNEL = "channel";
  private static final String KEY_CONSENT_REQUEST_ID = "consentRequestId";
  private static final String KEY_DEPRECATION = "deprecation";
  private static final String KEY_EXPERIMENTAL_CAPABILITIES_ACCEPTED =
      "experimentalCapabilitiesAccepted";
  private static final String KEY_MIGRATION_ACKNOWLEDGED = "migrationAcknowledged";
  private static final String KEY_PERMISSIONS = "permissions";
  private static final String KEY_POSITIVE = "positive";
  private static final String KEY_RECOMMENDED_ACTION = "recommendedAction";
  private static final String KEY_REMOVED = "removed";
  private static final String KEY_REQUIRES_ACKNOWLEDGEMENT = "requiresAcknowledgement";
  private static final String KEY_REQUIRES_APPROVAL = "requiresApproval";
  private static final String KEY_REVIEW_ACKNOWLEDGED = "reviewAcknowledged";
  private static final String KEY_REVIEW_TRUST = "reviewTrust";
  private static final String KEY_RISK_LEVEL = "riskLevel";
  private static final String KEY_SECTIONS = "sections";
  private static final String KEY_SECURITY_ADVISORIES = "securityAdvisories";
  private static final String KEY_SECURITY_DECISION = "securityDecision";
  private static final String KEY_SHA256 = "sha256";
  private static final String KEY_SNAPSHOT_DIGEST = "snapshotDigest";
  private static final String KEY_STATUS = "status";
  private static final String KEY_SUPPORT_STATUS = "supportStatus";
  private static final String KEY_TARGET_STABILITY = "targetStability";
  private static final String PERMISSION_CONTENT_FETCH = "content.fetch";
  private static final String REQUIRED = "required";
  private static final String ROUTE_CONSENT = "consent";
  private static final String ROUTE_UPDATE_PREVIEW = "update-preview";
  private static final String TEST_INSTANT = "2026-05-01T00:00:00Z";
  private static final String TRUSTED = "trusted";
  private static final String VALUE_BLOCKING = "blocking";
  private static final String VALUE_COMPATIBLE = "compatible";
  private static final String VALUE_MATERIAL = "material";
  private static final String VALUE_STABLE = "stable";
  private static final String VALUE_SUPPORTED = "supported";
  private static final String VERSION_1_0_0 = "1.0.0";
  private static final PlatformApiPrincipal HOST_OPERATOR = PlatformApiPrincipal.hostOperator();
  private static final PlatformApiPrincipal APP_PRINCIPAL =
      PlatformApiPrincipal.appToken(APP_ID, List.of("apps.manage", "catalogs.manage"));

  @Mock private AppCatalogsApiHandler catalogHandler;
  @Mock private AppUpdateService updateService;
  @Mock private AppServiceCoordinator appServiceCoordinator;

  @Test
  void installPreview_whenCatalogEntryHasMaterialMetadata_expectGroupedConsentSections() {
    when(catalogHandler.getApp(CATALOG_ID, APP_ID)).thenReturn(catalogApp());
    ConsentService service = new ConsentService(catalogHandler, null, null);

    Map<String, Object> preview = service.installPreview(CATALOG_ID, APP_ID);

    assertEquals("install_app", preview.get("action"));
    assertEquals(APP_ID, preview.get(KEY_APP_ID));
    assertEquals(DIGEST_PREFIX + DIGEST, preview.get("candidateDigest"));
    assertEquals(VALUE_MATERIAL, preview.get(KEY_RISK_LEVEL));
    assertEquals(true, preview.get(KEY_REQUIRES_APPROVAL));
    List<Map<String, Object>> sections = (List<Map<String, Object>>) preview.get(KEY_SECTIONS);
    assertSection(sections, KEY_PERMISSIONS);
    assertSection(sections, "review-trust");
    assertSection(sections, "catalog-support");
    assertSection(sections, "security");
    assertSection(sections, "app-service-grants");
    assertTrue(((List<String>) preview.get(KEY_BLOCKING_REASONS)).contains("permission_required"));
  }

  @Test
  void installPreview_whenSecurityDecisionBlocksInstallOnly_expectBlockingRisk() {
    when(catalogHandler.getApp(CATALOG_ID, APP_ID))
        .thenReturn(
            catalogAppWith(
                KEY_SECURITY_DECISION,
                Map.of(
                    KEY_STATUS,
                    "denylisted",
                    KEY_REQUIRES_ACKNOWLEDGEMENT,
                    true,
                    KEY_BLOCKS_INSTALL,
                    true,
                    KEY_BLOCKS_UPDATE,
                    false)));
    ConsentService service = new ConsentService(catalogHandler, null, null);

    Map<String, Object> preview = service.installPreview(CATALOG_ID, APP_ID);

    assertEquals(VALUE_BLOCKING, preview.get(KEY_RISK_LEVEL));
    assertEquals(true, preview.get(KEY_REQUIRES_APPROVAL));
    assertTrue(
        ((List<String>) preview.get(KEY_BLOCKING_REASONS)).contains("security_advisory_delta"));
  }

  @Test
  void installPreview_whenReviewTrustBlocksInstallOnly_expectBlockingRisk() {
    when(catalogHandler.getApp(CATALOG_ID, APP_ID))
        .thenReturn(
            catalogAppWith(
                KEY_REVIEW_TRUST,
                Map.of(
                    KEY_STATUS,
                    "revoked",
                    KEY_POSITIVE,
                    false,
                    KEY_REQUIRES_ACKNOWLEDGEMENT,
                    true,
                    KEY_BLOCKS_INSTALL,
                    true,
                    KEY_BLOCKS_UPDATE,
                    false)));
    ConsentService service = new ConsentService(catalogHandler, null, null);

    Map<String, Object> preview = service.installPreview(CATALOG_ID, APP_ID);

    assertEquals(VALUE_BLOCKING, preview.get(KEY_RISK_LEVEL));
    assertEquals(true, preview.get(KEY_REQUIRES_APPROVAL));
    assertTrue(((List<String>) preview.get(KEY_BLOCKING_REASONS)).contains("review_trust_delta"));
  }

  @Test
  void approve_whenSnapshotRiskIsBlocking_expectConsentBlockedAndNoApprovalAudit() {
    when(catalogHandler.getApp(CATALOG_ID, APP_ID))
        .thenReturn(
            catalogAppWith(
                KEY_SECURITY_DECISION,
                Map.of(
                    KEY_STATUS,
                    "denylisted",
                    KEY_REQUIRES_ACKNOWLEDGEMENT,
                    true,
                    KEY_BLOCKS_INSTALL,
                    true,
                    KEY_BLOCKS_UPDATE,
                    false)));
    ConsentService service = new ConsentService(catalogHandler, null, null);
    Map<String, Object> preview = service.installPreview(CATALOG_ID, APP_ID);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    Map<String, List<String>> approvalParams = params(requestId, digest);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class, () -> service.approve(approvalParams, HOST_OPERATOR));

    assertEquals(409, exception.statusCode());
    assertEquals("consent_blocked", exception.errorCode());
    assertTrue(service.audit(APP_ID).isEmpty());
  }

  @Test
  void requireApprovedUpdate_whenDigestMatches_expectMutationAcknowledgements() {
    when(updateService.previewForConsent(APP_ID, false)).thenReturn(updateSummary(DIGEST));
    when(updateService.previewReadOnly(APP_ID)).thenReturn(updateSummary(DIGEST));
    ConsentService service = new ConsentService(null, updateService, null);
    Map<String, Object> preview = service.updatePreview(APP_ID, false);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    service.approve(params(requestId, digest), HOST_OPERATOR);

    Map<String, List<String>> mutation =
        service.requireApprovedUpdateIfRequired(APP_ID, params(requestId, digest), HOST_OPERATOR);

    assertEquals(List.of("true"), mutation.get(KEY_REVIEW_ACKNOWLEDGED));
    assertEquals(List.of("true"), mutation.get("securityAcknowledged"));
    assertEquals(List.of("true"), mutation.get(KEY_MIGRATION_ACKNOWLEDGED));
  }

  @Test
  void updatePreview_whenCandidateStatusNone_expectNoUpdateConsentSnapshot() {
    when(updateService.previewForConsent(APP_ID, false)).thenReturn(noUpdateSummary());
    ConsentService service = new ConsentService(null, updateService, null);

    Map<String, Object> preview = service.updatePreview(APP_ID, false);

    assertEquals("none", preview.get(KEY_RISK_LEVEL));
    assertEquals(false, preview.get(KEY_REQUIRES_APPROVAL));
    assertEquals(false, preview.get("blocksAutoUpdate"));
    assertEquals("no_update_available", preview.get(KEY_RECOMMENDED_ACTION));
    assertEquals(List.of(), preview.get(KEY_BLOCKING_REASONS));
  }

  @Test
  void updatePreview_whenCandidateIsIncompatible_expectBlockingConsentSnapshot() {
    when(updateService.previewForConsent(APP_ID, false)).thenReturn(incompatibleUpdateSummary());
    ConsentService service = new ConsentService(null, updateService, null);

    Map<String, Object> preview = service.updatePreview(APP_ID, false);

    assertEquals(APP_ID, preview.get(KEY_APP_ID));
    assertEquals("1.1.0", preview.get("candidateVersion"));
    assertEquals(VALUE_BLOCKING, preview.get(KEY_RISK_LEVEL));
    assertEquals(true, preview.get(KEY_REQUIRES_APPROVAL));
    assertEquals("do_not_continue", preview.get(KEY_RECOMMENDED_ACTION));
    assertTrue(
        ((List<String>) preview.get(KEY_BLOCKING_REASONS)).contains("platform_api_compatibility"));
    assertSection((List<Map<String, Object>>) preview.get(KEY_SECTIONS), "api-stability");
  }

  @Test
  void requireApprovedUpdate_whenCandidateStatusNone_expectNoConsentRequired() {
    when(updateService.previewReadOnly(APP_ID)).thenReturn(noUpdateSummary());
    ConsentService service = new ConsentService(null, updateService, null);

    Map<String, List<String>> mutation =
        service.requireApprovedUpdateIfRequired(APP_ID, Map.of(), HOST_OPERATOR);

    assertEquals(Map.of(), mutation);
    verify(updateService, never()).previewForConsent(APP_ID, false);
  }

  @Test
  void requireApprovedUpdate_whenApprovalMissing_expectReadOnlyPreviewDoesNotPrepare() {
    when(updateService.previewReadOnly(APP_ID)).thenReturn(updateSummary(DIGEST));
    ConsentService service = new ConsentService(null, updateService, null);
    Map<String, List<String>> mutationParams = Map.of();

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.requireApprovedUpdateIfRequired(APP_ID, mutationParams, APP_PRINCIPAL));

    assertEquals("consent_required", exception.errorCode());
    verify(updateService).previewReadOnly(APP_ID);
    verify(updateService, never()).previewForConsent(APP_ID, false);
  }

  @Test
  void requireApprovedUpdate_whenApprovalReused_expectConsentNotApproved() {
    when(updateService.previewForConsent(APP_ID, false)).thenReturn(updateSummary(DIGEST));
    when(updateService.previewReadOnly(APP_ID)).thenReturn(updateSummary(DIGEST));
    ConsentService service = new ConsentService(null, updateService, null);
    Map<String, Object> preview = service.updatePreview(APP_ID, false);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    Map<String, List<String>> mutationParams = params(requestId, digest);
    service.approve(mutationParams, HOST_OPERATOR);
    service.requireApprovedUpdateIfRequired(APP_ID, mutationParams, HOST_OPERATOR);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.requireApprovedUpdateIfRequired(APP_ID, mutationParams, HOST_OPERATOR));

    assertEquals("consent_not_approved", exception.errorCode());
  }

  @Test
  void requireApprovedUpdate_whenApprovalExpires_expectConsentNotApprovedAndExpiredAudit() {
    when(updateService.previewForConsent(APP_ID, false)).thenReturn(updateSummary(DIGEST));
    when(updateService.previewReadOnly(APP_ID)).thenReturn(updateSummary(DIGEST));
    MutableClock clock = new MutableClock(Instant.parse(TEST_INSTANT));
    ConsentService service =
        new ConsentService(null, updateService, null, new InMemoryConsentAuditStore(), clock);
    Map<String, Object> preview = service.updatePreview(APP_ID, false);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    Map<String, List<String>> mutationParams = params(requestId, digest);
    service.approve(mutationParams, HOST_OPERATOR);
    clock.advance(Duration.ofMinutes(16));

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.requireApprovedUpdateIfRequired(APP_ID, mutationParams, HOST_OPERATOR));

    assertEquals("consent_not_approved", exception.errorCode());
    assertTrue(
        service.audit(APP_ID).stream().anyMatch(event -> "expired".equals(event.get("decision"))));
  }

  @Test
  void requireApprovedUpdate_whenPreviewExpiresAfterFreshApproval_expectApprovalStillUsable() {
    when(updateService.previewForConsent(APP_ID, false)).thenReturn(updateSummary(DIGEST));
    when(updateService.previewReadOnly(APP_ID)).thenReturn(updateSummary(DIGEST));
    MutableClock clock = new MutableClock(Instant.parse(TEST_INSTANT));
    ConsentService service =
        new ConsentService(null, updateService, null, new InMemoryConsentAuditStore(), clock);
    Map<String, Object> preview = service.updatePreview(APP_ID, false);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    clock.advance(Duration.ofMinutes(14).plusSeconds(59));
    service.approve(params(requestId, digest), HOST_OPERATOR);
    clock.advance(Duration.ofSeconds(2));

    Map<String, List<String>> mutation =
        service.requireApprovedUpdateIfRequired(APP_ID, params(requestId, digest), HOST_OPERATOR);

    assertEquals(List.of("true"), mutation.get(KEY_REVIEW_ACKNOWLEDGED));
    assertFalse(
        service.audit(APP_ID).stream().anyMatch(event -> "expired".equals(event.get("decision"))));
  }

  @Test
  void requireApprovedUpdate_whenCandidateDigestChanges_expectStaleApprovalRejected() {
    when(updateService.previewForConsent(APP_ID, false))
        .thenReturn(updateSummary(DIGEST))
        .thenReturn(
            updateSummary("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"));
    when(updateService.previewReadOnly(APP_ID))
        .thenReturn(
            updateSummary("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"));
    ConsentService service = new ConsentService(null, updateService, null);
    Map<String, Object> preview = service.updatePreview(APP_ID, false);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    Map<String, List<String>> mutationParams = params(requestId, digest);
    service.approve(mutationParams, HOST_OPERATOR);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.requireApprovedUpdateIfRequired(APP_ID, mutationParams, HOST_OPERATOR));

    assertEquals(ERROR_STALE_CONSENT_SNAPSHOT, exception.errorCode());
  }

  @Test
  void requireApprovedUpdate_whenMigrationRequiresReview_expectMutationAcknowledgement() {
    Map<String, Object> summary =
        updateSummary(DIGEST, noPermissionDelta(), migrationRequiresReview());
    when(updateService.previewForConsent(APP_ID, false)).thenReturn(summary);
    when(updateService.previewReadOnly(APP_ID)).thenReturn(summary);
    ConsentService service = new ConsentService(null, updateService, null);
    Map<String, Object> preview = service.updatePreview(APP_ID, false);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    service.approve(params(requestId, digest), HOST_OPERATOR);

    Map<String, List<String>> mutation =
        service.requireApprovedUpdateIfRequired(APP_ID, params(requestId, digest), HOST_OPERATOR);

    assertEquals(VALUE_MATERIAL, preview.get(KEY_RISK_LEVEL));
    assertEquals(true, preview.get(KEY_REQUIRES_APPROVAL));
    assertTrue(
        ((List<String>) preview.get(KEY_BLOCKING_REASONS)).contains("app_data_migration_plan"));
    assertTrue(
        migrationPlanSummary(preview).contains("Schema 1 to 2"),
        "migration consent summary should preserve numeric schema versions");
    assertEquals(List.of("true"), mutation.get(KEY_MIGRATION_ACKNOWLEDGED));
  }

  @Test
  void requireApprovedUpdate_whenPreparedMigrationRequiresReview_expectMutationAcknowledgement() {
    Map<String, Object> readOnly = updateSummary(DIGEST, noPermissionDelta(), noMigration());
    Map<String, Object> prepared =
        updateSummary(DIGEST, noPermissionDelta(), migrationRequiresReview());
    when(updateService.previewForConsent(APP_ID, false)).thenReturn(prepared);
    when(updateService.previewReadOnly(APP_ID)).thenReturn(readOnly);
    ConsentService service = new ConsentService(null, updateService, null);
    Map<String, Object> preview = service.updatePreview(APP_ID, false);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    service.approve(params(requestId, digest), HOST_OPERATOR);

    Map<String, List<String>> mutation =
        service.requireApprovedUpdateIfRequired(APP_ID, params(requestId, digest), HOST_OPERATOR);

    assertEquals(VALUE_MATERIAL, preview.get(KEY_RISK_LEVEL));
    assertEquals(List.of("true"), mutation.get(KEY_MIGRATION_ACKNOWLEDGED));
  }

  @Test
  void requireApprovedUpdate_whenOnlyLegacyAcknowledgementSupplied_expectAcknowledgementRemoved() {
    when(updateService.previewReadOnly(APP_ID))
        .thenReturn(updateSummary(DIGEST, noPermissionDelta(), noMigration()));
    ConsentService service = new ConsentService(null, updateService, null);

    Map<String, List<String>> mutation =
        service.requireApprovedUpdateIfRequired(
            APP_ID, Map.of(KEY_MIGRATION_ACKNOWLEDGED, List.of("true")), HOST_OPERATOR);

    assertFalse(mutation.containsKey(KEY_MIGRATION_ACKNOWLEDGED));
    verify(updateService).previewReadOnly(APP_ID);
    verify(updateService, never()).previewForConsent(APP_ID, false);
  }

  @Test
  void requireApprovedUpdate_whenSecurityAdvisoryIdentityChanges_expectStaleApprovalRejected() {
    Map<String, Object> original =
        updateSummary(
            DIGEST,
            noPermissionDelta(),
            noMigration(),
            List.of(securityAdvisory("CRYPTA-2026-0001", "https://example.invalid/a/1")));
    Map<String, Object> changed =
        updateSummary(
            DIGEST,
            noPermissionDelta(),
            noMigration(),
            List.of(securityAdvisory("CRYPTA-2026-0002", "https://example.invalid/a/2")));
    when(updateService.previewForConsent(APP_ID, false)).thenReturn(original).thenReturn(changed);
    when(updateService.previewReadOnly(APP_ID)).thenReturn(changed);
    ConsentService service = new ConsentService(null, updateService, null);
    Map<String, Object> preview = service.updatePreview(APP_ID, false);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    Map<String, List<String>> mutationParams = params(requestId, digest);
    service.approve(mutationParams, HOST_OPERATOR);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.requireApprovedUpdateIfRequired(APP_ID, mutationParams, HOST_OPERATOR));

    assertNotEquals(digest, service.updatePreview(APP_ID, false).get(KEY_SNAPSHOT_DIGEST));
    assertEquals(ERROR_STALE_CONSENT_SNAPSHOT, exception.errorCode());
  }

  @Test
  void requireApprovedUpdate_whenReviewReceiptIdentityChanges_expectStaleApprovalRejected() {
    Map<String, Object> original =
        updateSummary(
            DIGEST, materialPermissionDelta(), noMigration(), List.of(), trustedReviewTrust("1"));
    Map<String, Object> changed =
        updateSummary(
            DIGEST, materialPermissionDelta(), noMigration(), List.of(), trustedReviewTrust("2"));
    when(updateService.previewForConsent(APP_ID, false)).thenReturn(original).thenReturn(changed);
    when(updateService.previewReadOnly(APP_ID)).thenReturn(changed);
    ConsentService service = new ConsentService(null, updateService, null);
    Map<String, Object> preview = service.updatePreview(APP_ID, false);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    Map<String, List<String>> mutationParams = params(requestId, digest);
    service.approve(mutationParams, HOST_OPERATOR);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () -> service.requireApprovedUpdateIfRequired(APP_ID, mutationParams, HOST_OPERATOR));

    assertEquals(ERROR_STALE_CONSENT_SNAPSHOT, exception.errorCode());
  }

  @Test
  void updatePreview_whenGetIncludesRefreshCatalogs_expectReadOnlyPreviewWithoutRefresh() {
    when(updateService.previewReadOnly(APP_ID)).thenReturn(updateSummary(DIGEST));
    ConsentApiHandler handler =
        new ConsentApiHandler(new ConsentService(null, updateService, null));

    PlatformApiResponse response =
        handler.route(
            List.of(ROUTE_CONSENT, ROUTE_UPDATE_PREVIEW),
            new PlatformApiRequest(
                "GET",
                List.of(ROUTE_CONSENT, ROUTE_UPDATE_PREVIEW),
                Map.of(KEY_APP_ID, List.of(APP_ID), "refreshCatalogs", List.of("true"))));

    assertEquals(200, response.statusCode());
    verify(updateService).previewReadOnly(APP_ID);
    verify(updateService, never()).preview(APP_ID, false);
    verify(updateService, never()).previewForConsent(APP_ID, true);
    verify(updateService, never()).previewForConsent(APP_ID, false);
  }

  @Test
  void updatePreview_whenPostIncludesRefreshCatalogs_expectConsentPreviewRefresh() {
    when(updateService.previewForConsent(APP_ID, true)).thenReturn(updateSummary(DIGEST));
    ConsentApiHandler handler =
        new ConsentApiHandler(new ConsentService(null, updateService, null));

    PlatformApiResponse response =
        handler.route(
            List.of(ROUTE_CONSENT, ROUTE_UPDATE_PREVIEW),
            new PlatformApiRequest(
                "POST",
                List.of(ROUTE_CONSENT, ROUTE_UPDATE_PREVIEW),
                Map.of(KEY_APP_ID, List.of(APP_ID), "refreshCatalogs", List.of("true"))));

    assertEquals(200, response.statusCode());
    verify(updateService).previewForConsent(APP_ID, true);
    verify(updateService, never()).preview(APP_ID, true);
  }

  @Test
  void requireApprovedInstall_whenApiCompatibilityUnknown_expectApprovalPermitsMutation() {
    assertApiCompatibilityStatusAllowsApprovedInstall("unknown");
  }

  @Test
  void requireApprovedInstall_whenApiCompatibilityNewerThanTested_expectApprovalPermitsMutation() {
    assertApiCompatibilityStatusAllowsApprovedInstall("newer_than_tested");
  }

  private void assertApiCompatibilityStatusAllowsApprovedInstall(String status) {
    when(catalogHandler.getApp(CATALOG_ID, APP_ID))
        .thenReturn(catalogApp(apiCompatibility(status)));
    ConsentService service = new ConsentService(catalogHandler, null, null);
    Map<String, Object> preview = service.installPreview(CATALOG_ID, APP_ID);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    service.approve(params(requestId, digest), HOST_OPERATOR);

    Map<String, List<String>> mutation =
        service.requireApprovedInstallIfRequired(
            CATALOG_ID, APP_ID, params(requestId, digest), HOST_OPERATOR);

    assertEquals(VALUE_MATERIAL, preview.get(KEY_RISK_LEVEL));
    assertTrue(
        ((List<String>) preview.get(KEY_BLOCKING_REASONS)).contains("platform_api_compatibility"));
    assertEquals(List.of("true"), mutation.get(KEY_REVIEW_ACKNOWLEDGED));
  }

  @Test
  void requireApprovedPreparedInstall_whenPreparedEntryDiffers_expectStaleApprovalRejected() {
    when(catalogHandler.getApp(CATALOG_ID, APP_ID)).thenReturn(catalogApp());
    when(catalogHandler.summarizePreparedPlanForConsent(CATALOG_ID, null, false))
        .thenReturn(
            catalogAppWith(KEY_PERMISSIONS, List.of(PERMISSION_CONTENT_FETCH, "queue.read")));
    ConsentService service = new ConsentService(catalogHandler, null, null);
    Map<String, Object> preview = service.installPreview(CATALOG_ID, APP_ID);
    String requestId = (String) preview.get(KEY_CONSENT_REQUEST_ID);
    String digest = (String) preview.get(KEY_SNAPSHOT_DIGEST);
    Map<String, List<String>> mutationParams = params(requestId, digest);
    service.approve(mutationParams, HOST_OPERATOR);
    service.requireApprovedInstallIfRequired(CATALOG_ID, APP_ID, mutationParams, HOST_OPERATOR);

    PlatformApiException exception =
        assertThrows(
            PlatformApiException.class,
            () ->
                service.requireApprovedPreparedInstallIfRequired(
                    CATALOG_ID, null, mutationParams, HOST_OPERATOR));

    assertEquals(ERROR_STALE_CONSENT_SNAPSHOT, exception.errorCode());
  }

  @Test
  void serviceGrantPreview_whenBundleHasDependencies_expectGrantConsentSections() {
    when(appServiceCoordinator.listBundles(HOST_OPERATOR)).thenReturn(List.of(serviceBundle()));
    ConsentService service = new ConsentService(null, null, appServiceCoordinator);

    Map<String, Object> preview = service.serviceGrantPreview("bundle-1");

    assertEquals("app_service_grant", preview.get("action"));
    assertEquals(VALUE_MATERIAL, preview.get(KEY_RISK_LEVEL));
    assertEquals("review_before_service_grant", preview.get(KEY_RECOMMENDED_ACTION));
    List<Map<String, Object>> sections = (List<Map<String, Object>>) preview.get(KEY_SECTIONS);
    assertSection(sections, "app-service-dependencies");
    assertSection(sections, "audit");
  }

  @Test
  void auditEvent_whenRiskSummaryContainsSensitiveValues_expectRedactedJson() {
    ConsentAuditEvent event =
        new ConsentAuditEvent(
            "decision-1",
            "request-1",
            "local_operator",
            APP_ID,
            ConsentActionType.INSTALL_APP,
            ConsentDecisionStatus.REJECTED,
            Instant.parse(TEST_INSTANT),
            DIGEST_PREFIX + DIGEST,
            List.of("token=secret-value", "CHK@private-insert-material", "/tmp/local/secret/path"));

    String summary = event.toJsonValue().get("materialRiskSummary").toString();

    assertFalse(summary.contains("secret-value"));
    assertFalse(summary.contains("CHK@private"));
    assertFalse(summary.contains("/tmp/local/secret/path"));
    assertTrue(summary.contains("[redacted-secret]"));
    assertTrue(summary.contains("[redacted-private-uri]"));
    assertTrue(summary.contains("[redacted-local-path]"));
  }

  @Test
  void auditStore_whenHistoryExceedsLimit_expectOldestEventsDropped() {
    InMemoryConsentAuditStore store = new InMemoryConsentAuditStore();
    for (int index = 0; index < InMemoryConsentAuditStore.MAX_EVENTS + 3; index++) {
      store.append(auditEvent(index));
    }

    List<ConsentAuditEvent> events = store.list(null);

    assertEquals(InMemoryConsentAuditStore.MAX_EVENTS, events.size());
    assertEquals("decision-3", events.getFirst().decisionId());
    assertNull(store.list("missing.app").stream().findFirst().orElse(null));
  }

  private static ConsentAuditEvent auditEvent(int index) {
    return new ConsentAuditEvent(
        "decision-" + index,
        "request-" + index,
        "local_operator",
        APP_ID,
        ConsentActionType.INSTALL_APP,
        ConsentDecisionStatus.APPROVED,
        Instant.parse(TEST_INSTANT).plusSeconds(index),
        DIGEST_PREFIX + DIGEST,
        List.of("permission_required"));
  }

  private static void assertSection(List<Map<String, Object>> sections, String id) {
    assertTrue(
        sections.stream().anyMatch(section -> id.equals(section.get("id"))),
        "missing consent section " + id);
  }

  private static String migrationPlanSummary(Map<String, Object> preview) {
    List<Map<String, Object>> sections = (List<Map<String, Object>>) preview.get(KEY_SECTIONS);
    Map<String, Object> migrationSection =
        sections.stream()
            .filter(section -> "app-data-migration".equals(section.get("id")))
            .findFirst()
            .orElseThrow();
    List<Map<String, Object>> items = (List<Map<String, Object>>) migrationSection.get("items");
    return items.stream()
        .filter(item -> "app_data_migration_plan".equals(item.get("code")))
        .map(item -> String.valueOf(item.get("summary")))
        .findFirst()
        .orElseThrow();
  }

  private static Map<String, List<String>> params(String requestId, String digest) {
    return Map.of(KEY_CONSENT_REQUEST_ID, List.of(requestId), KEY_SNAPSHOT_DIGEST, List.of(digest));
  }

  private static Map<String, Object> catalogApp() {
    return catalogApp(apiCompatibility(VALUE_COMPATIBLE));
  }

  private static Map<String, Object> catalogAppWith(String key, Object value) {
    LinkedHashMap<String, Object> app = new LinkedHashMap<>(catalogApp());
    app.put(key, value);
    return app;
  }

  private static Map<String, Object> catalogApp(Map<String, Object> apiCompatibility) {
    return Map.ofEntries(
        Map.entry(KEY_APP_ID, APP_ID),
        Map.entry("name", "Example App"),
        Map.entry("version", "1.2.0"),
        Map.entry(KEY_CHANNEL, "beta"),
        Map.entry(KEY_SUPPORT_STATUS, VALUE_SUPPORTED),
        Map.entry(
            "maintenance",
            Map.of(
                "owner",
                "Crypta",
                "backupRestore",
                VALUE_SUPPORTED,
                "dataSchemaPolicy",
                VALUE_STABLE)),
        Map.entry(KEY_DEPRECATION, Map.of(KEY_STATUS, "none")),
        Map.entry(
            KEY_SECURITY_DECISION,
            Map.of(
                KEY_STATUS,
                "ok",
                KEY_REQUIRES_ACKNOWLEDGEMENT,
                false,
                KEY_BLOCKS_INSTALL,
                false,
                KEY_BLOCKS_UPDATE,
                false)),
        Map.entry(KEY_SECURITY_ADVISORIES, List.of()),
        Map.entry(
            KEY_REVIEW_TRUST,
            Map.of(
                KEY_STATUS,
                TRUSTED,
                KEY_POSITIVE,
                true,
                KEY_BLOCKS_INSTALL,
                false,
                KEY_BLOCKS_UPDATE,
                false)),
        Map.entry(
            "thirdPartyReview",
            Map.of(
                "reviewerKeyId",
                "crypta-reviewer",
                "receiptFingerprintSha256",
                "review-receipt-fingerprint")),
        Map.entry(KEY_PERMISSIONS, List.of(PERMISSION_CONTENT_FETCH)),
        Map.entry(
            "permissionRationales", Map.of(PERMISSION_CONTENT_FETCH, "Fetches app documents.")),
        Map.entry(KEY_API_COMPATIBILITY, apiCompatibility),
        Map.entry(KEY_BUNDLE, Map.of(KEY_SHA256, DIGEST)));
  }

  private static Map<String, Object> apiCompatibility(String status) {
    return Map.of(
        KEY_STATUS,
        status,
        KEY_TARGET_STABILITY,
        VALUE_STABLE,
        KEY_EXPERIMENTAL_CAPABILITIES_ACCEPTED,
        false);
  }

  private static Map<String, Object> updateSummary(String digest) {
    return updateSummary(
        digest,
        Map.of(KEY_ADDED, List.of(PERMISSION_CONTENT_FETCH), KEY_REMOVED, List.of()),
        noMigration());
  }

  private static Map<String, Object> updateSummary(
      String digest, Map<String, Object> permissionDelta, Map<String, Object> migration) {
    return updateSummary(digest, permissionDelta, migration, List.of());
  }

  private static Map<String, Object> updateSummary(
      String digest,
      Map<String, Object> permissionDelta,
      Map<String, Object> migration,
      List<Object> securityAdvisories) {
    return updateSummary(
        digest,
        permissionDelta,
        migration,
        securityAdvisories,
        Map.of(KEY_STATUS, TRUSTED, KEY_POSITIVE, true));
  }

  private static Map<String, Object> updateSummary(
      String digest,
      Map<String, Object> permissionDelta,
      Map<String, Object> migration,
      List<Object> securityAdvisories,
      Map<String, Object> reviewTrust) {
    return updateSummary(
        digest,
        permissionDelta,
        migration,
        securityAdvisories,
        reviewTrust,
        "available",
        Map.of(
            KEY_STATUS,
            VALUE_COMPATIBLE,
            KEY_TARGET_STABILITY,
            VALUE_STABLE,
            KEY_EXPERIMENTAL_CAPABILITIES_ACCEPTED,
            false));
  }

  private static Map<String, Object> updateSummary(
      String digest,
      Map<String, Object> permissionDelta,
      Map<String, Object> migration,
      List<Object> securityAdvisories,
      Map<String, Object> reviewTrust,
      String candidateStatus,
      Map<String, Object> apiCompatibility) {
    return Map.of(
        "candidate",
        Map.ofEntries(
            Map.entry(KEY_APP_ID, APP_ID),
            Map.entry("installedVersion", VERSION_1_0_0),
            Map.entry("targetVersion", "1.1.0"),
            Map.entry(KEY_STATUS, candidateStatus),
            Map.entry("catalogId", CATALOG_ID),
            Map.entry("catalogSourceId", CATALOG_ID),
            Map.entry(KEY_CHANNEL, VALUE_STABLE),
            Map.entry(KEY_SUPPORT_STATUS, VALUE_SUPPORTED),
            Map.entry(KEY_DEPRECATION, Map.of(KEY_STATUS, "none")),
            Map.entry(
                KEY_SECURITY_DECISION,
                Map.of(
                    KEY_STATUS,
                    "ok",
                    KEY_REQUIRES_ACKNOWLEDGEMENT,
                    false,
                    KEY_BLOCKS_UPDATE,
                    false)),
            Map.entry(KEY_SECURITY_ADVISORIES, securityAdvisories),
            Map.entry(KEY_REVIEW_TRUST, reviewTrust),
            Map.entry(KEY_API_COMPATIBILITY, apiCompatibility),
            Map.entry("permissionDelta", permissionDelta),
            Map.entry("dataMigration", migration),
            Map.entry(KEY_BUNDLE, Map.of(KEY_SHA256, digest))));
  }

  private static Map<String, Object> incompatibleUpdateSummary() {
    return updateSummary(
        DIGEST,
        noPermissionDelta(),
        noMigration(),
        List.of(),
        Map.of(KEY_STATUS, TRUSTED, KEY_POSITIVE, true),
        "incompatible",
        Map.of(
            KEY_STATUS,
            "below_minimum",
            KEY_TARGET_STABILITY,
            VALUE_STABLE,
            KEY_EXPERIMENTAL_CAPABILITIES_ACCEPTED,
            false));
  }

  private static Map<String, Object> securityAdvisory(String id, String uri) {
    return Map.of("id", id, "uri", uri);
  }

  private static Map<String, Object> materialPermissionDelta() {
    return Map.of(KEY_ADDED, List.of(PERMISSION_CONTENT_FETCH), KEY_REMOVED, List.of());
  }

  private static Map<String, Object> trustedReviewTrust(String suffix) {
    return Map.ofEntries(
        Map.entry(KEY_STATUS, "trusted_reviewed"),
        Map.entry(TRUSTED, true),
        Map.entry(KEY_POSITIVE, true),
        Map.entry(KEY_REQUIRES_ACKNOWLEDGEMENT, false),
        Map.entry(KEY_BLOCKS_INSTALL, false),
        Map.entry(KEY_BLOCKS_UPDATE, false),
        Map.entry("blocksPolicyApply", false),
        Map.entry("reviewerKeyId", "reviewer-" + suffix),
        Map.entry("reviewerDisplayName", "Reviewer " + suffix),
        Map.entry("reviewerKeyStatus", "active"),
        Map.entry("policyId", "crypta-app-review"),
        Map.entry("policyVersion", suffix),
        Map.entry("policyVersionStatus", "current"),
        Map.entry("policyMode", "advisory"),
        Map.entry("reviewedAt", "2026-05-0" + suffix + "T00:00:00Z"),
        Map.entry("expiresAt", "2026-06-0" + suffix + "T00:00:00Z"),
        Map.entry("evidenceSha256", suffix.repeat(64)),
        Map.entry("evidenceUri", "https://example.invalid/review/" + suffix),
        Map.entry("warnings", List.of()));
  }

  private static Map<String, Object> noUpdateSummary() {
    return Map.of(
        "candidate",
        Map.ofEntries(
            Map.entry(KEY_APP_ID, APP_ID),
            Map.entry("installedVersion", VERSION_1_0_0),
            Map.entry("targetVersion", VERSION_1_0_0),
            Map.entry(KEY_STATUS, "none"),
            Map.entry("catalogId", "none"),
            Map.entry("catalogSourceId", "none"),
            Map.entry(KEY_CHANNEL, VALUE_STABLE),
            Map.entry(KEY_SUPPORT_STATUS, VALUE_SUPPORTED),
            Map.entry(KEY_DEPRECATION, Map.of(KEY_STATUS, "none")),
            Map.entry(
                KEY_SECURITY_DECISION,
                Map.of(
                    KEY_STATUS,
                    "ok",
                    KEY_REQUIRES_ACKNOWLEDGEMENT,
                    false,
                    KEY_BLOCKS_UPDATE,
                    false)),
            Map.entry(KEY_SECURITY_ADVISORIES, List.of()),
            Map.entry(
                KEY_REVIEW_TRUST,
                Map.of(
                    KEY_STATUS,
                    "missing",
                    KEY_POSITIVE,
                    false,
                    KEY_REQUIRES_ACKNOWLEDGEMENT,
                    true)),
            Map.entry(
                KEY_API_COMPATIBILITY,
                Map.of(
                    KEY_STATUS,
                    VALUE_COMPATIBLE,
                    KEY_TARGET_STABILITY,
                    VALUE_STABLE,
                    KEY_EXPERIMENTAL_CAPABILITIES_ACCEPTED,
                    false)),
            Map.entry("permissionDelta", noPermissionDelta()),
            Map.entry("dataMigration", noMigration()),
            Map.entry(KEY_BUNDLE, Map.of(KEY_SHA256, "not_applicable"))));
  }

  private static Map<String, Object> noPermissionDelta() {
    return Map.of(KEY_ADDED, List.of(), KEY_REMOVED, List.of(), "unchanged", List.of());
  }

  private static Map<String, Object> noMigration() {
    return Map.of(REQUIRED, false);
  }

  private static Map<String, Object> migrationRequiresReview() {
    return Map.ofEntries(
        Map.entry(REQUIRED, true),
        Map.entry(KEY_STATUS, "ready"),
        Map.entry("currentSchemaVersion", 1),
        Map.entry("targetSchemaVersion", 2),
        Map.entry(
            "namespaces",
            List.of(
                Map.of(
                    "namespace",
                    "feeds",
                    "fromSchemaVersion",
                    1,
                    "toSchemaVersion",
                    2,
                    "stepId",
                    "feeds-v1-v2",
                    "rollbackCompatible",
                    false,
                    "requiresStopped",
                    true))),
        Map.entry("operatorReviewRequired", true),
        Map.entry("dryRunStatus", "passed"));
  }

  private static Map<String, Object> serviceBundle() {
    return Map.ofEntries(
        Map.entry("bundleId", "bundle-1"),
        Map.entry("consumerAppId", APP_ID),
        Map.entry("bundleAlias", "social"),
        Map.entry(KEY_STATUS, "pending"),
        Map.entry("purpose", "Show social inbox messages."),
        Map.entry("includeOptional", false),
        Map.entry(
            "dependencies",
            List.of(
                Map.ofEntries(
                    Map.entry("providerAppId", "provider.app"),
                    Map.entry("serviceId", "profile.lookup"),
                    Map.entry("kind", REQUIRED),
                    Map.entry(REQUIRED, true),
                    Map.entry("scopes", List.of("read")),
                    Map.entry("contexts", List.of("profile")),
                    Map.entry("grantExpiresAfter", "PT24H")))));
  }

  private static final class MutableClock extends Clock {
    private Instant instant;

    private MutableClock(Instant instant) {
      this.instant = instant;
    }

    private void advance(Duration duration) {
      instant = instant.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      if (!ZoneOffset.UTC.equals(zone)) {
        throw new IllegalArgumentException("Consent tests use UTC only.");
      }
      return this;
    }

    @Override
    public boolean equals(Object other) {
      return this == other;
    }

    @Override
    public int hashCode() {
      return System.identityHashCode(this);
    }

    @Override
    public Instant instant() {
      return instant;
    }
  }
}
