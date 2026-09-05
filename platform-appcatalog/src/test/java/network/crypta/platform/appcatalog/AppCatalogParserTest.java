package network.crypta.platform.appcatalog;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogParserTest {
  private static final String BUNDLE_URI_PROPERTY = "app.queue-manager.bundle.uri=";
  private static final String CATALOG_VERSION_5 = "catalog.version=5";
  private static final String CATALOG_VERSION_6 = "catalog.version=6";
  private static final String GENERATED_AT = "2026-04-21T18:22:40Z";
  private static final String SECURITY_ADVISORY_ID = "CRYPTA-2026-0001";
  private static final String SHA256 = "0".repeat(64);

  @Test
  void parse_whenCatalogIsValid_expectEntryOrderAndNormalizedFields() {
    AppCatalog catalog =
        AppCatalogParser.parse(
            bytes(
                """
                catalog.version=1
                catalog.id=Core
                catalog.name=Crypta Core Apps
                catalog.generatedAt=%s
                catalog.entries=Publisher,queue-manager
                app.publisher.id=Publisher
                app.publisher.name=Publisher
                app.publisher.version=1.0.0
                app.publisher.summary=Publish local files.
                app.publisher.bundle.uri=https://example.invalid/publisher.zip
                app.publisher.bundle.sha256=%s
                app.publisher.bundle.size.bytes=0
                app.publisher.bundle.type=ZIP
                app.publisher.permissions=QUEUE.READ,queue.write,queue.read
                app.queue-manager.id=queue-manager
                app.queue-manager.name=Queue Manager
                app.queue-manager.version=1.0.0
                app.queue-manager.summary=Manage transfer queues.
                app.queue-manager.bundle.uri=https://example.invalid/queue-manager.zip
                app.queue-manager.bundle.sha256=%s
                app.queue-manager.bundle.size.bytes=0
                app.queue-manager.bundle.type=zip
                app.queue-manager.permissions=
                """
                    .formatted(GENERATED_AT, SHA256, SHA256)));

    List<AppCatalogEntry> entries = catalog.entries();

    assertEquals("core", catalog.catalogId());
    assertEquals(
        List.of("publisher", "queue-manager"),
        entries.stream().map(AppCatalogEntry::appId).toList());
    assertEquals(List.of("queue.read", "queue.write"), entries.getFirst().permissions());
    assertTrue(entries.get(1).permissions().isEmpty());
    assertEquals("zip", entries.getFirst().bundleType());
  }

  @Test
  void parse_whenCatalogUsesCryptaChkArtifact_expectEntryAccepted() {
    AppCatalog catalog =
        AppCatalogParser.parse(
            bytes(
                """
                catalog.version=1
                catalog.id=core
                catalog.name=Crypta Core Apps
                catalog.generatedAt=%s
                catalog.entries=queue-manager
                app.queue-manager.id=queue-manager
                app.queue-manager.name=Queue Manager
                app.queue-manager.version=1.0.0
                app.queue-manager.summary=Manage transfer queues.
                app.queue-manager.bundle.uri=crypta:CHK@queue-manager-artifact
                app.queue-manager.bundle.sha256=%s
                app.queue-manager.bundle.size.bytes=0
                app.queue-manager.bundle.type=zip
                app.queue-manager.permissions=queue.read
                """
                    .formatted(GENERATED_AT, SHA256)));

    assertEquals(
        "crypta:CHK@queue-manager-artifact", catalog.entries().getFirst().bundleUri().toString());
  }

  @Test
  void parse_whenCatalogHasOptionalStoreMetadata_expectMetadataNormalized() {
    AppCatalog catalog =
        AppCatalogParser.parse(
            bytes(
                """
                catalog.version=7
                catalog.id=core
                catalog.name=Crypta Core Apps
                catalog.generatedAt=%s
                catalog.entries=queue-manager
                app.queue-manager.id=queue-manager
                app.queue-manager.name=Queue Manager
                app.queue-manager.version=1.2.0
                app.queue-manager.summary=Manage transfer queues.
                app.queue-manager.homepage=https://example.invalid/app
                app.queue-manager.source=https://example.invalid/repo
                app.queue-manager.license=MIT
                app.queue-manager.categories=Productivity,network,productivity
                app.queue-manager.minimumCryptaVersion=0.1.0
                app.queue-manager.api.minimumVersion=1
                app.queue-manager.api.maximumTestedVersion=1
                app.queue-manager.api.optionalCapabilities=alerts.read,diagnostics.read
                app.queue-manager.api.targetStability=experimental
                app.queue-manager.api.targetBaseline=1.1
                app.queue-manager.api.experimentalCapabilitiesAccepted=true
                app.queue-manager.review.status=reviewed
                app.queue-manager.review.note=Reviewed for local operator safety.
                app.queue-manager.permissions.rationale.queue.read=Reads the local transfer queue.
                app.queue-manager.permissions.rationale.queue.write=Updates queue state.
                app.queue-manager.screenshot.1=https://example.invalid/assets/shot-1.png
                app.queue-manager.screenshot.2=https://example.invalid/assets/shot-2.png
                app.queue-manager.changelog.summary=Adds queue retry controls.
                app.queue-manager.changelog.uri=https://example.invalid/changelog.txt
                app.queue-manager.bundle.uri=https://example.invalid/queue-manager.zip
                app.queue-manager.bundle.sha256=%s
                app.queue-manager.bundle.size.bytes=0
                app.queue-manager.bundle.type=zip
                app.queue-manager.permissions=queue.read,queue.write
                """
                    .formatted(GENERATED_AT, SHA256)));

    AppCatalogEntry entry = catalog.entries().getFirst();

    assertEquals(AppCatalog.VERSION_PLATFORM_API_TARGET_BASELINE, catalog.version());
    assertEquals("https://example.invalid/app", entry.homepage().orElseThrow().toString());
    assertEquals("https://example.invalid/repo", entry.source().orElseThrow().toString());
    assertEquals("MIT", entry.license().orElseThrow());
    assertEquals(List.of("productivity", "network"), entry.categories());
    assertEquals("0.1.0", entry.compatibility().minimumCryptaVersion());
    assertEquals(Integer.valueOf(1), entry.compatibility().apiCompatibility().minimumVersion());
    assertEquals(
        Integer.valueOf(1), entry.compatibility().apiCompatibility().maximumTestedVersion());
    assertEquals(
        List.of("alerts.read", "diagnostics.read"),
        entry.compatibility().apiCompatibility().optionalCapabilities());
    assertEquals(
        network.crypta.platform.appdist.AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL,
        entry.compatibility().apiCompatibility().targetStability());
    assertTrue(entry.compatibility().apiCompatibility().targetStabilityDeclared());
    assertEquals("1.1", entry.compatibility().apiCompatibility().targetBaseline());
    assertTrue(entry.compatibility().apiCompatibility().targetBaselineDeclared());
    assertTrue(entry.compatibility().apiCompatibility().experimentalCapabilitiesAccepted());
    assertTrue(entry.compatibility().apiCompatibility().experimentalCapabilitiesAcceptedDeclared());
    assertEquals(AppCatalogReviewStatus.REVIEWED, entry.review().status());
    assertEquals("Reviewed for local operator safety.", entry.review().note().orElseThrow());
    assertEquals("Reads the local transfer queue.", entry.permissionRationales().get("queue.read"));
    assertEquals(
        List.of(
            java.net.URI.create("https://example.invalid/assets/shot-1.png"),
            java.net.URI.create("https://example.invalid/assets/shot-2.png")),
        entry.screenshots());
    assertEquals("Adds queue retry controls.", entry.changelog().summary().orElseThrow());
    assertEquals(
        "https://example.invalid/changelog.txt", entry.changelog().uri().orElseThrow().toString());
  }

  @Test
  void parse_whenVersionSixCatalogDeclaresTargetBaseline_expectInvalidCatalogEntry() {
    String catalog =
        validStoreMetadataCatalog()
            .replace("catalog.version=2", CATALOG_VERSION_6)
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.api.targetBaseline=1.0\napp.queue-manager.bundle.uri=");
    byte[] catalogBytes = bytes(catalog);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogParser.parse(catalogBytes));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
    assertTrue(exception.getMessage().contains("catalog.version 7 is required"));
  }

  @Test
  void parse_whenCatalogHasProductionChannelMetadata_expectMetadataNormalized() {
    AppCatalog catalog =
        AppCatalogParser.parse(
            bytes(
                """
                catalog.version=3
                catalog.id=core
                catalog.name=Crypta Core Apps
                catalog.generatedAt=%s
                catalog.entries=queue-manager
                app.queue-manager.id=queue-manager
                app.queue-manager.name=Queue Manager
                app.queue-manager.version=1.2.0
                app.queue-manager.summary=Manage transfer queues.
                app.queue-manager.channel=nightly
                app.queue-manager.minimumCryptaVersion=0.1.0
                app.queue-manager.maximumCryptaVersion=0.9.99
                app.queue-manager.support.status=experimental
                app.queue-manager.deprecation.status=deprecated
                app.queue-manager.deprecation.message=Use Queue Manager stable.
                app.queue-manager.replacementAppId=Queue-Manager-Stable
                app.queue-manager.securityAdvisories=CRYPTA-2026-0001
                app.queue-manager.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001
                app.queue-manager.bundle.uri=https://example.invalid/queue-manager.zip
                app.queue-manager.bundle.sha256=%s
                app.queue-manager.bundle.size.bytes=0
                app.queue-manager.bundle.type=zip
                app.queue-manager.permissions=queue.read
                """
                    .formatted(GENERATED_AT, SHA256)));

    AppCatalogEntry entry = catalog.entries().getFirst();

    assertEquals(AppCatalog.VERSION_PRODUCTION_CHANNELS, catalog.version());
    assertEquals(AppCatalogChannel.NIGHTLY, entry.productionMetadata().channel());
    assertEquals(AppCatalogSupportStatus.EXPERIMENTAL, entry.productionMetadata().supportStatus());
    assertEquals(
        AppCatalogDeprecationStatus.DEPRECATED, entry.productionMetadata().deprecationStatus());
    assertEquals("0.9.99", entry.compatibility().maximumCryptaVersion());
    assertEquals(
        "Use Queue Manager stable.", entry.productionMetadata().deprecationMessage().orElseThrow());
    assertEquals(
        "queue-manager-stable", entry.productionMetadata().replacementAppId().orElseThrow());
    assertEquals(
        SECURITY_ADVISORY_ID, entry.productionMetadata().securityAdvisories().getFirst().id());
  }

  @Test
  void parse_whenCatalogHasMaintenanceMetadata_expectMetadataNormalized() {
    AppCatalog catalog = AppCatalogParser.parse(bytes(validMaintenanceCatalog()));

    AppCatalogEntry entry = catalog.entries().getFirst();
    AppCatalogMaintenanceMetadata metadata = entry.maintenanceMetadata();

    assertEquals(AppCatalog.VERSION_FIRST_PARTY_MAINTENANCE, catalog.version());
    assertEquals("crypta-core", metadata.owner().orElseThrow());
    assertEquals(
        "https://example.invalid/crypta/owners/core", metadata.ownerUri().orElseThrow().toString());
    assertEquals(
        AppCatalogMaintenanceMetadata.SupportLevel.CORE, metadata.supportLevel().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.DataSchemaPolicy.STATELESS,
        metadata.dataSchemaPolicy().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.MigrationPolicy.NONE,
        metadata.migrationPolicy().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.BackupRestoreSupport.NOT_APPLICABLE,
        metadata.backupRestore().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.SecurityPolicy.CATALOG_ADVISORIES,
        metadata.securityPolicy().orElseThrow());
    assertEquals(
        AppCatalogMaintenanceMetadata.DeprecationPolicy.NONE,
        metadata.deprecationPolicy().orElseThrow());
    assertEquals(
        "https://example.invalid/crypta/apps/queue-manager/support",
        metadata.supportUri().orElseThrow().toString());
  }

  @Test
  void parse_whenCatalogHasSubmissionReviewMetadata_expectMetadataNormalized() {
    AppCatalog catalog = AppCatalogParser.parse(bytes(validSubmissionReviewCatalog()));

    AppCatalogEntry entry = catalog.entries().getFirst();
    AppCatalogReviewMetadata review = entry.review();

    assertEquals(AppCatalog.VERSION_THIRD_PARTY_SUBMISSION_REVIEW, catalog.version());
    assertEquals(AppCatalogReviewStatus.REVIEWED, review.status());
    assertEquals("submission-1", review.submissionId().orElseThrow());
    assertEquals("1".repeat(64), review.submissionSha256().orElseThrow());
    assertEquals("pass", review.preReviewStatus().orElseThrow());
    assertEquals("2".repeat(64), review.preReviewSha256().orElseThrow());
    assertEquals("reviewer-dev", review.reviewerKeyId().orElseThrow());
    assertEquals("crypta-app-review-v1/1", review.reviewerPolicy().orElseThrow());
    assertEquals("3".repeat(64), review.receiptFingerprintSha256().orElseThrow());
    assertEquals("4".repeat(64), review.decisionReasonSha256().orElseThrow());
    assertEquals("previous-submission", review.resubmissionOf().orElseThrow());
    assertTrue(review.nonProduction());
  }

  @Test
  void parse_whenVersionFiveCatalogDeclaresSubmissionReviewMetadata_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validSubmissionReviewCatalog().replace(CATALOG_VERSION_6, CATALOG_VERSION_5));
  }

  @Test
  void parse_whenVersionFiveCatalogDeclaresSubmissionWorkflowStatus_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validMaintenanceCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.review.status=submitted\napp.queue-manager.bundle.uri="));
  }

  @Test
  void parse_whenCatalogHasSecurityPolicy_expectDecisionDenylisted() {
    AppCatalog catalog = AppCatalogParser.parse(bytes(validSecurityPolicyCatalog()));

    AppCatalogEntry entry = catalog.entries().getFirst();
    AppCatalogSecurityDecision decision = catalog.securityPolicy().decisionFor(entry);

    assertEquals(AppCatalog.VERSION_SECURITY_POLICY, catalog.version());
    assertEquals(1, catalog.securityPolicy().advisories().size());
    assertEquals(1, catalog.securityPolicy().denylist().size());
    assertEquals(AppCatalogSecurityDecisionStatus.DENYLISTED, decision.status());
    assertEquals(AppCatalogSecurityAction.DENYLIST, decision.action());
    assertEquals(AppCatalogSecuritySeverity.CRITICAL, decision.severity());
    assertEquals(List.of(SECURITY_ADVISORY_ID), decision.advisoryIds());
    assertTrue(decision.blocksInstall());
    assertTrue(decision.blocksUpdate());
    assertEquals("Export app data before removal.", decision.safeUninstallGuidance());
  }

  @Test
  void parse_whenSecurityAdvisoryLifecycleIsPublished_expectEntryAdvisoryEnforced() {
    AppCatalog catalog = AppCatalogParser.parse(bytes(advisoryLifecycleCatalog("published")));

    AppCatalogSecurityDecision decision =
        catalog.securityPolicy().decisionFor(catalog.entries().getFirst());

    assertEquals(AppCatalogSecurityDecisionStatus.BLOCKED, decision.status());
    assertEquals(AppCatalogSecurityAction.BLOCK_UPDATE, decision.action());
    assertTrue(decision.blocksUpdate());
    assertEquals(List.of("CRYPTA-2026-0004"), decision.advisoryIds());
  }

  @Test
  void parse_whenSecurityAdvisoryLifecycleIsNonEnforcing_expectEntryAdvisoryNotApplied() {
    for (String status :
        List.of("draft", "detected", "superseded", "resolved", "retracted", "withdrawn")) {
      AppCatalog catalog = AppCatalogParser.parse(bytes(advisoryLifecycleCatalog(status)));

      AppCatalogSecurityDecision decision =
          catalog.securityPolicy().decisionFor(catalog.entries().getFirst());

      assertEquals(AppCatalogSecurityDecisionStatus.OK, decision.status(), status);
      assertEquals(AppCatalogSecurityAction.INFORM, decision.action(), status);
      assertTrue(decision.advisoryIds().isEmpty(), status);
    }
  }

  @Test
  void parse_whenEntryHasMultipleSecurityActions_expectDecisionAccumulatesAllGates() {
    AppCatalog catalog = AppCatalogParser.parse(bytes(multiActionSecurityPolicyCatalog()));

    AppCatalogSecurityDecision decision =
        catalog.securityPolicy().decisionFor(catalog.entries().getFirst());

    assertEquals(AppCatalogSecurityDecisionStatus.BLOCKED, decision.status());
    assertEquals(AppCatalogSecurityAction.BLOCK_UPDATE, decision.action());
    assertEquals(AppCatalogSecuritySeverity.HIGH, decision.severity());
    assertEquals(
        List.of(SECURITY_ADVISORY_ID, "CRYPTA-2026-0002", "CRYPTA-2026-0003"),
        decision.advisoryIds());
    assertTrue(decision.requiresAcknowledgement());
    assertTrue(decision.blocksInstall());
    assertTrue(decision.blocksUpdate());
    assertTrue(decision.blocksAutomaticApply());
  }

  @Test
  void parse_whenVersionThreeCatalogDeclaresSecurityPolicy_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validSecurityPolicyCatalog().replace("catalog.version=4", "catalog.version=3"));
  }

  @Test
  void parse_whenSecurityPolicyHasDuplicateAdvisoryId_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validSecurityPolicyCatalog()
            .replace(
                "catalog.securityAdvisories=CRYPTA-2026-0001",
                "catalog.securityAdvisories=CRYPTA-2026-0001,CRYPTA-2026-0001"));
  }

  @Test
  void parse_whenSecurityPolicyHasInvalidSeverity_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validSecurityPolicyCatalog()
            .replace(
                "catalog.securityAdvisory.CRYPTA-2026-0001.severity=critical",
                "catalog.securityAdvisory.CRYPTA-2026-0001.severity=severe"));
  }

  @Test
  void parse_whenSecurityPolicyDenylistReferencesUnknownAdvisory_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validSecurityPolicyCatalog()
            .replace(
                "catalog.securityDenylist.deny-queue-1-2-0.advisoryId=CRYPTA-2026-0001",
                "catalog.securityDenylist.deny-queue-1-2-0.advisoryId=CRYPTA-2026-9999"));
  }

  @Test
  void parse_whenVersionTwoCatalogOmitsProductionMetadata_expectStableDefaults() {
    AppCatalog catalog = AppCatalogParser.parse(bytes(validStoreMetadataCatalog()));

    AppCatalogEntry entry = catalog.entries().getFirst();

    assertEquals(AppCatalogChannel.STABLE, entry.productionMetadata().channel());
    assertEquals(AppCatalogSupportStatus.SUPPORTED, entry.productionMetadata().supportStatus());
    assertEquals(AppCatalogDeprecationStatus.NONE, entry.productionMetadata().deprecationStatus());
    assertTrue(entry.productionMetadata().securityAdvisories().isEmpty());
  }

  @Test
  void parse_whenVersionTwoCatalogDeclaresProductionMetadata_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.channel=beta\napp.queue-manager.bundle.uri="));
  }

  @Test
  void parse_whenVersionFourCatalogDeclaresMaintenanceMetadata_expectInvalidCatalogEntry() {
    assertInvalidEntry(validMaintenanceCatalog().replace(CATALOG_VERSION_5, "catalog.version=4"));
  }

  @Test
  void parse_whenVersionOneCatalogDeclaresStoreMetadata_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validSingleEntryCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.homepage=https://example.invalid/app\n" + BUNDLE_URI_PROPERTY));
  }

  @Test
  void parse_whenEntriesAreBlank_expectCatalogWithoutEntries() {
    AppCatalog catalog =
        AppCatalogParser.parse(
            bytes(
                """
                catalog.version=1
                catalog.id=core
                catalog.name=Crypta Core Apps
                catalog.generatedAt=%s
                catalog.entries=
                """
                    .formatted(GENERATED_AT)));

    assertTrue(catalog.entries().isEmpty());
  }

  @Test
  void parse_whenCatalogHasDuplicateKey_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        """
        catalog.version=1
        catalog.id=core
        catalog.name=Crypta Core Apps
        catalog.name=Duplicate
        catalog.generatedAt=%s
        catalog.entries=
        """
            .formatted(GENERATED_AT));
  }

  @Test
  void parse_whenCatalogHasUnknownProperty_expectInvalidCatalogEntry() {
    assertInvalidEntry(validSingleEntryCatalog() + "catalog.future=value\n");
  }

  @Test
  void parse_whenCatalogEntriesContainDuplicateId_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validSingleEntryCatalog()
            .replace(
                "catalog.entries=queue-manager", "catalog.entries=queue-manager,Queue-Manager"));
  }

  @Test
  void parse_whenEntryIdDoesNotMatchDeclaredId_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validSingleEntryCatalog()
            .replace("app.queue-manager.id=queue-manager", "app.queue-manager.id=publisher"));
  }

  @Test
  void parse_whenBundleSizeIsMalformed_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validSingleEntryCatalog()
            .replace(
                "app.queue-manager.bundle.size.bytes=0",
                "app.queue-manager.bundle.size.bytes=NaN"));
  }

  @Test
  void parse_whenReviewStatusIsMalformed_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.review.status=trusted\napp.queue-manager.bundle.uri="));
  }

  @Test
  void parse_whenProductionChannelIsMalformed_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validProductionCatalog()
            .replace("app.queue-manager.channel=beta", "app.queue-manager.channel=preview"));
  }

  @Test
  void parse_whenMaintenanceSupportLevelIsMalformed_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validMaintenanceCatalog()
            .replace(
                "app.queue-manager.maintenance.supportLevel=core",
                "app.queue-manager.maintenance.supportLevel=forever"));
  }

  @Test
  void parse_whenMaintenanceOwnerIsBlank_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validMaintenanceCatalog()
            .replace(
                "app.queue-manager.maintenance.owner=crypta-core",
                "app.queue-manager.maintenance.owner=   "));
  }

  @Test
  void parse_whenMaintenanceOwnerUriUsesUnsafeScheme_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validMaintenanceCatalog()
            .replace(
                "app.queue-manager.maintenance.ownerUri=https://example.invalid/crypta/owners/core",
                "app.queue-manager.maintenance.ownerUri=file:///tmp/owner"));
  }

  @Test
  void parse_whenMaintenanceSupportUriUsesUnsafeScheme_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validMaintenanceCatalog()
            .replace(
                "app.queue-manager.maintenance.supportUri=https://example.invalid/crypta/apps/queue-manager/support",
                "app.queue-manager.maintenance.supportUri=file:///tmp/support"));
  }

  @Test
  void parse_whenMaintenancePolicyIsIncomplete_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validMaintenanceCatalog()
            .replace("app.queue-manager.maintenance.migrationPolicy=none\n", ""));
  }

  @Test
  void parse_whenDottedAppIdContainsMaintenance_expectNoMaintenanceVersionGate() {
    AppCatalog catalog =
        AppCatalogParser.parse(
            bytes(
                """
                catalog.version=4
                catalog.id=core
                catalog.name=Crypta Core Apps
                catalog.generatedAt=%s
                catalog.entries=foo,foo.maintenance
                app.foo.id=foo
                app.foo.name=Foo
                app.foo.version=1.0.0
                app.foo.summary=First dotted id regression fixture.
                app.foo.channel=stable
                app.foo.bundle.uri=https://example.invalid/foo.zip
                app.foo.bundle.sha256=%s
                app.foo.bundle.size.bytes=0
                app.foo.bundle.type=zip
                app.foo.permissions=
                app.foo.maintenance.id=foo.maintenance
                app.foo.maintenance.name=Foo Maintenance
                app.foo.maintenance.version=1.0.0
                app.foo.maintenance.summary=Ordinary app whose id contains maintenance.
                app.foo.maintenance.channel=stable
                app.foo.maintenance.bundle.uri=https://example.invalid/foo-maintenance.zip
                app.foo.maintenance.bundle.sha256=%s
                app.foo.maintenance.bundle.size.bytes=0
                app.foo.maintenance.bundle.type=zip
                app.foo.maintenance.permissions=
                """
                    .formatted(GENERATED_AT, SHA256, SHA256)));

    assertEquals(AppCatalog.VERSION_SECURITY_POLICY, catalog.version());
    assertEquals(
        List.of("foo", "foo.maintenance"),
        catalog.entries().stream().map(AppCatalogEntry::appId).toList());
  }

  @Test
  void parse_whenReplacementAppIdIsMalformed_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validProductionCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.replacementAppId=bad id\napp.queue-manager.bundle.uri="));
  }

  @Test
  void parse_whenSecurityAdvisoryUriUsesUnsafeScheme_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validProductionCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                """
                app.queue-manager.securityAdvisories=CRYPTA-2026-0001
                app.queue-manager.securityAdvisory.CRYPTA-2026-0001.uri=file:///tmp/advisory
                app.queue-manager.bundle.uri=\
                """));
  }

  @Test
  void parse_whenCategoryIsMalformed_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.categories=bad category\napp.queue-manager.bundle.uri="));
  }

  @Test
  void parse_whenMetadataUriUsesUnsafeScheme_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.homepage=http://example.invalid/app\n" + BUNDLE_URI_PROPERTY));
  }

  @Test
  void parse_whenMetadataUriUsesLoopbackHttp_expectAccepted() {
    AppCatalog catalog =
        AppCatalogParser.parse(
            bytes(
                validStoreMetadataCatalog()
                    .replace(
                        BUNDLE_URI_PROPERTY,
                        "app.queue-manager.homepage=http://localhost:8080/app\n"
                            + BUNDLE_URI_PROPERTY)));

    AppCatalogEntry entry = catalog.entries().getFirst();

    assertEquals("http://localhost:8080/app", entry.homepage().orElseThrow().toString());
  }

  @Test
  void parse_whenPermissionRationaleDoesNotMatchDeclaredPermission_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.permissions.rationale.queue.write=Writes queues.\n"
                    + BUNDLE_URI_PROPERTY));
  }

  @Test
  void parse_whenPermissionRationaleKeysNormalizeToDuplicate_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                "app.queue-manager.permissions=queue.read",
                """
                app.queue-manager.permissions.rationale.queue.read=Reads queues.
                app.queue-manager.permissions.rationale.QUEUE.READ=Reads queues again.
                app.queue-manager.permissions=queue.read\
                """));
  }

  @Test
  void parse_whenScreenshotIndexesHaveGap_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.screenshot.2=https://example.invalid/assets/shot-2.png\n"
                    + BUNDLE_URI_PROPERTY));
  }

  @Test
  void parse_whenScreenshotCountExceedsCap_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                """
                app.queue-manager.screenshot.1=https://example.invalid/assets/shot-1.png
                app.queue-manager.screenshot.2=https://example.invalid/assets/shot-2.png
                app.queue-manager.screenshot.3=https://example.invalid/assets/shot-3.png
                app.queue-manager.screenshot.4=https://example.invalid/assets/shot-4.png
                app.queue-manager.screenshot.5=https://example.invalid/assets/shot-5.png
                app.queue-manager.screenshot.6=https://example.invalid/assets/shot-6.png
                app.queue-manager.screenshot.7=https://example.invalid/assets/shot-7.png
                app.queue-manager.screenshot.8=https://example.invalid/assets/shot-8.png
                app.queue-manager.screenshot.9=https://example.invalid/assets/shot-9.png
                app.queue-manager.bundle.uri=\
                """));
  }

  @Test
  void parse_whenReviewNoteIsBlank_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                BUNDLE_URI_PROPERTY,
                "app.queue-manager.review.note=   \napp.queue-manager.bundle.uri="));
  }

  private static void assertInvalidEntry(String catalogText) {
    byte[] catalogBytes = bytes(catalogText);

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> AppCatalogParser.parse(catalogBytes));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }

  private static String validSingleEntryCatalog() {
    return """
    catalog.version=1
    catalog.id=core
    catalog.name=Crypta Core Apps
    catalog.generatedAt=%s
    catalog.entries=queue-manager
    app.queue-manager.id=queue-manager
    app.queue-manager.name=Queue Manager
    app.queue-manager.version=1.0.0
    app.queue-manager.summary=Manage transfer queues.
    app.queue-manager.bundle.uri=https://example.invalid/queue-manager.zip
    app.queue-manager.bundle.sha256=%s
    app.queue-manager.bundle.size.bytes=0
    app.queue-manager.bundle.type=zip
    app.queue-manager.permissions=queue.read
    """
        .formatted(GENERATED_AT, SHA256);
  }

  private static String validStoreMetadataCatalog() {
    return validSingleEntryCatalog().replace("catalog.version=1", "catalog.version=2");
  }

  private static String validProductionCatalog() {
    return validSingleEntryCatalog()
        .replace("catalog.version=1", "catalog.version=3")
        .replace(
            BUNDLE_URI_PROPERTY, "app.queue-manager.channel=beta\napp.queue-manager.bundle.uri=");
  }

  private static String validSecurityPolicyCatalog() {
    return """
    catalog.version=4
    catalog.id=core
    catalog.name=Crypta Core Apps
    catalog.generatedAt=%s
    catalog.entries=queue-manager
    catalog.securityAdvisories=CRYPTA-2026-0001
    catalog.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001
    catalog.securityAdvisory.CRYPTA-2026-0001.title=Queue Manager vulnerable draft handling
    catalog.securityAdvisory.CRYPTA-2026-0001.severity=critical
    catalog.securityAdvisory.CRYPTA-2026-0001.status=active
    catalog.securityAdvisory.CRYPTA-2026-0001.action=denylist
    catalog.securityAdvisory.CRYPTA-2026-0001.summary=Upgrade to a reviewed replacement version.
    catalog.securityAdvisory.CRYPTA-2026-0001.publishedAt=2026-06-11T00:00:00Z
    catalog.securityAdvisory.CRYPTA-2026-0001.updatedAt=2026-06-11T00:00:00Z
    catalog.securityAdvisory.CRYPTA-2026-0001.replacementAppId=queue-manager
    catalog.securityAdvisory.CRYPTA-2026-0001.safeUninstallGuidance=Export app data before uninstalling.
    catalog.securityDenylist=deny-queue-1-2-0
    catalog.securityDenylist.deny-queue-1-2-0.appId=queue-manager
    catalog.securityDenylist.deny-queue-1-2-0.version=1.2.0
    catalog.securityDenylist.deny-queue-1-2-0.advisoryId=CRYPTA-2026-0001
    catalog.securityDenylist.deny-queue-1-2-0.reason=Known vulnerable release.
    catalog.securityDenylist.deny-queue-1-2-0.replacementAppId=queue-manager
    catalog.securityDenylist.deny-queue-1-2-0.safeUninstallGuidance=Export app data before removal.
    app.queue-manager.id=queue-manager
    app.queue-manager.name=Queue Manager
    app.queue-manager.version=1.2.0
    app.queue-manager.summary=Manage transfer queues.
    app.queue-manager.channel=beta
    app.queue-manager.securityAdvisories=CRYPTA-2026-0001
    app.queue-manager.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001
    app.queue-manager.bundle.uri=https://example.invalid/queue-manager.zip
    app.queue-manager.bundle.sha256=%s
    app.queue-manager.bundle.size.bytes=0
    app.queue-manager.bundle.type=zip
    app.queue-manager.permissions=queue.read
    """
        .formatted(GENERATED_AT, SHA256);
  }

  private static String advisoryLifecycleCatalog(String status) {
    return """
    catalog.version=4
    catalog.id=core
    catalog.name=Crypta Core Apps
    catalog.generatedAt=%s
    catalog.entries=queue-manager
    catalog.securityAdvisories=CRYPTA-2026-0004
    catalog.securityAdvisory.CRYPTA-2026-0004.uri=https://example.invalid/advisories/CRYPTA-2026-0004
    catalog.securityAdvisory.CRYPTA-2026-0004.title=Queue Manager lifecycle advisory
    catalog.securityAdvisory.CRYPTA-2026-0004.severity=high
    catalog.securityAdvisory.CRYPTA-2026-0004.status=%s
    catalog.securityAdvisory.CRYPTA-2026-0004.action=block_update
    catalog.securityAdvisory.CRYPTA-2026-0004.summary=Do not update to this release.
    catalog.securityAdvisory.CRYPTA-2026-0004.publishedAt=2026-06-11T00:00:00Z
    catalog.securityAdvisory.CRYPTA-2026-0004.updatedAt=2026-06-11T00:00:00Z
    app.queue-manager.id=queue-manager
    app.queue-manager.name=Queue Manager
    app.queue-manager.version=1.2.0
    app.queue-manager.summary=Manage transfer queues.
    app.queue-manager.channel=beta
    app.queue-manager.securityAdvisories=CRYPTA-2026-0004
    app.queue-manager.securityAdvisory.CRYPTA-2026-0004.uri=https://example.invalid/advisories/CRYPTA-2026-0004
    app.queue-manager.bundle.uri=https://example.invalid/queue-manager.zip
    app.queue-manager.bundle.sha256=%s
    app.queue-manager.bundle.size.bytes=0
    app.queue-manager.bundle.type=zip
    app.queue-manager.permissions=queue.read
    """
        .formatted(GENERATED_AT, status, SHA256);
  }

  private static String validMaintenanceCatalog() {
    return """
    catalog.version=5
    catalog.id=core
    catalog.name=Crypta Core Apps
    catalog.generatedAt=%s
    catalog.entries=queue-manager
    app.queue-manager.id=queue-manager
    app.queue-manager.name=Queue Manager
    app.queue-manager.version=1.2.0
    app.queue-manager.summary=Manage transfer queues.
    app.queue-manager.channel=stable
    app.queue-manager.support.status=supported
    app.queue-manager.deprecation.status=none
    app.queue-manager.maintenance.owner=crypta-core
    app.queue-manager.maintenance.ownerUri=https://example.invalid/crypta/owners/core
    app.queue-manager.maintenance.supportLevel=core
    app.queue-manager.maintenance.dataSchemaPolicy=stateless
    app.queue-manager.maintenance.migrationPolicy=none
    app.queue-manager.maintenance.backupRestore=not-applicable
    app.queue-manager.maintenance.securityPolicy=catalog-advisories
    app.queue-manager.maintenance.deprecationPolicy=none
    app.queue-manager.maintenance.supportUri=https://example.invalid/crypta/apps/queue-manager/support
    app.queue-manager.bundle.uri=https://example.invalid/queue-manager.zip
    app.queue-manager.bundle.sha256=%s
    app.queue-manager.bundle.size.bytes=0
    app.queue-manager.bundle.type=zip
    app.queue-manager.permissions=queue.read
    """
        .formatted(GENERATED_AT, SHA256);
  }

  private static String validSubmissionReviewCatalog() {
    return validMaintenanceCatalog()
        .replace(CATALOG_VERSION_5, CATALOG_VERSION_6)
        .replace(
            BUNDLE_URI_PROPERTY,
            """
            app.queue-manager.review.status=reviewed
            app.queue-manager.review.submission.id=submission-1
            app.queue-manager.review.submission.sha256=%s
            app.queue-manager.review.preReview.status=pass
            app.queue-manager.review.preReview.sha256=%s
            app.queue-manager.review.reviewer.keyId=reviewer-dev
            app.queue-manager.review.reviewer.policy=crypta-app-review-v1/1
            app.queue-manager.review.receipt.fingerprint.sha256=%s
            app.queue-manager.review.decision.reason.sha256=%s
            app.queue-manager.review.resubmissionOf=previous-submission
            app.queue-manager.review.nonProduction=true
            app.queue-manager.bundle.uri=\
            """
                .formatted("1".repeat(64), "2".repeat(64), "3".repeat(64), "4".repeat(64)));
  }

  private static String multiActionSecurityPolicyCatalog() {
    return """
    catalog.version=4
    catalog.id=core
    catalog.name=Crypta Core Apps
    catalog.generatedAt=%s
    catalog.entries=queue-manager
    catalog.securityAdvisories=CRYPTA-2026-0001,CRYPTA-2026-0002,CRYPTA-2026-0003
    catalog.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001
    catalog.securityAdvisory.CRYPTA-2026-0001.title=Queue Manager warning advisory
    catalog.securityAdvisory.CRYPTA-2026-0001.severity=low
    catalog.securityAdvisory.CRYPTA-2026-0001.status=active
    catalog.securityAdvisory.CRYPTA-2026-0001.action=warn
    catalog.securityAdvisory.CRYPTA-2026-0001.summary=Acknowledge before manual action.
    catalog.securityAdvisory.CRYPTA-2026-0001.publishedAt=2026-06-11T00:00:00Z
    catalog.securityAdvisory.CRYPTA-2026-0001.updatedAt=2026-06-11T00:00:00Z
    catalog.securityAdvisory.CRYPTA-2026-0002.uri=https://example.invalid/advisories/CRYPTA-2026-0002
    catalog.securityAdvisory.CRYPTA-2026-0002.title=Queue Manager install block
    catalog.securityAdvisory.CRYPTA-2026-0002.severity=medium
    catalog.securityAdvisory.CRYPTA-2026-0002.status=active
    catalog.securityAdvisory.CRYPTA-2026-0002.action=block_install
    catalog.securityAdvisory.CRYPTA-2026-0002.summary=Do not install this release.
    catalog.securityAdvisory.CRYPTA-2026-0002.publishedAt=2026-06-11T00:00:00Z
    catalog.securityAdvisory.CRYPTA-2026-0002.updatedAt=2026-06-11T00:00:00Z
    catalog.securityAdvisory.CRYPTA-2026-0003.uri=https://example.invalid/advisories/CRYPTA-2026-0003
    catalog.securityAdvisory.CRYPTA-2026-0003.title=Queue Manager update block
    catalog.securityAdvisory.CRYPTA-2026-0003.severity=high
    catalog.securityAdvisory.CRYPTA-2026-0003.status=active
    catalog.securityAdvisory.CRYPTA-2026-0003.action=block_update
    catalog.securityAdvisory.CRYPTA-2026-0003.summary=Do not update to this release.
    catalog.securityAdvisory.CRYPTA-2026-0003.publishedAt=2026-06-11T00:00:00Z
    catalog.securityAdvisory.CRYPTA-2026-0003.updatedAt=2026-06-11T00:00:00Z
    app.queue-manager.id=queue-manager
    app.queue-manager.name=Queue Manager
    app.queue-manager.version=1.2.0
    app.queue-manager.summary=Manage transfer queues.
    app.queue-manager.channel=beta
    app.queue-manager.securityAdvisories=CRYPTA-2026-0001,CRYPTA-2026-0002,CRYPTA-2026-0003
    app.queue-manager.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001
    app.queue-manager.securityAdvisory.CRYPTA-2026-0002.uri=https://example.invalid/advisories/CRYPTA-2026-0002
    app.queue-manager.securityAdvisory.CRYPTA-2026-0003.uri=https://example.invalid/advisories/CRYPTA-2026-0003
    app.queue-manager.bundle.uri=https://example.invalid/queue-manager.zip
    app.queue-manager.bundle.sha256=%s
    app.queue-manager.bundle.size.bytes=0
    app.queue-manager.bundle.type=zip
    app.queue-manager.permissions=queue.read
    """
        .formatted(GENERATED_AT, SHA256);
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }
}
