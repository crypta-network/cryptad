package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import network.crypta.platform.appdist.AppApiCompatibilityMetadata;
import network.crypta.platform.appdist.AppBundleManifestParser;
import network.crypta.platform.appdist.AppBundlePackager;
import network.crypta.platform.appdist.TrustedAppKey;
import network.crypta.platform.appdist.TrustedAppKeys;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogWriterTest {
  private static final String KEY_ID = "catalog-writer-test";
  private static final String CATALOG_ID = "core";
  private static final String CATALOG_NAME = "Crypta Core Apps";
  private static final String QUEUE_APP_ID = "queue-manager";
  private static final String QUEUE_APP_NAME = "Queue Manager";
  private static final String QUEUE_APP_VERSION = "1.0.0";
  private static final String QUEUE_BUNDLE_URI = "https://example.invalid/apps/queue-manager.zip";
  private static final String QUEUE_DESCRIPTOR_FILE = "queue.properties";
  private static final String QUEUE_READ_PERMISSION = "queue.read";
  private static final String LOCAL_QUEUE_SUMMARY = "Manage local queues.";
  private static final String PUBLISHER_APP_ID = "publisher";
  private static final Instant GENERATED_AT = Instant.parse("2026-04-21T18:22:40Z");

  @TempDir private Path tempDir;

  @Test
  void write_whenDescriptorUsesManifestAndDisplayOverrides_expectDeterministicCatalogProperties()
      throws Exception {
    Path artifact =
        appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, "queue.read,queue.write");
    String bundleUri = QUEUE_BUNDLE_URI;
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            bundleUri,
            "Manage local Crypta transfer queues.",
            """
            app.id=Queue-Manager
            name=Catalog Queue Manager
            version=%s
            permissions=queue.inspect,QUEUE.READ,queue.inspect
            homepage=https://example.invalid/apps/queue-manager
            source=https://example.invalid/src/queue-manager
            license=MIT
            categories=Productivity,network,productivity
            minimumCryptaVersion=0.1.0
            maximumCryptaVersion=0.9.99
            channel=beta
            support.status=experimental
            deprecation.status=deprecated
            deprecation.message=Use Queue Manager stable.
            replacementAppId=queue-manager-stable
            securityAdvisories=CRYPTA-2026-0001
            securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001
            maintenance.owner=crypta-core
            maintenance.ownerUri=https://example.invalid/crypta/owners/core
            maintenance.supportLevel=core
            maintenance.dataSchemaPolicy=stateless
            maintenance.migrationPolicy=none
            maintenance.backupRestore=not-applicable
            maintenance.securityPolicy=catalog-advisories
            maintenance.deprecationPolicy=none
            maintenance.supportUri=https://example.invalid/crypta/apps/queue-manager/support
            api.minimumVersion=1
            api.maximumTestedVersion=1
            api.optionalCapabilities=alerts.read,diagnostics.read
            api.targetStability=experimental
            api.experimentalCapabilitiesAccepted=true
            review.status=reviewed
            review.note=Reviewed for local operator safety.
            permissions.rationale.queue.inspect=Inspects queue metadata.
            permissions.rationale.queue.read=Reads the local transfer queue.
            screenshot.1=https://example.invalid/assets/queue-1.png
            changelog.summary=Adds queue retry controls.
            changelog.uri=https://example.invalid/changelog.txt
            """
                .formatted(QUEUE_APP_VERSION));
    Path outputFile = tempDir.resolve("catalog").resolve(AppCatalogSignature.CATALOG_FILE_NAME);

    AppCatalogWriter.WriteResult result =
        AppCatalogWriter.write(request(List.of(descriptor)).withOutputFile(outputFile));

    String expected =
        lines(
            "catalog.version=5",
            "catalog.id=core",
            "catalog.name=Crypta Core Apps",
            "catalog.generatedAt=2026-04-21T18:22:40Z",
            "catalog.entries=queue-manager",
            "app.queue-manager.id=queue-manager",
            "app.queue-manager.name=Catalog Queue Manager",
            "app.queue-manager.version=" + QUEUE_APP_VERSION,
            "app.queue-manager.summary=Manage local Crypta transfer queues.",
            "app.queue-manager.homepage=https://example.invalid/apps/queue-manager",
            "app.queue-manager.source=https://example.invalid/src/queue-manager",
            "app.queue-manager.license=MIT",
            "app.queue-manager.categories=productivity,network",
            "app.queue-manager.minimumCryptaVersion=0.1.0",
            "app.queue-manager.maximumCryptaVersion=0.9.99",
            "app.queue-manager.api.minimumVersion=1",
            "app.queue-manager.api.maximumTestedVersion=1",
            "app.queue-manager.api.optionalCapabilities=alerts.read,diagnostics.read",
            "app.queue-manager.api.targetStability=experimental",
            "app.queue-manager.api.experimentalCapabilitiesAccepted=true",
            "app.queue-manager.channel=beta",
            "app.queue-manager.support.status=experimental",
            "app.queue-manager.deprecation.status=deprecated",
            "app.queue-manager.deprecation.message=Use Queue Manager stable.",
            "app.queue-manager.replacementAppId=queue-manager-stable",
            "app.queue-manager.securityAdvisories=CRYPTA-2026-0001",
            "app.queue-manager.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001",
            "app.queue-manager.maintenance.owner=crypta-core",
            "app.queue-manager.maintenance.ownerUri=https://example.invalid/crypta/owners/core",
            "app.queue-manager.maintenance.supportLevel=core",
            "app.queue-manager.maintenance.dataSchemaPolicy=stateless",
            "app.queue-manager.maintenance.migrationPolicy=none",
            "app.queue-manager.maintenance.backupRestore=not-applicable",
            "app.queue-manager.maintenance.securityPolicy=catalog-advisories",
            "app.queue-manager.maintenance.deprecationPolicy=none",
            "app.queue-manager.maintenance.supportUri=https://example.invalid/crypta/apps/queue-manager/support",
            "app.queue-manager.review.status=reviewed",
            "app.queue-manager.review.note=Reviewed for local operator safety.",
            "app.queue-manager.permissions.rationale.queue.inspect=Inspects queue metadata.",
            "app.queue-manager.permissions.rationale.queue.read=Reads the local transfer queue.",
            "app.queue-manager.screenshot.1=https://example.invalid/assets/queue-1.png",
            "app.queue-manager.changelog.summary=Adds queue retry controls.",
            "app.queue-manager.changelog.uri=https://example.invalid/changelog.txt",
            "app.queue-manager.bundle.uri=" + bundleUri,
            "app.queue-manager.bundle.sha256=" + sha256(artifact),
            "app.queue-manager.bundle.size.bytes=" + Files.size(artifact),
            "app.queue-manager.bundle.type=zip",
            "app.queue-manager.permissions=queue.inspect,queue.read");

    assertEquals(AppCatalog.VERSION_FIRST_PARTY_MAINTENANCE, result.catalog().version());
    assertEquals(expected, new String(result.catalogBytes(), StandardCharsets.UTF_8));
    assertEquals(expected, Files.readString(outputFile));
    assertEquals(outputFile.toAbsolutePath().normalize(), result.catalogFile().orElseThrow());
    assertEquals(
        expected, new String(AppCatalogWriter.serialize(result.catalog()), StandardCharsets.UTF_8));
  }

  @Test
  void write_whenMultipleDescriptorFiles_expectEntriesInRequestOrder() throws Exception {
    Path publisherArtifact = appZip(PUBLISHER_APP_ID, "Publisher", "2.0.0", "publish.write");
    Path queueArtifact =
        appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    Path publisherDescriptor =
        descriptor(
            "publisher.properties",
            publisherArtifact,
            "https://example.invalid/apps/publisher.zip",
            "Publish local files.",
            "");
    Path queueDescriptor =
        descriptor(QUEUE_DESCRIPTOR_FILE, queueArtifact, QUEUE_BUNDLE_URI, LOCAL_QUEUE_SUMMARY, "");

    AppCatalogWriter.WriteResult result =
        AppCatalogWriter.write(request(List.of(publisherDescriptor, queueDescriptor)));

    assertEquals(
        List.of(PUBLISHER_APP_ID, QUEUE_APP_ID),
        result.catalog().entries().stream().map(AppCatalogEntry::appId).toList());
    assertEquals(AppCatalog.VERSION_MINIMAL, result.catalog().version());
    assertTrue(
        new String(result.catalogBytes(), StandardCharsets.UTF_8)
            .contains("catalog.entries=publisher,queue-manager\n"));
  }

  @Test
  void write_whenDescriptorHasSubmissionReviewMetadata_expectCatalogVersionSix() throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            """
            review.status=reviewed
            review.submission.id=submission-1
            review.submission.sha256=%s
            review.preReview.status=pass
            review.preReview.sha256=%s
            review.reviewer.keyId=reviewer-dev
            review.reviewer.policy=crypta-app-review-v1/1
            review.receipt.fingerprint.sha256=%s
            review.decision.reason.sha256=%s
            review.nonProduction=true
            """
                .formatted("1".repeat(64), "2".repeat(64), "3".repeat(64), "4".repeat(64)));

    AppCatalogWriter.WriteResult result = AppCatalogWriter.write(request(List.of(descriptor)));
    String catalog = new String(result.catalogBytes(), StandardCharsets.UTF_8);

    assertEquals(AppCatalog.VERSION_THIRD_PARTY_SUBMISSION_REVIEW, result.catalog().version());
    assertTrue(catalog.contains("catalog.version=6\n"));
    assertTrue(catalog.contains("app.queue-manager.review.submission.id=submission-1\n"));
    assertTrue(catalog.contains("app.queue-manager.review.decision.reason.sha256="));
  }

  @Test
  void write_whenDescriptorHasSubmissionWorkflowStatus_expectCatalogVersionSix() throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            "review.status=submitted\n");

    AppCatalogWriter.WriteResult result = AppCatalogWriter.write(request(List.of(descriptor)));
    String catalog = new String(result.catalogBytes(), StandardCharsets.UTF_8);

    assertEquals(AppCatalog.VERSION_THIRD_PARTY_SUBMISSION_REVIEW, result.catalog().version());
    assertTrue(catalog.contains("catalog.version=6\n"));
    assertTrue(catalog.contains("app.queue-manager.review.status=submitted\n"));
  }

  @Test
  void serialize_whenVersionOneCatalogHasStoreMetadata_expectInvalidCatalogEntry() {
    AppCatalogEntry entry =
        directEntryWithStoreMetadata(
            Map.of(QUEUE_READ_PERMISSION, "Reads the local transfer queue."));
    AppCatalog catalog =
        new AppCatalog(
            AppCatalog.VERSION_MINIMAL, CATALOG_ID, CATALOG_NAME, GENERATED_AT, List.of(entry));

    AppCatalogException exception = captureInvalidEntry(() -> AppCatalogWriter.serialize(catalog));

    assertTrue(exception.getMessage().contains("catalog.version 2 is required"));
  }

  @Test
  void serialize_whenVersionTwoCatalogHasProductionMetadata_expectInvalidCatalogEntry() {
    AppCatalogEntry entry = directEntryWithProductionMetadata();
    AppCatalog catalog =
        new AppCatalog(
            AppCatalog.VERSION_STORE_METADATA,
            CATALOG_ID,
            CATALOG_NAME,
            GENERATED_AT,
            List.of(entry));

    AppCatalogException exception = captureInvalidEntry(() -> AppCatalogWriter.serialize(catalog));

    assertTrue(exception.getMessage().contains("catalog.version 3 is required"));
  }

  @Test
  void serialize_whenVersionFourCatalogHasMaintenanceMetadata_expectInvalidCatalogEntry() {
    AppCatalogEntry entry = directEntryWithMaintenanceMetadata();

    AppCatalogException exception =
        captureInvalidEntry(
            () ->
                AppCatalogWriter.serialize(
                    new AppCatalog(
                        AppCatalog.VERSION_SECURITY_POLICY,
                        CATALOG_ID,
                        CATALOG_NAME,
                        GENERATED_AT,
                        List.of(entry))));

    assertTrue(exception.getMessage().contains("catalog.version 5 is required"));
  }

  @Test
  void serialize_whenCatalogHasSecurityPolicy_expectVersionFourDeterministicOutput() {
    AppCatalog catalog =
        new AppCatalog(
            AppCatalog.VERSION_SECURITY_POLICY,
            CATALOG_ID,
            CATALOG_NAME,
            GENERATED_AT,
            securityPolicy(),
            List.of(directEntryWithProductionMetadata()));

    String serialized = new String(AppCatalogWriter.serialize(catalog), StandardCharsets.UTF_8);

    assertEquals(
        lines(
            "catalog.version=4",
            "catalog.id=core",
            "catalog.name=Crypta Core Apps",
            "catalog.generatedAt=2026-04-21T18:22:40Z",
            "catalog.entries=queue-manager",
            "catalog.securityAdvisories=CRYPTA-2026-0001",
            "catalog.securityAdvisory.CRYPTA-2026-0001.uri=https://example.invalid/advisories/CRYPTA-2026-0001",
            "catalog.securityAdvisory.CRYPTA-2026-0001.title=Queue Manager vulnerable release",
            "catalog.securityAdvisory.CRYPTA-2026-0001.severity=critical",
            "catalog.securityAdvisory.CRYPTA-2026-0001.status=active",
            "catalog.securityAdvisory.CRYPTA-2026-0001.action=denylist",
            "catalog.securityAdvisory.CRYPTA-2026-0001.summary=Upgrade to a reviewed replacement.",
            "catalog.securityAdvisory.CRYPTA-2026-0001.publishedAt=2026-06-11T00:00:00Z",
            "catalog.securityAdvisory.CRYPTA-2026-0001.updatedAt=2026-06-11T00:00:00Z",
            "catalog.securityAdvisory.CRYPTA-2026-0001.replacementAppId=queue-manager",
            "catalog.securityAdvisory.CRYPTA-2026-0001.safeUninstallGuidance=Export app data before"
                + " removal.",
            "catalog.securityDenylist=deny-queue-1-0-0",
            "catalog.securityDenylist.deny-queue-1-0-0.appId=queue-manager",
            "catalog.securityDenylist.deny-queue-1-0-0.version=1.0.0",
            "catalog.securityDenylist.deny-queue-1-0-0.advisoryId=CRYPTA-2026-0001",
            "catalog.securityDenylist.deny-queue-1-0-0.reason=Known vulnerable release.",
            "catalog.securityDenylist.deny-queue-1-0-0.replacementAppId=queue-manager",
            "catalog.securityDenylist.deny-queue-1-0-0.safeUninstallGuidance=Use app-data export"
                + " before removal.",
            "app.queue-manager.id=queue-manager",
            "app.queue-manager.name=Queue Manager",
            "app.queue-manager.version=1.0.0",
            "app.queue-manager.summary=Manage local queues.",
            "app.queue-manager.channel=beta",
            "app.queue-manager.support.status=experimental",
            "app.queue-manager.deprecation.status=none",
            "app.queue-manager.bundle.uri=https://example.invalid/apps/queue-manager.zip",
            "app.queue-manager.bundle.sha256=" + "0".repeat(64),
            "app.queue-manager.bundle.size.bytes=0",
            "app.queue-manager.bundle.type=zip",
            "app.queue-manager.permissions=queue.read"),
        serialized);
  }

  @Test
  void serialize_whenPermissionRationalesAreUnordered_expectDeclaredPermissionOrder() {
    Map<String, String> rationales = new LinkedHashMap<>();
    rationales.put("queue.write", "Writes queue state.");
    rationales.put(QUEUE_READ_PERMISSION, "Reads queue state.");
    AppCatalogEntry entry = directEntryWithStoreMetadata(rationales);
    AppCatalog catalog =
        new AppCatalog(
            AppCatalog.VERSION_STORE_METADATA,
            CATALOG_ID,
            CATALOG_NAME,
            GENERATED_AT,
            List.of(entry));

    String serialized = new String(AppCatalogWriter.serialize(catalog), StandardCharsets.UTF_8);
    int readIndex =
        serialized.indexOf("app.queue-manager.permissions.rationale.queue.read=Reads queue state.");
    int writeIndex =
        serialized.indexOf(
            "app.queue-manager.permissions.rationale.queue.write=Writes queue state.");

    assertTrue(readIndex >= 0);
    assertTrue(writeIndex > readIndex);
  }

  @Test
  void write_whenArtifactBytesAreRead_expectDigestAndSizeFromZip() throws Exception {
    Path artifact =
        appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, "queue.read,queue.write");
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE, artifact, artifact.toUri().toString(), LOCAL_QUEUE_SUMMARY, "");

    AppCatalogWriter.WriteResult result = AppCatalogWriter.write(request(List.of(descriptor)));
    AppCatalogEntry entry = result.catalog().entries().getFirst();

    assertEquals(Files.size(artifact), entry.bundleSizeBytes());
    assertEquals(sha256(artifact), entry.bundleSha256());
    assertTrue(entry.bundleSha256().matches("[0-9a-f]{64}"));
  }

  @Test
  void write_whenDescriptorApiRangeOmitsTargetStability_expectManifestTargetIsPreserved()
      throws Exception {
    Path artifact =
        appZip(
            QUEUE_APP_ID,
            QUEUE_APP_NAME,
            QUEUE_APP_VERSION,
            QUEUE_READ_PERMISSION,
            lines(
                "api.minimumVersion=1",
                "api.maximumTestedVersion=19",
                "api.targetStability=stable",
                "api.experimentalCapabilitiesAccepted=false"));
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            lines("api.minimumVersion=1", "api.maximumTestedVersion=19"));

    AppCatalogWriter.WriteResult result = AppCatalogWriter.write(request(List.of(descriptor)));

    AppApiCompatibilityMetadata api =
        result.catalog().entries().getFirst().compatibility().apiCompatibility();
    String catalog = new String(result.catalogBytes(), StandardCharsets.UTF_8);
    assertEquals(AppApiCompatibilityMetadata.TargetStability.STABLE, api.targetStability());
    assertTrue(api.targetStabilityDeclared());
    assertEquals(1, api.minimumVersion());
    assertEquals(19, api.maximumTestedVersion());
    assertTrue(catalog.contains("app.queue-manager.api.targetStability=stable\n"));
    assertTrue(catalog.contains("app.queue-manager.api.experimentalCapabilitiesAccepted=false\n"));
  }

  @Test
  void write_whenDescriptorExperimentalTargetOmitsAcceptance_expectManifestAcceptanceIsPreserved()
      throws Exception {
    Path artifact =
        appZip(
            QUEUE_APP_ID,
            QUEUE_APP_NAME,
            QUEUE_APP_VERSION,
            "vault.identities.read",
            lines(
                "api.minimumVersion=1",
                "api.maximumTestedVersion=19",
                "api.targetStability=experimental",
                "api.experimentalCapabilitiesAccepted=true"));
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            "api.targetStability=experimental");

    AppCatalogWriter.WriteResult result = AppCatalogWriter.write(request(List.of(descriptor)));

    AppApiCompatibilityMetadata api =
        result.catalog().entries().getFirst().compatibility().apiCompatibility();
    String catalog = new String(result.catalogBytes(), StandardCharsets.UTF_8);
    assertEquals(AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL, api.targetStability());
    assertTrue(api.targetStabilityDeclared());
    assertTrue(api.experimentalCapabilitiesAccepted());
    assertTrue(api.experimentalCapabilitiesAcceptedDeclared());
    assertEquals(1, api.minimumVersion());
    assertEquals(19, api.maximumTestedVersion());
    assertTrue(catalog.contains("app.queue-manager.api.targetStability=experimental\n"));
    assertTrue(catalog.contains("app.queue-manager.api.experimentalCapabilitiesAccepted=true\n"));
  }

  @Test
  void write_whenDescriptorExplicitlyRejectsManifestAcceptance_expectDescriptorOptOutIsPreserved()
      throws Exception {
    Path artifact =
        appZip(
            QUEUE_APP_ID,
            QUEUE_APP_NAME,
            QUEUE_APP_VERSION,
            "vault.identities.read",
            lines(
                "api.minimumVersion=1",
                "api.maximumTestedVersion=19",
                "api.targetStability=experimental",
                "api.experimentalCapabilitiesAccepted=true"));
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            lines(
                "api.targetStability=experimental", "api.experimentalCapabilitiesAccepted=false"));

    AppCatalogWriter.WriteResult result = AppCatalogWriter.write(request(List.of(descriptor)));

    AppApiCompatibilityMetadata api =
        result.catalog().entries().getFirst().compatibility().apiCompatibility();
    String catalog = new String(result.catalogBytes(), StandardCharsets.UTF_8);
    assertEquals(AppApiCompatibilityMetadata.TargetStability.EXPERIMENTAL, api.targetStability());
    assertTrue(api.targetStabilityDeclared());
    assertFalse(api.experimentalCapabilitiesAccepted());
    assertTrue(api.experimentalCapabilitiesAcceptedDeclared());
    assertEquals(1, api.minimumVersion());
    assertEquals(19, api.maximumTestedVersion());
    assertTrue(catalog.contains("app.queue-manager.api.targetStability=experimental\n"));
    assertTrue(catalog.contains("app.queue-manager.api.experimentalCapabilitiesAccepted=false\n"));
  }

  @Test
  void write_whenDescriptorAppIdDiffersFromArtifactManifest_expectInvalidCatalogEntry()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            "app.id=other-app");

    AppCatalogException exception =
        captureInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));

    assertTrue(exception.getMessage().contains("app.id must match artifact manifest app.id"));
  }

  @Test
  void write_whenDescriptorVersionDiffersFromArtifactManifest_expectInvalidCatalogEntry()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            "version=1.0.1");

    AppCatalogException exception =
        captureInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));

    assertTrue(exception.getMessage().contains("version must match artifact manifest app.version"));
  }

  @Test
  void write_whenInlineReceiptFingerprintMetadataDiffers_expectInvalidCatalogEntry()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(
            new AppReviewReceiptPayload(
                AppReviewReceiptPayload.RECEIPT_VERSION,
                QUEUE_APP_ID,
                QUEUE_APP_VERSION,
                sha256(artifact),
                Files.size(artifact),
                java.util.Optional.empty(),
                "crypta-app-review-v1",
                "1",
                AppReviewReceiptStatus.REVIEWED,
                "reviewer-dev",
                GENERATED_AT,
                java.util.Optional.empty(),
                java.util.Optional.empty(),
                java.util.Optional.empty(),
                java.util.Optional.empty(),
                java.util.Optional.empty()),
            keyPair.getPrivate());
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            "review.status=reviewed\n"
                + "review.receipt.fingerprint.sha256="
                + "f".repeat(64)
                + "\n"
                + AppReviewReceiptIO.serializeText(receipt));

    AppCatalogException exception =
        captureInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));

    assertTrue(
        exception
            .getMessage()
            .contains("review receipt fingerprint metadata does not match embedded receipt"));
  }

  @Test
  void write_whenAttachedReceiptFingerprintMetadataDiffers_expectInvalidCatalogEntry()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    AppReviewReceipt receipt =
        AppReviewReceiptSigner.sign(
            new AppReviewReceiptPayload(
                AppReviewReceiptPayload.RECEIPT_VERSION,
                QUEUE_APP_ID,
                QUEUE_APP_VERSION,
                sha256(artifact),
                Files.size(artifact),
                java.util.Optional.empty(),
                "crypta-app-review-v1",
                "1",
                AppReviewReceiptStatus.REVIEWED,
                "reviewer-dev",
                GENERATED_AT,
                java.util.Optional.empty(),
                java.util.Optional.empty(),
                java.util.Optional.empty(),
                java.util.Optional.empty(),
                java.util.Optional.empty()),
            keyPair.getPrivate());
    Path receiptFile = tempDir.resolve("review-receipt.properties");
    AppReviewReceiptIO.write(receiptFile, receipt);
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            "review.status=reviewed\n"
                + "review.receipt.fingerprint.sha256="
                + "f".repeat(64)
                + "\n");

    AppCatalogException exception =
        captureInvalidEntry(
            () ->
                AppCatalogWriter.write(
                    new AppCatalogBuildRequest(
                        CATALOG_ID,
                        CATALOG_NAME,
                        GENERATED_AT,
                        List.of(descriptor),
                        List.of(receiptFile))));

    assertTrue(
        exception
            .getMessage()
            .contains("review receipt fingerprint metadata does not match attached receipt"));
  }

  @Test
  void write_whenInlineReceiptPreReviewDigestMetadataDiffers_expectInvalidCatalogEntry()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    AppReviewReceipt receipt = signedReviewReceipt(artifact, "a".repeat(64), "b".repeat(64));
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            "review.status=reviewed\n"
                + "review.preReview.sha256="
                + "c".repeat(64)
                + "\n"
                + AppReviewReceiptIO.serializeText(receipt));

    AppCatalogException exception =
        captureInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));

    assertTrue(
        exception
            .getMessage()
            .contains("review pre-review digest metadata does not match embedded receipt"));
  }

  @Test
  void write_whenAttachedReceiptDecisionReasonDigestMetadataDiffers_expectInvalidCatalogEntry()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    AppReviewReceipt receipt = signedReviewReceipt(artifact, "a".repeat(64), "b".repeat(64));
    Path receiptFile = tempDir.resolve("review-receipt-with-reason.properties");
    AppReviewReceiptIO.write(receiptFile, receipt);
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE,
            artifact,
            QUEUE_BUNDLE_URI,
            LOCAL_QUEUE_SUMMARY,
            "review.status=reviewed\n" + "review.decision.reason.sha256=" + "d".repeat(64) + "\n");

    AppCatalogException exception =
        captureInvalidEntry(
            () ->
                AppCatalogWriter.write(
                    new AppCatalogBuildRequest(
                        CATALOG_ID,
                        CATALOG_NAME,
                        GENERATED_AT,
                        List.of(descriptor),
                        List.of(receiptFile))));

    assertTrue(
        exception
            .getMessage()
            .contains("review decision reason digest metadata does not match attached receipt"));
  }

  @Test
  void write_whenDescriptorIsMalformed_expectInvalidCatalogEntry() throws IOException {
    Path descriptor =
        Files.writeString(
            tempDir.resolve("missing-summary.properties"),
            lines(
                "artifact.path=" + tempDir.resolve("missing.zip"),
                "bundle.uri=" + QUEUE_BUNDLE_URI),
            StandardCharsets.UTF_8);

    assertInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));
  }

  @Test
  void write_whenArtifactIsMalformed_expectInvalidCatalogEntry() throws IOException {
    Path artifact = Files.writeString(tempDir.resolve("not-a-zip.zip"), "not a zip");
    Path descriptor =
        descriptor(QUEUE_DESCRIPTOR_FILE, artifact, QUEUE_BUNDLE_URI, LOCAL_QUEUE_SUMMARY, "");

    assertInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));
  }

  @Test
  void write_whenArtifactExceedsCatalogEntryCap_expectInvalidCatalogEntry() throws Exception {
    Path artifact = appZipExceedingCatalogEntryCap();
    Path descriptor =
        descriptor(QUEUE_DESCRIPTOR_FILE, artifact, QUEUE_BUNDLE_URI, LOCAL_QUEUE_SUMMARY, "");

    AppCatalogException exception =
        captureInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));

    assertTrue(exception.getMessage().contains("too many entries for catalog installation"));
  }

  @Test
  void write_whenArtifactPathIsSymbolicLink_expectInvalidCatalogEntry() throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    Path linkedArtifact = tempDir.resolve("linked-artifact.zip");
    Assumptions.assumeTrue(canCreateSymlink(linkedArtifact));
    Files.createSymbolicLink(linkedArtifact, artifact);
    Path descriptor =
        descriptor(
            QUEUE_DESCRIPTOR_FILE, linkedArtifact, QUEUE_BUNDLE_URI, LOCAL_QUEUE_SUMMARY, "");

    AppCatalogException exception =
        captureInvalidEntry(() -> AppCatalogWriter.write(request(List.of(descriptor))));

    assertTrue(exception.getMessage().contains("artifact.path must not be a symbolic link"));
  }

  @Test
  void write_whenOutputFileIsSymbolicLink_expectRejectsWithoutWritingThroughLink()
      throws Exception {
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    Path descriptor =
        descriptor(QUEUE_DESCRIPTOR_FILE, artifact, QUEUE_BUNDLE_URI, LOCAL_QUEUE_SUMMARY, "");
    Path realCatalog = tempDir.resolve("external-catalog.properties");
    Path linkedCatalog = tempDir.resolve("linked-catalog.properties");
    Files.writeString(realCatalog, "unchanged", StandardCharsets.UTF_8);
    Assumptions.assumeTrue(canCreateSymlink(linkedCatalog));
    Files.createSymbolicLink(linkedCatalog, realCatalog);

    IOException exception =
        assertThrows(
            IOException.class,
            () ->
                AppCatalogWriter.write(request(List.of(descriptor)).withOutputFile(linkedCatalog)));

    assertTrue(exception.getMessage().contains("catalog output path must not be a symbolic link"));
    assertEquals("unchanged", Files.readString(realCatalog, StandardCharsets.UTF_8));
  }

  @Test
  void verify_whenWrittenCatalogIsSigned_expectRoundTrip() throws Exception {
    KeyPair keyPair =
        KeyPairGenerator.getInstance(AppCatalogSignature.SIGNATURE_ALGORITHM).generateKeyPair();
    Path artifact = appZip(QUEUE_APP_ID, QUEUE_APP_NAME, QUEUE_APP_VERSION, QUEUE_READ_PERMISSION);
    Path descriptor =
        descriptor(QUEUE_DESCRIPTOR_FILE, artifact, QUEUE_BUNDLE_URI, LOCAL_QUEUE_SUMMARY, "");
    Path catalogFile = tempDir.resolve(AppCatalogSignature.CATALOG_FILE_NAME);
    AppCatalogWriter.WriteResult result =
        AppCatalogWriter.write(request(List.of(descriptor)).withOutputFile(catalogFile));

    AppCatalogSigner.sign(catalogFile, KEY_ID, keyPair.getPrivate());
    AppCatalog verifiedCatalog = AppCatalogVerifier.verify(catalogFile, trustedKeys(keyPair));

    assertEquals(result.catalog(), verifiedCatalog);
  }

  private AppCatalogBuildRequest request(List<Path> descriptors) {
    return new AppCatalogBuildRequest(CATALOG_ID, CATALOG_NAME, GENERATED_AT, descriptors);
  }

  private static AppReviewReceipt signedReviewReceipt(
      Path artifact, String evidenceSha256, String decisionReasonSha256) throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    return AppReviewReceiptSigner.sign(
        new AppReviewReceiptPayload(
            AppReviewReceiptPayload.RECEIPT_VERSION_WITH_DECISION_REASON,
            QUEUE_APP_ID,
            QUEUE_APP_VERSION,
            sha256(artifact),
            Files.size(artifact),
            java.util.Optional.empty(),
            "crypta-app-review-v1",
            "1",
            AppReviewReceiptStatus.REVIEWED,
            "reviewer-dev",
            GENERATED_AT,
            java.util.Optional.empty(),
            java.util.Optional.ofNullable(evidenceSha256),
            java.util.Optional.ofNullable(decisionReasonSha256),
            java.util.Optional.empty(),
            java.util.Optional.empty()),
        keyPair.getPrivate());
  }

  private static AppCatalogEntry directEntryWithStoreMetadata(Map<String, String> rationales) {
    return new AppCatalogEntry(
        QUEUE_APP_ID,
        QUEUE_APP_NAME,
        QUEUE_APP_VERSION,
        LOCAL_QUEUE_SUMMARY,
        URI.create("https://example.invalid/apps/queue-manager"),
        null,
        null,
        List.of(),
        AppCatalogCompatibilityMetadata.EMPTY,
        AppCatalogReviewMetadata.EMPTY,
        AppCatalogChangelog.EMPTY,
        List.of(),
        URI.create(QUEUE_BUNDLE_URI),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION, "queue.write"),
        rationales);
  }

  private static AppCatalogEntry directEntryWithProductionMetadata() {
    return new AppCatalogEntry(
        QUEUE_APP_ID,
        QUEUE_APP_NAME,
        QUEUE_APP_VERSION,
        LOCAL_QUEUE_SUMMARY,
        null,
        null,
        null,
        List.of(),
        AppCatalogCompatibilityMetadata.EMPTY,
        AppCatalogReviewMetadata.EMPTY,
        AppCatalogChangelog.EMPTY,
        List.of(),
        new AppCatalogProductionMetadata(
            AppCatalogChannel.BETA,
            AppCatalogSupportStatus.EXPERIMENTAL,
            AppCatalogDeprecationStatus.NONE,
            java.util.Optional.empty(),
            java.util.Optional.empty(),
            List.of(),
            true),
        URI.create(QUEUE_BUNDLE_URI),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION),
        Map.of());
  }

  private static AppCatalogEntry directEntryWithMaintenanceMetadata() {
    return new AppCatalogEntry(
        QUEUE_APP_ID,
        QUEUE_APP_NAME,
        QUEUE_APP_VERSION,
        LOCAL_QUEUE_SUMMARY,
        null,
        null,
        null,
        List.of(),
        AppCatalogCompatibilityMetadata.EMPTY,
        AppCatalogReviewMetadata.EMPTY,
        AppCatalogChangelog.EMPTY,
        List.of(),
        new AppCatalogProductionMetadata(
            AppCatalogChannel.STABLE,
            AppCatalogSupportStatus.SUPPORTED,
            AppCatalogDeprecationStatus.NONE,
            java.util.Optional.empty(),
            java.util.Optional.empty(),
            List.of(),
            true),
        maintenanceMetadata(),
        URI.create(QUEUE_BUNDLE_URI),
        "0".repeat(64),
        0L,
        AppCatalogEntry.ZIP_BUNDLE_TYPE,
        List.of(QUEUE_READ_PERMISSION),
        Map.of());
  }

  private static AppCatalogMaintenanceMetadata maintenanceMetadata() {
    return new AppCatalogMaintenanceMetadata(
        java.util.Optional.of("crypta-core"),
        java.util.Optional.of(URI.create("https://example.invalid/crypta/owners/core")),
        java.util.Optional.of(AppCatalogMaintenanceMetadata.SupportLevel.CORE),
        java.util.Optional.of(AppCatalogMaintenanceMetadata.DataSchemaPolicy.STATELESS),
        java.util.Optional.of(AppCatalogMaintenanceMetadata.MigrationPolicy.NONE),
        java.util.Optional.of(AppCatalogMaintenanceMetadata.BackupRestoreSupport.NOT_APPLICABLE),
        java.util.Optional.of(AppCatalogMaintenanceMetadata.SecurityPolicy.CATALOG_ADVISORIES),
        java.util.Optional.of(AppCatalogMaintenanceMetadata.DeprecationPolicy.NONE),
        java.util.Optional.of(
            URI.create("https://example.invalid/crypta/apps/queue-manager/support")),
        true);
  }

  private static AppCatalogSecurityPolicy securityPolicy() {
    return new AppCatalogSecurityPolicy(
        List.of(
            new AppCatalogSecurityAdvisoryRecord(
                "CRYPTA-2026-0001",
                URI.create("https://example.invalid/advisories/CRYPTA-2026-0001"),
                "Queue Manager vulnerable release",
                AppCatalogSecuritySeverity.CRITICAL,
                AppCatalogSecurityStatus.ACTIVE,
                AppCatalogSecurityAction.DENYLIST,
                "Upgrade to a reviewed replacement.",
                Instant.parse("2026-06-11T00:00:00Z"),
                Instant.parse("2026-06-11T00:00:00Z"),
                java.util.Optional.of(QUEUE_APP_ID),
                java.util.Optional.of("Export app data before removal."))),
        List.of(
            new AppCatalogVersionDenylistEntry(
                "deny-queue-1-0-0",
                QUEUE_APP_ID,
                QUEUE_APP_VERSION,
                "CRYPTA-2026-0001",
                "Known vulnerable release.",
                java.util.Optional.of(QUEUE_APP_ID),
                java.util.Optional.of("Use app-data export before removal."))));
  }

  private Path descriptor(
      String fileName, Path artifact, String bundleUri, String summary, String extraProperties)
      throws IOException {
    return Files.writeString(
        tempDir.resolve(fileName),
        lines(
            "artifact.path=" + artifact,
            "bundle.uri=" + bundleUri,
            "summary=" + summary,
            extraProperties),
        StandardCharsets.UTF_8);
  }

  private Path appZip(String appId, String appName, String appVersion, String permissions)
      throws IOException {
    return appZip(appId, appName, appVersion, permissions, "");
  }

  private Path appZip(
      String appId,
      String appName,
      String appVersion,
      String permissions,
      String extraManifestProperties)
      throws IOException {
    Path artifact = tempDir.resolve(appId + ".zip");
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(artifact))) {
      String manifest =
          lines(
              "manifest.version=1",
              "app.id=" + appId,
              "app.name=" + appName,
              "app.version=" + appVersion,
              "app.exec=bin/launch.sh",
              "app.permissions=" + permissions);
      if (!extraManifestProperties.isBlank()) {
        manifest += extraManifestProperties;
      }
      writeZipEntry(zip, AppBundleManifestParser.MANIFEST_FILE_NAME, manifest);
      writeZipEntry(zip, "bin/launch.sh", "#!/bin/sh\nexit 0\n");
    }
    return artifact;
  }

  private Path appZipExceedingCatalogEntryCap() throws IOException {
    Path artifact = tempDir.resolve("entry-cap.zip");
    try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(artifact))) {
      writeZipEntry(
          zip,
          AppBundleManifestParser.MANIFEST_FILE_NAME,
          lines(
              "manifest.version=1",
              "app.id=" + QUEUE_APP_ID,
              "app.name=" + QUEUE_APP_NAME,
              "app.version=" + QUEUE_APP_VERSION,
              "app.exec=bin/launch.sh"));
      for (int index = 0; index < AppBundlePackager.MAX_CATALOG_ZIP_ENTRIES; index++) {
        writeZipEntry(zip, "assets/file-" + index + ".txt", "asset " + index);
      }
    }
    return artifact;
  }

  private static String lines(String... values) {
    return String.join("\n", values) + "\n";
  }

  private static void writeZipEntry(ZipOutputStream zip, String name, String content)
      throws IOException {
    ZipEntry entry = new ZipEntry(name);
    entry.setTime(0L);
    zip.putNextEntry(entry);
    zip.write(content.getBytes(StandardCharsets.UTF_8));
    zip.closeEntry();
  }

  private static String sha256(Path file) throws IOException, NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(Files.readAllBytes(file));
    return HexFormat.of().formatHex(digest.digest());
  }

  private static TrustedAppKeys trustedKeys(KeyPair keyPair) {
    return TrustedAppKeys.of(
        new TrustedAppKey(KEY_ID, AppCatalogSignature.SIGNATURE_ALGORITHM, keyPair.getPublic()));
  }

  private static boolean canCreateSymlink(Path symlink) {
    try {
      Files.createSymbolicLink(symlink, Path.of("missing-target"));
      Files.deleteIfExists(symlink);
      return true;
    } catch (UnsupportedOperationException | IOException | SecurityException _) {
      return false;
    }
  }

  private static void assertInvalidEntry(Executable executable) {
    AppCatalogException exception = assertThrows(AppCatalogException.class, executable);

    assertInvalidCatalogEntryErrorCode(exception);
  }

  private static AppCatalogException captureInvalidEntry(Executable executable) {
    AppCatalogException exception = assertThrows(AppCatalogException.class, executable);

    assertInvalidCatalogEntryErrorCode(exception);
    return exception;
  }

  private static void assertInvalidCatalogEntryErrorCode(AppCatalogException exception) {
    assertEquals(AppCatalogSidecars.INVALID_CATALOG_ENTRY, exception.errorCode());
  }
}
