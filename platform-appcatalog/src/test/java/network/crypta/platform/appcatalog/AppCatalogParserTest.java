package network.crypta.platform.appcatalog;

import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogParserTest {
  private static final String GENERATED_AT = "2026-04-21T18:22:40Z";
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
  void parse_whenCatalogHasOptionalStoreMetadata_expectMetadataNormalized() {
    AppCatalog catalog =
        AppCatalogParser.parse(
            bytes(
                """
                catalog.version=2
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

    assertEquals(AppCatalog.VERSION_STORE_METADATA, catalog.version());
    assertEquals("https://example.invalid/app", entry.homepage().orElseThrow().toString());
    assertEquals("https://example.invalid/repo", entry.source().orElseThrow().toString());
    assertEquals("MIT", entry.license().orElseThrow());
    assertEquals(List.of("productivity", "network"), entry.categories());
    assertEquals("0.1.0", entry.compatibility().minimumCryptaVersion().orElseThrow());
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
  void parse_whenVersionOneCatalogDeclaresStoreMetadata_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validSingleEntryCatalog()
            .replace(
                "app.queue-manager.bundle.uri=",
                "app.queue-manager.homepage=https://example.invalid/app\n"
                    + "app.queue-manager.bundle.uri="));
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
                "app.queue-manager.bundle.uri=",
                "app.queue-manager.review.status=trusted\napp.queue-manager.bundle.uri="));
  }

  @Test
  void parse_whenCategoryIsMalformed_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                "app.queue-manager.bundle.uri=",
                "app.queue-manager.categories=bad category\napp.queue-manager.bundle.uri="));
  }

  @Test
  void parse_whenMetadataUriUsesUnsafeScheme_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                "app.queue-manager.bundle.uri=",
                "app.queue-manager.homepage=http://example.invalid/app\n"
                    + "app.queue-manager.bundle.uri="));
  }

  @Test
  void parse_whenMetadataUriUsesLoopbackHttp_expectAccepted() {
    AppCatalog catalog =
        AppCatalogParser.parse(
            bytes(
                validStoreMetadataCatalog()
                    .replace(
                        "app.queue-manager.bundle.uri=",
                        "app.queue-manager.homepage=http://localhost:8080/app\n"
                            + "app.queue-manager.bundle.uri=")));

    AppCatalogEntry entry = catalog.entries().getFirst();

    assertEquals("http://localhost:8080/app", entry.homepage().orElseThrow().toString());
  }

  @Test
  void parse_whenPermissionRationaleDoesNotMatchDeclaredPermission_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                "app.queue-manager.bundle.uri=",
                "app.queue-manager.permissions.rationale.queue.write=Writes queues.\n"
                    + "app.queue-manager.bundle.uri="));
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
                "app.queue-manager.bundle.uri=",
                "app.queue-manager.screenshot.2=https://example.invalid/assets/shot-2.png\n"
                    + "app.queue-manager.bundle.uri="));
  }

  @Test
  void parse_whenScreenshotCountExceedsCap_expectInvalidCatalogEntry() {
    assertInvalidEntry(
        validStoreMetadataCatalog()
            .replace(
                "app.queue-manager.bundle.uri=",
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
                "app.queue-manager.bundle.uri=",
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

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }
}
