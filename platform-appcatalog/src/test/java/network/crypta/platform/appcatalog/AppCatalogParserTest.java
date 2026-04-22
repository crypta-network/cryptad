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

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }
}
