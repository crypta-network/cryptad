package network.crypta.platform.appcatalog;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SuppressWarnings("java:S100")
class AppCatalogSourceStoreTest {
  private static final String SOURCE_FILE_NAME = "catalog-source.properties";
  private static final String STORE_DIRECTORY = "store";
  private static final String ALPHA_CATALOG_ID = "alpha";
  private static final Instant ADDED_AT = Instant.parse("2026-04-21T18:22:40Z");
  private static final Instant REFRESHED_AT = Instant.parse("2026-04-21T19:22:40Z");

  @TempDir private Path tempDir;

  @Test
  void list_whenStoreDirectoryMissing_expectEmptyList() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve("missing"));

    assertTrue(store.list().isEmpty());
  }

  @Test
  void writeAndRead_whenSourcePersists_expectSidecarBytesAndTimestamps() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    FetchedCatalog fetchedCatalog = fetchedCatalog("core");
    AppCatalogSource source = source("core");

    store.write(catalog("core"), source, fetchedCatalog, ADDED_AT, REFRESHED_AT);
    StoredCatalogSource stored = store.read("core");

    assertEquals(source, stored.source());
    assertEquals(ADDED_AT, stored.addedAt());
    assertEquals(REFRESHED_AT, stored.refreshedAt());
    assertArrayEquals(fetchedCatalog.catalogBytes(), stored.fetchedCatalog().catalogBytes());
    assertArrayEquals(fetchedCatalog.signatureBytes(), stored.fetchedCatalog().signatureBytes());
  }

  @Test
  void list_whenStagingDirectoryExists_expectStagingSkippedAndCatalogsSorted() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    store.write(catalog("zeta"), source("zeta"), fetchedCatalog("zeta"), ADDED_AT, REFRESHED_AT);
    store.write(
        catalog(ALPHA_CATALOG_ID),
        source(ALPHA_CATALOG_ID),
        fetchedCatalog(ALPHA_CATALOG_ID),
        ADDED_AT,
        REFRESHED_AT);
    Files.createDirectories(store.stagingDirectory());
    Files.writeString(store.stagingDirectory().resolve("scratch.tmp"), "scratch");

    List<StoredCatalogSource> stored = store.list();

    assertEquals(
        List.of(source(ALPHA_CATALOG_ID).displayUri(), source("zeta").displayUri()),
        stored.stream().map(source -> source.source().displayUri()).toList());
  }

  @Test
  void listAndWrite_whenDirectoryHasSidecarsButNoSource_expectSkippedAndRetrySucceeds()
      throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    Path catalogDirectory = Files.createDirectories(store.rootDirectory().resolve("core"));
    Files.write(
        catalogDirectory.resolve(AppCatalogSignature.CATALOG_FILE_NAME), bytes("partial catalog"));
    Files.write(
        catalogDirectory.resolve(AppCatalogSignature.SIGNATURE_FILE_NAME),
        bytes("partial signature"));
    FetchedCatalog fetchedCatalog = fetchedCatalog("core");

    assertFalse(store.exists("core"));
    assertTrue(store.list().isEmpty());

    store.write(catalog("core"), source("core"), fetchedCatalog, ADDED_AT, REFRESHED_AT);
    StoredCatalogSource stored = store.read("core");

    assertArrayEquals(fetchedCatalog.catalogBytes(), stored.fetchedCatalog().catalogBytes());
    assertArrayEquals(fetchedCatalog.signatureBytes(), stored.fetchedCatalog().signatureBytes());
  }

  @Test
  void remove_whenCatalogExists_expectCatalogDeletedAndStagingPreserved() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    store.write(catalog("core"), source("core"), fetchedCatalog("core"), ADDED_AT, REFRESHED_AT);
    Files.createDirectories(store.stagingDirectory());

    store.remove("core");

    assertFalse(store.exists("core"));
    assertTrue(Files.isDirectory(store.stagingDirectory()));
  }

  @Test
  void remove_whenCatalogMissing_expectCatalogNotFound() {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> store.remove("missing"));

    assertEquals(AppCatalogSidecars.CATALOG_NOT_FOUND, exception.errorCode());
  }

  @Test
  void read_whenMetadataIdDoesNotMatchDirectory_expectInvalidCatalogSource() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    store.write(catalog("core"), source("core"), fetchedCatalog("core"), ADDED_AT, REFRESHED_AT);
    Files.writeString(
        store.rootDirectory().resolve("core").resolve(SOURCE_FILE_NAME),
        sourceMetadata("other", source("core").displayUri()));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> store.read("core"));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  @Test
  void read_whenStoredSourceUriIsMalformed_expectInvalidCatalogSource() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    Path catalogDirectory = Files.createDirectories(store.rootDirectory().resolve("core"));
    Files.writeString(
        catalogDirectory.resolve(SOURCE_FILE_NAME), sourceMetadata("core", "not a uri"));

    AppCatalogException exception =
        assertThrows(AppCatalogException.class, () -> store.read("core"));

    assertEquals(AppCatalogSidecars.INVALID_CATALOG_SOURCE, exception.errorCode());
  }

  private static AppCatalog catalog(String catalogId) {
    return new AppCatalog(1, catalogId, "Catalog " + catalogId, REFRESHED_AT, List.of());
  }

  private static AppCatalogSource source(String catalogId) {
    return new AppCatalogSource(
        URI.create("https://example.invalid/" + catalogId + "/cryptad-app-catalog.properties"));
  }

  private static FetchedCatalog fetchedCatalog(String catalogId) {
    return new FetchedCatalog(
        bytes("catalog.id=" + catalogId + "\n"), bytes("catalog.signature.key.id=test\n"));
  }

  private static String sourceMetadata(String catalogId, String sourceUri) {
    return """
    catalog.source.version=1
    catalog.id=%s
    source.uri=%s
    source.addedAt=%s
    source.refreshedAt=%s
    """
        .formatted(catalogId, sourceUri, ADDED_AT, REFRESHED_AT);
  }

  private static byte[] bytes(String value) {
    return value.getBytes(StandardCharsets.UTF_8);
  }
}
