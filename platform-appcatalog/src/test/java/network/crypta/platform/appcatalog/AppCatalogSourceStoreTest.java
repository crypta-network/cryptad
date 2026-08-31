package network.crypta.platform.appcatalog;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
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
    assertEquals(REFRESHED_AT, stored.refreshMetadata().lastAttemptAt());
    assertEquals(REFRESHED_AT, stored.refreshMetadata().lastSuccessfulRefreshAt());
    assertEquals(AppCatalogFetchStatus.SUCCESS, stored.refreshMetadata().lastFetchStatus());
    assertTrue(stored.refreshMetadata().lastFetchErrorCode().isEmpty());
    assertEquals(
        source.resolvedCatalogFetchUri(), stored.refreshMetadata().lastResolvedUri().orElseThrow());
    assertArrayEquals(fetchedCatalog.catalogBytes(), stored.fetchedCatalog().catalogBytes());
    assertArrayEquals(fetchedCatalog.signatureBytes(), stored.fetchedCatalog().signatureBytes());
  }

  @Test
  void writeAndRead_whenFederatedBindingProvided_expectExactBindingIdentityPersists()
      throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    FetchedCatalog fetchedCatalog = fetchedCatalog("core");
    AppCatalogSource source = source("core");
    AppCatalogMirror primary = AppCatalogMirror.primary(source, ADDED_AT);

    store.write(
        new AppCatalogSourceStore.VerifiedCatalogWrite(
            catalog("core"),
            source,
            fetchedCatalog,
            ADDED_AT,
            REFRESHED_AT,
            Optional.of("binding-1"),
            Optional.of("a".repeat(64))),
        new AppCatalogSourceStore.EndpointWriteState(primary, List.of(primary), Map.of()));
    StoredCatalogSource stored = store.read("core");

    assertEquals(Optional.of("binding-1"), stored.trustBindingId());
    assertEquals(Optional.of("a".repeat(64)), stored.trustBindingDigest());
  }

  @Test
  void write_whenOriginRevisionIsPinned_expectPruningPreservesExactRevision() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    FetchedCatalog originRevision = fetchedCatalog("core");
    String originDigest = AppCatalogRevisions.catalogDigest(originRevision);
    AppCatalogSource catalogSource = source("core");
    store.write(catalog("core"), catalogSource, originRevision, ADDED_AT, REFRESHED_AT);
    store.retainOriginRevisions(List.of(originRevision(originRevision)));
    FetchedCatalog currentRevision = originRevision;
    for (int revision = 1; revision <= 7; revision++) {
      currentRevision =
          new FetchedCatalog(
              bytes("catalog.id=core\nrevision=" + revision + "\n"),
              signatureBytes("test-" + revision));
      store.write(
          catalog("core"),
          catalogSource,
          currentRevision,
          ADDED_AT,
          REFRESHED_AT.plusSeconds(revision));
    }

    List<AppCatalogVerifiedRevision> revisions =
        store.listRevisions("core", AppCatalogRevisions.catalogDigest(currentRevision));
    FetchedCatalog retained = store.readRevision("core", originDigest);

    assertTrue(
        revisions.stream().anyMatch(revision -> originDigest.equals(revision.revisionDigest())));
    assertArrayEquals(originRevision.catalogBytes(), retained.catalogBytes());
    assertArrayEquals(originRevision.signatureBytes(), retained.signatureBytes());
  }

  @Test
  void reconcileOriginRevisions_whenOriginSlotRotates_expectObsoletePinReleased() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    FetchedCatalog obsoleteRevision = fetchedCatalog("core");
    String obsoleteDigest = AppCatalogRevisions.catalogDigest(obsoleteRevision);
    AppCatalogSource catalogSource = source("core");
    store.write(catalog("core"), catalogSource, obsoleteRevision, ADDED_AT, REFRESHED_AT);
    store.retainOriginRevisions(List.of(originRevision(obsoleteRevision)));
    FetchedCatalog currentRevision = obsoleteRevision;
    for (int revision = 1; revision <= 7; revision++) {
      currentRevision =
          new FetchedCatalog(
              bytes("catalog.id=core\nrevision=" + revision + "\n"),
              signatureBytes("test-" + revision));
      store.write(
          catalog("core"),
          catalogSource,
          currentRevision,
          ADDED_AT,
          REFRESHED_AT.plusSeconds(revision));
    }
    String currentDigest = AppCatalogRevisions.catalogDigest(currentRevision);
    String currentContentDigest =
        AppCatalogRevisions.digestDirectoryName(
            AppCatalogRevisions.catalogContentDigest(currentRevision));

    store.reconcileOriginRevisions(
        List.of(
            new AppCatalogManager.OriginRevision(
                "core", currentContentDigest, "test-7", "feed-reader")));
    FetchedCatalog nextRevision =
        new FetchedCatalog(bytes("catalog.id=core\nrevision=8\n"), signatureBytes("test-8"));
    store.write(
        catalog("core"), catalogSource, nextRevision, ADDED_AT, REFRESHED_AT.plusSeconds(8));

    List<AppCatalogVerifiedRevision> revisions =
        store.listRevisions("core", AppCatalogRevisions.catalogDigest(nextRevision));

    assertFalse(
        revisions.stream().anyMatch(revision -> obsoleteDigest.equals(revision.revisionDigest())));
    assertTrue(
        revisions.stream().anyMatch(revision -> currentDigest.equals(revision.revisionDigest())));
  }

  @Test
  void read_whenLegacySingleSourceExists_expectPrimaryOnlyMirrorModel() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    FetchedCatalog fetchedCatalog = fetchedCatalog("core");
    AppCatalogSource source = source("core");

    store.write(catalog("core"), source, fetchedCatalog, ADDED_AT, REFRESHED_AT);
    StoredCatalogSource stored = store.read("core");

    assertEquals(1, stored.mirrors().size());
    AppCatalogMirror primary = stored.mirrors().getFirst();
    assertEquals(AppCatalogMirrorId.PRIMARY, primary.id());
    assertEquals(AppCatalogSourceRole.PRIMARY, primary.role());
    assertEquals(source, primary.source());
    assertEquals(0, primary.priority());
    assertTrue(primary.enabled());
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
  void write_whenExistingSourceMetadataWriteFails_expectPreviousSidecarsPreserved()
      throws Exception {
    Path rootDirectory = tempDir.resolve(STORE_DIRECTORY);
    AppCatalogSourceStore store = new AppCatalogSourceStore(rootDirectory);
    FetchedCatalog original = fetchedCatalog("core");
    FetchedCatalog replacement =
        new FetchedCatalog(
            bytes("catalog.id=core\nreplacement=true\n"),
            bytes("catalog.signature.key.id=replacement\n"));
    store.write(catalog("core"), source("core"), original, ADDED_AT, REFRESHED_AT);
    String originalDigest = AppCatalogRevisions.catalogDigest(original);
    String replacementDigest = AppCatalogRevisions.catalogDigest(replacement);
    Instant replacementRefreshedAt = REFRESHED_AT.plusSeconds(60);
    AppCatalogMirror primary = AppCatalogMirror.primary(source("core"), ADDED_AT);
    Map<AppCatalogMirrorId, AppCatalogMirrorHealth> replacementHealth =
        Map.of(
            primary.id(),
            AppCatalogMirrorHealth.skipped(primary)
                .successfulAttempt(
                    replacementRefreshedAt,
                    primary.source().resolvedCatalogFetchUri(),
                    replacementDigest,
                    "replacement",
                    replacementRefreshedAt));
    AppCatalogSourceStore.SourceMetadataWriter failingWriter =
        (_, _, _) -> {
          throw new IOException("metadata write failed");
        };
    AppCatalogSourceStore failingStore = new AppCatalogSourceStore(rootDirectory, failingWriter);

    IOException exception =
        assertThrows(
            IOException.class,
            () ->
                failingStore.write(
                    new AppCatalogSourceStore.VerifiedCatalogWrite(
                        catalog("core"),
                        source("core"),
                        replacement,
                        ADDED_AT,
                        replacementRefreshedAt),
                    new AppCatalogSourceStore.EndpointWriteState(
                        primary, List.of(primary), replacementHealth)));
    StoredCatalogSource stored = store.read("core");
    List<AppCatalogVerifiedRevision> revisions = store.listRevisions("core", originalDigest);

    assertEquals("metadata write failed", exception.getMessage());
    assertEquals(REFRESHED_AT, stored.refreshedAt());
    assertEquals(AppCatalogFetchStatus.SUCCESS, stored.refreshMetadata().lastFetchStatus());
    assertArrayEquals(original.catalogBytes(), stored.fetchedCatalog().catalogBytes());
    assertArrayEquals(original.signatureBytes(), stored.fetchedCatalog().signatureBytes());
    assertTrue(stored.mirrorHealth().isEmpty());
    assertEquals(
        List.of(originalDigest),
        revisions.stream().map(AppCatalogVerifiedRevision::revisionDigest).toList());
    assertFalse(
        Files.exists(
            rootDirectory
                .resolve("core")
                .resolve("history")
                .resolve(AppCatalogRevisions.digestDirectoryName(replacementDigest))));
  }

  @Test
  void recordRefreshFailure_whenRefreshFails_expectAttemptMetadataUpdatedOnly() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    FetchedCatalog original = fetchedCatalog("core");
    AppCatalogSource source = source("core");
    store.write(catalog("core"), source, original, ADDED_AT, REFRESHED_AT);
    StoredCatalogSource beforeFailure = store.read("core");
    Instant failedAt = REFRESHED_AT.plusSeconds(60);

    store.recordRefreshFailure(
        beforeFailure,
        failedAt,
        new AppCatalogException(AppCatalogSidecars.CATALOG_FETCH_FAILED, "fetch failed"));
    StoredCatalogSource stored = store.read("core");

    assertEquals(REFRESHED_AT, stored.refreshedAt());
    assertEquals(failedAt, stored.refreshMetadata().lastAttemptAt());
    assertEquals(REFRESHED_AT, stored.refreshMetadata().lastSuccessfulRefreshAt());
    assertEquals(AppCatalogFetchStatus.FAILED, stored.refreshMetadata().lastFetchStatus());
    assertEquals(
        AppCatalogSidecars.CATALOG_FETCH_FAILED,
        stored.refreshMetadata().lastFetchErrorCode().orElseThrow());
    assertArrayEquals(original.catalogBytes(), stored.fetchedCatalog().catalogBytes());
    assertArrayEquals(original.signatureBytes(), stored.fetchedCatalog().signatureBytes());
  }

  @Test
  void recordRefreshFailure_whenMessageHasUnsafeText_expectStoredMessageIsSafeSingleLine()
      throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    FetchedCatalog original = fetchedCatalog("core");
    AppCatalogSource source = source("core");
    store.write(catalog("core"), source, original, ADDED_AT, REFRESHED_AT);
    StoredCatalogSource beforeFailure = store.read("core");
    String unsafeMessage = "fetch failed\nwith\ttabs\r" + "x".repeat(600);

    store.recordRefreshFailure(
        beforeFailure,
        REFRESHED_AT.plusSeconds(60),
        new AppCatalogException(AppCatalogSidecars.CATALOG_FETCH_FAILED, unsafeMessage));
    StoredCatalogSource stored = store.read("core");

    String storedMessage = stored.refreshMetadata().lastFetchErrorMessage().orElseThrow();
    assertFalse(storedMessage.contains("\n"));
    assertFalse(storedMessage.contains("\r"));
    assertFalse(storedMessage.contains("\t"));
    assertTrue(storedMessage.length() <= 512);
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
  void read_whenSourceMetadataLineIsMalformed_expectInvalidCatalogSource() throws Exception {
    AppCatalogSourceStore store = new AppCatalogSourceStore(tempDir.resolve(STORE_DIRECTORY));
    Path catalogDirectory = Files.createDirectories(store.rootDirectory().resolve("core"));
    Files.writeString(catalogDirectory.resolve(SOURCE_FILE_NAME), "not-a-key-value-line\n");

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
    return new FetchedCatalog(bytes("catalog.id=" + catalogId + "\n"), signatureBytes("test"));
  }

  private static AppCatalogManager.OriginRevision originRevision(FetchedCatalog revision) {
    return new AppCatalogManager.OriginRevision(
        "core",
        AppCatalogRevisions.digestDirectoryName(AppCatalogRevisions.catalogContentDigest(revision)),
        "test",
        "feed-reader");
  }

  private static byte[] signatureBytes(String keyId) {
    return bytes(
        """
        catalog.signature.version=1
        catalog.signature.algorithm=Ed25519
        catalog.signature.key.id=%s
        catalog.signature.payload=cryptad-app-catalog.properties
        catalog.signature.value.base64=AA==
        """
            .formatted(keyId));
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
